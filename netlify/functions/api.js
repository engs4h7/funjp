'use strict';
const A = require('../lib/auth');
const V = require('../lib/validate');
const DB = require('../lib/db');

const MAX_FAILS = 5;                    // wrong passwords before a temporary lock
const LOCK_MS = 15 * 60 * 1000;         // lock length

function respond(status, body, cookie, extra) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
  if (cookie) headers['Set-Cookie'] = cookie;
  if (extra) Object.assign(headers, extra);
  return { statusCode: status, headers, body: JSON.stringify(body) };
}
const fail = (status, error, message, extra) => respond(status, { error, message }, null, extra);

function header(event, name) {
  const h = event.headers || {};
  const v = h[name] !== undefined ? h[name] : h[name.toLowerCase()];
  return v === undefined ? '' : String(v);
}

// State-changing requests must come from this site (blocks cross-site form posts / fetches).
function originOk(event) {
  const origin = header(event, 'origin');
  if (!origin) return true;             // non-browser client or same-origin without an Origin header
  const host = (header(event, 'x-forwarded-host') || header(event, 'host')).split(',')[0].trim();
  try { return new URL(origin).host === host; } catch (e) { return false; }
}

function parseJsonBody(event) {
  if (!/^application\/json/i.test(header(event, 'content-type'))) return { error: 'unsupported_media_type' };
  let raw = event.body || '';
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (raw.length > V.MAX_BODY_BYTES) return { error: 'too_large' };
  try {
    const v = JSON.parse(raw || '{}');
    return v && typeof v === 'object' ? { value: v } : { error: 'bad_request' };
  } catch (e) { return { error: 'bad_request' }; }
}

function createHandler(deps) {
  deps = deps || {};
  const nowMs = () => (deps.now ? deps.now() : Date.now());
  const nowSec = () => Math.floor(nowMs() / 1000);
  const iso = (ms) => new Date(ms).toISOString();

  async function currentUser(event, env, sql) {
    const token = A.parseCookies(header(event, 'cookie'))[A.COOKIE_NAME];
    const payload = A.verify(token, env.JWT_SECRET, nowSec());
    if (!payload || !/^\d{1,18}$/.test(String(payload.sub))) return null;
    const rows = await sql`select id, username, email from users where id = ${String(payload.sub)}`;
    return rows[0] ? { id: String(rows[0].id), username: rows[0].username, email: rows[0].email } : null;
  }

  function loginCookie(user, env) {
    const token = A.newSessionToken(user.id, env.JWT_SECRET, nowSec());
    return A.sessionCookie(token, { insecure: String(env.ALLOW_INSECURE_COOKIES) === 'true' });
  }

  // ---------- routes ----------
  async function me(event, env, sql) {
    const user = await currentUser(event, env, sql);
    return respond(200, {
      user,
      signup: { open: String(env.ALLOW_SIGNUP).toLowerCase() !== 'false', requiresCode: !!env.SIGNUP_CODE }
    });
  }

  async function signup(event, env, sql) {
    if (String(env.ALLOW_SIGNUP).toLowerCase() === 'false') return fail(403, 'signup_closed', 'New accounts are closed.');
    const parsed = parseJsonBody(event);
    if (parsed.error) return fail(parsed.error === 'unsupported_media_type' ? 415 : 400, parsed.error, 'Invalid request.');
    const body = parsed.value;
    if (env.SIGNUP_CODE && !A.safeEqual(body.code || '', env.SIGNUP_CODE)) return fail(403, 'bad_code', 'That invite code is not valid.');
    const u = V.username(body.username);
    if (!u.ok) return fail(400, 'bad_username', u.message);
    const e = V.email(body.email);
    if (!e.ok) return fail(400, 'bad_email', e.message);
    const p = V.password(body.password, u.value);
    if (!p.ok) return fail(400, 'bad_password', p.message);

    const hash = await A.hashPassword(body.password);
    let rows;
    try {
      rows = await sql`insert into users (username, username_lc, email, password_hash) values (${u.value}, ${u.lc}, ${e.value}, ${hash}) returning id, username, email`;
    } catch (e) {
      if (e && (e.code === '23505' || /unique|duplicate/i.test(e.message || ''))) {
        const emailConflict = /email/i.test(String(e.constraint || '') + ' ' + String(e.message || ''));
        return emailConflict
          ? fail(409, 'email_taken', 'That email address is already registered.')
          : fail(409, 'username_taken', 'That username is already taken.');
      }
      throw e;
    }
    const user = { id: String(rows[0].id), username: rows[0].username, email: rows[0].email };
    return respond(201, { user }, loginCookie(user, env));
  }

  async function login(event, env, sql) {
    const parsed = parseJsonBody(event);
    if (parsed.error) return fail(parsed.error === 'unsupported_media_type' ? 415 : 400, parsed.error, 'Invalid request.');
    const body = parsed.value;
    const lc = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const generic = () => fail(401, 'invalid_credentials', 'Invalid username or password.');
    if (!lc || !password || lc.length > 64 || password.length > 200) return generic();

    const nowIso = iso(nowMs());
    const rows = await sql`
      select id, username, password_hash, failed_attempts,
             (locked_until is not null and locked_until > ${nowIso}::timestamptz) as locked
      from users where username_lc = ${lc}`;
    const row = rows[0];

    if (!row) {                                   // unknown user: do equal work, then answer generically
      await A.verifyPassword(password, await A.dummyHash());
      return generic();
    }
    if (row.locked) return fail(429, 'locked', 'Too many failed attempts. Please try again in a few minutes.');

    const ok = await A.verifyPassword(password, row.password_hash);
    if (!ok) {
      const lockIso = iso(nowMs() + LOCK_MS);
      await sql`
        update users set
          failed_attempts = case when failed_attempts + 1 >= ${MAX_FAILS} then 0 else failed_attempts + 1 end,
          locked_until = case when failed_attempts + 1 >= ${MAX_FAILS} then ${lockIso}::timestamptz else locked_until end
        where id = ${row.id}`;
      return generic();
    }
    if (Number(row.failed_attempts) > 0) await sql`update users set failed_attempts = 0, locked_until = null where id = ${row.id}`;
    const user = { id: String(row.id), username: row.username };
    return respond(200, { user }, loginCookie(user, env));
  }

  function logout(event, env) {
    return respond(200, { ok: true }, A.sessionCookie('', { insecure: String(env.ALLOW_INSECURE_COOKIES) === 'true', maxAge: 0 }));
  }

  async function getProgress(event, env, sql) {
    const user = await currentUser(event, env, sql);
    if (!user) return fail(401, 'unauthorized', 'Please sign in.');
    const app = V.appId((event.queryStringParameters || {}).app);
    if (!app) return fail(400, 'bad_app', 'Unknown app.');
    const rows = await sql`select data, version, updated_at from user_progress where user_id = ${user.id} and app = ${app}`;
    const row = rows[0];
    return respond(200, row
      ? { data: row.data, version: Number(row.version), updatedAt: row.updated_at }
      : { data: null, version: 0, updatedAt: null });
  }

  async function putProgress(event, env, sql) {
    const user = await currentUser(event, env, sql);
    if (!user) return fail(401, 'unauthorized', 'Please sign in.');
    const parsed = parseJsonBody(event);
    if (parsed.error) return fail(parsed.error === 'unsupported_media_type' ? 415 : (parsed.error === 'too_large' ? 413 : 400), parsed.error, 'Invalid request.');
    const body = parsed.value;
    const check = V.progress(body.app, body.data);
    if (!check.ok) return fail(400, 'bad_data', check.message);
    const app = body.app;
    const base = Number.isInteger(body.baseVersion) && body.baseVersion >= 0 ? body.baseVersion : 0;
    const json = JSON.stringify(check.value);
    const nowIso = iso(nowMs());

    let rows;
    if (base === 0) {
      rows = await sql`
        insert into user_progress (user_id, app, data, version, updated_at)
        values (${user.id}, ${app}, ${json}::jsonb, 1, ${nowIso}::timestamptz)
        on conflict (user_id, app) do nothing
        returning version, updated_at`;
    } else {
      rows = await sql`
        update user_progress set data = ${json}::jsonb, version = version + 1, updated_at = ${nowIso}::timestamptz
        where user_id = ${user.id} and app = ${app} and version = ${base}
        returning version, updated_at`;
    }
    if (rows[0]) return respond(200, { ok: true, version: Number(rows[0].version), updatedAt: rows[0].updated_at });

    // Someone saved in between (another device): hand back the current copy so the client can merge.
    const cur = await sql`select data, version, updated_at from user_progress where user_id = ${user.id} and app = ${app}`;
    return respond(409, {
      error: 'conflict', message: 'Your progress changed on another device.',
      data: cur[0] ? cur[0].data : null, version: cur[0] ? Number(cur[0].version) : 0
    });
  }

  const ROUTES = {
    me:       { GET: me },
    signup:   { POST: signup },
    login:    { POST: login },
    logout:   { POST: logout },
    progress: { GET: getProgress, PUT: putProgress }
  };

  return async function handler(event) {
    const env = deps.env || process.env;
    const m = String(event.path || '').match(/\/api\/([A-Za-z]+)\/?$/);
    const name = m ? m[1].toLowerCase() : '';
    const route = Object.prototype.hasOwnProperty.call(ROUTES, name) ? ROUTES[name] : null;
    if (!route) return fail(404, 'not_found', 'Not found.');
    const fn = route[event.httpMethod];
    if (!fn) return fail(405, 'method_not_allowed', 'Method not allowed.', { Allow: Object.keys(route).join(', ') });
    if (event.httpMethod !== 'GET' && !originOk(event)) return fail(403, 'bad_origin', 'Cross-site request blocked.');

    try {
      if (!env.JWT_SECRET || String(env.JWT_SECRET).length < 32) {
        console.error('JWT_SECRET is missing or shorter than 32 characters');
        return fail(500, 'server_misconfigured', 'The server is not set up correctly yet.');
      }
      const sql = deps.sql || DB.getSql(env);
      await DB.ensureSchema(sql);
      return await fn(event, env, sql);
    } catch (e) {
      console.error('api error:', e && e.code, e && e.message);
      if (e && e.code === 'NO_DB') return fail(500, 'server_misconfigured', 'The server is not set up correctly yet.');
      return fail(500, 'server_error', 'Something went wrong on the server.');
    }
  };
}

exports.createHandler = createHandler;
exports.handler = createHandler();
