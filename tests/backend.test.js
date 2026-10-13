'use strict';
// Run with:  npm test      (needs Node 22.13+ because it uses the built-in node:sqlite)
//
// These tests run the REAL request handler against an in-memory SQLite database that
// accepts the same tagged-template queries. That checks the application logic (validation,
// hashing, cookies, lockout, versions, per-user isolation). It cannot prove Neon connectivity -
// do a real signup after deploying (see README).
let DatabaseSync;
try { ({ DatabaseSync } = require('node:sqlite')); }
catch (e) { console.log('SKIPPED: node:sqlite is not available in this Node version (use Node 22.13+).'); process.exit(0); }

const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../netlify/lib/auth');
const DB = require('../netlify/lib/db');
const V = require('../netlify/lib/validate');
const { createHandler } = require('../netlify/functions/api');

// ---- tiny Postgres->SQLite shim, just enough for the queries this app runs ----
function makeSql() {
  const db = new DatabaseSync(':memory:');
  const translate = (t) => t
    .replace(/::(timestamptz|jsonb|text)/gi, '')
    .replace(/bigint generated always as identity primary key/gi, 'integer primary key autoincrement')
    .replace(/\btimestamptz\b/gi, 'text')
    .replace(/\bjsonb\b/gi, 'text')
    .replace(/default now\(\)/gi, "default (strftime('%Y-%m-%dT%H:%M:%fZ','now'))");
  const sql = (strings, ...values) => {
    const text = strings.reduce((acc, s, i) => acc + s + (i < values.length ? '?' : ''), '');
    const rows = db.prepare(translate(text)).all(...values);
    return Promise.resolve(rows.map((r) => {
      const o = Object.assign({}, r);
      if (typeof o.data === 'string') o.data = JSON.parse(o.data);
      return o;
    }));
  };
  sql._db = db;
  return sql;
}

const SECRET = 'a'.repeat(48);
function setup(envExtra, startMs) {
  const clock = { t: startMs || Date.parse('2026-01-01T00:00:00Z') };
  const sql = makeSql();
  const handler = createHandler({ sql, env: Object.assign({ JWT_SECRET: SECRET }, envExtra || {}), now: () => clock.t });
  return { clock, sql, handler };
}
function ev(method, path, o) {
  o = o || {};
  const headers = { host: o.host || 'app.test' };
  if (o.origin) headers.origin = o.origin;
  if (o.cookie) headers.cookie = o.cookie;
  if (o.body !== undefined) headers['content-type'] = o.ct || 'application/json';
  return {
    httpMethod: method, path, headers, isBase64Encoded: false,
    queryStringParameters: o.query || null,
    body: o.body === undefined ? null : (typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
  };
}
const cookieOf = (res) => (res.headers['Set-Cookie'] || '').split(';')[0];
const bodyOf = (res) => JSON.parse(res.body);
async function signup(h, username, password, extra) {
  return h(ev('POST', '/api/signup', { body: Object.assign({ username, password }, extra || {}) }));
}

// ---------------------------------------------------------------- helpers
test('password hashing: verifies, salts differ, rejects wrong/garbage', async () => {
  const h1 = await A.hashPassword('correct horse battery');
  const h2 = await A.hashPassword('correct horse battery');
  assert.notEqual(h1, h2);
  assert.match(h1, /^scrypt\$16384\$8\$1\$/);
  assert.equal(await A.verifyPassword('correct horse battery', h1), true);
  assert.equal(await A.verifyPassword('wrong', h1), false);
  assert.equal(await A.verifyPassword('x', 'not-a-hash'), false);
  assert.equal(await A.verifyPassword('x', 'scrypt$1$1$1$AA$AA'), false);
});

test('tokens: round trip, tampering, wrong secret, expiry', () => {
  const now = 1_000_000;
  const tok = A.newSessionToken('7', SECRET, now);
  assert.equal(A.verify(tok, SECRET, now + 10).sub, '7');
  assert.equal(A.verify(tok, 'b'.repeat(48), now + 10), null);
  assert.equal(A.verify(tok + 'x', SECRET, now + 10), null);
  const [body, mac] = tok.split('.');
  const forged = Buffer.from(JSON.stringify({ sub: '8', iat: now, exp: now + 9999 })).toString('base64url') + '.' + mac;
  assert.equal(A.verify(forged, SECRET, now + 10), null);
  assert.equal(A.verify(tok, SECRET, now + A.SESSION_SECONDS + 1), null);
  assert.equal(A.verify('', SECRET, now), null);
  assert.equal(A.verify(undefined, SECRET, now), null);
  assert.equal(A.verify('nodots', SECRET, now), null);
});

test('validation: usernames, passwords, progress payloads', () => {
  assert.equal(V.username('ab').ok, false);
  assert.equal(V.username('has space').ok, false);
  assert.equal(V.username('<script>').ok, false);
  assert.equal(V.username('  Good_Name-1.x ').value, 'Good_Name-1.x');
  assert.equal(V.password('short', 'bob').ok, false);
  assert.equal(V.password('Bobbobbob', 'bobbobbob').ok, false);
  assert.equal(V.password('a'.repeat(201), 'bob').ok, false);
  assert.equal(V.password('long enough pw', 'bob').ok, true);
  assert.equal(V.progress('kanji', { n2: ['腕'], n3: [], n4: [], n5: ['日'] }).ok, true);
  assert.equal(V.progress('kanji', {}).ok, true);                       // missing levels default to []
  assert.equal(V.progress('kanji', { n2: ['ab'] }).ok, false);          // not a single kanji
  assert.equal(V.progress('kanji', { n2: ['a'] }).ok, false);
  assert.equal(V.progress('kanji', { n2: 'x' }).ok, false);
  assert.equal(V.progress('kanji', [1, 2]).ok, false);
  assert.equal(V.progress('kanji', { n2: Array(3001).fill('腕') }).ok, false);
  assert.equal(V.progress('nope', {}).ok, false);
  assert.equal(V.progress('__proto__', {}).ok, false);
  assert.deepEqual(V.progress('kanji', { n2: ['腕', '腕'] }).value.n2, ['腕']);   // de-duplicated
});

// ---------------------------------------------------------------- signup / login / me / logout
test('signup: creates the account, stores only a hash, sets a secure session cookie', async () => {
  const { handler, sql } = setup();
  const res = await signup(handler, 'Alice', 'a-good-password');
  assert.equal(res.statusCode, 201);
  assert.equal(bodyOf(res).user.username, 'Alice');
  const c = res.headers['Set-Cookie'];
  assert.match(c, /^nk_session=/);
  for (const attr of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', 'Max-Age=2592000']) assert.ok(c.includes(attr), attr);
  const rows = await sql`select password_hash from users`;
  assert.equal(rows.length, 1);
  assert.ok(!rows[0].password_hash.includes('a-good-password'));
  assert.match(rows[0].password_hash, /^scrypt\$/);
});

test('signup: duplicate usernames (any case), bad input', async () => {
  const { handler } = setup();
  assert.equal((await signup(handler, 'Alice', 'a-good-password')).statusCode, 201);
  assert.equal((await signup(handler, 'alice', 'another-password')).statusCode, 409);
  assert.equal((await signup(handler, 'ALICE', 'another-password')).statusCode, 409);
  assert.equal((await signup(handler, 'x', 'a-good-password')).statusCode, 400);
  assert.equal((await signup(handler, 'bobby', 'short')).statusCode, 400);
  assert.equal((await handler(ev('POST', '/api/signup', { body: 'not json' }))).statusCode, 400);
  assert.equal((await handler(ev('POST', '/api/signup', { body: { username: 'bobby', password: 'a-good-password' }, ct: 'text/plain' }))).statusCode, 415);
});

test('signup: invite code and closed registration', async () => {
  let t = setup({ SIGNUP_CODE: 'open-sesame' });
  assert.equal((await signup(t.handler, 'carol', 'a-good-password')).statusCode, 403);
  assert.equal((await signup(t.handler, 'carol', 'a-good-password', { code: 'nope' })).statusCode, 403);
  assert.equal((await signup(t.handler, 'carol', 'a-good-password', { code: 'open-sesame' })).statusCode, 201);
  const me = bodyOf(await t.handler(ev('GET', '/api/me')));
  assert.deepEqual(me.signup, { open: true, requiresCode: true });

  t = setup({ ALLOW_SIGNUP: 'false' });
  assert.equal((await signup(t.handler, 'dave', 'a-good-password')).statusCode, 403);
  assert.equal(bodyOf(await t.handler(ev('GET', '/api/me'))).signup.open, false);
});

test('login: success, wrong password and unknown user look identical', async () => {
  const { handler } = setup();
  await signup(handler, 'Erin', 'a-good-password');
  const ok = await handler(ev('POST', '/api/login', { body: { username: 'ERIN', password: 'a-good-password' } }));   // case-insensitive username
  assert.equal(ok.statusCode, 200);
  assert.equal(bodyOf(ok).user.username, 'Erin');
  const bad = await handler(ev('POST', '/api/login', { body: { username: 'erin', password: 'wrong-password' } }));
  const none = await handler(ev('POST', '/api/login', { body: { username: 'nobody', password: 'wrong-password' } }));
  assert.equal(bad.statusCode, 401);
  assert.equal(none.statusCode, 401);
  assert.equal(bad.body, none.body);                       // same message: no user enumeration
  assert.ok(!bad.headers['Set-Cookie'] && !none.headers['Set-Cookie']);
});

test('login lockout: 5 wrong passwords lock the account for 15 minutes, then it recovers', async () => {
  const { handler, clock } = setup();
  await signup(handler, 'Frank', 'a-good-password');
  for (let i = 0; i < 5; i++) {
    const r = await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'wrong-' + i + '-password' } }));
    assert.equal(r.statusCode, 401, 'attempt ' + i);
  }
  const locked = await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'a-good-password' } }));
  assert.equal(locked.statusCode, 429);                    // even the RIGHT password is refused while locked
  clock.t += 14 * 60 * 1000;
  assert.equal((await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'a-good-password' } }))).statusCode, 429);
  clock.t += 2 * 60 * 1000;                                // 16 minutes after the lock began
  assert.equal((await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'a-good-password' } }))).statusCode, 200);
  // counter was reset: one wrong guess afterwards does not lock again
  await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'wrong-again-pw' } }));
  assert.equal((await handler(ev('POST', '/api/login', { body: { username: 'frank', password: 'a-good-password' } }))).statusCode, 200);
});

test('me: valid session, none, tampered, expired, deleted user', async () => {
  const { handler, clock, sql } = setup();
  const su = await signup(handler, 'Gina', 'a-good-password');
  const cookie = cookieOf(su);
  const mine = bodyOf(await handler(ev('GET', '/api/me', { cookie })));
  assert.equal(mine.user.username, 'Gina');
  assert.equal(bodyOf(await handler(ev('GET', '/api/me'))).user, null);
  assert.equal(bodyOf(await handler(ev('GET', '/api/me', { cookie: cookie + 'tampered' }))).user, null);
  assert.equal(bodyOf(await handler(ev('GET', '/api/me', { cookie: 'nk_session=garbage' }))).user, null);
  await sql`delete from users where username_lc = ${'gina'}`;
  assert.equal(bodyOf(await handler(ev('GET', '/api/me', { cookie }))).user, null);     // account removed -> session useless
  const t2 = setup();
  const c2 = cookieOf(await signup(t2.handler, 'Hank', 'a-good-password'));
  t2.clock.t += (A.SESSION_SECONDS + 5) * 1000;
  assert.equal(bodyOf(await t2.handler(ev('GET', '/api/me', { cookie: c2 }))).user, null);   // expired
});

test('logout clears the cookie', async () => {
  const { handler } = setup();
  const res = await handler(ev('POST', '/api/logout', { body: {} }));
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['Set-Cookie'], /^nk_session=; .*Max-Age=0/);
});

// ---------------------------------------------------------------- progress
test('progress: needs login, starts empty, versions increase, stale writes get a 409 with the current copy', async () => {
  const { handler } = setup();
  assert.equal((await handler(ev('GET', '/api/progress', { query: { app: 'kanji' } }))).statusCode, 401);
  assert.equal((await handler(ev('PUT', '/api/progress', { body: { app: 'kanji', data: {}, baseVersion: 0 } }))).statusCode, 401);

  const cookie = cookieOf(await signup(handler, 'Ivy', 'a-good-password'));
  const empty = bodyOf(await handler(ev('GET', '/api/progress', { cookie, query: { app: 'kanji' } })));
  assert.deepEqual(empty, { data: null, version: 0, updatedAt: null });

  const put = (data, baseVersion) => handler(ev('PUT', '/api/progress', { cookie, body: { app: 'kanji', data, baseVersion } }));
  let r = await put({ n2: ['腕'], n3: [], n4: [], n5: [] }, 0);
  assert.equal(r.statusCode, 200); assert.equal(bodyOf(r).version, 1);
  r = await put({ n2: ['腕', '湾'], n3: [], n4: [], n5: ['日'] }, 1);
  assert.equal(r.statusCode, 200); assert.equal(bodyOf(r).version, 2);

  const got = bodyOf(await handler(ev('GET', '/api/progress', { cookie, query: { app: 'kanji' } })));
  assert.equal(got.version, 2);
  assert.deepEqual(got.data.n2.sort(), ['湾', '腕'].sort());
  assert.deepEqual(got.data.n5, ['日']);

  const stale = await put({ n2: [], n3: [], n4: [], n5: [] }, 1);          // another device already saved v2
  assert.equal(stale.statusCode, 409);
  const sb = bodyOf(stale);
  assert.equal(sb.version, 2);
  assert.deepEqual(sb.data.n5, ['日']);                                      // stale write did NOT clobber the data
  const again = await put({ n2: [], n3: [], n4: [], n5: [] }, 0);           // "first write" when a row exists -> conflict too
  assert.equal(again.statusCode, 409);
});

test('progress: rejects malformed data, unknown apps, oversized bodies', async () => {
  const { handler } = setup();
  const cookie = cookieOf(await signup(handler, 'Jack', 'a-good-password'));
  const put = (body) => handler(ev('PUT', '/api/progress', { cookie, body }));
  assert.equal((await put({ app: 'kanji', data: { n2: ['<script>'] }, baseVersion: 0 })).statusCode, 400);
  assert.equal((await put({ app: 'kanji', data: 'x', baseVersion: 0 })).statusCode, 400);
  assert.equal((await put({ app: 'other', data: {}, baseVersion: 0 })).statusCode, 400);
  assert.equal((await put({ app: 'kanji', data: { n2: Array(100000).fill('腕') }, baseVersion: 0 })).statusCode, 413);
  assert.equal((await handler(ev('GET', '/api/progress', { cookie, query: { app: 'nope' } }))).statusCode, 400);
});

test('progress: users are isolated from each other', async () => {
  const { handler } = setup();
  const a = cookieOf(await signup(handler, 'Alice2', 'a-good-password'));
  const b = cookieOf(await signup(handler, 'Bob2', 'a-good-password'));
  await handler(ev('PUT', '/api/progress', { cookie: a, body: { app: 'kanji', data: { n2: ['腕'] }, baseVersion: 0 } }));
  const bGet = bodyOf(await handler(ev('GET', '/api/progress', { cookie: b, query: { app: 'kanji' } })));
  assert.equal(bGet.data, null);                                             // Bob sees nothing of Alice's
  await handler(ev('PUT', '/api/progress', { cookie: b, body: { app: 'kanji', data: { n3: ['与'] }, baseVersion: 0 } }));
  const aGet = bodyOf(await handler(ev('GET', '/api/progress', { cookie: a, query: { app: 'kanji' } })));
  assert.deepEqual(aGet.data.n2, ['腕']);
  assert.deepEqual(aGet.data.n3, []);
});

// ---------------------------------------------------------------- hardening
test('cross-site requests are blocked, same-site allowed', async () => {
  const { handler } = setup();
  const evil = await handler(ev('POST', '/api/login', { origin: 'https://evil.example', body: { username: 'a', password: 'b' } }));
  assert.equal(evil.statusCode, 403);
  const evilSignup = await handler(ev('POST', '/api/signup', { origin: 'https://evil.example', body: { username: 'abcd', password: 'a-good-password' } }));
  assert.equal(evilSignup.statusCode, 403);
  const same = await handler(ev('POST', '/api/login', { origin: 'https://app.test', body: { username: 'a', password: 'b' } }));
  assert.equal(same.statusCode, 401);
  const port = await handler(ev('POST', '/api/login', { origin: 'http://localhost:8888', host: 'localhost:8888', body: { username: 'a', password: 'b' } }));
  assert.equal(port.statusCode, 401);
});

test('routing: unknown route 404, wrong method 405', async () => {
  const { handler } = setup();
  assert.equal((await handler(ev('GET', '/api/nope'))).statusCode, 404);
  assert.equal((await handler(ev('GET', '/api/login'))).statusCode, 405);
  assert.equal((await handler(ev('DELETE', '/api/progress'))).statusCode, 405);
  assert.equal((await handler(ev('GET', '/.netlify/functions/api/me'))).statusCode, 200);   // direct function path works too
  assert.equal((await handler(ev('GET', '/api/ME/'))).statusCode, 200);
});

test('server misconfiguration is reported generically (never leaks details)', async () => {
  const noSecret = createHandler({ sql: makeSql(), env: {} });
  const r = await noSecret(ev('GET', '/api/me'));
  assert.equal(r.statusCode, 500);
  assert.equal(bodyOf(r).error, 'server_misconfigured');
  const shortSecret = createHandler({ sql: makeSql(), env: { JWT_SECRET: 'short' } });
  assert.equal((await shortSecret(ev('GET', '/api/me'))).statusCode, 500);
  DB.getSql.length;                                                          // (db module loads without the driver installed)
  const noDb = createHandler({ env: { JWT_SECRET: SECRET } });                // no DATABASE_URL, no injected sql
  const r2 = await noDb(ev('GET', '/api/me'));
  assert.equal(r2.statusCode, 500);
  assert.ok(!/DATABASE_URL/.test(r2.body));
});

test('secrets never appear in any response body', async () => {
  const { handler } = setup();
  const res = [
    await signup(handler, 'Kate', 'a-good-password'),
    await handler(ev('POST', '/api/login', { body: { username: 'kate', password: 'a-good-password' } })),
    await handler(ev('GET', '/api/me', { cookie: 'nk_session=zzz' }))
  ];
  for (const r of res) {
    assert.ok(!r.body.includes('scrypt$'));
    assert.ok(!r.body.includes(SECRET));
    assert.ok(!r.body.includes('password_hash'));
  }
});
