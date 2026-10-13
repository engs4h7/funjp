'use strict';
// Password hashing (scrypt) and signed session tokens (HMAC-SHA256).
// Everything here uses Node's built-in crypto module - no extra dependencies.
const crypto = require('crypto');

const COOKIE_NAME = 'nk_session';
const SESSION_SECONDS = 60 * 60 * 24 * 30; // 30 days

// ---------- passwords ----------
function scrypt(password, salt, N, r, p, keylen) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N, r, p, maxmem: 128 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key));
  });
}

// Format: scrypt$N$r$p$salt(base64)$hash(base64). The parameters are stored with the hash so
// they can be raised later without breaking existing accounts.
async function hashPassword(password) {
  const N = 16384, r = 8, p = 1;
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(password).normalize('NFKC'), salt, N, r, p, 64);
  return ['scrypt', N, r, p, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, saltB64, keyB64] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(keyB64, 'base64');
    const key = await scrypt(String(password).normalize('NFKC'), Buffer.from(saltB64, 'base64'),
      parseInt(N, 10), parseInt(r, 10), parseInt(p, 10), expected.length);
    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
  } catch (e) {
    return false;
  }
}

// A real hash of a throwaway password, used so a login for an UNKNOWN username costs the same
// time as one for a known username (stops attackers discovering which usernames exist).
let _dummy = null;
function dummyHash() {
  if (!_dummy) _dummy = hashPassword('not-a-real-password-' + crypto.randomBytes(8).toString('hex'));
  return _dummy;
}

// ---------- session tokens ----------
function sign(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + mac;
}

function verify(token, secret, nowSec) {
  if (typeof token !== 'string') return null;
  const i = token.indexOf('.');
  if (i < 1) return null;
  const body = token.slice(0, i);
  const expected = crypto.createHmac('sha256', secret).update(body).digest();
  let given;
  try { given = Buffer.from(token.slice(i + 1), 'base64url'); } catch (e) { return null; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!payload || typeof payload.exp !== 'number' || payload.exp <= nowSec) return null;
  return payload;
}

function newSessionToken(userId, secret, nowSec) {
  return sign({ sub: String(userId), iat: nowSec, exp: nowSec + SESSION_SECONDS }, secret);
}

// ---------- cookies ----------
function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i <= 0) return;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { /* ignore */ }
  });
  return out;
}

function sessionCookie(token, opts) {
  const secure = !(opts && opts.insecure);
  const maxAge = opts && typeof opts.maxAge === 'number' ? opts.maxAge : SESSION_SECONDS;
  return `${COOKIE_NAME}=${token}; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

// constant-time string comparison (used for the optional invite code)
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = {
  COOKIE_NAME, SESSION_SECONDS,
  hashPassword, verifyPassword, dummyHash,
  sign, verify, newSessionToken,
  parseCookies, sessionCookie, safeEqual
};
