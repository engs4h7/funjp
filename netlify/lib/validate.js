'use strict';
// Strict validation of everything that arrives from the browser.

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const KANJI_RE = /^[\u4e00-\u9fff]$/;
const LEVELS = ['n2', 'n3', 'n4', 'n5'];
const MAX_KANJI_PER_LEVEL = 3000;
const MAX_BODY_BYTES = 300 * 1024;

function username(raw) {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!USERNAME_RE.test(v)) {
    return { ok: false, message: 'Username must be 3–32 characters: letters, numbers, dot, dash or underscore.' };
  }
  return { ok: true, value: v, lc: v.toLowerCase() };
}

function email(raw) {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (value.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    return { ok: false, message: 'Enter a valid email address.' };
  }
  return { ok: true, value: value.toLowerCase() };
}

function password(raw, uname) {
  if (typeof raw !== 'string' || raw.length < 8) return { ok: false, message: 'Password must be at least 8 characters.' };
  if (raw.length > 200) return { ok: false, message: 'Password is too long (200 characters max).' };
  if (uname && raw.toLowerCase() === String(uname).toLowerCase()) {
    return { ok: false, message: "Password can't be the same as your username." };
  }
  return { ok: true };
}

// The kanji app stores which kanji the user has covered, per JLPT level.
// Accept ONLY: { n2: ["腕", ...], n3: [...], n4: [...], n5: [...] } with single CJK characters.
function cleanKanjiProgress(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const out = { v: 1 };
  for (const lvl of LEVELS) {
    const arr = data[lvl];
    if (arr === undefined) { out[lvl] = []; continue; }
    if (!Array.isArray(arr) || arr.length > MAX_KANJI_PER_LEVEL) return null;
    const seen = new Set();
    for (const ch of arr) {
      if (typeof ch !== 'string' || !KANJI_RE.test(ch)) return null;
      seen.add(ch);
    }
    out[lvl] = [...seen];
  }
  return out;
}

// One validator per app id. Add an entry here to let another app (e.g. 'srs') store data too.
const APPS = { kanji: cleanKanjiProgress };

function appId(raw) {
  return typeof raw === 'string' && Object.prototype.hasOwnProperty.call(APPS, raw) ? raw : null;
}

function progress(app, data) {
  if (!appId(app)) return { ok: false, message: 'Unknown app.' };
  const clean = APPS[app](data);
  return clean ? { ok: true, value: clean } : { ok: false, message: 'Invalid progress data.' };
}

module.exports = { username, email, password, appId, progress, MAX_BODY_BYTES };
