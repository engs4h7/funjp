'use strict';
// Neon Postgres access. The connection string comes ONLY from the DATABASE_URL environment
// variable on the server - it is never sent to (or visible in) the browser.

let _sql = null;
const _schemaDone = new WeakMap();   // sql function -> Promise (so tables are created once per instance)

function getSql(env) {
  if (_sql) return _sql;
  const url = env && env.DATABASE_URL;
  if (!url) {
    const e = new Error('DATABASE_URL is not set');
    e.code = 'NO_DB';
    throw e;
  }
  const { neon } = require('@neondatabase/serverless');   // HTTP driver: ideal for serverless functions
  _sql = neon(url);
  return _sql;
}

// Creates the tables if they don't exist yet (safe to run on every cold start).
// The same statements are in schema.sql if you prefer to run them by hand in Neon's SQL editor.
function ensureSchema(sql) {
  if (!_schemaDone.has(sql)) {
    const p = (async () => {
      await sql`
        create table if not exists users (
          id bigint generated always as identity primary key,
          username text not null,
          username_lc text not null unique,
          password_hash text not null,
          failed_attempts integer not null default 0,
          locked_until timestamptz,
          created_at timestamptz not null default now()
        )`;
      await sql`
        create table if not exists user_progress (
          user_id bigint not null references users(id) on delete cascade,
          app text not null,
          data jsonb not null default '{}'::jsonb,
          version integer not null default 1,
          updated_at timestamptz not null default now(),
          primary key (user_id, app)
        )`;
    })().catch((e) => { _schemaDone.delete(sql); throw e; });
    _schemaDone.set(sql, p);
  }
  return _schemaDone.get(sql);
}

module.exports = { getSql, ensureSchema };
