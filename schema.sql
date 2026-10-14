-- Tables for the kanji app accounts.
-- The API creates these automatically on its first request, so running this by hand is optional
-- (useful if you want to see/inspect them in Neon's SQL Editor first).

create table if not exists users (
  id bigint generated always as identity primary key,
  username text not null,
  username_lc text not null unique,
  email text,
  password_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

create unique index if not exists users_email_unique on users (lower(email)) where email is not null;

create table if not exists user_progress (
  user_id bigint not null references users(id) on delete cascade,
  app text not null,
  data jsonb not null default '{}'::jsonb,
  version integer not null default 1,
  updated_at timestamptz not null default now(),
  primary key (user_id, app)
);
