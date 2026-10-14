# Kanji highlighter — accounts + saved progress (Netlify + Neon)

Your N5–N2 kanji app, now with sign-in. Each person's coverage progress is saved to their own
account in a Neon Postgres database and follows them to any device.

```
 Browser (public/index.html)
     │  fetch('/api/...')   ← login cookie (HttpOnly, never readable by page scripts)
     ▼
 Netlify Function  netlify/functions/api.js     ← holds DATABASE_URL + JWT_SECRET (server only)
     │
     ▼
 Neon Postgres  (tables: users, user_progress)
```

The browser **never** talks to Neon directly, and your database password is **never** in the page.

---

## ⚠️ Keep your secrets out of chats, code and Git

`DATABASE_URL` is your database password. Only ever put it in **Netlify's environment variables**
(or a local `.env` file, which `.gitignore` already excludes). If one ever leaks, reset the
password in Neon and update the Netlify variable.

---

## Setup (about 10 minutes)

### 1. Neon
1. In the Neon dashboard open your project → **Connect** → copy the **pooled** connection string
   (the host contains `-pooler`). It looks like `postgresql://user:pass@ep-xxx-pooler.region.aws.neon.tech/neondb?sslmode=require`.

### 2. Make a signing secret
```
openssl rand -base64 48
```
(or any random string of 32+ characters). This signs login cookies. Changing it later just logs everyone out.

### 3. Deploy to Netlify

> **Important:** drag-and-drop deploys of a folder **cannot** bundle the function's dependency,
> so the accounts API won't work that way. Use one of these instead.

**Option A — Git (recommended)**
1. Put this folder in a GitHub repo (the `.gitignore` keeps secrets out).
2. Netlify → **Add new site → Import an existing project** → pick the repo.
   `netlify.toml` already sets the publish folder (`public`) and functions folder — no build command needed.

**Option B — Netlify CLI**
```
npm install
npx netlify-cli login
npx netlify-cli init          # link or create the site
npx netlify-cli deploy --prod
```

### 4. Add the environment variables
Netlify → your site → **Site configuration → Environment variables**:

| Name | Value | Required |
|---|---|---|
| `DATABASE_URL` | the Neon pooled connection string | yes |
| `JWT_SECRET` | the random string from step 2 (32+ chars) | yes |
| `SIGNUP_CODE` | an invite code people must enter to create an account | recommended |
| `ALLOW_SIGNUP` | `false` to stop new accounts (existing users can still sign in) | optional |

Then **redeploy** (Deploys → Trigger deploy) so the function picks them up.

> Anyone who finds your site can create an account (and store rows in your database) unless you
> set `SIGNUP_CODE`. For a personal/small-group tool, set it.

### 5. Check it works
1. Open your site. A **Sign in** button appears in the header (if it doesn't, the API isn't reachable — see Troubleshooting).
2. **Create account** with a username, email address, and password; tick a few kanji and wait for "Saved ✓" in the header.
3. In Neon's **SQL Editor**: `select id, username, email from users;` and `select * from user_progress;`
4. Open the site in another browser, sign in — your progress appears.

The tables are created automatically on the first request. `schema.sql` has the same statements if you
prefer to create them by hand.

---

## Already have the SRS site on Netlify?

Either create a **second Netlify site** from this folder, or merge into the existing project:
copy `netlify/`, `netlify.toml` and `package.json` in, and put `public/index.html` there under another
name (e.g. `kanji.html`). One API serves any number of pages. The API already has an app id
(`kanji`); to save the SRS app's progress too, add a validator for `srs` in `netlify/lib/validate.js`
(`APPS`) and call the same `/api/progress` endpoints from that page.

---

## How it behaves

**Security**
- Passwords: scrypt with a per-user random salt (built into Node). Plain passwords are never stored or logged.
- Login cookie: signed, `HttpOnly`, `Secure`, `SameSite=Lax`, 30 days. Page scripts can't read it.
- Cross-site requests to sign-up/login/save are rejected (Origin check + JSON-only).
- 5 wrong passwords lock that account for 15 minutes. Unknown usernames and wrong passwords give the same answer and take the same time.
- Everything from the browser is validated; progress data must be single kanji only.

**Sync**
- Progress is always saved in the browser first; when signed in it's also saved to the account (a second after you stop clicking).
- Progress you made **before** signing in is added to your account at your first sign-in.
- A different person signing in on the same browser never sees or inherits the previous person's data;
  **Sign out** clears this browser's copy (it stays safe in the account). Sign-out waits to save pending changes first.
- Two devices: if both changed things, the results are **merged** (kanji covered on either device stay covered).
- Offline: changes are kept and uploaded automatically when you're back online.
- If the API isn't there (opening the file directly, a preview), the account button hides and the app works locally exactly as before.

**Limitations**
- No email, so **no automatic password reset**. If someone forgets theirs, delete their row in Neon (`delete from users where username_lc = 'name';`) and let them sign up again.
- Because devices merge by union, *un*-marking a kanji on one device can be undone by another device that still has it marked.
- Neon's free tier can pause when idle, so the first request after a quiet period may take a second or two.

---

## Local development
```
npm install
cp .env.example .env     # fill in DATABASE_URL and JWT_SECRET
npx netlify dev          # http://localhost:8888
```
Safari rejects `Secure` cookies on plain http; for local dev only, add `ALLOW_INSECURE_COOKIES=true` to `.env`.

## Tests
```
npm test      # needs Node 22.13+ (uses the built-in node:sqlite)
```
These run the real request handler against an in-memory SQLite database (validation, hashing, cookies,
lockout, versions, user isolation, origin checks). They can't prove your Neon connection — step 5 above does.

## Troubleshooting
- **No "Sign in" button:** the page couldn't reach `/api/me`. Check Netlify → Functions shows `api`, and that you deployed via Git/CLI (not drag-and-drop).
- **"The server is not set up correctly yet":** `DATABASE_URL` or `JWT_SECRET` is missing/too short, or you haven't redeployed since adding them. Netlify's function logs show which.
- **Sign-up says "invite code is not valid":** `SIGNUP_CODE` is set; enter that code in the form.
- **Works on desktop, not Safari local dev:** see `ALLOW_INSECURE_COOKIES` above.
