# Filter — Managed Content Filtering Platform

A managed content filtering platform. An admin signs up, creates one or more
**profiles** (one per device/person they want to filter), downloads a
`.mobileconfig` for each profile, and installs it on the target Mac/iPhone.
The profile routes all browser DNS through a per-profile NextDNS configuration.
Blocked sites redirect to a custom block page where the user can request access;
the admin approves or denies from a dashboard.

The admin can customize, **per profile**, what is blocked: category filters
(porn, gambling, dating, social networks, …), Safe Browsing, Safe Search,
YouTube Restricted Mode, plus an explicit allowlist and denylist of domains.

See `filtering-platform-spec.md` for the original architecture spec.

## Layout

```
backend/       Node.js + Express API, SQLite (node:sqlite), JWT auth
admin/         Plain-HTML/JS admin dashboard (no build step)
block-page/    Plain-HTML block page shown when NextDNS blocks a site
```

## Prerequisites

- **Node.js 22+** (uses the built-in `node:sqlite` module).
- A **NextDNS account** — get an API key at https://my.nextdns.io/account.
- (Optional) A **Resend** API key for email notifications. Without one,
  notifications log to the backend console.

## Quick start (local — for testing on your own Mac)

```bash
# 1. Backend
cd backend
npm install
cp .env.example .env
# edit .env — set NEXTDNS_API_KEY and JWT_SECRET to something long
npm start

# 2. Block page (in a second terminal)
cd block-page
python3 -m http.server 5174

# 3. Admin dashboard (in a third terminal)
cd admin
python3 -m http.server 5173
```

Open http://localhost:5173/ → click **Sign up** → create your account →
create a profile → download its `.mobileconfig` → install it on your Mac.

## Hosting / production

**Running this only on your laptop works for filtering yourself, but not for
filtering anyone else's device.** Reason: NextDNS redirects blocked traffic to
the block page URL you configured per profile. If that URL is `localhost:5174`
or a private IP, the user's browser on a different machine can't reach it.
Same goes for the API — the block page calls it from the user's browser.

The `.mobileconfig` itself **does not** reference your backend at all — it
only contains the user's NextDNS DoH endpoint
(`https://dns.nextdns.io/<profile-id>`). So the device-side filtering keeps
working even if your backend is offline. What breaks without public hosting is
the request-access flow.

To go beyond your own machine, deploy:

| Component        | Where (cheap)                 | Notes |
|---|---|---|
| Backend API      | Render, Railway, Fly, Hetzner | Needs persistent disk for `data/filter.db` (or swap to Postgres) |
| Block page       | Vercel / Cloudflare Pages     | Static. Set `window.FILTER_API_BASE` in the HTML. |
| Admin dashboard  | Vercel / Cloudflare Pages     | Static. Same `FILTER_API_BASE` knob. |

Then set `BLOCK_PAGE_URL` in the backend env to the public block page origin
(e.g. `https://blocked.yourplatform.com`). New profiles created after that
will redirect blocks to the public page.

`window.FILTER_API_BASE` lets the static frontends point at any backend host:

```html
<script>window.FILTER_API_BASE = 'https://api.yourplatform.com';</script>
<!-- before the existing <script src="app.js"></script> in admin/index.html
     or before the inline script in block-page/index.html -->
```

## Multi-tenant model

- Anyone can sign up at `POST /api/auth/register`. Each admin sees only their
  own profiles and their own access requests.
- A profile (`users` table row) is owned by exactly one admin (`admin_id`
  foreign key). All admin endpoints scope by the JWT subject.

## API

All endpoints are JSON. Admin endpoints require `Authorization: Bearer <jwt>`.

### Auth

| Method | Path                  | Auth  | Purpose |
|---|---|---|---|
| POST   | `/api/auth/register`  | none  | Create admin account, returns JWT |
| POST   | `/api/auth/login`     | none  | Returns JWT |
| GET    | `/api/auth/me`        | admin | Current admin info |

### Profiles (a.k.a. users)

| Method | Path                          | Auth  | Purpose |
|---|---|---|---|
| GET    | `/api/users`                  | admin | List your profiles |
| POST   | `/api/users`                  | admin | Create profile (creates NextDNS profile, sets safe defaults) |
| GET    | `/api/users/:id/profile`      | admin | Download `.mobileconfig` |
| DELETE | `/api/users/:id`              | admin | Delete profile + NextDNS profile |
| GET    | `/api/users/:id/settings`     | admin | Read NextDNS security + parental control |
| PATCH  | `/api/users/:id/settings`     | admin | Update NextDNS security and/or parental control |
| GET    | `/api/users/:id/allowlist`    | admin | List allowlist domains |
| POST   | `/api/users/:id/allowlist`    | admin | Add domain `{ "domain": "example.com" }` |
| DELETE | `/api/users/:id/allowlist/:domain` | admin | Remove domain |
| GET    | `/api/users/:id/denylist`     | admin | List denylist domains |
| POST   | `/api/users/:id/denylist`     | admin | Add domain |
| DELETE | `/api/users/:id/denylist/:domain` | admin | Remove domain |

### Access requests

| Method | Path                  | Auth  | Purpose |
|---|---|---|---|
| POST   | `/api/requests`       | none  | Block page submits `{ profile_id, domain, reason }` |
| GET    | `/api/requests`       | admin | List requests for your profiles (filter via `?status=pending`/`approved`/`denied`) |
| PATCH  | `/api/requests/:id`   | admin | `{ "status": "approved" \| "denied" }` — approval adds to NextDNS allowlist |

`GET /api/health` returns `{ ok: true, time }` (unauthenticated).

## Security notes

- Admin passwords are bcrypt-hashed (cost 12).
- Removal passwords for `.mobileconfig` are stored plaintext in the DB so the
  same profile can be re-downloaded with the same password. Protect the DB.
- The block page `POST /api/requests` is unauthenticated by design — users
  hitting it haven't logged in. It only accepts a `profile_id` that already
  exists. Add rate-limiting at your reverse proxy.
- JWTs are signed with `JWT_SECRET` and expire after 7 days. Set a long random
  value in production.

## Spec deviations

- **Block page redirect doesn't exist.** The original spec said "NextDNS will
  redirect blocked sites to your custom block page URL". This is not true —
  NextDNS's API only exposes `{ enabled: true/false }` for the block page,
  and shows their own NextDNS-branded block page when enabled. There is no
  way to inject a custom URL via the API. As a workaround, the dashboard
  shows each profile's **Request Access URL** (the user's hosted block
  page with the profile id pre-filled). Share that URL with the person
  using the profile — they bookmark it, and use it manually whenever they
  need to request access to a blocked site.
- The original spec described a single seeded admin with a hashed removal
  password. This implementation supports public admin signup (multi-tenant),
  and stores removal passwords plaintext (see Security notes for why).
- Safari and Firefox limitations on macOS Tahoe described in the spec are not
  solvable from this codebase — they require ABM enrollment or shipping a
  Firefox `policies.json` via the app bundle.
