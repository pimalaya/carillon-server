# Self-hosting Carillon

Carillon ships as **one core** (watcher supervisor + delivery + metering + store) behind a REST + SSE API, deployed in one of three fronts. The core is identical in each; only the *front* differs.

The API contract is [openapi.yaml](openapi.yaml), served live at `GET /openapi.yaml`. The reference UI is a separate repo, `carillon-frontend` (a pure client of this API); you can embed its build, serve it yourself, or bring your own.

## Config

The daemon config is **infrastructure only** (carillon.sample.toml); watches live in the store, not the config. The `[api]` block controls the front:

```toml
[api]
listen = "127.0.0.1:3000"
# Serve a built carillon-frontend dist/ at the origin (self-host + UI):
# ui_dir = "/var/lib/carillon/ui"
# Allow a cross-origin CDN front to call the API (SaaS):
# cors_allow_origin = "https://carillon.example.org"
# Master bearer token for unscoped, fleet-wide access (ops / headless):
# admin_token = "<a long random secret>"
```

## Authentication (every data route)

Every route that touches watches, deliveries, accounts or the live stream requires a bearer token: there is **no unauthenticated data access**, in any front (§ DECISIONS 5). Two kinds of token are accepted on `Authorization: Bearer <token>`:

- **Capability link**: per account, minted by `POST /auth` (prove control of a mailbox). Scopes every call to that account's own watches, deliveries, events and pool. This is what the dashboard and SaaS users hold.
- **Admin token**: the optional `api.admin_token`. Grants **unscoped** access to every account: the ops / headless escape hatch. Unset (the default) means no unscoped access exists at all. Keep it long, random and secret: it is the whole fleet's key.

Only `/health`, `/`, `/openapi.yaml`, `POST /discover`, `POST /test`, `POST /auth`, `POST /oauth/start`, `GET /oauth/callback`, `GET /billing/packs` and the billing webhook are public.

**OAuth mailboxes** (M10): a mailbox can be watched via OAuth instead of a password: the server holds a **refresh token**, not a password, and the held IMAP connection authenticates with `OAUTHBEARER`. Fastmail uses RFC 7591 dynamic registration (no setup); Google/Microsoft use Thunderbird's public client IDs for now (swap for Carillon-owned apps later). Set `public_url` so the OAuth redirect (`{public_url}/oauth/callback`) is reachable by the browser; for Google/Microsoft that redirect must be a loopback/localhost URL until Carillon registers its own hosted apps.

## Mode 1: headless self-host

The daemon and its API on localhost; no UI. Manage watches with the control API or the bundled `carillon-backend import`. `carillon-backend import` writes the store directly, so it needs no token; the HTTP API does: set an `admin_token` to drive it from a script.

```toml
[api]
listen = "127.0.0.1:3000"          # localhost only
admin_token = "s3cr3t-…-long"      # to read/write via the HTTP API
```

```sh
carillon-backend import accounts.toml      # bulk-populate the store (no token needed)
carillon-backend serve                     # run the daemon
curl -s localhost:3000/watches \
  -H "Authorization: Bearer s3cr3t-…-long"   # drive the API with the admin token
```

Bind to localhost and put it behind your own auth/proxy if you expose it; the process holds every credential and can redirect every webhook, so do not rely on "it's internal".

## Mode 2: self-host with the UI

Same daemon, plus the reference dashboard served from the same origin (no CORS). Build `carillon-frontend` (`vite build` → `dist/`) and point `ui_dir` at it:

```toml
[api]
listen = "0.0.0.0:3000"
ui_dir = "/var/lib/carillon/ui"    # a carillon-frontend dist/
```

Static files own `/` (unknown paths fall back to the SPA entrypoint); the API routes (`/watches`, `/events`, …) take precedence. Because the UI is same-origin, `VITE_API_BASE_URL` is empty when you build it.

> A future single-binary option can compile the UI in via `rust-embed`; today `ui_dir` (serve a directory) covers self-host and BYO-UI without pinning a build into the binary.

## Mode 3: SaaS (API box + CDN front)

The API box serves only JSON; carillon-frontend's `dist/` is served from a CDN/Netlify with `VITE_API_BASE_URL` set to the API host. Enable CORS for that origin:

```toml
[api]
listen = "0.0.0.0:3000"
cors_allow_origin = "https://app.carillon.example.org"
```

The capability link travels as an `Authorization: Bearer` header (M7), so cross-origin needs only a preflight + this allow-list: no cookies, SameSite or CSRF. Terminate TLS at a reverse proxy (e.g. Caddy) in front.

## Endpoints at a glance

| Path | Purpose |
|---|---|
| `GET /` | Service metadata (headless) or the UI (with `ui_dir`) |
| `GET /health` | Liveness (`ok`) |
| `GET /openapi.yaml` | The API contract |
| `POST /discover` | IMAP config discovery from an email/server (rate-limited) |
| `POST /test` | Read-only credential probe (rate-limited) |
| `… /watches …` | Watch CRUD, pause/resume, rotate-secret |
| `GET /deliveries` | Delivery log |
| `GET /accounts…` | Balances (two counters), credit, auto-refill |
| `GET /events` | SSE live stream |

See [WEBHOOKS.md](WEBHOOKS.md) for the delivery payload and signature verification.
