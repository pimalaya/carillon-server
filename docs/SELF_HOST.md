# Self-hosting Carillon

Carillon ships as **one core** (watcher supervisor + delivery + metering +
store) behind a REST + SSE API, deployed in one of three fronts. The core
is identical in each; only the *front* differs.

The API contract is [`openapi.yaml`](openapi.yaml), served live at
`GET /openapi.yaml`. The reference UI is a separate repo, `carillon-admin`
(a pure client of this API); you can embed its build, serve it yourself,
or bring your own.

## Config

The daemon config is **infrastructure only** (`carillon.sample.toml`);
watches live in the store, not the config. The `[api]` block controls the
front:

```toml
[api]
listen = "127.0.0.1:3000"
# Serve a built carillon-admin dist/ at the origin (self-host + UI):
# ui_dir = "/var/lib/carillon/ui"
# Allow a cross-origin CDN front to call the API (SaaS):
# cors_allow_origin = "https://carillon.example.org"
```

## Mode 1 — headless self-host

The daemon and its API on localhost; no UI. Manage watches with the
control API or the bundled `carillon import`.

```toml
[api]
listen = "127.0.0.1:3000"   # localhost only
```

```sh
carillon import accounts.toml      # bulk-populate the store
carillon serve                     # run the daemon
curl -s localhost:3000/watches     # drive it with the API / a script
```

Bind to localhost and put it behind your own auth/proxy if you expose it;
the process holds every credential and can redirect every webhook, so do
not rely on "it's internal".

## Mode 2 — self-host with the UI

Same daemon, plus the reference dashboard served from the same origin (no
CORS). Build `carillon-admin` (`vite build` → `dist/`) and point `ui_dir`
at it:

```toml
[api]
listen = "0.0.0.0:3000"
ui_dir = "/var/lib/carillon/ui"    # a carillon-admin dist/
```

Static files own `/` (unknown paths fall back to the SPA entrypoint);
the API routes (`/watches`, `/events`, …) take precedence. Because the UI
is same-origin, `VITE_API_BASE_URL` is empty when you build it.

> A future single-binary option can compile the UI in via `rust-embed`;
> today `ui_dir` (serve a directory) covers self-host and BYO-UI without
> pinning a build into the binary.

## Mode 3 — SaaS (API box + CDN front)

The API box serves only JSON; `carillon-admin`'s `dist/` is served from a
CDN/Netlify with `VITE_API_BASE_URL` set to the API host. Enable CORS for
that origin:

```toml
[api]
listen = "0.0.0.0:3000"
cors_allow_origin = "https://app.carillon.example.org"
```

The capability link travels as an `Authorization: Bearer` header (M7), so
cross-origin needs only a preflight + this allow-list — no cookies,
SameSite or CSRF. Terminate TLS at a reverse proxy (e.g. Caddy) in front.

## Endpoints at a glance

| Path | Purpose |
|---|---|
| `GET /` | Service metadata (headless) or the UI (with `ui_dir`) |
| `GET /health` | Liveness (`ok`) |
| `GET /openapi.yaml` | The API contract |
| `POST /test` | Read-only credential probe (rate-limited) |
| `… /watches …` | Watch CRUD, pause/resume, rotate-secret |
| `GET /deliveries` | Delivery log |
| `GET /accounts…` | Balances (two counters), credit, auto-refill |
| `GET /events` | SSE live stream |

See [`WEBHOOKS.md`](WEBHOOKS.md) for the delivery payload and signature
verification.
