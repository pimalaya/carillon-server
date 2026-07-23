# Carillon backend

*Carillon watch server — prototype.* Holds IMAP IDLE for many accounts on one
box and, the instant a mailbox changes, POSTs a small, HMAC-signed,
**content-free** signal to each account's notify URL.

> **Carillon signals; it never syncs.** It emits *that* something changed and
> *which* UID — never the sender, subject or body. The consumer (which holds the
> credentials) enriches the notification itself; the signal Carillon emits stays
> pure.

This is the P0–P5 prototype: the async IMAP-IDLE → signed-webhook beast, a
supervisor, at-rest credential encryption, sqlite persistence, and a control
API. Billing, the dashboard, and non-IMAP source protocols are out of scope
here (see the roadmap).

## Docs

- [`docs/CARILLON_PLAN.md`](docs/CARILLON_PLAN.md) — the original north-star vision
  (what Carillon is, scope, cost model, business shape).
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — product & design decisions refined
  since the plan (onboarding, credits, webhook security, self-host vs SaaS,
  transport/architecture).
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — the action plan from this prototype to
  the shippable product.

## Architecture

```
                  ┌───────────── supervisor ─────────────┐
 store (sqlite) ─►│ one task / active watch:              │
   watches        │   connect (TCP+TLS+LOGIN)             │
                  │   → ImapMailboxWatch (IDLE + QRESYNC)  │──┐  ChangeEvent
                  │   → reconnect w/ backoff              │  │  (account,event,uid)
                  │  handshake semaphore throttles TLS    │  │
                  └───────────────────────────────────────┘  ▼
 control API (axum) ── writes ──► store            delivery worker
   /watches CRUD, /deliveries      ▲                 sign (HMAC-SHA256)
        │ reconcile                │  log            POST notify_url (reqwest, pooled)
        └──────────────────────────┴──────────────► retry w/ backoff → store.deliveries
```

- **`imap::pump`** — the async coroutine driver. `io-imap` coroutines are
  I/O-free; this ~30-line loop drives them over a `tokio-rustls` stream. It is
  the whole trick that lets one box hold tens of thousands of IDLE connections.
- **`imap::session`** — TCP + TLS + greeting + LOGIN → a live authenticated
  session (TCP keepalive + nodelay set for liveness).
- **`supervisor`** — one task per watch; reconnect loop with jittered backoff; a
  shared semaphore caps concurrent TLS handshakes (reconnect-storm / per-IP
  throttle); reconciles the running set against the store.
- **`delivery`** — decoupled webhook sender (a slow endpoint never stalls IDLE);
  one shared pooled `reqwest::Client`; HMAC-signs and retries; logs outcomes.
- **`store`** — sqlite (WAL) via rusqlite: `watch` + `delivery` tables.
- **`crypto`** — passwords encrypted at rest to a per-box age (x25519) key.
- **`api`** — axum control surface.

## Build & run

The repo uses the shared Pimalaya nix toolchain (no system `cargo`):

```sh
nix develop --command cargo build
cp carillon.sample.toml carillon.toml   # then edit
nix develop --command cargo run -- carillon.toml
```

Logging honours `RUST_LOG` (default `info,carillon_server=debug`).

## Control API

```sh
# health
curl localhost:3000/health

# add a watch (password is encrypted at rest)
curl -X POST localhost:3000/watches -H 'content-type: application/json' -d '{
  "id": "me",
  "imap_host": "imap.example.org",
  "login": "user@example.org",
  "password": "app-password",
  "notify_url": "https://ntfy.sh/my-topic",
  "hmac_secret": "change-me"
}'

curl localhost:3000/watches                     # list (no secrets)
curl -X POST localhost:3000/watches/me/pause    # stop watching
curl -X POST localhost:3000/watches/me/resume   # resume
curl -X DELETE localhost:3000/watches/me        # remove
curl 'localhost:3000/deliveries?account=me&limit=20'
```

## Webhook payload

Content-free JSON, signed with `X-Carillon-Signature: sha256=<hmac_sha256(body)>`:

```json
{ "account": "me", "event": "new", "uid": 4213 }
```

Headers: `X-Carillon-Event` (`new` | `flags_added` | `flags_removed` |
`removed`), `X-Carillon-Account`, `X-Carillon-Signature`.

## Notes & caveats (prototype)

- Watched servers must advertise **QRESYNC** (Gmail, Fastmail, Dovecot do); a
  server without it disables that one watch with a logged error.
- **Read-only:** io-imap's watcher opens the mailbox with `EXAMINE`, never
  `SELECT` — Carillon issues no write commands (see `docs/DECISIONS.md` §7).
- Idle refresh is done by a periodic reconnect (15 min) plus TCP keepalive,
  rather than in-place DONE/re-IDLE — simpler and robust for the prototype.
- Single box = SPOF; no redundancy on the IDLE side yet.

(Historical: `imap-types` 2.0.0-alpha.6 had a bug parsing the `QRESYNC`/`CONDSTORE`
capability atoms to `Capability::Unselect`; fixed upstream in alpha.7 (via
imap-codec alpha.9). The interim vendored patch has been removed;
`tests/qresync.rs` guards against a regression.)
