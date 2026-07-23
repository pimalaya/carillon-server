# Carillon — roadmap / action plan

From the working prototype to the shippable product. Rationale for the ordering:
**validate the load-bearing pieces before the UI** — metering correctness,
credential trust, and webhook security decide whether the product works at all;
the dashboard is the least risky part and comes once they're proven. Decisions
behind each item live in [DECISIONS.md](DECISIONS.md); the north star is
[CARILLON_PLAN.md](CARILLON_PLAN.md).

**Aim:** a "signal-not-sync" watch service — IMAP-IDLE → signed, content-free
webhook — shipped in two fronts (self-hosted daemon + optional UI; multi-tenant
SaaS with billing), monetised by prepaid-metered credits, then grown across
source protocols (never payload).

---

## M0 — Prototype beast · LANDED (2026-07-19)

The core, built and exercised:

- Async IMAP-IDLE → signed-webhook: `imap::pump` (inline tokio-rustls driver over
  io-imap coroutines), `imap::session` (TCP+TLS+LOGIN+capability), `supervisor`
  (one task/watch, handshake semaphore, jittered reconnect backoff, reconcile),
  `delivery` (decoupled worker, pooled reqwest, HMAC-SHA256, retry).
- `store` (rusqlite WAL: `watch` + `delivery`), `crypto` (age x25519 at rest),
  `api` (axum control surface), tracing, graceful shutdown.
- Smoke-tested end to end; the control plane, supervisor, decrypt, backoff and
  reconcile all verified against a real server.
- **Read-only watcher (2026-07-20):** io-imap's `ImapMailboxWatch` now opens the
  mailbox with `EXAMINE`, not `SELECT` (DECISIONS §7) — pushed upstream and pulled
  in via the git dep.
- Found an upstream **imap-types alpha.6 bug** (QRESYNC/CONDSTORE atoms mis-parsed
  to `Unselect`, breaking io-imap's watch guard for every server). **Now resolved
  upstream in imap-types alpha.7** (via imap-codec alpha.9); the interim vendored
  `[patch.crates-io]` workaround has been **removed**, `tests/qresync.rs` still
  guards against a regression. Deps on current majors (axum 0.8, reqwest 0.13,
  rand 0.10, rusqlite 0.40, …).

**Not yet confirmed:** a full live IDLE→emit→POST against a real mailbox past the
capability guard (needs real creds + a reachable endpoint).

---

## M1–M7 · LANDED (2026-07-20)

The whole product core and both fronts landed and were **verified live
against a real Fastmail mailbox** (`imap.fastmail.com`, IMAP IDLE + SMTP
to trigger events). Merged to `master` (2026-07-20); 12 unit tests + the
qresync guard, clippy-clean.

- **M1** — `[accounts]` dropped; config is `[server]`+`[api]` only; the
  store is the sole watch source; `carillon import` / `serve` subcommands.
  *Verified: import → serve adopts the watch and reaches `watching`.*
- **M2** — `POST /test` (connect→auth→capability→LOGOUT) with a structured
  verdict; per-`(IP, login)` rate limit. *Verified: real creds → `ok`;
  wrong password → reachable-but-unauthenticated; 6th attempt → 429.*
- **M3** — Stripe-style `t=…,v1=…` signature (replay-protected), event-id
  idempotency, HTTPS-only notify URLs, HMAC rotation with a dual-signed
  overlap; `docs/WEBHOOKS.md`. *Verified: signed delivery `VALID`+fresh;
  post-rotation delivery still `VALID` under the old secret; DB migrated.*
- **M4** — SSE `GET /events` (delivery + status), content-free.
  *Verified: pause→`stopped`, resume→`watching`, real mail→`delivery`.*
- **M5** — two-counter metering (mailbox trial drained before the account
  pool), continuous debit, entitlement at watch-start, auto-refill,
  low-balance/exhaustion notices (SSE + signed webhook). *Verified live:
  trial drained to exhaustion → auto-pause; zero-credit resume refused;
  auto-refill kept a watch alive across the threshold.*
- **M6** — embedded OpenAPI 3.1 (`docs/openapi.yaml`, served at
  `/openapi.yaml`); serve modes (headless / `ui_dir` static + SPA / CORS
  CDN); `docs/SELF_HOST.md`. *Verified: spec served, UI+SPA fallback,
  CORS preflight scoped.*
- **M7** — login-less capability-link accounts (`/auth`, `/me`,
  `/signout`; hashed tokens, expiry, per-call validation, recovery) +
  billing behind a swappable `Billing` trait (stub) with stateless
  checkout→webhook fulfilment. *Verified: created→joined→recovered,
  checkout→idempotent webhook credit, signout→401.*

Remaining before production (documented, not blockers to the core):
real Stripe + RevenueCat `Billing` impls (need provider keys); deploy
infra (VPS, DNS, Caddy); OAuth-based watching (see M9). The original
milestone briefs are kept below for reference.

---

## M8 — Route scoping & authenticated SSE · LANDED (2026-07-20)

Every data route now requires a bearer token and is scoped to the caller
— **by default, in every front** (the simplest posture; self-host is a
narrow audience and gets the same model). No more global/unauthenticated
watches, deliveries, accounts or stream.

- A `Caller` extractor resolves the bearer to either a **capability-link
  account** (scoped to its own watches/deliveries/events/pool) or the
  optional **admin token** (`api.admin_token`, unscoped — ops / headless).
  Unset admin token = no unscoped access exists.
- `GET/POST /watches`, `/watches/{id}/…`, `/deliveries`, `/accounts…` are
  scoped: list routes filter to the account; single-resource routes 404
  across account boundaries (hiding existence). `POST /watches` forces the
  caller's account and requires the mailbox to have been proven via `/auth`
  (you can't watch what you can't log into — the anti-farming linchpin).
- **`GET /events` (SSE) is authed and scoped.** Live events carry the
  billing account they concern (`Routed`), and the stream forwards only the
  subscriber's own (admin sees all). Since `EventSource` can't send an
  `Authorization` header, `carillon-frontend` reads the stream via an
  authenticated fetch + SSE-frame parser carrying the Bearer link. A
  forwarding task pumps the scoped broadcast into a bounded channel backing
  the response body and ends on **either** server shutdown (a `watch` signal
  flipped on ctrl_c) **or** client disconnect — so a held SSE connection
  never blocks graceful shutdown (fixed 2026-07-20; hyper waits for
  in-flight connections, and an open SSE body never completes on its own).
- Public routes unchanged: `/health`, `/`, `/openapi.yaml`, `POST /test`,
  `POST /auth`, `GET /billing/packs`, the billing webhook. OpenAPI now
  declares a default `capabilityLink` requirement with explicit `security:
  []` opt-outs. 11 unit tests + qresync guard still green, clippy-clean.

## M9 — Discovery · LANDED (2026-07-20); OAuth watching · planned

**Discovery landed.** `POST /discover` (public, rate-limited per IP) takes a
"put anything" identifier — an email, or a bare domain/server — and returns
candidate **IMAP** endpoints + the auth methods each accepts, via
`io-pim-discovery` (provider rules, PACC, Mozilla autoconfig/ISPDB, RFC 6186
SRV). IMAP-only for now; SMTP/JMAP/DAV later. Results are hints the wizard
confirms/overrides; an unresolvable input returns an empty list, never an
error. `src/discover.rs` (blocking std client in `spawn_blocking`) + the
`ImapCandidate`/`AuthMethod` OpenAPI schemas. Live-verified against
gmail.com (→ imap.gmail.com:993, Google OAuth + password) and fastmail.com.
carillon-frontend's Identify stage rewritten to email/server → discover →
choose (himalaya/ortie-style, TLS candidate auto-picked).

**OAuth watching — Stages A–C BUILT (2026-07-20); interactive e2e pending.**
A watch can authenticate via OAuth instead of a password: the server holds a
**refresh token** and the held IMAP connection authenticates with SASL
`OAUTHBEARER`, minting a fresh access token per connect.

- **Stage A** — `src/oauth.rs`: RFC 8414 issuer resolution, RFC 7591 dynamic
  registration, auth-code + S256 PKCE, code exchange, refresh. `ClientId` =
  `Dynamic` (Fastmail) | `Static` (config/known client). Live-verified vs
  Fastmail (opt-in test).
- **Stage B** — store (`oauth_session` + `oauth_credential` tables, watch
  `auth_kind`); `session.rs` `ImapAuth::{Password,OauthBearer}`; supervisor
  refreshes per connect (rotated refresh tokens persisted); `POST /oauth/start`
  + `GET /oauth/callback` (exchange → verify via IMAP → mint/join capability
  link like `/auth` → store credential → popup `postMessage`); `create_watch`
  makes an OAuth watch when the mailbox has a stored credential.
- **Provider knowledge**: Fastmail = dynamic registration, scope from its
  advertised metadata (`urn:ietf:params:oauth:scope:mail offline_access`).
  Google/Microsoft = **Thunderbird's public client IDs** for now (swap for
  Carillon-owned apps later), mail-only scopes, Google's `access_type=offline`+
  `prompt=consent`. `/oauth/start` verified non-interactively for both.
- **Stage C** — carillon-frontend: the Authenticate stage branches to an OAuth
  sign-in popup (`/oauth/start` → provider → callback `postMessage`), Configure
  creates a password-less OAuth watch.

### IDLE-only watch path · LANDED (2026-07-20)

Gmail (and Yahoo, others) support IDLE but **not QRESYNC**, which the QRESYNC
watcher requires — confirmed live (`imap.gmail.com`: IDLE yes, QRESYNC no).
QRESYNC is now an *optimization*, not a requirement:

- **`pump::run_watch_idle`** — a read-only IDLE-only watcher for servers
  without QRESYNC. It keeps the mailbox's `UIDNEXT` and, on each IDLE wake,
  re-`EXAMINE`s and `UID FETCH`es the newly-appeared UIDs (bounded range,
  avoiding the `UIDNEXT:*` gotcha), emitting one `new` event each. **New
  messages only** — flag changes and deletions need QRESYNC/CONDSTORE. Built
  from io-imap's public `ImapMailboxExamine`/`ImapMessageFetch`/`ImapIdle`
  coroutines over the async pump; no io-imap change.
- **The supervisor picks** `run_watch` (QRESYNC, full deltas) when the server
  advertises QRESYNC, else `run_watch_idle`. `Probe::watchable()` now requires
  only **IDLE** (QRESYNC dropped from the gate); the `/test` verdict and OAuth
  callback carry `qresync` so the dashboard **warns "new messages only"** when
  it's absent. This broadens Carillon to nearly any IDLE-capable IMAP server.

**Pending**: the interactive consent → callback → live IDLE (QRESYNC *or*
IDLE-only) needs a real browser sign-in against a real account (can't be
auto-tested).
`config.public_url` must be reachable by the browser; Google/Microsoft need a
loopback/localhost redirect until Carillon registers hosted apps. RFC 8707
`resource` plumbing is present (unused; add if a provider needs it).

---

## Now — make it a real product core

### M1 — Accounts to the database; config = infra only
- Drop `[accounts]` from config and the `seed_accounts` step; config keeps only
  `[server]` + `[api]`.
- Control API becomes the **sole** way watches enter the DB. Add a thin bundled
  CLI (or one-shot `import`) so headless self-host can populate it.
- *Why:* unifies self-host + SaaS onto one account path; prerequisite for the UI
  and for metering. (DECISIONS §5.)

### M2 — Test-connect endpoint (separate Test from Activate)
- `POST /test`: connect → auth → **capability check `⊇ {IDLE, QRESYNC}`** →
  `LOGOUT`. Return a structured verdict (auth ok / caps ok / which missing).
- **Rate-limit per mailbox** (credential-oracle defence).
- *Why:* de-risks onboarding; free, repeatable iteration before spending a credit.
  (DECISIONS §2.)

### M3 — Webhook hardening
- **Timestamp in the signed content** (`t=…,v1=…`) → replay protection.
- **Event ID + idempotency** so receivers dedupe our retries.
- **HTTPS-only** enforcement on notify URLs; **secret rotation** with overlap.
- Ship documented verification recipes / copy-paste snippets.
- *Why:* the HMAC is only the foundation; these close the real gaps and let
  external endpoints trust us. (DECISIONS §4.)

### M4 — End-to-end "it works" demo + live stream (read-only)
- *(Watcher is already read-only via `EXAMINE` — landed in M0.)*
- **Read-only demo:** user sends themselves a mail (or waits for the next); no
  `APPEND` — Carillon never takes write access (DECISIONS §7).
- **SSE** endpoint streaming the delivery log + connection status to the UI.
- *Why:* the conversion moment — the user watches their own endpoint fire.
  (DECISIONS §2, §6, §7.)

### M5 — Metering & entitlement (the business model)
- Continuous **watch-time debit** against the **account's shared pool**; a paused
  watch stops debiting. Entitlement enforced at **watch-start** (server boundary).
- **Two watch-time counters, drained in order:** ① a **mailbox counter** (trial,
  non-refillable once emptied, granted once per `(login, provider)`), then ② the
  **account counter** (shared paid pool, refillable, ~12-month expiry). **Always
  debit ① then ②** — each mailbox burns its own trial before shared paid time; the
  pool is the only thing money touches (anti-farming + no stranding, no transfer).
- **Auto-refill** (opt-in) + low-balance / pre-expiry warnings via webhook (kill
  the silent outage).
- *Why:* correctness of the model lives here, not in the payment vendor.
  (DECISIONS §3.)

## Next — the fronts

### M6 — OpenAPI + self-host serving modes (the UI is its own repo)
- **The dashboard is a separate repo, `carillon-frontend`** — the default/reference
  SPA (Vite + React + TS + Tailwind + shadcn/ui), a pure client of this API. Its
  own build plan lives in `carillon-frontend/docs/PLAN.md`. carillon-backend's job here
  is only to make it *consumable*.
- Publish an **OpenAPI** spec (the contract `carillon-frontend` and any third-party UI
  build against).
- **Serve `carillon-frontend`'s `dist/` per-front:** self-host **embeds** a pinned
  build via `rust-embed` (one binary, no CORS) *or* points at a self-served copy;
  SaaS serves it from a **CDN** (M7). API base URL via `VITE_API_BASE_URL`.
- Self-host modes: headless (localhost API + token) and daemon+UI (local token).
- *Why:* separation of concerns — the daemon owns the API contract; the UI is one
  consumer, swappable/BYO. (DECISIONS §5, §6.)

### M7 — SaaS layer
- **No signup: a login-less account behind one capability link.** Public static
  dashboard (CDN); first auth creates an account + issues its unguessable bearer
  **capability URL** (shown on-screen, held in localStorage), server-validated per
  call, **rate-limited** (the one oracle surface); auth to another mailbox while
  holding the link adds it to the account. Recovery = re-auth to any member.
  (DECISIONS §5.)
- Billing tops up the **account's shared pool**; stateless on our side (Stripe/IAP
  keeps the customer + receipt, Carillon persists only the balance).
- Billing rails: **Stripe** Checkout on the web; **RevenueCat** to unify IAP across
  Play / App Store / Stripe (consumables = credit packs).
- Dashboard: onboarding wizard (M2+M4), account balance, delivery log, multi-mailbox
  switcher, watch CRUD.
- *Why:* the paid product. Built once M1–M5 are proven.

## Later — harden, scale, broaden (plan Phases 2-4)

### M8 — Harden & scale the IDLE side
- **Egress IP pool** (provider per-IP limits + receiver allowlisting).
- **KMS** for credentials (replaces the local age key).
- **Process split** for fault isolation (admin panic must not drop watchers) and
  independent restart/deploy — an ops decision, not a throughput one.
- IDLE-side **redundancy / SPOF** mitigation; reconnect-storm shaping; dead-socket
  liveness tuning; metrics + alerting on missed-notification conditions.

### Broaden source protocols (never payload) — plan roadmap
- **JMAP** — register a PushSubscription pointing at Carillon; re-emit
  `StateChange`. Near-free.
- **Gmail / Graph** — webhook ingress (`users.watch` → Pub/Sub; Graph
  subscriptions) + renewal cron; re-emit uniformly.
- **CalDAV / CardDAV** — poll sync-token/ctag, or WebDAV-Push where supported →
  PIM-wide notifier.
- **Native FCM/APNs + the consumer monolith app** (mail+contacts+calendar,
  offline-first) consuming Carillon.

Every step grows the *source protocols*; none grows the *payload*.

---

## Cross-cutting tracks (run throughout)

- **Credential custody** — the adoption gate, not a feature: OAuth-first where
  the provider allows; encrypt at rest (age → KMS); keep self-host a real option.
  Decide the posture before the dashboard. (DECISIONS, cross-cutting.)
- **Observability** — tracing → metrics (live connections, deliveries, credit
  debit rate); alert on the worst failure (silent-dead socket = missed notif).
- **Docs** — verification recipes, self-host guide, OpenAPI reference, and this
  living roadmap with a Landed history.

## The invariant

Everything above obeys one spine: **gate the standing resource; keep the
ephemeral free and un-authed; let content-free payloads + signatures carry the
trust.** Test is free, activation is metered, the self-hosted daemon needs no
inbound auth because nothing stands to receive.
