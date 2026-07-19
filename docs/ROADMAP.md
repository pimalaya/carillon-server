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
to trigger events). One commit per milestone on the `milestones-m1-m7`
branch; 12 unit tests + the qresync guard, clippy-clean.

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
gate the watch/account routes behind the capability link in SaaS mode;
real Stripe + RevenueCat `Billing` impls (need provider keys); the
`carillon-admin` SPA; deploy infra (VPS, DNS, Caddy). The original
milestone briefs are kept below for reference.

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
- **The dashboard is a separate repo, `carillon-admin`** — the default/reference
  SPA (Vite + React + TS + Tailwind + shadcn/ui), a pure client of this API. Its
  own build plan lives in `carillon-admin/docs/PLAN.md`. carillon-server's job here
  is only to make it *consumable*.
- Publish an **OpenAPI** spec (the contract `carillon-admin` and any third-party UI
  build against).
- **Serve `carillon-admin`'s `dist/` per-front:** self-host **embeds** a pinned
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
