---
cairn: log
change: bootstrap
landed: 2026-07-23
---

# Adopt Cairn and migrate the docs/ folder

Adopted the Cairn convention for carillon-backend. Created the `cairn/` root, added the activation surface (`AGENTS.md` with `CLAUDE.md`, Cursor and Copilot pointers) and the `verify.sh` Stop hook vendored from pimalaya/cairn, and removed the old `docs/` folder after migrating its content.

Moved `openapi.yaml` from `docs/` to the repository root — it is a served contract artifact compiled into the binary via `include_str!`, not prose — and repointed the `include_str!` path in `src/api.rs` plus every reference in the README, CONTRIBUTING, the frontend, and the deploy repo. `cargo check` green.

Seeded the spec from the current-truth content of the design docs as twelve capabilities, all ADDED: `overview`, `architecture`, `service-model`, `billing`, `webhooks`, `carddav`, `email`, `auth`, `serving`, `hardening`, `production`, `nixos`. The operator runbooks (production, hardening, nixos) were folded in as capabilities rather than left as loose files. The spec holds current truth only; the build history and the paths not taken are recorded here.

## Superseded / reverted decisions (not in the spec)

The former `docs/DECISIONS.md` and versioned models carried supersessions in place; the spec keeps only the winner:

- **Billing: prepaid credits, not subscription.** DECISIONS §3a introduced a single flat subscription (2026-07-21) superseding the §3 pay-as-you-go model, but the subscription was later **reverted**; current truth is the prepaid credit pool (`BILLING_MODEL.md` v2), matching the frontend's own reversal.
- **Metering: credit pool + free credit, not the two-counter trial.** The earlier two-watch-time-counter model (per-mailbox trial drained before the account pool, roadmap M5) was replaced by the fungible credit pool plus a 7-day free credit on the first service.
- **Service model: credentials on the service (v3), not shared.** `SERVICE_MODEL.md` v3 (built 2026-07-22) put credentials on each service; the v2 shared-credential model is superseded and omitted.

## Landed milestone history (migrated from docs/ROADMAP.md)

Predates Cairn; preserved here rather than in the spec:

- **M0 — Prototype beast (2026-07-19).** Async IMAP-IDLE → signed-webhook core: `imap::pump` / `session`, `supervisor` (one task per watch, jittered reconnect, reconcile), `delivery` (pooled reqwest, HMAC-SHA256, retry), SQLite WAL store, age-x25519 at rest, axum control surface. Read-only via `EXAMINE` landed 2026-07-20. Worked around then dropped an upstream imap-types alpha.6 QRESYNC/CONDSTORE bug (fixed upstream in alpha.7).
- **M1–M7 — product core + both fronts (2026-07-20).** Verified live against a real Fastmail mailbox. M1 accounts-to-DB (config = infra only, `import`/`serve`); M2 `POST /test` verdict + rate limit; M3 webhook hardening (signed timestamp, idempotency, HTTPS-only, rotation with overlap); M4 SSE `GET /events` (content-free); M5 metering; M6 embedded OpenAPI + serve modes; M7 login-less capability-link accounts (`/auth`, `/me`, `/signout`) + billing behind a swappable trait.
- **M8 — route scoping & authenticated SSE (2026-07-20).** Every data route bearer-scoped via a `Caller` extractor (capability-link account or unscoped admin token); cross-account single-resource reads 404; authed SSE read over an authenticated fetch (native `EventSource` can't send headers); held SSE connections no longer block graceful shutdown.
- **M9 — discovery + OAuth watching (2026-07-20).** `POST /discover` (io-pim-discovery: provider rules, PACC, Mozilla autoconfig, RFC 6186 SRV), IMAP-only. OAuth watching stages A–C built (refresh-token custody, SASL `OAUTHBEARER`), interactive end-to-end pending. An IDLE-only watch path landed for servers with IDLE but no QRESYNC (e.g. Gmail); QRESYNC became an optimisation, not a gate.

## Still open at migration time

Real Stripe/RevenueCat billing impls (need provider keys), production deploy infra (VPS, DNS, Caddy, live keys, provider app verification), and interactive OAuth end-to-end (real browser consent). The forward roadmap (harden/scale the IDLE side, broaden source protocols — JMAP, Gmail/Graph, CalDAV/CardDAV, native push — never the payload) is captured in the roadmap history, not the spec.

This log entry and the `bootstrap` change are the first stones.
