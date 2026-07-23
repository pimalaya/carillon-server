---
cairn: spec
capability: architecture
status: current
---

# Runtime & Deployment Architecture

The MVP is the IMAP-IDLE-to-signed-webhook transformer: register credentials plus a notify URL, and Carillon holds an IDLE connection and POSTs a signed, content-free payload on change. The notify URL is either a developer's own webhook or an ntfy topic URL, giving one delivery mechanism for two audiences with no app on Carillon's side. IMAP IDLE is the one input that needs a standing process; isolating it as this transformer homogenises everything downstream to webhooks.

Carillon runs as a single async Rust process on one VPS with a local SQLite store, not on lambda. Watchers and the control API are both I/O-bound tokio tasks that sleep at `await` almost all the time, so one process interleaves them safely; splitting is a later fault-isolation and independent-restart decision, not a throughput one. See [[overview]] for the governing principle, [[serving]] for how the UI is served, [[webhooks]] for the delivery contract, and [[auth]] / [[billing]] for the SaaS front.

### Requirement: IMAP-IDLE to signed-webhook transformer
The core watcher SHALL, per watch, connect to the IMAP server, authenticate, open the mailbox read-only, and run IDLE; on a mailbox change it SHALL POST a signed, content-free payload carrying the event type and mailbox identity to the configured notify URL. It SHALL re-IDLE periodically (per RFC 2177, roughly every 29 minutes) to keep the connection alive.

### Requirement: Single-VPS topology
Carillon SHALL deploy as a single box (one VPS) with a local SQLite store as the entire backend, folding stateless webhook handling onto the box that must run for IDLE regardless. It SHALL NOT depend on lambda or a second platform at this stage. The transformer SHALL remain cleanly separable and self-hostable, and the delivery path SHALL remain stateless and datastore-backed, so either can lift to another box or to lambda later without a rewrite.

### Requirement: Async IMAP pump
The IMAP watchers SHALL run on an async runtime (tokio), holding one standing TCP/IDLE connection per watch, so that thousands of connections fit on a single box. Watchers SHALL park on socket readability and SHALL NOT block the runtime.

### Requirement: One supervised task per watch
Each watch SHALL run as its own supervised async task. A supervisor SHALL spawn and stop watcher tasks as watches are added, removed, or as entitlement flips active or lapsed. Each watcher SHALL reconnect with backoff on failure and SHALL detect dead sockets (liveness), since a silently dead socket is a missed notification, the worst failure mode.

#### Scenario: A watch loses its connection
- **GIVEN** a live watch whose IMAP connection drops or goes silently dead
- **WHEN** the supervisor's watcher detects the failure
- **THEN** it reconnects with backoff and resumes IDLE without taking down other watches or the control API

### Requirement: Decoupled delivery worker
Webhook delivery SHALL be decoupled from the watcher hot path: outbound POSTs are `reqwest` calls, HMAC-signed, retried with backoff, and blocking DB/crypto work SHALL run in `spawn_blocking` so it never stalls the runtime.

### Requirement: SQLite store
Persistent state (watches, webhooks/notify config, delivery log, and the SaaS account/billing state) SHALL live in a local SQLite database accessed via `sqlx` in WAL mode. Postgres is adopted only when SQLite is outgrown.

### Requirement: Credentials encrypted at rest
Mailbox credentials SHALL be encrypted at rest using the `age` crate with a key held in the box's secrets file (KMS deferred). See [[overview]] on credential custody as the adoption ground.

### Requirement: Axum control API
The control surface SHALL be an axum HTTP server exposing REST+JSON for control and SSE for the live delivery-log / connection-status stream, running in the same process as the watchers at MVP. It SHALL be splittable into a separate service later purely for fault isolation and independent deploy.

### Requirement: Tech stack shape
The MVP stack SHALL be: Rust with tokio (async throughout); `io-imap` for async IMAP/IDLE; axum for the API and dashboard control; SQLite via `sqlx` (WAL) for storage; `reqwest` with HMAC-signed retrying POSTs for delivery; the `age` crate for credentials at rest; and, on the host, Debian with systemd and Caddy for auto TLS. Stripe backs SaaS billing (see [[billing]]).
