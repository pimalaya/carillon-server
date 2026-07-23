---
cairn: delta
change: bootstrap
---

This bootstrap seeds the whole spec; the headline requirement per capability is
listed below. The full text lives in `cairn/spec/`.

## ADDED Requirements

### Requirement: Signal, not sync
Carillon holds a standing connection and emits signed, content-free webhooks; it grows source protocols, never payload. ([[overview]])

### Requirement: One core, two fronts
One daemon core serves a self-hosted front (± UI) and a multi-tenant SaaS front. ([[overview]])

### Requirement: Read-only posture
Carillon never writes to a mailbox; it opens with `EXAMINE`, never `SELECT`. ([[overview]])

### Requirement: IMAP-IDLE → webhook transformer
A supervisor holds one task per watch (reconnect backoff, reconcile) feeding a decoupled delivery worker; SQLite store; credentials age-encrypted at rest; axum control API. ([[architecture]])

### Requirement: Account / PIM-account / service hierarchy
A Carillon account holds PIM accounts, each holding services; a service is one watched connection with its own credentials (v3). ([[service-model]])

### Requirement: Prepaid credit billing
You pay per service via a prepaid credit pool (1 credit = one service-month); the first service runs free for 7 days; Stripe Checkout with stateless webhook fulfilment. ([[billing]])

### Requirement: Signed content-free webhooks
`{account, event, uid}` payloads with a Stripe-style `t=…,v1=…` HMAC-SHA256 signature, replay + idempotency protection, HTTPS-only, secret rotation with overlap. ([[webhooks]])

### Requirement: CardDAV polling
CardDAV sources are polled by sync-token/ctag (no IDLE), emitting the same content-free events without an activation storm. ([[carddav]])

### Requirement: Deliverable transactional email
Magic links and notices are sent with SPF/DKIM/DMARC alignment through the configured provider. ([[email]])

### Requirement: Authenticated, scoped routes
Every data route requires a bearer token; a `Caller` resolves it to a scoped capability-link account or the optional unscoped admin token; cross-account single-resource reads 404. ([[auth]])

### Requirement: Capability link mint / rotate / revoke
`/auth` mints an unguessable per-account bearer, stored hashed with expiry, validated per call, rotatable, revoked by `/signout`. ([[auth]])

### Requirement: Three serving fronts
Headless self-host, self-host + embedded UI (`ui_dir`), and SaaS (CDN + `cors_allow_origin`), from one binary. ([[serving]])

### Requirement: Blast-radius-ordered hardening
SSRF on the public request surface is the top priority, then secret/key custody, TLS/host, capacity, durability, and observability. ([[hardening]])

### Requirement: Single-VPS production runbook
Capacity budget (fds, ephemeral ports, conntrack above the ~29-min re-IDLE bound), hardened host baseline, and offline age-key custody backed up out-of-band. ([[production]])

### Requirement: NixOS module
A two-layer module + overlay runs the daemon, keeping the two age keys distinct and reading secrets through a sops/agenix seam. ([[nixos]])
