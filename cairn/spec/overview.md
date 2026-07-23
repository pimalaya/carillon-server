---
cairn: spec
capability: overview
status: current
---

# Carillon: Signal, Not Sync

Carillon is a hosted watcher that turns a change on a remote mailbox into an outbound notification. It holds the standing connection a phone or lambda cannot (IMAP IDLE) and, the instant a mailbox changes, POSTs a small, signed, content-free signal to a notify URL the user controls. The single governing principle is that Carillon *signals; it never syncs*: it emits a uniform "something changed" webhook and never stores, syncs, or serves message content. Everything about scope, cost, and trust follows from that line.

The consumer does its own incremental fetch after the ping (it holds the credentials); the push provider and Carillon itself never see sender, subject, or body. See [[architecture]] for the runtime shape, [[webhooks]] for the delivery contract, [[auth]] for identity, and [[billing]] for entitlement.

### Requirement: Signal not sync
Carillon SHALL emit a uniform, content-free "something changed" event when a watched mailbox changes, and SHALL NOT store, sync, serve, or transmit message content, bodies, envelopes, full state, or deltas.

#### Scenario: New mail arrives
- **GIVEN** a live watch on a mailbox
- **WHEN** new mail arrives (a new UID / `EXISTS`)
- **THEN** Carillon POSTs a content-free signal carrying the event type and mailbox identity, not the message or its envelope
- **AND** the receiving client performs its own fetch to obtain any content it needs

### Requirement: Two-axis scope rule
Carillon SHALL grow along the breadth axis (source protocols) freely and SHALL stay shallow along the depth axis (event detail / content). Adding source protocols (IMAP, later JMAP, Gmail/Graph, CalDAV/CardDAV) is in scope; growing the payload toward content, full deltas, storage, search, or message operations is permanently out of scope.

#### Scenario: A feature would deepen the payload
- **GIVEN** a proposed feature
- **WHEN** it would emit message content, full deltas, stored state, search, or perform operations on the user's behalf
- **THEN** it is rejected as crossing the permanent hard stop, regardless of source protocol

### Requirement: One core, two fronts
The same core (watcher supervisor, delivery, store) SHALL ship in two deployments distinguished only by their front, never by different code paths: a self-hosted daemon (optionally with the reference UI) that connects out and POSTs webhooks, and a multi-tenant SaaS that is the same daemon plus tenant auth, dashboard, and billing. Deployment topology is not product topology: the transformer stays cleanly separable and self-hostable.

### Requirement: Read-only posture
Carillon SHALL be read-only toward mailboxes: it uses `EXAMINE` (not `SELECT`), `FETCH`, and `IDLE`, and SHALL never issue write commands (`APPEND`, `STORE`, `EXPUNGE`). No feature that requires write access is admitted, because a write breach would allow injecting perfectly-spoofed phishing (bypassing SPF/DKIM/DMARC via `APPEND`) into every watched inbox, whereas a read-only breach leaks only content-free signals.

#### Scenario: A feature needs write access
- **GIVEN** a proposed feature (e.g. an `APPEND`-injected test message, in-mailbox warnings, or in-mailbox link delivery)
- **WHEN** it requires issuing a write command to a watched mailbox
- **THEN** it is rejected; the equivalent capability is delivered read-only instead (verification via a live log, warnings via webhook or the payer's Stripe email)

### Requirement: Credential custody as the adoption ground
Because Carillon holds mailbox credentials in order to watch, credential custody SHALL be treated as the trust-sensitive core and the adoption gate. Carillon SHALL prefer scoped OAuth read-only access wherever the provider allows it (Gmail, Microsoft, Fastmail), SHALL encrypt credentials at rest, and SHALL keep self-hosting a real option. OAuth read-only scopes make write provider-impossible even on full breach; for password / app-password mailboxes read-only is code discipline only, so the encrypted credential store is the crown jewels and content-free payloads are the backstop.
