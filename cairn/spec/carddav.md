---
cairn: spec
capability: carddav
status: current
---

# CardDAV Addressbook Watching

CardDAV is Carillon's second source protocol alongside IMAP, and it obeys the same two-axis rule: grow the source protocols, never the payload. A CardDAV service emits the same content-free "this addressbook changed" signal, never the vCard. Because CardDAV is WebDAV over HTTP with no long-held push, it is watched by polling rather than IDLE. See [[overview]] for the scope rule and [[webhooks]] for the delivery contract the emitted events flow into.

### Requirement: Poll, not IDLE
Because CardDAV is WebDAV over HTTP and has no long-held push equivalent to IMAP IDLE, a CardDAV service SHALL be watched by polling. Carillon SHALL poll via WebDAV-Sync (RFC 6578) with a sync-token, the one universal mechanism (WebDAV-Push, APNs `push-transports`, and JMAP-for-contacts each being provider-specific and out of scope here).

### Requirement: Sync-token poll model
Every poll interval (`carddav_poll_interval_secs`, default 300s, per-service override possible) the poller SHALL run one `sync-collection` REPORT against the collection URL, returning the members changed or removed since the stored sync-token plus the next token to checkpoint. The request SHALL ask for `getetag` only, never `address-data`, so the signal stays content-free by construction. The sync-token is runtime state kept across edits and reset only on re-baseline.

### Requirement: Emitted events
A CardDAV poll SHALL fold into the same change-event shape as IMAP, with two differences: only `new` (created or updated) and `removed` occur, since WebDAV has no flag concept; and there is no UID — the changed member is identified by `resource`, the href's last path segment (the vCard resource name), a content-free locator analogous to an IMAP UID. The webhook payload SHALL carry `resource` and omit `uid`.

### Requirement: Baseline with no activation storm
The first poll of a service, when no sync-token is stored, SHALL be a baseline that enumerates the collection to establish the current sync-token but emits nothing, so that activating a service does not fire one event per existing contact. Every later poll SHALL emit the real delta. If a server rejects a stale token (surfacing as an invalid-sync-token condition), the poller SHALL reset to a fresh baseline.

#### Scenario: A service is first activated
- **GIVEN** a CardDAV service with no stored sync-token
- **WHEN** its first poll runs
- **THEN** the poller enumerates the collection, records the current sync-token, and emits no events
- **AND** the next poll emits only members changed or removed since that baseline

### Requirement: Service model reuses the PIM account credential
A CardDAV service SHALL be a watch with source kind `carddav`, added under an existing PIM account (one validated via IMAP) and reusing that account's stored credential, reflecting the common provider reality that one app password authenticates IMAP and CardDAV. The account identity keys the mailbox key and stored credential, while a separate collection URL is what the poller connects to; dedup targets the collection URL, so two addressbooks under one account are two distinct services.

### Requirement: Not yet — discovery and CardDAV-only accounts
Addressbook discovery (RFC 6764 well-known plus `addressbook-home-set` listing) is not yet implemented; the collection URL is entered manually. A CardDAV service currently requires an IMAP-validated PIM account for its shared credential; a first-class CardDAV-only account (validated via `PROPFIND`) is a later step.
