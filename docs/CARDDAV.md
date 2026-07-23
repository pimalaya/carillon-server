# Carillon: CardDAV addressbook watching

Carillon's second source protocol, alongside IMAP. Same two-axis rule as the rest of the plan: **grow the source protocols, never the payload.** A CardDAV service emits the same content-free signal ("this addressbook changed"), never the vCard.

## Why polling (there is no IDLE)

CardDAV is WebDAV over HTTP: there is **no long-held push** like IMAP IDLE. The mechanisms that exist, most to least available:

1. **Polling via WebDAV-Sync (RFC 6578) + CTag**: universal. A `sync-collection` REPORT returns the members changed/removed since a checkpoint *sync-token*, plus the next token. This is what Carillon uses.
2. **WebDAV-Push** (draft): real Web Push, but essentially Nextcloud-only today.
3. **APNs `push-transports`**: iCloud-specific.
4. **JMAP-for-contacts** (RFC 9610): Fastmail's push path is JMAP, not CardDAV.

So a CardDAV service is **polled**: every `carddav_poll_interval_secs` (default 300s, per-service override possible) the poller runs one `sync-collection` REPORT and emits an event per changed / removed member. Only `getetag` is requested, never `address-data`, so the signal stays content-free by construction.

## Model

A CardDAV service is a `watch` row with `source_kind = 'carddav'`. It is added **under an existing PIM account** (one validated via `POST /auth`, i.e. IMAP) and **reuses that account's stored credential**, the common provider reality (a Fastmail app password authenticates IMAP *and* CardDAV). Concretely:

| Column | CardDAV meaning |
|---|---|
| `source_kind` | `'carddav'` |
| `imap_host` / `imap_port` / `login` | the **PIM-account identity**: keys the mailbox key + stored credential (shared with the account's IMAP membership), **not** the CardDAV host |
| `carddav_url` | the full collection URL the poller actually connects to |
| `mailbox` | a display name for the addressbook |
| `carddav_sync_token` | the RFC 6578 checkpoint (runtime state; kept across edits, reset on re-baseline) |
| `carddav_poll_secs` | per-service poll override (null = server default) |

Billing is unchanged: a CardDAV service is a billed unit like any other, **1 credit / month** (§ BILLING_MODEL.md). Its dedup target is the collection URL, so two addressbooks under one account are two distinct services.

## Events

CardDAV changes fold into the same [`ChangeEvent`] shape as IMAP, with two differences:

- Only `new` (created/updated) and `removed` occur: WebDAV has no flag concept.
- There is no UID. The changed member is identified by `resource`: the href's last path segment (the vCard resource name), a content-free locator exactly analogous to an IMAP UID. The webhook payload carries `resource` and omits `uid` (the delivery log stores `uid = 0`).

## Baseline (no activation storm)

The **first** poll of a service (no stored token) is a *baseline*: it enumerates the collection to establish the current sync-token but **emits nothing**, otherwise activating a service would fire one event per existing contact. Every later poll emits the real delta. A server that rejects a stale token surfaces as `InvalidSyncToken`; the poller resets to a fresh baseline.

## Implementation

- src/carddav/session.rs: TLS open (SSRF-guarded like IMAP), the async pump that drives io-webdav's I/O-free coroutines over the stream, `probe` (for `/test`) and `sync_changes` (one `sync-collection` REPORT).
- src/carddav/pump.rs: `poll_once`: one poll round, baseline-aware, emitting the delta and returning the next token to checkpoint.
- src/supervisor.rs: `carddav_watch_loop`: resolve credential (Basic, or a fresh OAuth bearer), poll, checkpoint, sleep, back off on failure.

Built on the [`io-webdav`](https://github.com/pimalaya/io-webdav) crate (RFC 6578 `SyncCollection`) over [`io-http`](https://github.com/pimalaya/io-http), driven exactly like the IMAP coroutines: no blocking client, our own tokio-rustls stream.

## Not yet

- **Addressbook discovery** (RFC 6764 well-known + `addressbook-home-set` listing): today the collection URL is entered manually. A CardDAV service also currently requires an IMAP-validated PIM account (shared credential); a first-class CardDAV-only account (validate via `PROPFIND`) is a later step.

[`ChangeEvent`]: ../src/event.rs
