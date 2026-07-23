---
cairn: change
id: sse-change-stream
status: active
created: 2026-07-24
---

# Authenticated SSE change stream (the pull dual of the webhook)

## Why
Webhook delivery is push: carillon dials out to a public URL the consumer must host. A large class of consumers cannot host one — a desktop PIM client, a CLI, a phone app, anything behind NAT. For them the change signal is currently unreachable except indirectly: `/events` exists, but it carries only delivery *outcomes*, connection *status*, and billing *notices*, scoped to the dashboard's billing account, and the **change signal itself is never put on the live bus** — it flows on a private mpsc straight to the delivery worker (`main.rs` → `delivery::run`). So today you can only infer a change over SSE as a side effect of a `delivery` event, and only if a `notify_url` is configured.

SSE is the natural pull dual of the webhook: the consumer opens one long-lived authenticated connection **outbound** (NAT-friendly, no public URL), receives the same opaque content-free event, and enriches it with its own credentials. This is the principled answer to "system notifications" kept from the design discussion: the user's own client is the notifier — carillon ships no app, holds no extra secret, and the signal stays content-free.

## What
- Put the change signal on the live bus: add a `LiveEvent::Change { account, event, uid, resource, id, at }` variant (`live.rs`) carrying the same content-free fields as `ChangeEvent`, published for every folded event, tagged (`Routed`) with the watch's billing `account_id`. Publish it in the delivery worker (`delivery::deliver`) — it already receives every event and holds the `LiveBus` — independent of whether a webhook is delivered. (Alternative: publish at the pump for stricter fold-time decoupling, at the cost of threading `LiveBus` into `imap/pump.rs` + `carddav/pump.rs`. Flagged for review.)
- Surface it on the existing authenticated, scoped `/events` stream as a `change` event type. Reuse the capability-link / admin scoping already in `events()` (a subscriber sees only its own account's changes; admin sees all). Add an optional `?watch=<id>` filter so a consumer can subscribe to a single service.
- Make `notify_url` optional so a watch can be SSE-only. Prefer the empty-string sentinel (`notify_url TEXT NOT NULL DEFAULT ''`, `''` → "no push sink") to avoid a table rebuild, mirroring the existing `account_id ... DEFAULT ''`; Option-ize at the Rust boundary. The delivery worker SHALL skip the POST (and the delivery-log row) when the sink is empty, but still publish the change to the bus. The create/onboarding path SHALL allow an empty `notify_url` and skip the webhook-test step.
- Entitlement: an SSE-only watch is still a billed service (a standing connection is what costs); confirm trial/credit/metering treat it identically to a webhook watch.
- Verify: a NAT-bound consumer subscribes to `/events?watch=…` with a capability link and receives `change` events on new mail / contact change, with no public URL and no webhook configured.

Spec home: a new `spec/streaming.md` capability (the pull-output contract, symmetric to `webhooks.md`), with pointers from `serving.md` (endpoint surface) and `service-model.md` (notify URL now optional). Open to folding into `serving.md` instead — flagged for review.

Out of scope: per-sink formatting (see [[sink-breadth]]), multi-destination fan-out, and a dedicated per-watch subscribe token (the account capability link is reused).
