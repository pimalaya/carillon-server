---
cairn: tasks
change: sse-change-stream
---

- [ ] Add `LiveEvent::Change { account, event, uid, resource, id, at }` to `live.rs` (content-free, same fields as `ChangeEvent`) and its `name()` → `"change"`
- [ ] Publish the change to the live bus for every folded event, scoped by the watch's billing `account_id`, in `delivery::deliver` (independent of webhook delivery); note the pump-publish alternative if fold-time decoupling is wanted
- [ ] Surface `change` on `GET /events`, reusing the existing capability-link/admin scoping; add an optional `?watch=<id>` filter
- [ ] Make `notify_url` optional: `DEFAULT ''` sentinel in the `watch` schema, Option-ize `Watch.notify_url` / `CreateWatch.notify_url` at the Rust boundary, skip `validate_notify_url` when empty
- [ ] Delivery worker: when the sink is empty, skip the POST and the delivery-log row but still publish the change to the bus
- [ ] Create/onboarding path: allow an empty `notify_url` and skip the webhook-test step (`POST /test` / VerifyStage) for an SSE-only service
- [ ] Metering/entitlement: confirm an SSE-only watch is billed and trialled exactly like a webhook watch
- [ ] Verify: a consumer behind NAT subscribes to `/events?watch=…` with a capability link and receives `change` events on new mail and on a contact change — no public URL, no webhook
- [ ] Frontend (optional): surface live `change` events in the dashboard activity view
- [ ] Fold the delta into the spec (new [[streaming]] capability; [[serving]] endpoint surface; [[service-model]] optional notify URL) and add the log entry
