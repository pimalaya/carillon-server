---
cairn: tasks
change: sink-breadth
---

- [ ] MODIFY the two-axis scope rule in `overview.md` so output sinks grow like source protocols, while the payload never deepens or is reshaped per sink (opaque-only)
- [ ] Amend `webhooks.md`: add the relay-sink security model (headers/signature do not survive a push relay; TLS + topic/endpoint-URL secrecy + content-free carry it) and name own-webhook / ntfy / UnifiedPush as the blessed content-free targets
- [ ] Add a UnifiedPush endpoint example to `accounts.sample.toml` next to the ntfy topic example
- [ ] Verify end-to-end: own webhook sink (HMAC verifies); ntfy topic (phone shows the raw content-free ping); UnifiedPush endpoint via a distributor (ntfy app / NextPush) round-trips opaque bytes to a consuming app
- [ ] Confirm no delivery-path code change is required (`validate_notify_url` already accepts these; the body is already opaque) — capture the finding, or note the one-line exception if any is found
- [ ] Fold the delta into the spec ([[overview]], [[webhooks]]) and add the log entry
