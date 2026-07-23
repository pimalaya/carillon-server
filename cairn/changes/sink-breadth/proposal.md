---
cairn: change
id: sink-breadth
status: active
created: 2026-07-24
---

# Bless content-free sink breadth (webhook is the universal push sink)

## Why
The delivery path is already a generic content-free sink. `delivery.rs` POSTs the opaque `{id, ts, account, event, uid|resource}` body to any `https://` `notify_url`, and `validate_notify_url` accepts any of them. That means two of the three "outputs" users ask for already work today with **zero new code**: an **ntfy topic** URL and a **UnifiedPush endpoint** are just HTTPS URLs, and carillon already sends them exactly the opaque bytes they need (`accounts.sample.toml` even ships the ntfy example).

What's missing is not code, it's truth-in-spec:

- The scope model (`overview.md`, "Two-axis scope rule") blesses growing *source protocols* and forbids growing the *payload*, but is silent on *output sinks* — so "UnifiedPush and ntfy are first-class delivery targets" has no blessed home, and the next sink request has nothing to point at.
- The webhook contract (`webhooks.md`) mandates end-to-end signature verification by "a receiver". That silently does not hold when a **relay** (an ntfy / UnifiedPush push server) sits in the middle: relays forward the *body* and drop the `X-Carillon-*` headers, so the HMAC never reaches the consumer. Security there is transport TLS plus the secrecy of the topic/endpoint URL — and content-free is exactly what makes that downgrade acceptable (a leaked relay push reveals only "something changed").

This change codifies what is already true and draws the line we chose deliberately: **one opaque content-free shape for every sink, forever.** Carillon does not format per-sink (no ntfy titles/tags/priority), because a "pretty" notification means rendering a human-readable string, and that is a step down the payload-depth axis we do not take. Prettiness is the consuming app's job, downstream of the signal.

## What
- Bless **output/sink breadth** as an in-scope growth axis in `overview.md`, the mirror of source breadth: carillon MAY deliver its content-free signal to any HTTPS sink; it SHALL NOT deepen or reshape the payload to suit one. The payload stays opaque regardless of sink.
- Document the three blessed content-free push recipes and their trust models:
  - **Own webhook** — first-party receiver; verifies the HMAC end-to-end (the existing contract, unchanged).
  - **ntfy topic** — relay sink; receives the opaque body; the HMAC does not survive the relay; a human reads a raw "something changed" ping (or their app deep-links).
  - **UnifiedPush endpoint** — relay sink via the user's chosen distributor; carillon POSTs opaque bytes; the *consuming app* decodes and enriches with its own credentials (the full signal-not-sync loop). From carillon's side this is indistinguishable from any other webhook — the endpoint URL is just a `notify_url`.
- Amend `webhooks.md` to acknowledge relay sinks explicitly: end-to-end signature verification is the contract for first-party receivers; for relay sinks the guarantee degrades to TLS + URL secrecy, backstopped by content-free.
- Add a UnifiedPush endpoint example alongside the ntfy one in `accounts.sample.toml`.
- Verify all three recipes end-to-end.

Out of scope (explicit, per the opaque-only decision): any per-sink formatter (ntfy title/tags/priority), multi-destination fan-out, and the pull/SSE output path — that is its own change, [[sse-change-stream]].
