---
cairn: delta
change: sse-change-stream
---

## ADDED Requirements

### Requirement: Authenticated change stream (pull output)
Carillon SHALL expose the content-free change signal over an authenticated, account-scoped Server-Sent Events stream, so a consumer that cannot host a public webhook (behind NAT: a desktop client, CLI, or app) can receive changes by dialing out. The stream SHALL carry the same opaque `{id, account, event, uid|resource}` payload as a webhook, scoped by capability link (own account) or admin (all), with an optional per-watch filter, and SHALL enrich nothing — the consumer fetches content itself with its own credentials. ([[streaming]])

### Requirement: Change signal on the live bus
Every folded `ChangeEvent` SHALL be published to the live bus as a content-free `change` event tagged with its billing account, independent of webhook delivery, so an SSE-only watch (no notify URL) still emits its changes. ([[streaming]])

## MODIFIED Requirements

### Requirement: Service is one watched connection with its own credential
A service SHALL own its config, target, and its own credential; its notify URL is OPTIONAL. A service with no notify URL is watched and billed identically, delivering its change signal only to authenticated stream subscribers; a service with a notify URL delivers to both. ([[service-model]])

### Requirement: Endpoints at a glance
`GET /events` SHALL, in addition to delivery outcomes, connection status, and notices, carry the content-free `change` signal as a `change` event type — account-scoped and optionally filtered to a single watch. ([[serving]])
