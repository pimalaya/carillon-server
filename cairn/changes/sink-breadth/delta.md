---
cairn: delta
change: sink-breadth
---

## ADDED Requirements

### Requirement: Content-free sink breadth
Carillon MAY deliver its content-free signal to any HTTPS sink — a first-party webhook, an ntfy topic, or a UnifiedPush endpoint — and SHALL keep one opaque payload shape across all of them. A UnifiedPush endpoint or ntfy topic is just a `notify_url`; no per-sink code path exists. Output/sink breadth grows on the same terms as source breadth; the payload SHALL NOT be deepened, rendered, or reshaped to suit a particular sink. ([[overview]])

### Requirement: Relay-sink security model
For a relay sink (an ntfy / UnifiedPush push server that forwards the body and drops headers), the `X-Carillon-Signature` SHALL NOT be assumed to reach the end consumer; genuineness there rests on transport TLS plus the secrecy of the topic/endpoint URL, backstopped by the content-free payload. End-to-end HMAC verification remains the contract for first-party webhook receivers. ([[webhooks]])

## MODIFIED Requirements

### Requirement: Two-axis scope rule
Carillon SHALL grow along the breadth axis — source protocols AND output sinks — freely, and SHALL stay shallow along the depth axis (payload detail). Adding source protocols (IMAP, JMAP, Gmail/Graph, CalDAV/CardDAV) and adding content-free delivery sinks (webhook, ntfy, UnifiedPush, authenticated stream) is in scope; growing or reshaping the payload toward content, per-sink rendering, full deltas, storage, search, or message operations is permanently out of scope. ([[overview]])
