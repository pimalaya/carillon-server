---
cairn: change
id: starttls-support
status: active
created: 2026-07-23
---

# Wire STARTTLS (explicit TLS) for IMAP watching

## Why
The IMAP watcher only supports **implicit TLS** (TCP → immediate TLS handshake, port 993). `src/imap/session.rs` `open()` wraps the socket in TLS straight away, and `ImapAccount` has no transport-security field — there is no plaintext-greeting → `STARTTLS` → upgrade path. Servers that offer IMAP only over explicit TLS (port 143 + `STARTTLS`) cannot be watched.

This is a gap the rest of the stack already anticipates: `POST /discover` reports a `starttls` security kind alongside `tls`/`plain` (`discover.rs`), and the frontend onboarding surfaces `security?: "tls" | "starttls" | "plain"` — but its own comment admits the field is *informational* today ("Carillon watches over implicit TLS today; starttls/plain aren't wired yet"). So a user can discover a STARTTLS-only server, see it offered, and still not be able to watch it.

## What
Implement STARTTLS in the IMAP session path and thread the discovered/selected transport security through to the watcher:

- Add a transport-security field to `ImapAccount` (e.g. `tls` implicit vs `starttls` explicit), persisted with the watch.
- In `session::open`, branch on it: for `starttls`, read the plaintext greeting, confirm the server advertises the `STARTTLS` capability, issue `STARTTLS`, then perform the TLS handshake over the existing TCP stream (SNI/cert validation against the hostname, same as implicit today); for `tls`, keep today's immediate handshake.
- Thread the security kind from discovery / onboarding / `POST /watches` through the store into `ImapAccount`.
- Flip the frontend `security` field from informational to load-bearing (drop the "not wired yet" caveat) once the server accepts it.
- Decide the posture on `plain` (no TLS): almost certainly refuse it, keeping the read-only + credential-custody stance — confirm and document.

Out of scope: CardDAV transport (always HTTPS), and any change to the OAuth/password auth axis.
