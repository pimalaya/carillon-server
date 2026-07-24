---
cairn: delta
change: credential-residency-hardening
---

## ADDED Requirements

### Requirement: Minimal decrypted-credential residency
A decrypted credential SHALL exist in process memory only transiently, around the connection that needs it. The watcher SHALL hold the credential in encrypted form, decrypt it just-in-time at each connect into a zeroize-on-drop secret type, expose it only for the authentication call, and drop it immediately after — re-decrypting on reconnect, symmetric with the OAuth mint-per-connect path. No long-lived plaintext credential SHALL persist for the lifetime of a watch. ([[hardening]])

### Requirement: Suppress accidental secret capture
The service SHALL disable coredumps (`LimitCORE=0`) and keep decrypted secrets out of swap (swapless operation or locked pages), so an accidental capture — core dump, swap, memory scrape — does not yield a plaintext credential. This complements at-rest key custody: it addresses the plaintext in RAM, not the key on disk. ([[hardening]])

## MODIFIED Requirements

### Requirement: Credentials encrypted at rest
Mailbox credentials SHALL be encrypted at rest using the `age` crate with a key held in the box's secrets file (external wrapping deferred to the custody-boundary work). Beyond at-rest encryption, the decrypted plaintext SHALL be minimised in memory: decrypted just-in-time per connect, held in a zeroizing secret type, and dropped after the authentication call rather than held for the watch's lifetime. ([[architecture]])
