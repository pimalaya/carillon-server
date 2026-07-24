---
cairn: change
id: credential-residency-hardening
status: active
created: 2026-07-24
---

# Minimise decrypted-credential residency in the process

## Why
`overview.md` and `hardening.md` already treat the age-encrypted credential store as the crown jewel and cover its *at-rest* custody (0600 key, `LoadCredential`, backup separation, rotation runbook). But nothing governs the plaintext *in memory*, and the current password path is needlessly exposed:

- `spawn_watcher` decrypts a password **once** at spawn into a bare `Credential::Password(String)` (`supervisor.rs:44-45, 232`), and the connect/reconnect loop `.clone()`s that plaintext on every reconnect (`supervisor.rs:416`, CardDAV twin `:592`). So an active password sits in process memory as an un-zeroized `String` for the **entire lifetime of the watch** — recoverable from a core dump, swap, or `/proc/<pid>/mem`.
- The OAuth path already does the right thing by contrast: it holds no long-term plaintext, decrypts the refresh token per connect, and mints a fresh short-lived access token each time (`supervisor.rs:217-218, 711`).

This does **not** touch the operator's *ability* to decrypt — the age key is on the box by design; that is the [[credential-custody-boundary]] question. It shrinks the *window and residency* of the plaintext so an accidental leak (core dump, swap, memory scrape between reconnects) captures nothing, and makes the password path symmetric with OAuth: **hold ciphertext, decrypt just-in-time, zeroize immediately.**

## What
- Change `Credential::Password` to carry the **encrypted** form (plus the `Arc<Crypto>` handle already on the supervisor), not the plaintext. Decrypt at each `connect` into a `secrecy::SecretString` (secrecy is already a dependency and zeroizes on drop), expose it only for the `ImapLogin` / HTTP Basic call, and drop it the instant auth completes. Re-decrypt on reconnect, mirroring the OAuth mint-per-connect shape.
- Apply the same zeroizing-secret discipline to the OAuth refresh/access-token plaintext in `mint_access_token` (`supervisor.rs:692-713`) so no decrypted token outlives its use.
- Suppress the accidental-capture paths for the process: disable coredumps (`LimitCORE=0`) and keep decrypted secrets out of swap (swapless operation, or `LimitMEMLOCK` + locked secret pages). Fold these into the NixOS module ([[nixos]]) alongside the existing sandbox directives and into the [[hardening]] host baseline.
- Verify: decrypt happens per connect (not once at spawn); the plaintext is absent from a core dump taken mid-watch; a watch reconnects correctly across a dropped connection with the new JIT path.

Out of scope: the age key's own custody and the operator's ability to decrypt at rest — that is [[credential-custody-boundary]]. This change is purely about not leaving plaintext lying around in RAM.
