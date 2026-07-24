---
cairn: change
id: credential-custody-boundary
status: active
created: 2026-07-24
---

# Credential custody boundary: hold less, move the wrap-key off the box

## Why
The daemon can decrypt every stored credential: one per-box age identity is loaded for the daemon's whole life (`crypto.rs:17-50`), so root-on-the-box, a stolen disk-plus-key, or the operator can decrypt the lot offline. `overview.md` names this ("for password mailboxes read-only is code discipline only, so the encrypted store is the crown jewels") but stops at "prefer OAuth" and "encrypt at rest."

The governing reality is a trilemma — **autonomy (unattended 24/7, survives restart) × password auth × operator-zero-knowledge: pick two.** A watcher that re-authenticates unattended at 3 a.m. must be able to obtain the credential unattended, so whoever controls the daemon can too. "Never able to decrypt" is therefore unreachable for autonomous password watching. The honest programme is: (1) hold a *less dangerous* secret, (2) hold it *briefly* ([[credential-residency-hardening]]), (3) move the *wrap-key off the box* so at-rest theft and quiet insider decryption stop and every decryption becomes auditable/revocable, and (4) make the residual trust *verifiable*. This change writes that trilemma and posture into the spec and commits to (1) and (3).

## What
**Tier 1 — reduce what we hold (biggest blast-radius win).**
- Elevate scoped **read-only OAuth** from "preferred" to the **default** wherever the provider supports it (Gmail, Microsoft, Fastmail — path already built): a full breach then cannot write, send, or delete (provider-enforced) and the grant is user-revocable without a password change.
- For password providers, make onboarding steer to a **dedicated, revocable app-password** (never the account's primary password; read-only scope where the provider offers it), with per-provider guidance; consider refusing / hard-warning on an obviously-primary password.

**Tier 2 — move the wrap-key off the box (defeats stolen-disk/backup and quiet insider decryption, keeps autonomy).**
- Extend age-key custody to **external wrapping** behind the existing `Crypto` interface (deliberately pluggable — the `crypto.rs:6` roadmap note): a per-credential/per-account data key wrapped by a KMS/HSM, or **TPM-sealed** for self-host, unwrapped at connect via an API the daemon cannot extract the key from. A cold disk/backup becomes inert and every unwrap is an auditable, rate-limitable, revocable event. Spike one backend end-to-end first.
- State plainly what this does **not** buy: a live, honest-looking daemon can still unwrap on demand.

**Document the boundary.**
- Write the trilemma and the layered posture (reduce → shrink → move-wrap-key → verify) into [[overview]]/[[auth]], and make the residual trust *verifiable* (reproducible build + a single, audited decrypt path), leaning on the existing backstops (content-free payloads, read-only posture, per-service credential isolation) so a watcher breach leaks signals, not mail.

**Deferred / opt-in (captured here, deliberately not built).**
- **Operator-zero-knowledge mode** — credential unwrappable only with a user-supplied secret at watch-start, plaintext RAM-only. Truly defeats at-rest/insider access but sacrifices unattended restart (every restart darkens watches until each user re-unlocks). A future opt-in for users who value that over always-on; out of scope now.
- **Confidential-computing enclave** — the only thing that also hides RAM from the operator (closing the live-daemon gap), at the cost of enclave infra, CPU-vendor trust, and self-host friction. Out of scope.

Out of scope beyond the above: no change to the content-free payload, the read-only posture, or the per-service credential isolation — those already hold and are the backstops this leans on. In-memory plaintext residency is its own change, [[credential-residency-hardening]].
