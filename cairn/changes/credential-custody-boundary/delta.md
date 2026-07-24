---
cairn: delta
change: credential-custody-boundary
---

## ADDED Requirements

### Requirement: Custody trilemma governs the posture
Carillon SHALL treat autonomous watching, password custody, and operator-zero-knowledge as mutually constrained — any two, not all three — because a daemon that re-authenticates unattended must be able to obtain the credential unattended. The credential posture SHALL therefore be layered — reduce what is held (read-only OAuth / app-passwords), minimise how long plaintext exists in memory, move the wrap-key off the box, and make the residual trust verifiable — rather than claiming an unreachable "cannot decrypt." Operator-zero-knowledge (user-supplied unlock, plaintext RAM-only) is recorded as an opt-in future that trades away unattended restart, not a default. ([[overview]])

### Requirement: External-wrapped credential keys
The credential-encryption key SHALL be movable off the data disk into an external wrapper (KMS/HSM, or a TPM seal for self-host) behind the existing `Crypto` interface, so a stolen disk or backup is inert and every unwrap is an auditable, rate-limitable, revocable event. This defends at-rest theft and quiet insider decryption; it SHALL be documented as NOT defending a live, un-tampered daemon, which can still unwrap on demand. ([[hardening]])

## MODIFIED Requirements

### Requirement: Credential custody as the adoption ground
Because Carillon holds mailbox credentials in order to watch, credential custody SHALL be the trust-sensitive core and the adoption gate. Carillon SHALL make scoped **read-only OAuth the default** wherever the provider allows it (Gmail, Microsoft, Fastmail), so even a full breach cannot write, send, or delete and the grant is user-revocable without a password change. Where OAuth is unavailable, onboarding SHALL steer the user to a **dedicated, revocable app-password** (never the account's primary password; read-only scope where offered), storing no more authority than watching needs. Credentials SHALL be encrypted at rest with the wrap-key movable off the box (see [[hardening]]), and self-hosting SHALL remain a real option. For password mailboxes read-only is code discipline only, so the content-free payload and read-only posture remain the breach backstops. ([[overview]])
