---
cairn: tasks
change: starttls-support
---

- [ ] Add a transport-security field (`tls` implicit | `starttls` explicit) to `ImapAccount` and the watch store schema/migration
- [ ] Implement the STARTTLS branch in `src/imap/session.rs` `open()`: plaintext greeting → require the `STARTTLS` capability → issue `STARTTLS` → TLS-upgrade the existing TCP stream (SNI + cert validation as today)
- [ ] Keep the implicit-`tls` path unchanged; select the branch on the account's security field
- [ ] Thread the security kind from `/discover` + onboarding + `POST /watches` through to the stored `ImapAccount`
- [ ] Decide and enforce the `plain` (no-TLS) posture — likely refuse; document it
- [ ] Verify live against a STARTTLS-only IMAP server (143 + STARTTLS): connect → auth → IDLE
- [ ] Frontend: make the `security` field load-bearing (drop the "not wired yet" caveat in onboarding/types.ts)
- [ ] Fold the delta into the spec (transport security under [[architecture]]) and add the log entry
