---
cairn: tasks
change: credential-custody-boundary
---

Tier 1 — reduce what we hold
- [ ] Make scoped read-only OAuth the default auth where the provider advertises it; keep password as the explicit fallback (spec [[overview]] + onboarding [[service-model]])
- [ ] Onboarding: steer to dedicated, revocable app-passwords for password providers (never the primary password; read-only scope where available); add per-provider guidance
- [ ] Consider refusing / hard-warning on an obviously-primary password at create time

Tier 2 — move the wrap-key off the box
- [ ] Design the external-wrap seam behind the `Crypto` interface (KMS/HSM for SaaS, TPM-seal for self-host); envelope a per-credential data key with the external key
- [ ] Spike one backend end-to-end: unwrap at connect via an API the daemon cannot extract the key from; confirm audit + revoke + rate-limit on unwrap
- [ ] Extend the age-key custody + rotation runbook in [[hardening]] to cover the wrapped-key model
- [ ] Document explicitly what external wrap does NOT defend (a live, honest-looking daemon)

Document the boundary
- [ ] Write the autonomy × password × zero-knowledge trilemma and the layered posture (reduce → shrink → move wrap-key → verify) into [[overview]]/[[auth]]
- [ ] Make the residual trust verifiable: reproducible build + a single audited decrypt path; reference the content-free / read-only / per-service-isolation backstops

Deferred (captured, not built here)
- [ ] Record operator-zero-knowledge mode (user-supplied unlock, RAM-only, restart cost) as an opt-in future non-goal in the spec
- [ ] Record confidential-computing enclave as the live-daemon-gap option, out of scope

- [ ] Fold the deltas into the spec ([[overview]], [[auth]], [[hardening]]) and add the log entry
