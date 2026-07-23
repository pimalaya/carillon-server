---
cairn: tasks
change: token-mint-rotate-lifecycle
---

- [ ] Locate the token mint / hash / expiry / rotate / revoke code in `src/` (auth + store) and write down the current semantics
- [ ] Decide the link TTL under magic-link identity (short + refresh vs long-lived session)
- [ ] Decide the rotation triggers (re-auth only? scheduled? on-demand refresh endpoint?)
- [ ] Decide revocation breadth (`/signout` = this link; is there sign-out-everywhere across an account's links?)
- [ ] Decide naming: keep "capability link" or rename to "session token" in the API + OpenAPI + docs
- [ ] Document expected client custody (no long-term persistence beyond a session)
- [ ] Update the `auth` spec requirements to match the decisions; open a follow-up change if code changes are needed
