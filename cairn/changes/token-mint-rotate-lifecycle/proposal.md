---
cairn: change
id: token-mint-rotate-lifecycle
status: active
created: 2026-07-23
---

# Revisit capability-link mint / rotate / expiry now that identity is the email

## Why
The capability link began (roadmap M7, DECISIONS §5) as *the* login-less credential: the thing the user keeps, copies, and re-auths to re-mint. Since accounts became magic-link email identities, the frontend has reframed the link as an **internal session token** — no longer shown, copied, or safeguarded (see the frontend's `capability-link-as-session` change). The server still mints, hashes, expires, and rotates it, but its lifecycle was designed for the old model and has not been reconsidered against the new one.

Open questions worth deciding deliberately rather than by inertia:
- **Expiry.** What is the link's TTL now that recovery is a fresh magic link, not a kept link? Should it be short with silent refresh, or long-lived like a session?
- **Rotation.** Is `/auth`-remint the only rotation path, or should the server rotate on a schedule / on privilege change / on suspected compromise? Is there a refresh endpoint distinct from re-auth?
- **Revocation breadth.** `/signout` revokes the presented link; should "sign out everywhere" revoke all of an account's links at once?
- **Naming.** The API and docs still say "capability link" (a user-facing concept); align on "session token" if the server agrees it is no longer a user credential.
- **Custody guidance.** Confirm the server never needs the client to persist the token beyond a normal session, and document the expected client handling.

## What
Audit the current mint/rotate/expiry/revoke implementation in `src/` against the questions above, decide the target lifecycle, and record the outcome in the `auth` capability (updating the "Capability link supports rotation and expiry" and "Sign out revokes" requirements as needed). Implementation may follow in a separate change. No behaviour is changed by this proposal itself.
