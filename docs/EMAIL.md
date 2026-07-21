# Carillon — transactional email & deliverability

Carillon sends two kinds of transactional email: the **magic-link sign-in** (the
human identity flow) and **billing notices** (watch ending / stopped, low pool —
the account-level channel the webhook/SSE bus cannot reach). The mailer lives in
`src/email.rs` behind a small enum (`Mailer::{Stub, Resend}`), mirroring the
billing provider; `[email.resend]` in the config turns real sending on, absent =
a stub that **logs** the message (magic-link URL included) so a dev flow works
with no provider.

**Deliverability here is existential.** A magic link that lands in spam means the
user cannot sign in *at all* — for a notification company, the most embarrassing
failure mode. The provider matters less than three things you control regardless.

## The three things that actually keep mail out of spam

1. **Never send from the Carillon box.** A cold VPS IP with no reputation is the
   fastest route to the spam folder (or an outright Gmail/Microsoft block).
   Always relay through a provider; the daemon sends *to* the relay's API/SMTP,
   never direct-to-MX.
2. **Authenticate a dedicated sending subdomain** — e.g.
   `mail.carillon.pimalaya.org`, never the root. Publish **SPF** (the provider's
   include), **2048-bit DKIM**, and **DMARC** (start `p=none` with a `rua=`
   report address, tighten to `quarantine`/`reject` once alignment is confirmed).
   SPF/DKIM alignment under DMARC is required by Gmail/Yahoo bulk-sender rules. A
   subdomain also isolates reputation so a noisy notice can't poison sign-in mail.
3. **No link tracking on the auth stream.** Providers rewrite URLs through their
   own domain for click analytics; on a magic link that looks like a redirect to
   a stranger domain, trips filters, and can break the token. Keep tracking
   **off** for sign-in mail (the `from`/stream you use for magic links).

Because you authenticate *your own subdomain*, the sending reputation is largely
yours, not the provider's — so the provider choice is **reversible**; switching
later is low-risk.

## Provider

Implemented: **Resend** (EU data region, simple HTTP API, generous free tier) —
a good brand-fit for a privacy-oriented audience. The enum makes **Amazon SES**
(`eu-central-1`, cheapest, more plumbing) or **Postmark** (transactional
specialist, best inbox placement, US data residency) a new variant if inbox
placement ever disappoints. Avoid shared-pool marketing ESPs for auth mail.

Config:

```toml
[email.resend]
api_key = "re_…"                                    # inject via LoadCredential in prod
from = "Carillon <no-reply@mail.carillon.pimalaya.org>"
```

## Operational notes

- **Separate streams for auth vs. notices.** A user might mute reminders; they
  must never mute the sign-in link. Keep them on distinct streams/subdomains so
  reputation and any unsubscribe logic don't cross. (Today both go through the
  one `from`; split it before volume grows.)
- **Handle bounces and complaints.** Suppress hard-bounced addresses, honor
  complaints, and surface "we couldn't send your link" in the UI rather than
  silently retrying — repeated sends to dead addresses is what tanks a new
  domain's reputation. (Wire the provider's bounce webhook when sending goes
  live; not yet consumed.)
- **Treat the auth email as a first-class reliability surface**, on par with the
  outbound webhooks: monitor delivery rate, alert on a drop, and treat a send
  failure as a hard onboarding error (`POST /auth/magic/request` returns `502`
  when the send fails, rather than pretending success).
</content>
