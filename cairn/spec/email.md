---
cairn: spec
capability: email
status: current
---

# Transactional Email & Deliverability

Carillon sends two kinds of transactional email: the magic-link sign-in (the human identity flow) and billing notices (watch ending or stopped, low pool — the account-level channel the webhook and SSE bus cannot reach). Deliverability here is existential: a magic link that lands in spam means the user cannot sign in at all, the most embarrassing failure mode for a notification company. The provider matters less than three things Carillon controls regardless. See [[auth]] for the identity flow the magic link serves and [[overview]] for the read-only posture that pushes notices to email rather than into the mailbox.

### Requirement: Relay through a provider, never send from the box
Carillon SHALL relay all transactional mail through a sending provider (to the provider's API or SMTP) and SHALL NOT send direct-to-MX from the daemon's own host. A cold VPS IP with no reputation is the fastest route to the spam folder or an outright Gmail/Microsoft block. Absent a configured provider, the mailer SHALL fall back to a stub that logs the message (magic-link URL included) so a dev flow works with no provider.

### Requirement: Authenticate a dedicated sending subdomain
Carillon SHALL send from a dedicated sending subdomain (e.g. `mail.carillon.pimalaya.org`), never the root domain, and SHALL publish SPF (the provider's include), 2048-bit DKIM, and DMARC — starting at `p=none` with a `rua=` report address and tightening to `quarantine`/`reject` once alignment is confirmed. SPF/DKIM alignment under DMARC is required by Gmail/Yahoo bulk-sender rules, and a subdomain isolates reputation so a noisy notice cannot poison sign-in mail.

### Requirement: No link tracking on the auth stream
Carillon SHALL keep click/link tracking off for the sign-in stream (the `from`/stream used for magic links). Providers rewrite URLs through their own domain for click analytics; on a magic link that looks like a redirect to a stranger domain, trips filters, and can break the token.

### Requirement: Provider posture is reversible
Carillon SHALL implement sending behind a small provider enum (currently Resend, EU data region), with Amazon SES or Postmark addable as new variants if inbox placement disappoints. Because reputation attaches to Carillon's own authenticated subdomain rather than the provider, the provider choice is reversible and switching later is low-risk. Shared-pool marketing ESPs SHALL be avoided for auth mail.

### Requirement: Separate streams for auth vs notices
Carillon SHALL keep auth mail and billing notices on distinct streams/subdomains so reputation and any unsubscribe logic do not cross: a user may mute reminders but must never be able to mute the sign-in link. (Both currently share one `from`; the split SHALL happen before volume grows.)

### Requirement: Handle bounces and complaints
Carillon SHALL suppress hard-bounced addresses, honor complaints, and surface "we couldn't send your link" in the UI rather than silently retrying, since repeated sends to dead addresses is what tanks a new domain's reputation. (The provider's bounce webhook SHALL be wired when sending goes live; not yet consumed.)

### Requirement: Treat auth email as a first-class reliability surface
Carillon SHALL treat the auth email as a first-class reliability surface on par with outbound webhooks: monitor delivery rate, alert on a drop, and treat a send failure as a hard onboarding error. A failed magic-link send SHALL return `502` rather than pretending success.

#### Scenario: The magic-link send fails
- **GIVEN** a user requesting a sign-in link
- **WHEN** the provider rejects or fails the send
- **THEN** the request returns `502` and the UI surfaces the failure
- **AND** Carillon does not report success or silently retry into a dead address
