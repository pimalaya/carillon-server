---
cairn: spec
capability: service-model
status: current
---

# Account / Service Model

Carillon organises watching as a three-level hierarchy: a login-less **Carillon account** (the sign-in + billing identity), the **PIM account** it groups (an email or contacts login), and the **service** underneath — one watched connection that owns its own credential. A service is the billed unit: one standing, content-free watch of a single IMAP mailbox/folder or CardDAV collection. Onboarding is a single type-first "Add service" wizard; there is no separate "Add account" flow.

### Requirement: Three-level hierarchy
The model SHALL expose exactly three levels: (1) a **Carillon account** — a magic-link email plus credit pool, the sign-in and billing identity; (2) a **PIM account** — a user's email/contacts login, labelled by type (Email, Contacts); (3) a **service** — a single watched target beneath it. See [[billing]] for the account credit/subscription model and [[auth]] for magic-link sign-in.

### Requirement: Service is one watched connection with its own credential
A service (watch) SHALL be exactly one watched connection: an IMAP mailbox/folder for email, or a collection for CardDAV. Each service SHALL own its config (host/port/path, with protocol implicit), its target (folder or collection), its notify URL, and **its own credential** (`enc_password`) stored on the watch. No shared/per-identity credential layer sits above the service; a leaked credential is blast-scoped to a single service. See [[carddav]] for collection watching.

### Requirement: Self-proving credential on create
Creating a service with a password SHALL be self-proving and require no prior membership: the wizard validates the credential (via `/test` for email, or the target listing for contacts) and the create call stores `enc_password` on the watch. Only the empty-password path — reusing a stored OAuth credential proven at `/oauth/callback` — SHALL still check membership.

### Requirement: Type-first Add-service onboarding
Onboarding SHALL be a single "Add service" wizard driven by type-first selection; there is no "Add account" entry. The wizard SHALL run five stages, each doing one thing:

1. **Identify** — choose what to watch (Email / Contacts, Email pre-selected) and enter the address/server; discover the endpoint (IMAP autoconfig/SRV for Email, RFC 6764 for Contacts).
2. **Authenticate** — enter credentials; the wizard *holds* the password (email validates it via `/test`; contacts defer validation to the target listing). The password is not stored until create.
3. **Configure** — list targets with the held credential (`/mailboxes` or `/addressbooks`), pick the folder/collection, and set the notify URL.
4. **Verify** — read-only end-to-end check.
5. **Commit** — create the watch, storing the held credential on it.

The target-listing call doubles as the credential check, so no separate step stores anything before create.

#### Scenario: Contacts service with OAuth
- **GIVEN** a user selects Contacts and the discovered CardDAV endpoint advertises OAuth
- **WHEN** they authenticate via the OAuth popup
- **THEN** `/oauth/callback` probes the endpoint with the bearer, records a `carddav` membership, and stores the OAuth credential keyed to the DAV mailbox, and the addressbook target dropdown lists the account's actual collections.

### Requirement: Free trial of watch-time per service
A newly created service SHALL auto-watch free for a trial period (`free_trial_secs()`, default 7 days), set as its `watching_until` at create — there is no separate activate step. The trial SHALL be granted once per mailbox via the global claim ledger (`Store::claim_free_trial`), so delete-and-recreate cannot renew it. The trial is non-fungible time on that specific service, not a spendable credit, so a farmed mailbox yields nothing. See [[billing]].

### Requirement: Password-and-OAuth choice for both protocols
Discovery SHALL always offer a Password choice, plus an OAuth choice when the endpoint advertises it, for both IMAP and CardDAV. CardDAV SHALL mirror IMAP here rather than dropping Password when OAuth is advertised.

### Requirement: CardDAV target is a listed collection
A CardDAV service's target SHALL be selected from a dropdown of the account's actual collections (discovered current-user-principal → addressbook-home-set → list), using each addressbook's own name, with a pasted-URL fallback only when listing fails. Targets SHALL NOT be free-typed display names. See [[carddav]].
