---
cairn: spec
capability: auth
status: current
---

# Authentication and Access Scoping

Accounts are database entities, not configuration: a login-less account is a set of mailboxes the user has proven control of, grouped under one bearer capability link. Configuration carries only infrastructure (`[server]` store/keys/tuning, `[api]` listen/bind/auth); it never carries accounts or watches. Every route that touches watches, deliveries, accounts, or the live stream requires a bearer token and is scoped to the caller, in every front — there is no unauthenticated data access. See [[serving]] for how each front is deployed and [[billing]] for what an authenticated account is entitled to.

### Requirement: Accounts live in the database, config is infra only
Carillon SHALL persist accounts and watches in the store, never in configuration. Configuration SHALL carry only `[server]` (store path, encryption key, tuning) and `[api]` (listen/bind, auth) infrastructure. This collapses the config-path-vs-API-path duplication into one path so the UI is a reusable layer over the API in every deployment.

### Requirement: Every data route is authenticated and scoped
Every route that touches watches, deliveries, accounts, or the live stream SHALL require a bearer token on `Authorization: Bearer <token>` and SHALL scope the request to the caller. This holds in every front, including self-host; there is no unauthenticated data access.

### Requirement: The Caller extractor resolves the bearer
A `Caller` extractor SHALL resolve the presented bearer token to exactly one of two identities: a capability-link account, scoped to its own watches, deliveries, events, and pool; or the optional unscoped admin token `api.admin_token`, which grants fleet-wide access for ops and headless use. When `api.admin_token` is unset (the default), no unscoped access exists at all.

#### Scenario: Bearer matches a capability link
- **GIVEN** a request carrying a valid, unexpired, un-revoked capability link
- **WHEN** the `Caller` extractor resolves it
- **THEN** the request is scoped to that link's account and may reach only that account's own resources

#### Scenario: Bearer matches the admin token
- **GIVEN** `api.admin_token` is set and the request carries it
- **WHEN** the `Caller` extractor resolves it
- **THEN** the request is granted unscoped, fleet-wide access to every account

#### Scenario: Admin token unset
- **GIVEN** `api.admin_token` is unset (the default)
- **WHEN** a request presents a bearer that is not a valid capability link
- **THEN** no unscoped access is available and the request is rejected

### Requirement: Single-resource routes 404 across account boundaries
When a scoped caller requests a single resource that belongs to another account, Carillon SHALL respond `404 Not Found` rather than `403`, to hide the existence of resources outside the caller's scope.

### Requirement: Watch creation forces scope and requires proven mailbox
`POST /watches` SHALL force the caller's own account as the owner and SHALL require that the target mailbox has already been proven via `POST /auth`. A watch cannot be created for a mailbox the caller has not authenticated to; this is the anti-farming linchpin, since free watching is granted only for a mailbox the caller has successfully authenticated to.

### Requirement: Public routes opt out of authentication
Only the following routes SHALL be public (no bearer required): `GET /health`, `GET /`, `GET /openapi.yaml`, `POST /test`, `POST /discover`, `POST /auth`, `POST /oauth/start`, `GET /oauth/callback`, `GET /billing/packs`, and the billing webhook. The public onboarding routes (`/test`, `/discover`, `/auth`, `/oauth/*`) SHALL be rate-limited, since they are the credential-oracle surface. Every other route SHALL require an authenticated, scoped `Caller`.

### Requirement: Capability link is an unguessable minted bearer
On successful `POST /auth`, Carillon SHALL mint a capability link: a long, unguessable, per-account bearer token. The link SHALL be stored hashed with an expiry, SHALL be validated by the server on every call (never client-only gating), and SHALL be one account per link. First auth creates an account and issues its link; authenticating to another mailbox while holding the link adds that mailbox to the same account.

### Requirement: Capability link supports rotation and expiry
Carillon SHALL support minting, rotating, and expiring a capability link server-side, so a link's lifetime is bounded and a compromised link can be replaced without abandoning the account. Recovery is re-auth to any member mailbox, which re-mints the account's link.

### Requirement: Sign out revokes the capability link
`POST /signout` SHALL invalidate the caller's capability link so it no longer authenticates any subsequent call.

#### Scenario: A signed-out link is reused
- **GIVEN** a capability link that has been signed out
- **WHEN** a later request presents it
- **THEN** the `Caller` extractor rejects it and no account scope is granted
