# Carillon: the account / service model

> **Future: multiple webhooks per service (2026-07-22, noted not built).** A service currently has exactly one `notify_url`. A user may want the same folder/addressbook to fan out to several endpoints. Until that lands, the workaround is to add the service twice (same target, different notify URL), now allowed (the same-target dedup was removed) and simply billed per service. A first-class version would let one service carry N notify URLs (billed once, or per-endpoint, TBD) instead of duplicate services.

## v3: credentials on the service (BUILT 2026-07-22)

Landed. The service (watch) now owns its credential; there is no PIM-account layer in the flow. What shipped:

- **Backend** (`api.rs::create_watch`): the create-watch gate is relaxed. A password-bearing create is self-proving (the wizard validated it via `/test` + the target listing) and stores `enc_password` on the watch, needing no prior membership. Only the empty-password path (reuse a stored OAuth credential, proven at `/oauth/callback`) still checks membership. The welcome credit is claimed on the account's **first service** (`claim_free_credit`, sybil-barred by mailbox key), and the create response echoes the `free_credit` outcome. `password_credential` is no longer read on create (dormant; OAuth stays).
- **Frontend**: one wizard (`features/services/ServiceWizard`) runs all five steps: Identify → Authenticate → Configure → Verify → Commit. Authenticate **holds** the password (email path validates it with `/test`; contacts defer to the addressbook listing); `/mailboxes` + `/addressbooks` list with that password; create stores it on the watch. The separate onboarding wizard, the account picker, the `/onboarding` route, Forget, and the SettingsPanel PIM list are gone. The Carillon account (magic link + credits + switcher) stays.
- **Deferred** (unchanged from the plan below): credential dedup / extraction to a shared store; retiring the now-dormant `/auth`, `account_mailbox`, `password_credential` machinery (kept for OAuth + backward compatibility).

### Free trial replaces the free credit (2026-07-22)

The fungible welcome **credit** was farmable: it was claimed per `mailbox_key` (normalised `login`+host), so a farmer pointing many **subdomains** at one IMAP server got one spendable credit each. Fix: **no free credits, a free-trial of watch-time on the service instead.**

- A newly-created service auto-watches free for `free_trial_secs()` (default **7 days**, ~¼ of a month), set as its `watching_until` at `create_watch`. No "activate" step in onboarding; the Commit stage just shows the trial and a buy-credits path.
- Granted **once per mailbox** via the reused global claim ledger (`Store::claim_free_trial`), so delete+recreate can't renew it. It's time-on-THIS-service (non-fungible), so a farmed mailbox is worthless.
- Removed the fungible grant everywhere it was reachable: `create_watch`, `/oauth/callback`, and the dormant `/auth` (a live route that also minted a credit, a direct-API farm vector). `Store::claim_free_credit` + `FreeCreditOutcome` deleted; `grant_free_credit` kept only for unmetered self-host bootstrap. Create response now returns `free_trial: bool`.

### CardDAV discovery, auth + OAuth (2026-07-22)

- `discover_carddav` was **OAuth-preferred**: it emitted one choice per URL and dropped Password when the endpoint advertised OAuth, so Fastmail showed only an OAuth card. Now it mirrors IMAP: **Password always** (+ OAuth when advertised). The wizard's `pickDav` respects the choice's auth.
- **OAuth-over-CardDAV is now wired end-to-end.** The poller already resolved a DAV bearer (`resolve_oauth_access` → `CardDavAuth::Bearer`); the gap was the login flow. Fixed: `oauth_session` carries `source_kind` + `carddav_url`; `/oauth/start` accepts them; `/oauth/callback` branches: for CardDAV it probes the endpoint with the bearer via `carddav::session::verify_auth`, records a `carddav` membership (base_url = context root), and stores the OAuth credential keyed to the DAV mailbox (login + DAV host, matching the poller). `/addressbooks` gained the OAuth fallback (`/mailboxes` already had it), so the target dropdown lists for OAuth accounts too. Front end surfaces the OAuth choice for contacts and routes it through the same popup as IMAP.
- **Addressbook target is now a dropdown** of the account's actual collections (like the IMAP folder picker), using each addressbook's own name: the separate display-name field and the manual CardDAV test are gone; a pasted-URL fallback remains for when listing fails.

## v3 direction: credentials on the service (agreed 2026-07-22, supersedes the shared-credential parts of v2 below)

The v2 shared/per-identity credential + PIM-account layer is being **removed** as too complex. Iteration step: **the credential lives on the service.** No PIM account, no membership, no shared credential table: account + credential + service collapse into one thing (the watch). Accepted trade: duplicate credentials across services, but a leaked one is blast-scoped to a single service. (This is where Carillon started: `watch.enc_password` predates the whole PIM layer.)

- **Carillon account** (magic link + credit pool + capability link): **stays**; the sign-in + billing identity.
- **Service (watch)**: owns its config (host/port/path → protocol is implicit) + **its own credential** (`enc_password`) + its target (folder / collection) + notify. Nothing above it.
- **One "Add service" flow:** what to watch → discover → sign in (creds held in the wizard) → pick target → notify → activate. The target-listing call (`/mailboxes` or `/addressbooks`, called with the entered password) doubles as the credential check, so there's no separate auth step storing anything: the password rides through to the watch on create.
- Free credit → granted on the **first service** (still sybil-barred by normalized login). Dedup → per `(account, config, target)`.
- **Backend cost is small:** the watch already carries `enc_password`; relax the create-watch "must have authenticated this mailbox first" gate to "provide a working credential", and point free-credit at first-service. Stop populating/reading `account_mailbox` + `password_credential`.
- **Frontend is the real work:** collapse the two wizards into one and delete the account/membership UX (account picker, Forget, `/me` memberships, the onboarding↔service bounce).
- Dedup / credential extraction into a shared store is explicitly **deferred**: revisit after this is working and consistent.

---

# Carillon: the account / service model (v2, superseded on the credential axis)

Converged 2026-07-22. Fixes the blurry account↔service frontier surfaced once CardDAV became a second source. Supersedes the "PIM account = an IMAP `/auth`" assumption in earlier docs.

## The three levels

1. **Carillon account**: a magic-link email + the prepaid credit pool. The billing identity. *(unchanged)*
2. **PIM account**: a **proven connection**: `(identity, protocol, server, credential)`, labelled by protocol (Email/IMAP, Contacts/CardDAV, …). It is **not created explicitly**: it is the credential the *first service* on it leaves behind, then reused to skip auth on later services. The **credential is keyed to the identity** and shared across that identity's protocol-accounts (one Fastmail app password serves IMAP + CardDAV); membership is per `(identity, protocol)`.
3. **Service**: a watch *target within* a PIM account: an IMAP folder, a CardDAV addressbook. Many per PIM account. **The billed unit** (1 credit / month), regardless of protocol.

**Keying, deliberately split:**
- *Identity key* = `mailbox_key` (normalised `login`, protocol-blind). Owns the **credential**, the **welcome credit**, and the **sybil barrier**, so adding both Email and Contacts of one mailbox is one credential, one free credit.
- *PIM-account key* = `(account_id, mailbox_key, protocol)`. Owns **membership** (proven endpoint + how to re-list its targets) and the services under it.

## The one flow: "Add service" (type-first)

There is no "Add account" wizard. Everything is *add a service*; the account is an accelerator + a grouping label, never a thing you create.

1. **Add a service** → pick a *known* PIM account (→ straight to its target list) **or** connect new.
2. New → **What do you want to watch?** Email / Contacts *(Email pre-selected; the protocol word never shows, type→protocol is 1:1 today)*.
3. Enter email/server → **discover that domain** (IMAP autoconfig/SRV for Email, RFC 6764 for Contacts) → confirm the found server.
4. **Authenticate**: provider-framed, and **skipped** when we already hold a working credential for that identity (we try the cached credential against the new endpoint first, so Contacts-after-Email needs zero prompts).
5. Pick the target (folder / addressbook) + notify URL → service created; the credential persists behind it.

**Decisions locked:** keep the cached credential after an account's last service is removed (fast re-add) with an explicit **Forget this account**; CardDAV targets are **listed** (discover the collections), not pasted.

## Staged implementation

**Stage 1: server (additive + backward-compatible; default = email/imap so the current admin keeps working):**
- [x] `/discover` takes an optional `kind` (`email`|`contacts`); Contacts resolves CardDAV via io-pim-discovery `rfc6764` (`discover_carddav` → context-root URL choices). Response echoes `kind`; choices shaped per kind. *(2026-07-22)*
- [x] `account_mailbox` gained a **protocol** axis (PK → `(account_id, mailbox_key, protocol)`, + `imap_port`/`base_url`); table-rebuild migration backfills old rows to `protocol='imap'`. Membership methods take a protocol; `memberships()` returns it + server info. *(2026-07-22)*
- [x] `/auth` takes an optional `protocol`; Contacts validates via current-user-principal `PROPFIND` (`carddav::session::verify_auth`). Credential stays keyed to the identity (shared). *(2026-07-22)*
- [x] `POST /addressbooks`: lists a CardDAV account's collections (current-user-principal → addressbook-home-set → list, redirect-following pump added to `carddav::session`). *(2026-07-22)*
- [x] `/me` exposes each PIM account's protocol + server (memberships + `balance.mailboxes[].protocol`). *(2026-07-22)*
- [x] `POST /forget`: removes one protocol's membership + its services; drops the shared credential only when no membership of that identity remains. *(2026-07-22)*

**Stage 2: admin (the unified type-first wizard):**
- [x] **Type-first onboarding** (the required piece: a CardDAV service now needs a CardDAV PIM account): IdentifyStage leads with **Email / Contacts**, scoped discovery (`useDiscoverContacts`), CardDAV context-root choices; AuthenticateStage validates a Contacts account via `/auth protocol=carddav`. ServiceWizard auto-selects the addressbook type for a CardDAV account. *(2026-07-22)*
- [x] **Single "Add service" entry**: dashboard + sidebar now have one "Add service" button; "Add account" (PIM) is gone as a top-level action. The service flow offers a **Connect a new account** shortcut (→ onboarding) and an account selector that disambiguates by protocol (an identity can have both an Email and a Contacts account, same `mailbox_key`). *(2026-07-22)*
- [x] **Addressbook target picker**: the Contacts service step lists the account's collections via `POST /addressbooks` (`useAddressbooks`), with a manual-URL fallback when there's no base URL / listing fails. *(2026-07-22)*
- [x] Dashboard **groups services by PIM account** (login + protocol header; rows show just the target). **Forget** action wired into Settings per PIM account (`useForgetAccount` → `POST /forget`, confirm dialog). *(2026-07-22)*
- [x] **i18n for the onboarding wizard**: OnboardingWizard + IdentifyStage + AuthenticateStage fully translated (new `onboarding` en/fr namespace). The service wizard's Verify/Commit stages remain English (a smaller follow-up). *(2026-07-22)*

**Stage 2 essentially complete.** Remaining nits: Verify/Commit stage i18n; the `useAddressbooks` picker could auto-select when there's a single collection.
