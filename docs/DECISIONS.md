# Carillon — product & design decisions

Decisions taken since [`CARILLON_PLAN.md`](CARILLON_PLAN.md), converged while
building and exercising the prototype. The plan is the north star (what Carillon
is, scope, cost model); this is the refined *how*. Where the two differ, this
document wins.

The whole thing hangs off one governing line, unchanged from the plan:

> **Carillon signals; it never syncs.** It watches remotes and emits a uniform,
> content-free "something changed" webhook. It never stores, syncs, or serves
> content.

And one spine that ties every decision below together:

> **Gate the standing resource; keep everything ephemeral free and un-authed.**
> Testing is free and repeatable; only *activation* (a standing IDLE process) is
> metered; the self-hosted daemon needs no inbound auth precisely because
> nothing stands to receive. Content-free payloads + signatures carry the trust.

---

## 1. Product shape — one core, two fronts

The same core (watcher supervisor + delivery + store) ships in two deployments,
distinguished only by their *front*, never by different code paths:

- **Self-hosted** — a daemon you run; connects out to IMAP, POSTs webhooks. A
  hidden service.
- **SaaS** — the same daemon plus multi-tenant auth, a dashboard, and billing.

This mirrors the plan's "deployment topology ≠ product topology": the transformer
stays cleanly separable and self-hostable; the SaaS is a front bolted onto it.

## 2. Onboarding flow

Organised around one axis — **ephemeral vs standing**:

- **Test** — free, repeatable, ephemeral. Connect → auth → **capability check** →
  `LOGOUT`. Lets users iterate on credentials/webhook at zero cost.
- **Activate** — spends from the balance, starts the standing IDLE process.

The wizard is a five-stage line, each stage doing one thing:

1. **Identify** — email → discovery (reuse `io-pim-discovery`, Himalaya's wizard)
   → pick the discovered config.
2. **Authenticate** — credentials → *Test*. The green light is
   `TLS + auth + CAPABILITY ⊇ {IDLE, QRESYNC}`, **not just auth** — a server can
   authenticate fine and still fail the watch (see the QRESYNC lesson in
   [ROADMAP](ROADMAP.md) / the imap-types bug). "Auth OK ✓" with a silent later
   failure is the worst onboarding outcome, so capability support is surfaced
   explicitly. This endpoint is **rate-limited per mailbox** — an open
   "we'll try your creds" endpoint is otherwise a credential-testing oracle.
3. **Configure output** — notify URL + show the signing secret.
4. **Verify end-to-end (read-only)** — activate the watch, then the user sends
   themselves a mail (or waits for the next one) and watches their own endpoint
   fire in a **live log**. *Rejected: an `APPEND`-injected test message.* It was
   slick, but `APPEND` requires **write access**, and Carillon is fundamentally
   read-only (see the read-only posture in §7). Taking write access to power a
   demo turns a breach from "leak content-free signals" into "inject
   perfectly-spoofed phishing (no SPF/DKIM, since `APPEND` bypasses SMTP) into
   every watched inbox" — not a trade worth an animation.
5. **Commit** — spend the credit, watch goes live.

Running underneath: the web flow means users hand over mailbox credentials.
**OAuth-first** wherever the provider allows (Gmail/MS/Fastmail) is a posture,
not a step — it colours the whole Authenticate stage, gates adoption, *and*
scope-limits the blast radius (read-only scopes; see §7).

## 3. Business model — prepaid, metered like pay-as-you-go

The choice between prepaid credits and postpaid pay-as-you-go dissolves:
**prepaid credits, debited continuously, *are* pay-as-you-go** — with postpaid's
one flaw removed.

- **Postpaid (bill in arrears) is rejected.** You deliver first, collect later →
  dunning, failed cards, involuntary churn, chargebacks. Decisive killer: **Apple
  and Google IAP cannot meter in arrears** — postpaid is dead on two of three
  billing rails the moment mobile is a channel.
- **Prepaid balance + continuous debit** gives postpaid's fairness anyway: debit
  watch-*time* against the balance in real time; a paused watch stops debiting;
  nobody overpays for idle they didn't use. (Twilio / OpenAI / AWS-credits model.)
  Keeps the "not a subscription" feel and keeps breakage.

Model specifics:

- **Unit:** a credit is watch-*time* (hours/days), debited as consumed — **not**
  per calendar month. Invariant: *credits spent = Σ(active watches × time)*.
- **Balance is per *account*, not per mailbox** *(v2 — supersedes the earlier
  per-mailbox balance).* An "account" is a **login-less, bearer-capability
  grouping** of mailboxes the user has proven control of (one link — see §5), with
  **one shared paid pool**. Rationale: multi-mailbox users want one wallet + one
  link, not islands. **Two watch-time counters** per watch, drained in order:
  - **① Mailbox counter (trial)** — per mailbox, **non-refillable once emptied**,
    granted once ever, keyed globally on normalised `(login, provider)`.
  - **② Account counter (paid pool)** — shared across the account's mailboxes,
    **refillable by paying**, expire ~12 months (bounds deferred-revenue liability,
    yields breakage).
  - **Consumption rule: always debit the mailbox counter first, then the account
    pool.** So each mailbox burns its own free trial before touching shared paid
    time; a dead trial is dead forever (nobody can refill mailbox-level); the pool
    is the only thing money touches. This is why the trial can't be farmed (it's
    per-mailbox, locked, spent-first) and why a shared pool never strands credit
    (no "transfer between mailboxes" feature needed).
- **Payment stays stateless on our side.** A purchase tops up *the account you're
  logged into via the link* at checkout — not a payment-email-keyed account — so
  the two-emails-→-two-accounts problem stays solved. Stripe/IAP keeps the customer
  + receipt; Carillon persists only the account's balance, no PII.
- **Trial framing** beats "free credits" — credits read as money and invite
  farming; a per-mailbox **trial of a few days** does not.
- **Auto-refill (opt-in)** is important, not optional polish: "balance hit zero →
  watch silently stopped → missed notifications" is the *worst* failure for a
  notification service. Auto-refill = a subscription for those who want the
  safety net, PAYG for those who don't — same code path. Guard with low-balance
  and pre-expiry warnings.

### Anti-abuse

The threat is **not** individual double-dipping (the free resource costs
sub-cent/month — irrelevant). It is **scale-farming** a parasitic free service.
Per-mailbox keying caps that at "mailboxes the farmer actually controls", and the
linchpin falls out of the architecture: **you only grant free watching for a
mailbox you have successfully authenticated to** — proof-of-control is free
because you can't watch what you can't log into. (Same mailbox-control proof the
plan reserved for passwordless recovery — one mechanism, two jobs.) Normalise
aggressively (lowercase, strip plus-addressing, canonical provider domain).

## 4. Webhook security — what we provide vs what they enforce

The receiver is a public endpoint that will get internet noise; **the signature
is the authentication**, not decoration. Without verification, anyone who guesses
the URL can POST fake events. We can't secure their server — we hand them the
tools to tell real events from noise and tampering.

**Carillon provides (sender side):**

1. **HMAC-SHA256 signature** — *done* (`X-Carillon-Signature: sha256=…`).
2. **Timestamp inside the signed content** — sign `timestamp.body` (Stripe-style
   `t=…,v1=…`) → enables **replay protection**. *Gap to close.*
3. **Event ID + idempotency** — a unique id per event so receivers dedupe; we
   retry, so the same event *will* arrive twice. *Gap to close.*
4. **HTTPS-only** — refuse / loudly warn on plain `http://` notify URLs.
5. **Static egress IPs** — publish the outbound range so receivers can
   firewall-allowlist us (the cost model's "egress IP pool" doing double duty).
6. **Secret rotation** — rotate the HMAC secret with an overlap window.
7. **Optional custom auth header / mTLS** — for enterprise receivers.

**Receiver enforces (we document + ship verify snippets):** verify signature on
every call; check the timestamp; dedupe by event id; respond `2xx` fast and
process async; HTTPS only; optionally allowlist our IPs.

Quiet superpower: events are **content-free**, so a leaked or spoofed endpoint
exposes no sender/subject/body — the content-free design is itself a security
property.

## 5. Accounts live in the database; config is infra only

**Watches belong in the DB, always.** Config carries only `[server]` (db path,
age key, tuning) and `[api]` (listen/bind, auth). This collapses the awkward
"config-path vs API-path for accounts" duplication into one path and makes the
UI a reusable layer over the API in *every* deployment.

Deployment modes become toggles over one core, not different code:

| Mode | Daemon | Control API | UI | Auth |
|---|---|---|---|---|
| Headless self-host | ✓ | localhost | — | token (for a CLI/script) |
| Self-host + UI | ✓ | ✓ | ✓ | local admin login/token |
| SaaS | ✓ | ✓ | CDN | **capability link** per account (no signup); stateless payment |

### Identity — a login-less "account", not a signup (no magic-link)

*(v2 — supersedes "no entity at all".)* There **is** a lightweight server-side
entity — an **account**: a set of mailboxes the user has proven control of, grouped
under **one bearer capability link**, holding **one shared paid pool** (§3). But it
is a *login-less* entity — no email/password signup, no PII — anchored purely by
possession of the link + proof-of-control of its member mailboxes. Minimal-trust
shape: *read-only · login-less account · per-account pool (free mailbox-locked) ·
capability-link access.*

- **Access = proof-of-mailbox-auth.** Anyone reaches the (public, static)
  dashboard; authenticating to a mailbox proves control of it. First auth **creates
  an account** and issues its link; authenticating to another mailbox **while
  holding the link** adds that mailbox to the same account. One link → all the
  account's mailboxes and its wallet.
- **Capability link, not repeated re-auth.** On the first successful auth, issue a
  **capability URL** — a long, unguessable, per-*account* bearer link — shown
  **on-screen** (nothing is written to the mailbox; you already proved control by
  authenticating). A signed bearer token Carillon issues and validates with its own
  secret is the whole mechanism — no keypair, no in-mailbox key (asymmetric keys
  only earn their keep if a *third party* must verify offline, which never happens
  here; and delivering a key via
  `APPEND` would reintroduce write access — see §7).
- **Server-validate the link on every call** (never client-only gating). The link
  now controls the **whole account** (all its mailboxes + the shared wallet), so it
  is more valuable → hygiene matters more: long-random, one account per link,
  expiry + rotation, keep it out of `Referer`-leaking URLs (fragment or POST, not
  query string), and a **"sign out"** that invalidates it. localStorage is fine for
  holding it (bearer header, pairs with the cross-origin CDN split in §6) — keep CSP
  tight (XSS reads localStorage).
- **Recovery = re-auth** to *any member mailbox* → re-mint the account's link.
  Stays read-only, needs no email.
- **Rate-limit the auth endpoint hard** per (IP, mailbox) with backoff — it's the
  one credential-testing-oracle surface. (Mitigated too by the IMAP server *being*
  the oracle already: Carillon adds no guessing power, only parallelization, which
  the limit caps.)

**Billing needs no signup, just the account.** A purchase tops up the **account's
shared pool** (§3); Stripe/IAP keeps the customer + email for its own receipts,
Carillon persists only the balance, no PII. Because checkout is tied to the
logged-in account (via the link), paying with different emails still funds the same
account — the two-emails-→-two-accounts problem stays solved. Warnings (low balance
/ expiry) go via **webhook events** (not into the mailbox — read-only, §7) or the
payer's Stripe email.

**Multi-mailbox is served by the account itself** (the shared link + pool), not by
client tricks. The browser still keeps the account's link in localStorage so a
returning visitor lands straight in their dashboard; cross-device just means
carrying the link (the account is server-side, so all its mailboxes/balance appear
wherever the link is presented — no per-device re-add, unlike the earlier islands
model). A user can hold several *accounts* if they want them separate; the browser
can list those links as a switcher. The account groups by **credential** — watching
several folders of one credential is one auth / one membership, so the switcher only
ever spans genuinely separate accounts.

Two honest consequences:

- The pure **"no auth at all"** case shrinks. Once accounts are DB-only,
  *something* writes them — an API — so even headless has a listening surface
  (localhost) and wants a **token**. "No auth" only survives if a human pre-seeds
  the DB out-of-band. Realistically: **self-host = localhost API + token**, and
  never rely on "it's internal" (dies to Docker ports, proxy misconfig, SSRF —
  and the thing holds every credential and can redirect every webhook).
- Headless still needs an **entrypoint to populate the DB** — a thin bundled CLI
  that talks to the local API, or a one-shot `import` command.

**Landed refinement (2026-07-20): scope by default, in every front.** Rather
than gate the data routes "in SaaS mode" only, *every* front requires a bearer
token and scopes to it — self-host is a narrow audience and gets the same,
simpler model. A `Caller` is either a **capability-link account** (scoped to
its own watches/deliveries/events/pool) or the optional **admin token**
(`api.admin_token` — the "token for a CLI/script" this section anticipated),
which is the single unscoped, fleet-wide escape hatch for ops / headless. Unset
= no unscoped access exists. `carillon import` still writes the store directly
(no token); only the HTTP API is gated. Cross-account single-resource access
returns `404` (hides existence); `POST /watches` forces the caller's account
and requires the mailbox to have been proven via `/auth`.

## 6. Transport & process architecture

**HTTP for everything.** The browser UI is a first-class client and browsers only
speak HTTP natively — that single constraint settles it: raw gRPC/RPC narrows
client reach (no browser without a proxy, not curl-able); REST+JSON is spoken by
every client with zero codegen and is trivially remoteable (TLS + auth).

- **REST + JSON** for control (already built).
- **SSE (Server-Sent Events)** for the live delivery-log / connection-status
  stream — one-way server→client, browser-native `EventSource`, proxy-friendly.
  (One-way → SSE > WebSocket > long-poll.)
- **OpenAPI spec** to give REST a typed contract, so any client can generate an
  SDK: REST's reach + a schema.
- **UI stack: Vite + React + TypeScript + Tailwind + shadcn/ui**, data via TanStack
  Query, live log via native `EventSource`, capability link as a `Bearer` header.
  Pure client SPA, no SSR (preserves serve-per-front). Chosen for build velocity and
  consistency with the charlie web stack; SvelteKit-static was the runner-up.

**The UI is a separate repo — `carillon-admin` — a *client* of the API, not part of
the daemon.** It is the **default / reference** admin SPA that Carillon ships and
the SaaS serves; a self-hoster can embed its build **or bring their own**. This is
the point: the daemon exposes only the REST+SSE API (the contract); the UI is one
consumer of it. Separation of concerns — the API can evolve a typed contract
(OpenAPI) and anyone can build against it.

**One static `dist/` from `carillon-admin`, served per-front:**

- **Self-host: embed** a pinned `carillon-admin` build in the daemon via
  `rust-embed` (one binary, one port, no CORS, airgapped) — or point at your own.
  The standard self-hosted pattern (Grafana, Syncthing, Portainer).
- **SaaS: serve `carillon-admin` from a CDN / Netlify.** The API box serves only
  JSON; static assets get edge caching and scale/deploy independently. CORS is a
  non-issue — a preflight + an allowlist — and pairs cleanly with the localStorage
  **bearer token** (§5): `Authorization` header cross-origin, no cookie/SameSite/
  CSRF complications.

Safety lives in API auth + binding (localhost + token self-host; token + TLS when
exposed), not in where the UI is served. The API base URL is a build/runtime env
(`VITE_API_BASE_URL`): same-origin for self-host, the API host for the CDN SaaS.

**Single process is fine.** Watchers and the admin server are both I/O-bound
async tasks parked at `await` almost all the time (watchers sleep on socket
readability; the admin sees a few clicks a minute). tokio interleaves them; an
HTTP handler can't starve a watcher. The **one discipline**: never block the
runtime — keep DB/crypto calls in `spawn_blocking` (the hot delivery path already
does). The real reason to ever split daemon from admin is **fault isolation**
(an admin panic shouldn't take the watchers down) and independent restart/deploy
— *not* throughput. One process now; split later as an ops decision.

## 7. Read-only posture — Carillon never writes

A notification service is fundamentally **read-only**: it needs `SELECT`/`EXAMINE`
+ `FETCH` + `IDLE`, never `APPEND`/`STORE`/`EXPUNGE`. Holding **write** access is
the difference between two breach outcomes:

- Read-only breach → leaks content-free "something changed" signals. Low value.
- Write breach → lets an attacker **inject perfectly-spoofed phishing** into every
  watched inbox at once. `APPEND` bypasses SMTP, so **no SPF/DKIM/DMARC** apply —
  an injected `no-reply@amazon.com` looks pristine. Catastrophic.

So Carillon never issues write commands, and no feature that needs write (the
`APPEND` test demo, in-mailbox warnings, in-mailbox link delivery) is worth that
blast radius — all rejected. Verify-onboarding is read-only (§2); warnings go via
webhook (§4) or the payer's Stripe email (§3).

**Use `EXAMINE`, not `SELECT`.** `EXAMINE` is the read-only `SELECT` (RFC 3501),
and IDLE runs on the examined mailbox exactly the same (QRESYNC/CONDSTORE params
are valid on `EXAMINE` — RFC 7162). This makes "no `SELECT` in the code" a clean,
grep-able invariant that prevents *accidental* writes (flag/`\Seen`/expunge) and
avoids `SELECT`'s `\Recent` reset on every re-select. **Done (2026-07-20):**
io-imap's `watch::ImapMailboxWatch` now uses `ImapMailboxExamine` (states
`ExamineInitial`/`ExamineQresync`) — pushed upstream, pulled into carillon via the
git dep. Caveat on scope: `EXAMINE` constrains
*Carillon's own* sessions (accident prevention); it does **not** stop a stolen
credential from opening its own session and `APPEND`ing — that's what OAuth
read-only scopes are for. Layer both.

**Enforcement depends on the auth type**, which is the real reason OAuth-first is
security, not UX:

- **OAuth read-only scopes** (e.g. Gmail `gmail.readonly`) make write *impossible*
  even on a full breach — provider-enforced. Prefer these.
- **Password / app-password** IMAP has no scope: read-only is *code discipline*
  only; a breach of the credential store could still `APPEND`. So for password
  mailboxes the credential store is crown jewels and content-free is the backstop.

## Cross-cutting: credential custody is the ground, not a feature

Handling mailbox credentials is the trust-sensitive core and the actual adoption
gate. It runs under every section above: OAuth-first where possible (read-only
scopes — §7), encrypt at rest (age now, KMS later), and keep self-host a real
option. Decide this posture before the dashboard — it decides who signs up at all.
