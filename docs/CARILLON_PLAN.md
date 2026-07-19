# Carillon — design & plan

> Bells that announce. Carillon watches your remote PIM accounts and chimes when
> something changes. Status: design (2026-07-18/19). No code yet.

## 1. What Carillon is

A **hosted watcher that turns a change on a remote into an outbound notification.**
You give it credentials and a *notify URL*; it holds the connection you can't hold
on a phone (IMAP IDLE), and the instant something changes it POSTs a small, signed,
**content-free** signal to your URL.

The single governing principle:

> **Carillon signals; it never syncs.** It watches remotes and emits a uniform
> "something changed" webhook. It never stores, syncs, or serves content.

Everything about scope, cost, and trust follows from that one line.

Sibling of the PIM gateway thread (`GATEWAY_PLAN.md`, `pimgate/`). Carillon is the
*push/watch* slice, extracted and productised on its own.

## 2. Name & domain

- **Name:** Carillon (chosen 2026-07-19). A set of bells rung to announce — a
  notification is a chime. Fits the Pimalaya evocative-word tradition
  (Neverest, Mirador, Limier). No collision with existing Pimalaya names or a
  dominant push brand.
- **Home:** `carillon.pimalaya.org` — free subdomain, on-brand, instant.
- **.org is fine to sell on.** PIR/.org is unrestricted; Stripe and app stores don't
  care. For a FOSS org it's a *trust asset* (open/community, DAVx5-style). Add a
  vanity domain later (`carillon.email`, `getcarillon.com`) pointed at the same box
  if a standalone commercial face is ever wanted.

## 3. Scope — the two-axis rule

Split every scope question onto two axes:

- **Breadth (source protocols): expand freely.** This is where the value is —
  "unify webhook creation" behind one output format.
- **Depth (event detail / content): stay shallow.** Going deep turns Carillon into
  EmailEngine/Nylas — a heavier, higher-liability, crowded product.

### Axis 1 — event granularity (deliberately shallow)

- **New mail** (`EXISTS` / new UID) — universal, reliable. The 90% case. **v1.**
- **Removals** (`EXPUNGE`) — nearly free with IDLE; useful for cache honesty.
  A distinct event type. **v1.1.**
- **Flag / move changes** — plain IDLE surfaces these only unreliably; doing it
  properly needs **CONDSTORE/QRESYNC** (RFC 7162, MODSEQ). And they're *noise as
  notifications* (nobody wants a push when another device marks something read).
  So: **opt-in, later, framed as a "sync trigger," off by default.**
- **Never full deltas or bodies.** Emit the event *type* ("mailbox X changed,
  modseq now Y"), not the delta. The consumer does its own incremental fetch
  (QRESYNC) after the ping. This is what keeps Carillon cheap and private.

**Content-line nuance:** "New mail" is weaker than "Email from Alice — Q3 budget,"
but the rich version needs envelope headers = content. Resolve it **client-side**:
Carillon pings "new mail," the app wakes and fetches From/Subject itself (it has the
creds) and builds the rich notification locally — the push provider still sees
nothing. For the **no-app ntfy path**, offer envelope-fetch as an **explicit opt-in**
with the privacy trade-off disclosed (the relay would see sender/subject). Default
stays pure signal.

### Axis 2 — source protocols (the real product = uniform output)

Carillon absorbs each protocol's ugliness and emits *one* event format regardless
of source:

- **IMAP (IDLE)** — the "beast" (one held TCP socket per mailbox). The
  differentiator. **v1.**
- **JMAP** — the opposite of the beast: native push (PushSubscription/WebPush).
  Register a subscription pointing at Carillon, re-emit `StateChange`. Nearly free.
  Easy early add.
- **Gmail / Graph** — webhook-native (`users.watch` → Pub/Sub; Graph subscriptions).
  Register their webhooks, handle renewal, re-emit uniformly. Literally "unify
  webhook creation."
- **CalDAV / CardDAV** — no native push: **poll the sync-token/ctag** (RFC 6578),
  a cheap timer watcher; or use **WebDAV-Push** where the server supports it
  (DavX5 + ntfy are piloting it). Turns Carillon from a *mail* notifier into a
  *PIM* notifier and feeds the eventual monolith app.
- **Skip:** POP3 (dying, poll-only), EWS/ActiveSync (legacy, proprietary, heavy).

### The hard STOP (permanent)

Out of scope forever: message content/bodies/vCards/full state; storage or sync
state; full-text search; message operations (send/move/delete on the user's behalf).
That's the EmailEngine/Nylas product. Refusing to cross this line is what keeps
Carillon thin, cheap, low-liability, and distinct.

### Output transports (the fan-out side)

Mirror image of Axis 2: as inputs fan *in* to one canonical event, that event fans
*out* to a small set of transports. **Design the event schema once (the product);
transports are pluggable delivery adapters.** One rule dominates the choice:

> Some output transports reintroduce the held-connection cost on the *output* side.
> Webhook doesn't; long-poll / WebSocket / SSE do (Carillon holds one connection per
> consumer — the beast on the other side of the pipe).

- **Webhook (HTTPS POST) — canonical, default, cheapest.** Servers, integrations,
  relays. Both sides hold nothing. Keep primary.
- **Push relay (ntfy/UnifiedPush → later FCM/APNs) — the output for phones.** Just a
  webhook pointed at a relay, so ~free for Carillon, and it offloads the held
  connection to the platform's shared push socket. A **direct WS/long-poll to a phone
  is an anti-pattern** — the phone would hold the connection in the background, which
  is exactly the battery/OS problem Carillon exists to eliminate.
- **SSE / WebSocket — premium/opt-in, for always-on foreground non-public clients**
  (browser dashboards, desktop daemons). Real value as a *multiplexed* single feed
  (one connection, all your accounts' events). But held-connection cost on the output
  side → gate and price it. For one-way notification **SSE > WebSocket > long-poll**
  (long-poll has the cost with none of the efficiency).
- **Message queue (MQTT/AMQP/Kafka/cloud pub-sub) — enterprise integration.** Defer.
- **Channel integrations (email/Slack/Telegram) — out of core scope.** Channel
  sprawl; let the webhook + the user's own Zapier/n8n fan out.

**MVP = webhook only** (ntfy is free — just a webhook URL). Add transports as demand
justifies, and only when they don't wreck the cost model. The invariant to get right
now is the **event schema**, not the transport list.

## 4. Push architecture (the wider context)

Two independent planes:

- **Emit plane** (server → push gateway): what watches the remote and fires the
  signal. Can be generic and per-token.
- **Receive plane** (push gateway → phone): the OS channel. **FCM/APNs is the
  gateway; our server is only the "provider"/app-server handing off to it** — it
  never reaches the phone directly. Push is **content-free** (signal only; the app
  syncs after): privacy win (Google/Apple never see content) and it matches JMAP
  `StateChange`.

Generic "any app links with a token" = **UnifiedPush** (endpoint URL = the token),
but **Android/desktop only**. iOS APNs is bundle-locked → on iOS you *must* own an
app. That's why the eventual consumer product is a single app (below).

**Emit plane is all-lambda EXCEPT IMAP IDLE.** Gmail/Graph/JMAP-WebPush = event
lambda; DAV = timer/poll lambda; watch renewals = cron lambda. **IMAP IDLE is the
sole thing needing a standing process** — the "black beast." Isolating it (the
transformer, below) homogenises everything to webhooks so the rest is stateless.

## 5. The MVP shape — the IMAP-IDLE→webhook transformer

The fastest *sellable* form of Carillon is the transformer: **no app, no FCM/APNs,
no app store.** Register on the web, add IMAP creds + a notify URL, pay via Stripe,
Carillon holds IDLE and POSTs on change.

The elegant bit: the notify URL is either a **developer's own webhook** (integration
buyers) or an **ntfy topic URL** (a consumer gets real phone push via ntfy/
UnifiedPush, with *zero app development* on our side). One delivery mechanism, two
audiences.

**Validated market:** EmailEngine (near-exact self-host commercial product, licenses
by connected-account count), Nylas (enterprise), context.io (shuttered pioneer = an
open niche below them). The opening is a **thin, cheap, self-hostable** transformer.

The consumer monolith app, Gmail/Graph ingress, native FCM/APNs, and contacts/
calendar are all *later* phases that consume this same core.

## 6. The eventual consumer app (context, not MVP)

Push *forces* a monolith. You need an app (iOS APNs is bundle-locked); the app must
own sync (empty push → app fetches the diff); sync needs the view → you ship a full
offline-first client regardless. So: **one app for mail + contacts + calendar, one
push setup, one subscription** — mail owned end-to-end (no OS store), contacts/
calendar mirrored into the OS PIM stores. This revisits the earlier 3-app split
*for push economics*. Not the MVP; Carillon-the-service ships first.

## 7. Deployment topology — ONE VPS, not lambda (this stage)

You must run a VPS for IDLE regardless. Folding stateless webhook handling onto it
costs ~0 marginal (spare CPU) and **deletes a whole second platform** (no cross-
cloud, cold starts, separate deploy/IAM/monitoring). A VPS *dedicated to hooks alone*
would lose to Lambda's free tier at low volume — the win is free-riding the box you
already run.

- One **Hetzner CAX21** (4 vCPU / 8 GB ARM, ~€7/mo) + **local SQLite** = the entire
  backend for the first several thousand accounts (~€10/mo, one bill).
- Keep IDLE and webhooks as **separate processes** on the box (IDLE churn must not
  take down webhooks). At MVP a single binary with separate tokio task-trees is fine;
  split into two systemd services when hardening.
- **Deployment topology ≠ product topology:** the transformer stays a cleanly
  separable, self-hostable service; the webhook handler stays stateless +
  datastore-backed. Either lifts to Lambda / its own box later without a rewrite.
- **Lambda is a later tool** (burst absorption, fleet avoidance), premature now.
- **Caveat:** single box = SPOF (IDLE restart = reconnect storm + missed-notif
  window). Add redundancy to the IDLE side before the webhook side when it matters.

## 8. Cost model

Both sides are **sub-cent per account per month**; the real floor is fixed infra +
ops, not per-account.

- **Lambda (event side):** ~$0.6 per **million** invocations
  (`events × (2e-7 + duration_s × mem_GB × 1.6667e-5)`); 3000 events/acct/mo ≈
  $0.002. Use **Lambda Function URLs (free)**, not API Gateway ($1/M). The datastore
  is the floor, not the compute.
- **IDLE side:** async runtime (tokio, `io-imap`), ~50 KB/conn → **~50–100k conns
  per 8 GB box**. Hetzner CAX21 (~€7) → **€0.00014/account/month**. CPU near-zero
  (RFC 2177 re-IDLE every ~29 min = trivial).
- **The IDLE costs that don't divide per-account:** reconnect/TLS-handshake storms
  (over-provision ~2× CPU), **egress IP pool** (providers cap connections per IP;
  Gmail = 15 simultaneous IMAP/account), dead-socket liveness detection (silent-dead
  socket = missed notif = worst failure), ops/supervision.
- **Baseline ≈ €30–80/mo** covers the first several thousand accounts. At ~€2/acct
  effective, break-even ≈ **25–35 accounts**; beyond = **>97% infra margin**. Cost
  proves the recurring model is sustainable; it does **not** set the price — price on
  the €3–5 market band and on value.

## 9. Monetization

- **Free, unlimited offline CLIENT** (on-device sync = zero server cost). Charge only
  for the **WATCH** (the standing server resource).
- **Free download** (or DAVx5-style €5 Play / free F-Droid).
- **Packs = prepaid consumable credits ("notifier-months"), NOT permanent slots.**
  Permanent slots = one-time-pay-for-perpetual-cost (the DAVx5 mistake, only works
  on-device). Credits are store-legal (Android native multi-qty consumables; iOS
  accumulate server-side) and genuinely pay-as-you-go.
- **Auto-refill ≈ a hidden subscription** (retention of a sub, freedom-feel of PAYG).
  Guard the silent-outage UX hazard with low-balance warnings + optional auto-refill.
- **~€2/account effective, capped tail.** Store IAP can't do linear €N×accounts
  metering (fixed SKUs only); true metering lives on the Stripe/web channel.
- **Entitlement enforced at the SERVER boundary** (a cracked client still gets no
  push, because push originates server-side).

## 10. Identity & setup

- **No signup.** Customer = a self-minted UUID (= RevenueCat app-user-id, in the
  keystore) authorised by a payment receipt; the server verifies entitlement and
  issues a bearer token. The app forwards the grant it already holds (no re-auth) +
  the device push token + a watch descriptor.
- **Recovery is the weak spot** (flagged): fallback = self-verifying email (we
  already watch the mailbox → prove control for free), never the primary key;
  store restore-purchases re-establishes entitlement.
- **Credential custody** concentrates in Carillon (it holds creds to *watch*). Prefer
  scoped OAuth over passwords; encrypt at rest; self-hostable is a GTM necessity for
  a credential-handling product.

**MVP setup flow (dashboard-driven):**
1. Sign up at carillon.pimalaya.org — email magic-link, no password.
2. Add a watch — IMAP server/port/user/password + a notify URL (own webhook, or an
   ntfy topic); folder defaults to INBOX.
3. Test connection — validate creds + IDLE support, show green.
4. Pay — first watch free (funnel), then Stripe Checkout for credit packs;
   entitlement flips the watch on.
5. Live — IDLE starts; new mail → signed POST; dashboard shows connection status +
   delivery log.

## 11. MVP tech stack

- **One box:** Hetzner CAX21, Debian, systemd.
- **Runtime:** Rust + tokio, async throughout.
- **IMAP:** existing **`io-imap`** (async IDLE already built — ~80% of the beast).
- **API/dashboard:** **axum**.
- **DB:** **SQLite** via `sqlx` (WAL), local. Postgres only when outgrown.
- **Billing:** **Stripe** (Checkout + Customer Portal + webhooks).
- **TLS/proxy:** **Caddy** (auto Let's Encrypt).
- **Delivery:** `reqwest` POST, **HMAC-signed**, retry with backoff.
- **Creds at rest:** `age` crate + a key in the box's secrets file (KMS later).
- **Process model:** one binary at MVP (watcher + API as separate tokio task-trees);
  split into two systemd services when hardening.

## 12. Build order (MVP)

1. **Scaffold** — axum + tokio + sqlx; DNS `carillon.pimalaya.org` → box; Caddy
   auto-TLS.
2. **Data model** — `accounts` (imap host/port/user, enc_password, folder=INBOX),
   `webhooks` (notify_url, hmac_secret), `customers` (stripe_id, credits/status),
   `deliveries` (log).
3. **Watcher core** — `io-imap`: connect → login → SELECT INBOX → IDLE; on new-UID,
   POST the signed content-free payload (`{account, event:"new", uid, count}`);
   re-IDLE every ~29 min; reconnect with backoff. One task per account.
4. **Supervisor** — spawn/stop watcher tasks as accounts are added/removed/paid/
   lapsed; dead-socket liveness.
5. **Auth + minimal dashboard** — email magic-link; add-watch form; test-connect
   button; connection status + delivery log.
6. **Stripe entitlement gate** — Checkout for credits; Stripe webhook flips accounts
   active/inactive; enforce entitlement at watch-start (server boundary).
7. **Deploy** — systemd unit(s), Caddy, `tracing` → journald, a couple of gauges
   (live connections, deliveries). Ship.

Realistically a working paid MVP in a couple of focused weeks, given `io-imap`
already exists.

## 13. Roadmap (breadth, never depth)

- **Phase 1 (MVP):** IMAP IDLE → signed webhook (new mail; + removals). ntfy path for
  no-app consumer push. Stripe credits.
- **Phase 2:** JMAP (native push re-emit); Gmail/Graph (webhook ingress + renewal).
  Process split (API vs watcher). Egress IP pool. KMS for creds.
- **Phase 3:** CalDAV/CardDAV (poll sync-token, or WebDAV-Push) → PIM-wide notifier.
- **Phase 4:** native FCM/APNs + the consumer monolith app (mail+contacts+calendar,
  offline-first) consuming Carillon.

Every step grows the **source protocols**; none grows the **payload**.

## 14. Open questions / risks

- **Recovery** of the passwordless customer identity (self-verifying email fallback
  is the current answer; validate under real churn).
- **Credential custody** liability — the trust-sensitive core; self-host option
  matters for security-conscious buyers.
- **SPOF** on the single box; reconnect storms on restart.
- **Provider connection/IP limits** (Gmail 15/account, per-IP throttling) at scale.
- **Rich-notification vs content-free** tension for the no-app path.
