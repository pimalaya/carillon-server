# Carillon — accounts, credits & billing model (v2)

The product model Carillon bills on. Converged in a design pass that rejected the
first model (**authless capability links + flat recurring subscription + 7-day
trial**, see below) as unworkable. Where this document differs from
[`BILLING.md`](BILLING.md) (subscription/trial) or the "un-authed" spine in
[`DECISIONS.md`](DECISIONS.md), **this document wins**. `BILLING.md` remains
valid only as Stripe *operational* setup once re-pointed at one-shot payments.

Two governing lines, replacing the old "gate the standing resource, keep
everything un-authed":

> **An account is the anchor.** Every PIM account, credit, and (future) API key
> hangs off one Carillon account — a magic-link-verified email. No account, no
> durable identity, no cross-device, no REST API. Ephemeral *testing* stays free
> and account-free; *standing watches* require an account.

> **You buy months, not a subscription.** Credits are a prepaid, fungible pool.
> One credit buys one PIM account one month of watching. Nothing recurs unless
> the user opts in, and even then it only ever spends credits they already own.

The plan's core line is unchanged: **Carillon signals; it never syncs.**

---

## 1. The hierarchy — three levels

| Level | What it is | Key property |
|---|---|---|
| **Carillon account** | Verified email (magic-link) + the **credit pool** | The billing identity. Everything hangs off it. |
| **PIM account** | A credential set, **validated by authenticating to it** | The ownership/credential unit. Ownership proof *and* the credential we hold to watch. Not itself billed. |
| **Service** | A watch (one watched source + its sinks) under a PIM account | The **billed unit** — 1 credit / month per service. |

Validating a PIM account does double duty: you couldn't authenticate to it if it
weren't yours (**ownership proof**), and success hands us the **credential we
persist** (KMS — Carillon is a credential custodian by design) to run the watch.

**Terminology, fixed:** a **service** is a watched source + its routing; a
**sink** is an output channel (webhook / SSE / FCM/UnifiedPush relay). Sinks are
free fan-out per the two-axis rule (grow source protocols, never payload).

**Source protocols** are the growth axis: today an IMAP mailbox (held IDLE) or a
CardDAV addressbook (polled — WebDAV has no IDLE; see `CARDDAV.md`). Every source
is the same billed unit — **1 credit / month** — regardless of protocol; the
poll-vs-IDLE distinction is a cost-side detail, not a pricing one.

---

## 2. What you pay for — the service (per connection), not the account

**1 € / service / month.** A service = one watched source = ~one held IMAP IDLE
connection = our unit cost.

Per-*service* pricing is **cost-aligned**, which is the decisive property: usage
and cost move together, so there is **no abuse surface** (50 services = 50
connections = 50 credits — self-metering; no fair-use policing, no "unlimited
but capped"). It also lowers the entry price for the majority single-INBOX user
(1 € vs a 3 €/account flat), converts the multi-provider target user far better
(3 services = 3 € vs 9 € under per-account), and grows revenue as a user adds
mailboxes (expansion). Lower ARPU on single-service users is offset by
conversion, ~99 % margin (break-even at a few dozen services), and the fact that
the price is trivial to raise later. Per-*account* flat pricing was rejected: it
undercharges heavy users and forces the abuse machinery it then has to contain.

The fair-use cap is no longer a pricing tool (billing self-meters); keep only a
high **sanity cap** as an infra DoS guard, not a tier.

---

## 3. Credits & the pool

- **1 credit = 1 € = one service-month.**
- **Refill only in packs of 5** (`PACK_SIZE = 5`, one €5 pack). A single-service
  user buys a €5 pack ≈ every 5 months (effective 1 €/mo); the pack amortizes
  Stripe's per-transaction fee and gives a prepaid runway that lowers churn.
- Credits live in a **fungible pool** on the Carillon account. Never
  pre-assigned to a service — services *pull* from the shared pool.
- **No refund. No expiry.** Once bought, a credit sits in the pool forever until
  spent. Its only exit is consumption by a service.
- **Consumed on activation.** You spend one or more credits at once (you choose
  the quantity, all-or-nothing) → the service watches (IDLE push) for that many
  months → it stops → we notify you. Activation **stacks** onto any time still
  remaining.
- **Manual by default.** Nothing auto-renews. A stopped service stays configured;
  spending a credit restarts it (which also turns auto-renew on — see below).
- **Opt-in auto-renew** (per service): at expiry, pull the next credit from the
  pool instead of stopping. **Card-free and subscription-free** — it only ever
  spends credits already in the pool. In the SaaS UI, auto-renew is the single
  lifecycle switch: on = keep renewing, off = ride out the paid month then stop.
- **Pause/resume is not a billing control.** A separate *active* toggle can stop
  webhook deliveries even mid-month (e.g. endpoint maintenance), but the paid
  clock keeps running — the credit bought the month either way (it is wall-clock,
  not a mid-month meter). Self-host (unmetered) uses the same toggle to freely
  start/stop, with no credit clock.

*Half-month note:* a service watched for two weeks costs the same as a full
month. Accepted: no proration. Because the spend is a deliberate, discrete
prepaid month (not a silent recurring charge), it is *more* honest than a
subscription, not less.

---

## 4. Service lifecycle

```
declared ──(free)──▶ inactive ──spend 1 credit──▶ watching(until D)
                        ▲                               │
                        │                        D reached
                        │                               ▼
                        └──────────── stopped ◀── notify user
                                 (re-click, or auto-renew
                                  pulls the next credit if on
                                  and the pool is non-empty)
```

Declaring a service (a watch) is free; it only starts when activated. When a
`watching` service reaches `D`:
- **auto-renew on & pool ≥ 1** → draw a credit, extend a month, no interruption.
- **otherwise** → **stop** (a hard stop — there is no degraded polling fallback)
  and notify.

*Empty pool at renewal:* the sweep processes services in **declaration order**
(`rowid` = insertion order), debiting the shared pool until it empties — so the
oldest services renew first and the rest stop with a notice.

---

## 5. The free credit (replaces the free polling tier)

There is **one watch mechanism** (IDLE). "Free" is just a **granted credit**, not
a second code path:

- **1 free credit per Carillon account**, gated on having **≥1 validated PIM
  account** — *not* per PIM account, or one account could mint free credits by
  registering aliases.
- **AND ≤1 free credit per PIM account globally** (keyed by `mailbox_key`): the
  **first Carillon account to validate a given PIM account claims** its one free
  credit; a second account that later adds the *same* mailbox earns nothing for
  it (and is told so). This is what lets two Carillon accounts watch the same
  mailbox without becoming a free-credit farm. Enforced atomically in the
  `free_credit_claim` table (see `POST /auth` → `free_credit`).
- **Abuse barrier:** to farm another free credit you need a **new real inbox**
  (magic-link is delivered there) **and** a **new, not-yet-claimed authenticatable
  PIM account**. Magic-link + PIM-auth-validation + the per-mailbox claim *are*
  the sybil control — no fraud engine needed for a 1 € value.
- Expiry of a free-credit month is a **hard stop**, same as any paid month.

This is distinct from **free testing** (§ onboarding in `DECISIONS.md`): the
ephemeral connect → auth → capability-check → `LOGOUT` path stays free and
account-free forever. The free *credit* buys one *standing* month.

---

## 6. Buying credits

- **One purchase type:** a one-shot pool top-up, **custom quantity**, linear —
  `N credits = N × 3 €`. No packs, no volume discount, no minimum quantity.
- Small purchases (a single 3 € credit loses ~11 % to Stripe fees) are **accepted
  as-is for now** — users decide their quantity; margin loss on tiny buys is not
  worth adding friction.
- **No auto-refill in v1.** The pool depth *is* the buffer: buy 20, watch 2
  accounts, and that's ~10 months of runway. Continuity comes from **opt-in
  auto-renew + good low-pool warnings**, not from auto-buying.
- **If auto-refill is ever wanted**, it is the **auto-recharge** pattern
  (Stripe `SetupIntent` off-session card + a threshold-triggered one-off
  `PaymentIntent`) — *not* a subscription: no fixed date/amount, charges only on
  a usage condition. Caveat: off-session charges can be SCA-declined, dropping
  back to "notify the user to finish it manually" — so even auto-refill leans on
  the notification system. Deferred.

Stripe integration therefore shifts from **recurring Price + Checkout
subscription** to **one-shot PaymentIntent / Checkout in `payment` mode**. The
webhook of record becomes `checkout.session.completed` (or
`payment_intent.succeeded`) crediting the pool by the purchased quantity; the
subscription webhooks (`customer.subscription.*`) are dropped.

---

## 7. Auth

- **Magic-link only.** Verifying an email creates the Carillon account; PIM
  accounts bind under it. We store no passwords; sessions + (future) tokens are
  ours, identity is the verified email.
- **No anonymous / bearer-token tier.** Considered and cut — a 5-second
  magic-link gives most of the benefit without a second ownership model.
- **API keys: deferred.** Machine/REST integration (dynamically registering PIM
  accounts and services) needs issued API keys, not human magic-links — but
  there's no need yet. When built, keys are issued *inside* an authenticated
  account and draw from the same pool.

---

## 8. Notifications — the guardrail (and the dogfood)

With everything manual by default and no polling fallback, **coverage gaps are
prevented by notifications, nothing else.** They must be flawless — Carillon is a
notification company; flaky billing notices are self-refuting. Required triggers:

- **Pre-expiry** — "watch on X ends in 3 days — extend, or turn on auto-renew."
  (Warn *before* expiry; at-expiry is already a gap.)
- **Low-pool** — "N credits left (~X weeks at your current burn)."
- **Stopped** — "X stopped: no credits."

---

## 9. What this supersedes / migration

- **`BILLING.md` model paragraph** (flat recurring subscription + 7-day trial):
  superseded. Its Stripe setup steps stay useful once re-pointed at one-shot
  `payment`-mode Checkout instead of a recurring Price.
- **`DECISIONS.md` "un-authed" spine:** *testing* stays free/un-authed;
  **activation now requires a Carillon account + a credit**, not an authless
  capability link.
- **Capability-link accounts** (current authless mechanism) → migrate to
  magic-link Carillon accounts; existing entitlement state maps to an opening
  pool balance.

## 10. Open knobs

- Sanity cap (`max_watches_per_account`) — an infra DoS guard now, not a tier.
- Notification lead times (3-day pre-expiry, low-pool threshold).
- Pack size (`PACK_SIZE = 5`) and the per-credit price (1 €) — both easy to raise.
- Auto-recharge (off-session) — future, only if manual + warnings prove
  insufficient.
- API keys — future, for REST/integration.

## 11. Implementation status (built 2026-07-21)

The model above is **implemented** in the server (clippy-clean, tests green):

- **Store** — `account {id, email, credits, free_credited}`; the **watch** gained
  `watching_until` + `auto_renew` (the service = billed unit); `magic_link` table;
  `checkout_session.quantity`. Subscription columns/tables removed. `upsert_watch`
  preserves activation across edits; `active_watches` is `rowid`-ordered.
- **Billing** — Stripe `mode=payment` one-shot Checkout; the line item is the
  **pack** Price, `quantity` = number of packs; the webhook credits the pool by
  the session's credit count. `PACK_SIZE = 5`.
- **Metering** — the sweep iterates active **services** in declaration order and
  renews (auto-renew) or stops each, warns pre-expiry, and warns low-pool. Gated
  by a `metered` flag (`true` only when Stripe is configured) — self-host stays
  unmetered. The entitlement gate is continuous in the supervisor's `reconcile`
  (a lapsed service is dropped; re-activating brings it back).
- **Email** — `Mailer::{Stub, Resend}` (`src/email.rs`); magic-link sign-in and
  account-level notices. See `docs/EMAIL.md`.
- **API** — `+/auth/magic/request`, `+/auth/magic/verify`,
  `+/watches/{id}/activate`, `+/watches/{id}/auto-renew`; `/billing/checkout`
  takes `packs`; `/billing/plans` and `/billing/portal` removed. `openapi.yaml`
  updated.

Not built: auto-refill / auto-recharge (deferred), API keys (deferred), and the
`carillon-admin` dashboard (separate repo — still shows the old subscription UI).
