---
cairn: spec
capability: billing
status: current
---

# Billing

Carillon bills the **service**, not the account. A service is one standing watch (one watched source plus its sinks) and is the sole billed unit at 1 credit per service-month. Credits are a prepaid, fungible pool held on the Carillon account (see [[auth]]): 1 credit = 2 € = one service-month, sold only in packs of 5 (€10). A service spends credits all-or-nothing to run for a whole number of months, then stops unless opt-in auto-renew pulls the next credit from the pool. Every account gets one free credit so a first service runs free for 7 days. Credits are bought through Stripe one-shot Checkout with stateless [[webhooks]] fulfilment: Stripe owns the customer and receipt, Carillon persists only the balance. This is "signal, not sync" billing: you buy months of watching, nothing recurs unless the user opts in.

### Requirement: Bill the service, not the account
Carillon SHALL bill per standing service (one watched source, ~one held IMAP IDLE connection) at 1 credit per service-month, independent of source protocol, and SHALL NOT bill the Carillon account or the PIM account. See [[service-model]].

#### Scenario: multiple services on one account
A Carillon account watching 3 services SHALL be charged 3 credits per month, one per active service, self-metering with no fair-use policing beyond a high infra sanity cap (`max_watches_per_account`).

### Requirement: Prepaid fungible credit pool
Carillon SHALL hold credits as a single fungible pool on the Carillon account, never pre-assigned to a service; services SHALL pull from the shared pool. A credit SHALL have no expiry and SHALL NOT be refundable; its only exit SHALL be consumption by a service.

### Requirement: Sell credits only in packs of 5
Carillon SHALL sell credits only in packs of 5 (`PACK_SIZE = 5`, €10 per pack), linearly (`N packs = N × 5 credits = N × 10 €`), with no sub-pack granularity and no volume discount.

### Requirement: All-or-nothing credit spend on activation
Activating a service SHALL consume one or more credits at once, in a quantity chosen by the user, granting that many whole service-months of watching. Activation SHALL stack onto any time still remaining, and SHALL NOT prorate a partially-used month.

### Requirement: Service billing lifecycle
A declared service SHALL be free and inactive until activated. On activation Carillon SHALL debit the pool and run the watch until its paid expiry `D`, then SHALL hard-stop (no degraded polling fallback) and notify the user, unless auto-renew renews it. A stopped service SHALL stay configured and SHALL be restartable by spending credits again. See [[service-model]].

### Requirement: Opt-in auto-renew from the pool
Carillon SHALL support a per-service auto-renew toggle that, at expiry, draws the next credit from the pool to extend the service by one month with no interruption. Auto-renew SHALL be card-free and subscription-free, spending only credits already in the pool, and SHALL stop the service when the pool is empty.

#### Scenario: empty pool at the renewal sweep
When the renewal sweep runs and the pool cannot cover every due service, Carillon SHALL process services in declaration order (`rowid`), renewing the oldest first until the pool empties and stopping the remainder with a notice.

### Requirement: Pause is not a billing control
Carillon SHALL provide a service `active` toggle that can stop sink deliveries mid-month without affecting billing: the paid wall-clock month SHALL keep running regardless, and pausing SHALL NOT refund or extend credit. Self-hosted (unmetered) deployments SHALL use the same toggle with no credit clock.

### Requirement: One free credit per account, gated on a validated PIM account
Carillon SHALL grant exactly one free credit per Carillon account, gated on that account holding at least one validated PIM account, letting a first service run free for 7 days. This free credit SHALL replace any free-polling tier: "free" SHALL be a granted credit on the single IDLE watch path, not a separate code path. Its expiry SHALL be a hard stop like any paid month. See [[auth]].

#### Scenario: one free credit per mailbox globally
Carillon SHALL grant at most one free credit per PIM account globally, keyed by `mailbox_key`, claimed atomically by the first Carillon account to validate that mailbox; a later account adding the same mailbox SHALL earn no free credit and SHALL be told so.

### Requirement: Buy credits via Stripe one-shot Checkout
Carillon SHALL top up the pool through Stripe Checkout in `payment` mode using a one-time pack Price, with `quantity` equal to the number of packs purchased. It SHALL NOT use recurring subscriptions.

### Requirement: Stateless webhook fulfilment
Carillon SHALL credit the pool from the `checkout.session.completed` (or `payment_intent.succeeded`) webhook, adding the session's purchased credit count to the account bound via `client_reference_id`. Carillon SHALL persist only the resulting balance, holding no customer PII, receipt, or subscription state; Stripe SHALL own the customer and receipt. See [[webhooks]].

#### Scenario: event without a bound account
A webhook event carrying no `client_reference_id` (e.g. a bare `stripe trigger`) SHALL be ignored, since no account can be credited.

### Requirement: Idempotent fulfilment
Carillon SHALL fulfil each checkout session at most once. A retried or duplicate webhook for an already-fulfilled session SHALL be a no-op, leaving the balance unchanged.

### Requirement: Stripe configuration and signature verification
Carillon SHALL read the Stripe secret key (`sk_test_…` / `sk_live_…`) and webhook signing secret (`whsec_…`) from server config `[billing.stripe]`, and SHALL select the keyless stub provider when `[billing.stripe]` is absent. Metering SHALL be active only when Stripe is configured; self-host SHALL stay unmetered. Every inbound webhook SHALL have its signature verified against the signing secret, and a forged, expired, or wrong-secret signature SHALL be rejected with HTTP 400.

### Requirement: Money invariants
Carillon SHALL preserve these invariants at all times:
- 1 credit = 2 € = one service-month; the pool balance SHALL be a non-negative integer count of credits.
- Credits SHALL enter the pool only through fulfilled Stripe purchases or the one free-credit grant, and SHALL leave it only through consumption by a service (activation or auto-renew).
- No credit SHALL be created, refunded, or expired; a spent credit SHALL never return to the pool.
- A service SHALL run only while covered by spent credits; a lapsed service SHALL be dropped and SHALL resume watching only when re-activated with fresh spend.
