# Carillon — Billing (Stripe) setup & sandbox testing

Carillon sells a **per-mailbox subscription** — each mailbox is subscribed (and
cancelled) independently. It ships in two cadences — **`month`** and **`year`** —
and the buyer picks one per mailbox. The price lives in **Stripe** (a recurring
Price object), never in the code; the year's discount is just its Price. Payment
is stateless on our side: Stripe owns the customer and receipt; we persist only
the subscription *state* Stripe reports (status + period end). A new mailbox gets
a one-time **free-trial window** (7 days by default) so it can be tried before
subscribing.

Provider is chosen by config: no `[billing.stripe]` → the keyless **stub**
(dev); `[billing.stripe]` present → the real **Stripe** adapter.

---

## Which keys, and where they go

| Key | Looks like | Where | Needed? |
|---|---|---|---|
| **Secret key** | `sk_test_…` / `sk_live_…` | server config `[billing.stripe] secret_key` | **yes** |
| **Webhook signing secret** | `whsec_…` | server config `[billing.stripe] webhook_secret` | **yes** |
| **Publishable key** | `pk_test_…` | — | **no** |

We use Stripe **hosted Checkout** (we redirect the buyer to a Stripe-hosted
page), so the **publishable key is not used server-side at all**. You'd only need
it in the *admin* front (`VITE_STRIPE_PUBLISHABLE_KEY`) if you later embed
Stripe Elements/embedded checkout in the dashboard — not now.

> Production: inject `secret_key` / `webhook_secret` via systemd
> `LoadCredential` or a secrets manager, **not** a world-readable `carillon.toml`
> (see `DEPLOY_HARDENING.md` §2).

---

## One-time Stripe dashboard setup (sandbox)

1. Create a Stripe account — it starts in **Test mode**. Keep the "Test mode"
   toggle **on** for all of the below (test keys/prices are separate from live).
2. **Products → Prices**: create **two products**, each with a **recurring**
   Price in your currency: e.g. "Carillon — monthly" at €1 billed **monthly**,
   and "Carillon — yearly" at €10 billed **yearly**. Copy each **Price id**
   (`price_…`).
3. **Developers → API keys**: copy the **Secret key** (`sk_test_…`).
4. **Settings → Billing → Customer portal**: activate the portal (once) so the
   Manage / Cancel button works.

Put them in `carillon.toml` (the price keys must be `month` and `year`):

```toml
[billing.stripe]
secret_key = "sk_test_…"
webhook_secret = "whsec_…"                 # from step below

[billing.stripe.prices]
month = "price_…"                          # €1/month  (recurring)
year  = "price_…"                          # €10/year  (recurring — the discount)
```

`success_url` / `cancel_url` are **optional** — where Stripe returns the browser
after checkout. Left unset they default to your `dashboard_url` (or `public_url`)
with a `?checkout=success` / `?checkout=cancel` marker, which is fine for local
testing.

---

## Getting the webhook secret

**Local dev — Stripe CLI (recommended):**

```sh
stripe login
stripe listen --forward-to localhost:3000/billing/webhook
```

`stripe listen` prints `whsec_…` — put it in `webhook_secret`. It forwards real
test events to your local server, correctly signed. No public URL needed.

**Deployed server — dashboard endpoint:**
Developers → Webhooks → *Add endpoint* → URL
`https://your-server/billing/webhook`, events **`checkout.session.completed`**,
**`customer.subscription.updated`** and **`customer.subscription.deleted`**.
Copy that endpoint's signing secret (`whsec_…`).

---

## Testing the full flow

1. Start the server: `carillon serve carillon.toml` (logs `billing: stripe`).
2. If local: keep `stripe listen …` running in another terminal.
3. Start a checkout (through the dashboard, or by hand with a capability link):

   ```sh
   curl -X POST http://localhost:3000/billing/checkout \
     -H "Authorization: Bearer <capability-link>" \
     -H "content-type: application/json" \
     -d '{"plan":"year","mailbox_key":"you@example.com"}'
   ```

   (`mailbox_key` is a mailbox you authenticated via `/auth`; it appears in
   `GET /me` under `balance.mailboxes[].mailbox_key`.) →
   `{"provider":"stripe","checkout_url":"https://checkout.stripe.com/…", …}`.
4. Open `checkout_url`, subscribe with a **test card**: `4242 4242 4242 4242`,
   any future expiry, any CVC/ZIP.
5. Stripe fires `checkout.session.completed` → `/billing/webhook` → signature
   verified → subscription bound to that mailbox and activated. Server logs
   `subscription activated`.
6. Verify: `GET /me` → the mailbox's entry in `balance.mailboxes` has
   `subscribed: true`, `status: "active"`, and a `current_period_end`.
7. In the Stripe **customer portal** (via the dashboard's Manage button, or the
   portal URL from `POST /billing/portal`), cancel the subscription →
   `customer.subscription.updated`/`deleted` → `/billing/webhook` → status flips
   to `canceled`; the entitlement sweep pauses the account's watches when the
   period (plus a short grace) ends.

### Notes
- `stripe trigger checkout.session.completed` alone won't activate anything — a
  triggered event has no `client_reference_id`, so it's (correctly) **ignored**.
  Real activation needs an actual checkout so our session id round-trips.
- Activation is **idempotent**: Stripe retries the webhook; the second one is
  ignored (the session is already fulfilled).
- A forged/expired/wrong-secret signature is rejected with **400** (unit-tested
  in `billing.rs`).
- Going live: swap `sk_test_…`/`whsec_…`/`price_…` for their live equivalents
  and activate the account. Nothing else changes.
