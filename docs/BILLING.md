# Carillon — Billing (Stripe) setup & sandbox testing

Carillon sells **watch-time** as prepaid packs (`week`, `quarter`, `year`). The
price lives in **Stripe** (a Price object), never in the code — a pack maps only
to watch-seconds. Payment is stateless on our side: Stripe owns the customer and
receipt; we persist only what a paid session grants.

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
2. **Products → Prices**: create three products, one Price each (e.g. €X
   one-off). Copy each **Price id** (`price_…`).
3. **Developers → API keys**: copy the **Secret key** (`sk_test_…`).

Put them in `carillon.toml`:

```toml
[billing.stripe]
secret_key = "sk_test_…"
webhook_secret = "whsec_…"                 # from step below

[billing.stripe.prices]
week    = "price_…"
quarter = "price_…"
year    = "price_…"
```

`success_url` / `cancel_url` are **optional** — where Stripe returns the browser
after payment. Left unset they default to your `dashboard_url` (or `public_url`)
with a `?checkout=success` / `?checkout=cancel` marker, which is fine for local
testing. Set them explicitly to override:

```toml
[billing.stripe]
# …
success_url = "https://app.example.org/?checkout=success"
cancel_url  = "https://app.example.org/?checkout=cancel"
```

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
`https://your-server/billing/webhook`, event **`checkout.session.completed`**.
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
     -d '{"pack":"week"}'
   ```

   → returns `{"provider":"stripe","checkout_url":"https://checkout.stripe.com/…", …}`.
4. Open `checkout_url`, pay with a **test card**: `4242 4242 4242 4242`, any
   future expiry, any CVC/ZIP.
5. Stripe fires `checkout.session.completed` → `/billing/webhook` → signature
   verified → session fulfilled once → pool credited. Server logs
   `checkout fulfilled`.
6. Verify: `GET /me` → `balance.paid_secs` went up by the pack's seconds.

### Notes
- `stripe trigger checkout.session.completed` alone won't credit anything — a
  triggered event has no `client_reference_id`, so it's (correctly) **ignored**.
  Real fulfilment needs an actual checkout so our session id round-trips.
- Fulfilment is **idempotent**: Stripe retries the webhook; the second one is
  ignored (the session is already fulfilled).
- A forged/expired/wrong-secret signature is rejected with **400** (unit-tested
  in `billing.rs`).
- Going live: swap `sk_test_…`/`whsec_…`/`price_…` for their live equivalents
  and activate the account. Nothing else changes.
