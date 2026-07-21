//! Billing — the payment provider behind a small enum.
//!
//! Payment is **stateless on our side** (§ DECISIONS 3, 5): the provider
//! (Stripe on the web, RevenueCat unifying the app stores) owns the customer
//! and the receipt; Carillon persists only the subscription *state* Stripe
//! reports (status + period end) — never card details or PII. A plan maps to a
//! recurring Stripe Price; its *price* lives in the provider, not encoded here.
//!
//! [`Billing::Stub`] needs no keys and stands in for local/dev use:
//! `create_checkout` returns a placeholder URL and the webhook activates on
//! trust. [`Billing::Stripe`] creates a real hosted Checkout Session in
//! `subscription` mode, verifies the webhook signature, and turns the
//! `checkout.session.completed` / `customer.subscription.*` events into
//! subscription state changes. An enum (not a `dyn` trait) keeps the async
//! calls native.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use tracing::warn;
use url::form_urlencoded;

use crate::config::StripeConfig;
use crate::util::now_secs;

type HmacSha256 = Hmac<Sha256>;

const DAY: f64 = 86_400.0;

/// A subscription plan (a recurring billing cadence). The *price* — and any
/// annual discount — lives in the provider's Prices; only the nominal cadence
/// length (for a provisional period end) is known here.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    /// Stable plan id (the SKU key the provider prices): `month`, `year`, …
    pub id: &'static str,
    /// Nominal length of one billing period, for the provisional period end.
    pub cadence_secs: f64,
}

/// The default plan catalogue (used by the stub, and for cadence lengths).
pub const PLANS: &[Plan] = &[
    Plan {
        id: "month",
        cadence_secs: 30.0 * DAY,
    },
    Plan {
        id: "year",
        cadence_secs: 365.0 * DAY,
    },
];

/// The nominal length of a plan's billing period, for the provisional period
/// end recorded at checkout (later refined by subscription lifecycle events).
/// Known cadences map exactly; an unknown id defaults to a month.
pub fn cadence_secs(plan_id: &str) -> f64 {
    match plan_id {
        "day" => DAY,
        "week" => 7.0 * DAY,
        "month" => 30.0 * DAY,
        "quarter" => 90.0 * DAY,
        "year" => 365.0 * DAY,
        _ => PLANS
            .iter()
            .find(|plan| plan.id == plan_id)
            .map(|plan| plan.cadence_secs)
            .unwrap_or(30.0 * DAY),
    }
}

/// A plan surfaced to clients: its id and nominal cadence length (the price
/// itself is the provider's, shown on the hosted checkout page).
#[derive(Clone, Debug, Serialize)]
pub struct PlanInfo {
    pub id: String,
    pub cadence_secs: f64,
}

/// Stripe rejects/accepts a webhook within this clock skew of its timestamp
/// (replay-window guard), matching Stripe's own default tolerance.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// The Stripe Checkout Sessions endpoint.
const STRIPE_CHECKOUT_URL: &str = "https://api.stripe.com/v1/checkout/sessions";
/// The Stripe billing-portal Sessions endpoint (manage / cancel).
const STRIPE_PORTAL_URL: &str = "https://api.stripe.com/v1/billing_portal/sessions";

/// What a verified provider webhook tells us to do.
pub enum WebhookOutcome {
    /// A checkout completed: bind the Stripe subscription to the account
    /// referenced by our internal session id and activate it.
    Activate {
        /// Our internal checkout session id (Stripe's `client_reference_id`).
        session_id: String,
        /// The Stripe subscription id, keyed on by later lifecycle events.
        subscription_id: String,
        /// The Stripe customer id, for the billing-portal link.
        customer_id: Option<String>,
    },
    /// A subscription's status/period changed (renewed, cancelled, past_due).
    Update {
        subscription_id: String,
        status: String,
        current_period_end: Option<i64>,
    },
    /// A valid but irrelevant event (wrong type, unsigned test ping).
    Ignore,
}

/// The payment provider. `Stub` is keyless (dev/self-host on trust); `Stripe`
/// talks to the real API.
pub enum Billing {
    /// Keyless stand-in: placeholder checkout URL, webhook activates on trust.
    Stub,
    /// The Stripe adapter (hosted subscription Checkout + signed webhooks).
    Stripe(StripeBilling),
}

impl Billing {
    /// The provider name, surfaced to clients.
    pub fn provider(&self) -> &'static str {
        match self {
            Billing::Stub => "stub",
            Billing::Stripe(_) => "stripe",
        }
    }

    /// The subscription plans on offer: the stub's default catalogue, or the
    /// plan ids configured against Stripe Prices (cheapest cadence first).
    pub fn plans(&self) -> Vec<PlanInfo> {
        match self {
            Billing::Stub => PLANS
                .iter()
                .map(|plan| PlanInfo {
                    id: plan.id.to_string(),
                    cadence_secs: plan.cadence_secs,
                })
                .collect(),
            Billing::Stripe(stripe) => {
                let mut plans: Vec<PlanInfo> = stripe
                    .prices
                    .keys()
                    .map(|id| PlanInfo {
                        id: id.clone(),
                        cadence_secs: cadence_secs(id),
                    })
                    .collect();
                plans.sort_by(|a, b| a.cadence_secs.total_cmp(&b.cadence_secs));
                plans
            }
        }
    }

    /// Starts a subscription checkout for `plan` and returns the URL to send
    /// the buyer to. The internal `session_id` is threaded through so the
    /// webhook maps the payment back to the pending session we recorded.
    pub async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        plan: &str,
    ) -> Result<String> {
        match self {
            Billing::Stub => Ok(format!(
                "https://checkout.stub.local/subscribe/{session_id}"
            )),
            Billing::Stripe(stripe) => stripe.create_checkout(session_id, account_id, plan).await,
        }
    }

    /// Creates a billing-portal session for a customer (manage / cancel), and
    /// returns the URL to send them to.
    pub async fn create_portal(&self, customer_id: &str, return_url: &str) -> Result<String> {
        match self {
            Billing::Stub => Ok(format!("https://billing.stub.local/portal/{customer_id}")),
            Billing::Stripe(stripe) => stripe.create_portal(customer_id, return_url).await,
        }
    }

    /// Verifies a provider webhook over its **raw** body and returns what to
    /// do. The stub trusts a `{"session_id": …}` (activate) or
    /// `{"subscription_id": …, "status": …}` (update) body; Stripe verifies the
    /// `Stripe-Signature` HMAC then maps the event.
    pub fn verify_webhook(
        &self,
        signature: Option<&str>,
        raw_body: &[u8],
    ) -> Result<WebhookOutcome> {
        match self {
            Billing::Stub => {
                let body: Value =
                    serde_json::from_slice(raw_body).context("invalid webhook body")?;
                if let Some(id) = body.get("session_id").and_then(Value::as_str) {
                    return Ok(WebhookOutcome::Activate {
                        session_id: id.to_string(),
                        subscription_id: format!("sub_stub_{id}"),
                        customer_id: None,
                    });
                }
                match (
                    body.get("subscription_id").and_then(Value::as_str),
                    body.get("status").and_then(Value::as_str),
                ) {
                    (Some(sub), Some(status)) => Ok(WebhookOutcome::Update {
                        subscription_id: sub.to_string(),
                        status: status.to_string(),
                        current_period_end: body.get("current_period_end").and_then(Value::as_i64),
                    }),
                    _ => Ok(WebhookOutcome::Ignore),
                }
            }
            Billing::Stripe(stripe) => stripe.verify_webhook(signature, raw_body),
        }
    }
}

/// The Stripe adapter: a hosted subscription Checkout Session per purchase, a
/// billing-portal session for self-service, and signature-verified webhooks.
/// Deliberately minimal — a couple of form-encoded API calls over the shared
/// `reqwest` client and an HMAC check — rather than a heavyweight SDK.
pub struct StripeBilling {
    http: reqwest::Client,
    secret_key: String,
    webhook_secret: String,
    success_url: String,
    cancel_url: String,
    portal_return_url: String,
    /// Plan id → Stripe recurring Price id (`price_…`).
    prices: BTreeMap<String, String>,
}

impl StripeBilling {
    /// Builds the adapter from config, sharing the server's pooled client.
    /// `default_base` (the dashboard URL) is where the buyer is returned after
    /// payment / portal when the config leaves the URLs unset.
    pub fn new(http: reqwest::Client, config: &StripeConfig, default_base: &str) -> Self {
        let base = default_base.trim_end_matches('/');
        Self {
            http,
            secret_key: config.secret_key.clone(),
            webhook_secret: config.webhook_secret.clone(),
            success_url: config
                .success_url
                .clone()
                .unwrap_or_else(|| format!("{base}/?checkout=success")),
            cancel_url: config
                .cancel_url
                .clone()
                .unwrap_or_else(|| format!("{base}/?checkout=cancel")),
            portal_return_url: format!("{base}/billing"),
            prices: config.prices.clone(),
        }
    }

    /// Creates a hosted Checkout Session in `subscription` mode for `plan`,
    /// tagging it with our internal `session_id` (as `client_reference_id`)
    /// and the account, and returns the hosted page URL.
    async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        plan: &str,
    ) -> Result<String> {
        let price = self
            .prices
            .get(plan)
            .with_context(|| format!("no Stripe price configured for plan '{plan}'"))?;

        // Form-encoded, Stripe's wire format (incl. its bracketed nesting).
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("mode", "subscription")
            .append_pair("success_url", &self.success_url)
            .append_pair("cancel_url", &self.cancel_url)
            .append_pair("client_reference_id", session_id)
            .append_pair("line_items[0][price]", price)
            .append_pair("line_items[0][quantity]", "1")
            .append_pair("metadata[account_id]", account_id)
            .append_pair("metadata[carillon_session]", session_id)
            .append_pair("subscription_data[metadata][carillon_account]", account_id)
            .finish();

        let session: Value = self
            .post_form(STRIPE_CHECKOUT_URL, body, "checkout")
            .await?;
        session
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("Stripe checkout response carried no url")
    }

    /// Creates a billing-portal session for a customer and returns its URL.
    async fn create_portal(&self, customer_id: &str, return_url: &str) -> Result<String> {
        let return_url = if return_url.is_empty() {
            self.portal_return_url.as_str()
        } else {
            return_url
        };
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("customer", customer_id)
            .append_pair("return_url", return_url)
            .finish();

        let session: Value = self.post_form(STRIPE_PORTAL_URL, body, "portal").await?;
        session
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("Stripe portal response carried no url")
    }

    /// POSTs a form-encoded body to a Stripe endpoint and parses the JSON,
    /// surfacing Stripe's error body on a non-2xx.
    async fn post_form(&self, url: &str, body: String, what: &str) -> Result<Value> {
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.secret_key)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .with_context(|| format!("Stripe {what} request failed"))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Stripe {what} error ({status}): {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("invalid Stripe {what} response"))
    }

    /// Verifies the `Stripe-Signature` HMAC over `"{t}.{raw_body}"` and maps
    /// the event to an outcome. Rejects a missing/expired/forged signature.
    fn verify_webhook(&self, signature: Option<&str>, raw_body: &[u8]) -> Result<WebhookOutcome> {
        let header = signature.context("missing Stripe-Signature header")?;

        let mut timestamp: Option<i64> = None;
        let mut candidates: Vec<&str> = Vec::new();
        for part in header.split(',') {
            match part.split_once('=') {
                Some(("t", value)) => timestamp = value.trim().parse().ok(),
                Some(("v1", value)) => candidates.push(value.trim()),
                _ => {}
            }
        }

        let timestamp = timestamp.context("Stripe-Signature missing timestamp")?;
        if (now_secs() - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
            bail!("Stripe webhook timestamp outside tolerance");
        }

        // Recompute the MAC over "{t}.{body}" and constant-time compare (via
        // `verify_slice`) against each provided v1 signature.
        let verified = candidates.iter().any(|candidate| {
            let Ok(expected) = hex::decode(candidate) else {
                return false;
            };
            let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(timestamp.to_string().as_bytes());
            mac.update(b".");
            mac.update(raw_body);
            mac.verify_slice(&expected).is_ok()
        });
        if !verified {
            bail!("Stripe webhook signature mismatch");
        }

        let event: Value = serde_json::from_slice(raw_body).context("invalid Stripe event JSON")?;
        let object = event.pointer("/data/object");
        match event.get("type").and_then(Value::as_str) {
            Some("checkout.session.completed") => Ok(activate_from_session(object)),
            Some("customer.subscription.updated") | Some("customer.subscription.deleted") => {
                Ok(update_from_subscription(object))
            }
            _ => Ok(WebhookOutcome::Ignore),
        }
    }
}

/// Maps a completed subscription checkout to an [`WebhookOutcome::Activate`],
/// or [`WebhookOutcome::Ignore`] when it is unpaid or lacks the ids we bind on.
fn activate_from_session(object: Option<&Value>) -> WebhookOutcome {
    let Some(object) = object else {
        return WebhookOutcome::Ignore;
    };
    // A subscription checkout completes with status "complete" and its first
    // invoice paid; ignore anything else.
    let paid = object.get("payment_status").and_then(Value::as_str) == Some("paid")
        || object.get("status").and_then(Value::as_str) == Some("complete");
    let session = object.get("client_reference_id").and_then(Value::as_str);
    let subscription = object.get("subscription").and_then(Value::as_str);
    let customer = object.get("customer").and_then(Value::as_str);

    match (paid, session, subscription) {
        (true, Some(session), Some(subscription)) => WebhookOutcome::Activate {
            session_id: session.to_string(),
            subscription_id: subscription.to_string(),
            customer_id: customer.map(str::to_string),
        },
        (false, _, _) => {
            warn!("stripe checkout.session.completed but not paid; ignoring");
            WebhookOutcome::Ignore
        }
        _ => {
            warn!("stripe checkout.session.completed missing session/subscription id; ignoring");
            WebhookOutcome::Ignore
        }
    }
}

/// Maps a subscription lifecycle event to an [`WebhookOutcome::Update`].
fn update_from_subscription(object: Option<&Value>) -> WebhookOutcome {
    let Some(object) = object else {
        return WebhookOutcome::Ignore;
    };
    let subscription = object.get("id").and_then(Value::as_str);
    let status = object.get("status").and_then(Value::as_str);
    match (subscription, status) {
        (Some(subscription), Some(status)) => WebhookOutcome::Update {
            subscription_id: subscription.to_string(),
            status: status.to_string(),
            current_period_end: object.get("current_period_end").and_then(Value::as_i64),
        },
        _ => WebhookOutcome::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETED: &[u8] = br#"{"type":"checkout.session.completed","data":{"object":{"status":"complete","payment_status":"paid","client_reference_id":"sess_123","subscription":"sub_abc","customer":"cus_xyz"}}}"#;
    const UPDATED: &[u8] = br#"{"type":"customer.subscription.updated","data":{"object":{"id":"sub_abc","status":"past_due","current_period_end":1893456000}}}"#;

    fn stripe(webhook_secret: &str) -> StripeBilling {
        StripeBilling {
            http: reqwest::Client::new(),
            secret_key: "sk_test_x".into(),
            webhook_secret: webhook_secret.into(),
            success_url: "https://dash/ok".into(),
            cancel_url: "https://dash/no".into(),
            portal_return_url: "https://dash/billing".into(),
            prices: BTreeMap::new(),
        }
    }

    /// Reconstruct the header a real Stripe would send, to pin our scheme.
    fn sign(secret: &str, ts: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        format!("t={ts},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn valid_signature_activates_completed_checkout() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), COMPLETED);
        match s.verify_webhook(Some(&header), COMPLETED).unwrap() {
            WebhookOutcome::Activate {
                session_id,
                subscription_id,
                customer_id,
            } => {
                assert_eq!(session_id, "sess_123");
                assert_eq!(subscription_id, "sub_abc");
                assert_eq!(customer_id.as_deref(), Some("cus_xyz"));
            }
            _ => panic!("expected activate"),
        }
    }

    #[test]
    fn subscription_update_carries_status_and_period() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), UPDATED);
        match s.verify_webhook(Some(&header), UPDATED).unwrap() {
            WebhookOutcome::Update {
                subscription_id,
                status,
                current_period_end,
            } => {
                assert_eq!(subscription_id, "sub_abc");
                assert_eq!(status, "past_due");
                assert_eq!(current_period_end, Some(1_893_456_000));
            }
            _ => panic!("expected update"),
        }
    }

    #[test]
    fn tampered_body_is_rejected() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), COMPLETED);
        let tampered = br#"{"type":"checkout.session.completed","data":{"object":{"status":"complete","payment_status":"paid","client_reference_id":"sess_HACK","subscription":"sub_abc"}}}"#;
        assert!(s.verify_webhook(Some(&header), tampered).is_err());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let s = stripe("whsec_real");
        let header = sign("whsec_attacker", now_secs(), COMPLETED);
        assert!(s.verify_webhook(Some(&header), COMPLETED).is_err());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs() - 10_000, COMPLETED);
        assert!(s.verify_webhook(Some(&header), COMPLETED).is_err());
    }

    #[test]
    fn missing_signature_is_rejected() {
        let s = stripe("whsec_test");
        assert!(s.verify_webhook(None, COMPLETED).is_err());
    }

    #[test]
    fn unpaid_completed_session_is_ignored() {
        let s = stripe("whsec_test");
        let body = br#"{"type":"checkout.session.completed","data":{"object":{"status":"open","payment_status":"unpaid","client_reference_id":"x","subscription":"sub_1"}}}"#;
        let header = sign("whsec_test", now_secs(), body);
        assert!(matches!(
            s.verify_webhook(Some(&header), body).unwrap(),
            WebhookOutcome::Ignore
        ));
    }

    #[test]
    fn other_event_type_is_ignored() {
        let s = stripe("whsec_test");
        let body = br#"{"type":"payment_intent.created","data":{"object":{}}}"#;
        let header = sign("whsec_test", now_secs(), body);
        assert!(matches!(
            s.verify_webhook(Some(&header), body).unwrap(),
            WebhookOutcome::Ignore
        ));
    }

    #[test]
    fn stub_activates_from_session_id() {
        let outcome = Billing::Stub
            .verify_webhook(None, br#"{"session_id":"sess_9"}"#)
            .unwrap();
        assert!(matches!(
            outcome,
            WebhookOutcome::Activate { session_id, .. } if session_id == "sess_9"
        ));
    }

    #[test]
    fn stub_updates_from_subscription_body() {
        let outcome = Billing::Stub
            .verify_webhook(None, br#"{"subscription_id":"sub_9","status":"canceled"}"#)
            .unwrap();
        assert!(matches!(
            outcome,
            WebhookOutcome::Update { status, .. } if status == "canceled"
        ));
    }
}
