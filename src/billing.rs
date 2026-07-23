//! Billing — the payment provider behind a small enum.
//!
//! Payment is **stateless on our side** (§ BILLING_MODEL): the provider (Stripe)
//! owns the customer and the receipt; Carillon persists only the integer credit
//! balance a purchase tops up — never card details or PII. There is **no
//! subscription**: a purchase is a one-shot payment for a chosen quantity of
//! credits (1 credit = one PIM-account-month), priced by a one-time Stripe Price.
//!
//! The purchase unit is a **pack** (`PACK_SIZE` credits, § BILLING_MODEL): one
//! Stripe line item priced per pack, `quantity` = number of packs. The credit
//! count a pack yields is resolved by the caller (`api`), not here.
//!
//! [`Billing::Stub`] needs no keys and stands in for local/dev use:
//! `create_checkout` returns a placeholder URL and the webhook credits on trust.
//! [`Billing::Stripe`] creates a real hosted Checkout Session in `payment` mode,
//! verifies the webhook signature, and turns `checkout.session.completed` into a
//! pool top-up. An enum (not a `dyn` trait) keeps the async calls native.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use tracing::warn;
use url::form_urlencoded;

use crate::config::StripeConfig;
use crate::util::now_secs;

type HmacSha256 = Hmac<Sha256>;

/// The Stripe price-map key for the pack line item (a one-time Price = the
/// price of one [`PACK_SIZE`]-credit pack).
const PACK_PRICE_KEY: &str = "pack";

/// Credits per pack — the only purchase quantum (§ BILLING_MODEL: refill only
/// in 5-credit packs).
pub const PACK_SIZE: i64 = 5;

/// Stripe rejects/accepts a webhook within this clock skew of its timestamp
/// (replay-window guard), matching Stripe's own default tolerance.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// The Stripe Checkout Sessions endpoint.
const STRIPE_CHECKOUT_URL: &str = "https://api.stripe.com/v1/checkout/sessions";

/// What a verified provider webhook tells us to do.
pub enum WebhookOutcome {
    /// A payment completed: credit the pool of the account referenced by our
    /// internal session id, by the quantity that session recorded.
    Credit {
        /// Our internal checkout session id (Stripe's `client_reference_id`).
        session_id: String,
    },
    /// A valid but irrelevant event (wrong type, unpaid, unsigned test ping).
    Ignore,
}

/// The payment provider. `Stub` is keyless (dev/self-host on trust); `Stripe`
/// talks to the real API.
pub enum Billing {
    /// Keyless stand-in: placeholder checkout URL, webhook credits on trust.
    Stub,
    /// The Stripe adapter (hosted one-shot Checkout + signed webhooks).
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

    /// Starts a one-shot checkout for `packs` packs and returns the URL to send
    /// the buyer to. The internal `session_id` is threaded through so the webhook
    /// maps the payment back to the pending session (which holds the credit count
    /// the pool is topped up by).
    pub async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        packs: i64,
    ) -> Result<String> {
        match self {
            Billing::Stub => Ok(format!("https://checkout.stub.local/buy/{session_id}")),
            Billing::Stripe(stripe) => stripe.create_checkout(session_id, account_id, packs).await,
        }
    }

    /// Verifies a provider webhook over its **raw** body and returns what to do.
    /// The stub trusts a `{"session_id": …}` body; Stripe verifies the
    /// `Stripe-Signature` HMAC then maps a paid checkout to a credit.
    pub fn verify_webhook(
        &self,
        signature: Option<&str>,
        raw_body: &[u8],
    ) -> Result<WebhookOutcome> {
        match self {
            Billing::Stub => {
                let body: Value =
                    serde_json::from_slice(raw_body).context("invalid webhook body")?;
                match body.get("session_id").and_then(Value::as_str) {
                    Some(id) => Ok(WebhookOutcome::Credit {
                        session_id: id.to_string(),
                    }),
                    None => Ok(WebhookOutcome::Ignore),
                }
            }
            Billing::Stripe(stripe) => stripe.verify_webhook(signature, raw_body),
        }
    }
}

/// The Stripe adapter: a hosted one-shot Checkout Session per purchase and
/// signature-verified webhooks. Deliberately minimal — a form-encoded API call
/// over the shared `reqwest` client and an HMAC check — rather than an SDK.
pub struct StripeBilling {
    http: reqwest::Client,
    secret_key: String,
    webhook_secret: String,
    success_url: String,
    cancel_url: String,
    /// Plan-key → Stripe Price id. The `credit` key is the one-time credit Price.
    prices: BTreeMap<String, String>,
}

impl StripeBilling {
    /// Builds the adapter from config, sharing the server's pooled client.
    /// `default_base` (the dashboard URL) is where the buyer is returned after
    /// payment when the config leaves the URLs unset.
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
            prices: config.prices.clone(),
        }
    }

    /// Creates a hosted Checkout Session in `payment` mode for `packs` packs
    /// (one pack-priced line item, `quantity` = packs), tagging it with our
    /// internal `session_id` and the account, and returns the hosted page URL.
    async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        packs: i64,
    ) -> Result<String> {
        let price = self
            .prices
            .get(PACK_PRICE_KEY)
            .with_context(|| format!("no Stripe price configured for '{PACK_PRICE_KEY}'"))?;

        // Form-encoded, Stripe's wire format (incl. its bracketed nesting).
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("mode", "payment")
            .append_pair("success_url", &self.success_url)
            .append_pair("cancel_url", &self.cancel_url)
            .append_pair("client_reference_id", session_id)
            .append_pair("line_items[0][price]", price)
            .append_pair("line_items[0][quantity]", &packs.to_string())
            .append_pair("metadata[account_id]", account_id)
            .append_pair("metadata[carillon_session]", session_id)
            .finish();

        let session: Value = self.post_form(STRIPE_CHECKOUT_URL, body).await?;
        session
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("Stripe checkout response carried no url")
    }

    /// POSTs a form-encoded body to a Stripe endpoint and parses the JSON,
    /// surfacing Stripe's error body on a non-2xx.
    async fn post_form(&self, url: &str, body: String) -> Result<Value> {
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.secret_key)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("Stripe checkout request failed")?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Stripe checkout error ({status}): {text}");
        }
        serde_json::from_str(&text).context("invalid Stripe checkout response")
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
            Some("checkout.session.completed") => Ok(credit_from_session(object)),
            _ => Ok(WebhookOutcome::Ignore),
        }
    }
}

/// Maps a completed one-shot checkout to a [`WebhookOutcome::Credit`], or
/// [`WebhookOutcome::Ignore`] when it is unpaid or lacks our session reference.
fn credit_from_session(object: Option<&Value>) -> WebhookOutcome {
    let Some(object) = object else {
        return WebhookOutcome::Ignore;
    };
    let paid = object.get("payment_status").and_then(Value::as_str) == Some("paid")
        || object.get("status").and_then(Value::as_str) == Some("complete");
    let session = object.get("client_reference_id").and_then(Value::as_str);

    match (paid, session) {
        (true, Some(session)) => WebhookOutcome::Credit {
            session_id: session.to_string(),
        },
        (false, _) => {
            warn!("stripe checkout.session.completed but not paid; ignoring");
            WebhookOutcome::Ignore
        }
        _ => {
            warn!("stripe checkout.session.completed missing client_reference_id; ignoring");
            WebhookOutcome::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETED: &[u8] = br#"{"type":"checkout.session.completed","data":{"object":{"status":"complete","payment_status":"paid","client_reference_id":"sess_123"}}}"#;

    fn stripe(webhook_secret: &str) -> StripeBilling {
        StripeBilling {
            http: reqwest::Client::new(),
            secret_key: "sk_test_x".into(),
            webhook_secret: webhook_secret.into(),
            success_url: "https://dash/ok".into(),
            cancel_url: "https://dash/no".into(),
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
    fn valid_signature_credits_completed_checkout() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), COMPLETED);
        match s.verify_webhook(Some(&header), COMPLETED).unwrap() {
            WebhookOutcome::Credit { session_id } => assert_eq!(session_id, "sess_123"),
            _ => panic!("expected credit"),
        }
    }

    #[test]
    fn tampered_body_is_rejected() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), COMPLETED);
        let tampered = br#"{"type":"checkout.session.completed","data":{"object":{"status":"complete","payment_status":"paid","client_reference_id":"sess_HACK"}}}"#;
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
        let body = br#"{"type":"checkout.session.completed","data":{"object":{"status":"open","payment_status":"unpaid","client_reference_id":"x"}}}"#;
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
    fn stub_credits_from_session_id() {
        let outcome = Billing::Stub
            .verify_webhook(None, br#"{"session_id":"sess_9"}"#)
            .unwrap();
        assert!(matches!(
            outcome,
            WebhookOutcome::Credit { session_id } if session_id == "sess_9"
        ));
    }

    #[test]
    fn stub_ignores_unrelated_body() {
        let outcome = Billing::Stub
            .verify_webhook(None, br#"{"foo":"bar"}"#)
            .unwrap();
        assert!(matches!(outcome, WebhookOutcome::Ignore));
    }
}
