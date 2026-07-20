//! Billing — the payment provider behind a small enum.
//!
//! Payment is **stateless on our side** (§ DECISIONS 3, 5): the provider
//! (Stripe on the web, RevenueCat unifying the app stores) owns the
//! customer and the receipt; Carillon persists only what a paid session
//! grants (watch-seconds) and, on fulfilment, the resulting account
//! balance — never card details or PII. A pack maps to watch-time; its
//! *price* lives in the provider (a Stripe Price), not encoded here.
//!
//! [`Billing::Stub`] needs no keys and stands in for local/dev use:
//! `create_checkout` returns a placeholder URL, and the webhook fulfils on
//! trust. [`Billing::Stripe`] creates a real hosted Checkout Session and
//! verifies the webhook signature. An enum (not a `dyn` trait) keeps the
//! async checkout call native.

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

/// A prepaid credit pack: what it grants, in watch-seconds. The price is
/// configured in the payment provider (a Stripe Price), not here.
#[derive(Clone, Copy, Debug)]
pub struct Pack {
    /// Stable pack id (the SKU key the provider prices).
    pub id: &'static str,
    /// Watch-seconds granted on fulfilment.
    pub secs: f64,
}

const DAY: f64 = 86_400.0;

/// The catalogue of packs. Watch-time only — pricing is the provider's.
pub const PACKS: &[Pack] = &[
    Pack {
        id: "week",
        secs: 7.0 * DAY,
    },
    Pack {
        id: "quarter",
        secs: 90.0 * DAY,
    },
    Pack {
        id: "year",
        secs: 365.0 * DAY,
    },
];

/// Looks up a pack by id.
pub fn pack(id: &str) -> Option<Pack> {
    PACKS.iter().copied().find(|pack| pack.id == id)
}

/// Stripe rejects/accepts a webhook within this clock skew of its timestamp
/// (replay-window guard), matching Stripe's own default tolerance.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// The Stripe Checkout Sessions endpoint.
const STRIPE_CHECKOUT_URL: &str = "https://api.stripe.com/v1/checkout/sessions";

/// What a verified provider webhook tells us to do.
pub enum WebhookOutcome {
    /// Credit the pending checkout identified by this internal session id.
    Fulfil(String),
    /// A valid but irrelevant event (wrong type, unpaid, unsigned test ping).
    Ignore,
}

/// The payment provider. `Stub` is keyless (dev/self-host on trust); `Stripe`
/// talks to the real API.
pub enum Billing {
    /// Keyless stand-in: placeholder checkout URL, webhook fulfils on trust.
    Stub,
    /// The Stripe adapter (hosted Checkout + signed webhooks).
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

    /// Starts a purchase and returns the URL to send the buyer to. The
    /// internal `session_id` is threaded through so the webhook maps the
    /// payment back to the pending session we recorded.
    pub async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        pack: &Pack,
    ) -> Result<String> {
        match self {
            Billing::Stub => Ok(format!("https://checkout.stub.local/pay/{session_id}")),
            Billing::Stripe(stripe) => stripe.create_checkout(session_id, account_id, pack).await,
        }
    }

    /// Verifies a provider webhook over its **raw** body and returns what to
    /// fulfil. The stub trusts a `{"session_id": …}` body; Stripe verifies the
    /// `Stripe-Signature` HMAC then extracts the completed, paid session.
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
                    Some(id) => Ok(WebhookOutcome::Fulfil(id.to_string())),
                    None => Ok(WebhookOutcome::Ignore),
                }
            }
            Billing::Stripe(stripe) => stripe.verify_webhook(signature, raw_body),
        }
    }
}

/// The Stripe adapter: a hosted Checkout Session per purchase, and
/// signature-verified webhooks to fulfil. Deliberately minimal — a couple of
/// form-encoded API calls over the shared `reqwest` client and an HMAC check
/// — rather than a heavyweight SDK.
pub struct StripeBilling {
    http: reqwest::Client,
    secret_key: String,
    webhook_secret: String,
    success_url: String,
    cancel_url: String,
    /// Pack id → Stripe Price id (`price_…`).
    prices: BTreeMap<String, String>,
}

impl StripeBilling {
    /// Builds the adapter from config, sharing the server's pooled client.
    /// `default_base` (the dashboard URL) is where the buyer is returned after
    /// payment when the config leaves `success_url`/`cancel_url` unset.
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

    /// Creates a hosted Checkout Session for `pack`, tagging it with our
    /// internal `session_id` (as `client_reference_id`) and the account, and
    /// returns the hosted page URL.
    async fn create_checkout(
        &self,
        session_id: &str,
        account_id: &str,
        pack: &Pack,
    ) -> Result<String> {
        let price = self
            .prices
            .get(pack.id)
            .with_context(|| format!("no Stripe price configured for pack '{}'", pack.id))?;

        // Form-encoded, Stripe's wire format (incl. its bracketed nesting).
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("mode", "payment")
            .append_pair("success_url", &self.success_url)
            .append_pair("cancel_url", &self.cancel_url)
            .append_pair("client_reference_id", session_id)
            .append_pair("line_items[0][price]", price)
            .append_pair("line_items[0][quantity]", "1")
            .append_pair("metadata[account_id]", account_id)
            .append_pair("metadata[carillon_session]", session_id)
            .finish();

        let response = self
            .http
            .post(STRIPE_CHECKOUT_URL)
            .bearer_auth(&self.secret_key)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("Stripe checkout request failed")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Stripe checkout error ({status}): {body}");
        }

        let session: Value = serde_json::from_str(&body).context("invalid Stripe response")?;
        session
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("Stripe checkout response carried no url")
    }

    /// Verifies the `Stripe-Signature` HMAC over `"{t}.{raw_body}"` and, on a
    /// paid `checkout.session.completed`, returns the internal session id to
    /// fulfil. Rejects a missing/expired/forged signature.
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
        if event.get("type").and_then(Value::as_str) != Some("checkout.session.completed") {
            return Ok(WebhookOutcome::Ignore);
        }

        let object = event.pointer("/data/object");
        let paid = object
            .and_then(|o| o.get("payment_status"))
            .and_then(Value::as_str)
            == Some("paid");
        let session = object
            .and_then(|o| o.get("client_reference_id"))
            .and_then(Value::as_str);

        match (paid, session) {
            (true, Some(id)) => Ok(WebhookOutcome::Fulfil(id.to_string())),
            (false, _) => {
                warn!("stripe checkout.session.completed but not paid; ignoring");
                Ok(WebhookOutcome::Ignore)
            }
            (_, None) => {
                warn!("stripe checkout.session.completed without client_reference_id; ignoring");
                Ok(WebhookOutcome::Ignore)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAID: &[u8] = br#"{"type":"checkout.session.completed","data":{"object":{"payment_status":"paid","client_reference_id":"sess_123"}}}"#;

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
    fn valid_signature_fulfils_paid_session() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), PAID);
        match s.verify_webhook(Some(&header), PAID).unwrap() {
            WebhookOutcome::Fulfil(id) => assert_eq!(id, "sess_123"),
            WebhookOutcome::Ignore => panic!("expected fulfil"),
        }
    }

    #[test]
    fn tampered_body_is_rejected() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs(), PAID);
        let tampered = br#"{"type":"checkout.session.completed","data":{"object":{"payment_status":"paid","client_reference_id":"sess_HACK"}}}"#;
        assert!(s.verify_webhook(Some(&header), tampered).is_err());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let s = stripe("whsec_real");
        let header = sign("whsec_attacker", now_secs(), PAID);
        assert!(s.verify_webhook(Some(&header), PAID).is_err());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let s = stripe("whsec_test");
        let header = sign("whsec_test", now_secs() - 10_000, PAID);
        assert!(s.verify_webhook(Some(&header), PAID).is_err());
    }

    #[test]
    fn missing_signature_is_rejected() {
        let s = stripe("whsec_test");
        assert!(s.verify_webhook(None, PAID).is_err());
    }

    #[test]
    fn unpaid_completed_session_is_ignored() {
        let s = stripe("whsec_test");
        let body = br#"{"type":"checkout.session.completed","data":{"object":{"payment_status":"unpaid","client_reference_id":"x"}}}"#;
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
    fn stub_fulfils_from_session_id() {
        let outcome = Billing::Stub
            .verify_webhook(None, br#"{"session_id":"sess_9"}"#)
            .unwrap();
        assert!(matches!(outcome, WebhookOutcome::Fulfil(id) if id == "sess_9"));
    }
}
