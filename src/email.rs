//! Transactional email — the magic-link and billing-notice sender behind a
//! small enum, mirroring [`crate::billing::Billing`].
//!
//! Deliverability is existential here: a magic-link that spam-folders means a
//! user cannot sign in at all (§ BILLING_MODEL / docs/EMAIL.md). So Carillon
//! never sends from its own box — it relays through a provider, over an
//! authenticated sending subdomain (SPF + DKIM + DMARC), with link tracking
//! **off** on the auth stream (a rewritten magic link looks like a redirect and
//! trips filters).
//!
//! [`Mailer::Stub`] needs no keys and stands in for local/dev: it logs what it
//! would send (the magic-link URL included, so a dev flow is testable without a
//! provider). [`Mailer::Resend`] posts to the Resend HTTP API over the shared
//! `reqwest` client. The enum makes adding SES/Postmark/SMTP a new variant.

use anyhow::{Context, Result, bail};
use serde_json::json;
use tracing::{info, warn};

use crate::config::EmailConfig;

/// The Resend send endpoint.
const RESEND_URL: &str = "https://api.resend.com/emails";

/// The transactional email sender. `Stub` logs (dev/self-host); `Resend` sends.
pub enum Mailer {
    /// Keyless stand-in: logs the message (magic-link URL included) instead of
    /// sending. Lets a dev flow complete with no provider configured.
    Stub,
    /// The Resend adapter (HTTP API over the shared client).
    Resend(ResendMailer),
}

impl Mailer {
    /// Builds the mailer from config, sharing the server's pooled client.
    /// `[email.resend]` present → the Resend adapter; absent → the stub.
    pub fn new(http: reqwest::Client, config: &EmailConfig) -> Self {
        match &config.resend {
            Some(resend) => {
                info!("email: resend");
                Mailer::Resend(ResendMailer {
                    http,
                    api_key: resend.api_key.clone(),
                    from: resend.from.clone(),
                })
            }
            None => {
                info!("email: stub (no [email.resend] configured)");
                Mailer::Stub
            }
        }
    }

    /// Sends a sign-in email carrying the magic link. Link tracking is off so
    /// the token URL is delivered verbatim.
    pub async fn send_magic_link(&self, to: &str, link: &str) -> Result<()> {
        let text = format!(
            "Sign in to Carillon by opening this link (valid briefly, single use):\n\n{link}\n\n\
             If you did not request this, ignore this email."
        );
        let html = format!(
            "<p>Sign in to Carillon:</p>\
             <p><a href=\"{link}\">Sign in</a></p>\
             <p>The link is valid briefly and can be used once. If you did not \
             request this, ignore this email.</p>"
        );
        self.send(to, "Sign in to Carillon", &text, Some(&html))
            .await
    }

    /// Sends a plain billing notice (low pool, watch ending / stopped) — the
    /// account-level channel the live bus cannot reach.
    pub async fn send_notice(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        self.send(to, subject, body, None).await
    }

    /// Sends one message, or logs it (stub).
    async fn send(&self, to: &str, subject: &str, text: &str, html: Option<&str>) -> Result<()> {
        match self {
            Mailer::Stub => {
                info!(to, subject, body = text, "email (stub, not sent)");
                Ok(())
            }
            Mailer::Resend(resend) => resend.send(to, subject, text, html).await,
        }
    }
}

/// The Resend adapter: one form-free JSON POST per message.
pub struct ResendMailer {
    http: reqwest::Client,
    api_key: String,
    /// The `From:` header — a monitored address on your authenticated sending
    /// subdomain (e.g. `Carillon <no-reply@mail.carillon.pimalaya.org>`).
    from: String,
}

impl ResendMailer {
    async fn send(&self, to: &str, subject: &str, text: &str, html: Option<&str>) -> Result<()> {
        let mut body = json!({
            "from": self.from,
            "to": [to],
            "subject": subject,
            "text": text,
        });
        if let Some(html) = html {
            body["html"] = json!(html);
        }

        let response = self
            .http
            .post(RESEND_URL)
            .bearer_auth(&self.api_key)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).context("cannot encode email body")?)
            .send()
            .await
            .context("Resend request failed")?;

        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            warn!(%status, to, "resend send failed");
            bail!("Resend error ({status}): {detail}");
        }
        info!(to, subject, "email sent");
        Ok(())
    }
}
