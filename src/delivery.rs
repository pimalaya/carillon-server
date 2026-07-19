//! Webhook delivery.
//!
//! Consumes canonical [`ChangeEvent`]s off a channel — decoupled from
//! the watchers so a slow endpoint never stalls IDLE — and POSTs each
//! as a signed, content-free JSON body. One shared, pooled
//! [`reqwest::Client`] fans out to every endpoint; failures retry with
//! bounded backoff; every outcome is logged to the store.

use std::sync::Arc;

use anyhow::{Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use sha2::Sha256;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use url::{Host, Url};

use crate::event::ChangeEvent;
use crate::live::{LiveBus, LiveEvent};
use crate::store::{DeliveryOutcome, Store};
use crate::util::now_secs;

type HmacSha256 = Hmac<Sha256>;

/// Give up after this many attempts.
const MAX_ATTEMPTS: u32 = 3;

/// Ceiling on in-flight deliveries, so a burst never spawns unbounded
/// work.
const CONCURRENCY: usize = 64;

/// Runs the delivery loop until the event channel closes.
pub async fn run(
    mut events: mpsc::Receiver<ChangeEvent>,
    store: Arc<Store>,
    client: Client,
    live: LiveBus,
) {
    let sem = Arc::new(Semaphore::new(CONCURRENCY));

    while let Some(event) = events.recv().await {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("delivery semaphore never closes");
        let store = store.clone();
        let client = client.clone();
        let live = live.clone();

        tokio::spawn(async move {
            deliver(store, client, event, live).await;
            drop(permit);
        });
    }
}

async fn deliver(store: Arc<Store>, client: Client, event: ChangeEvent, live: LiveBus) {
    let account = event.account.clone();

    // The store is the source of truth for the endpoint and secret.
    let watch = {
        let store = store.clone();
        let lookup_id = account.clone();
        match tokio::task::spawn_blocking(move || store.get_watch(&lookup_id)).await {
            Ok(Ok(Some(watch))) => watch,
            Ok(Ok(None)) => {
                warn!(account = %account, "delivery skipped: unknown watch");
                return;
            }
            Ok(Err(err)) => {
                warn!(account = %account, error = %err, "delivery skipped: store error");
                return;
            }
            Err(err) => {
                warn!(account = %account, error = %err, "delivery skipped: join error");
                return;
            }
        }
    };

    let body = serde_json::to_vec(&event).expect("ChangeEvent always serializes");
    // Sign the timestamped preimage `t.body` with every currently-valid
    // secret (current, plus the previous one during a rotation overlap),
    // Stripe-style, so a mid-rotation receiver validates against either.
    let signature = sign(&watch.signing_secrets(now_secs()), event.ts, &body);

    let mut attempts = 0;
    let mut last_status = None;
    let mut last_error = None;
    let mut ok = false;

    while attempts < MAX_ATTEMPTS {
        attempts += 1;

        let response = client
            .post(&watch.notify_url)
            .header("content-type", "application/json")
            .header("x-carillon-event", event.event.as_str())
            .header("x-carillon-account", &event.account)
            .header("x-carillon-id", &event.id)
            .header("x-carillon-signature", &signature)
            .body(body.clone())
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                last_status = Some(status.as_u16());
                if status.is_success() {
                    ok = true;
                    break;
                }
                last_error = Some(format!("HTTP {status}"));
                // 4xx is the caller's fault: do not retry.
                if !status.is_server_error() {
                    break;
                }
            }
            Err(err) => last_error = Some(err.to_string()),
        }

        if attempts < MAX_ATTEMPTS {
            let backoff = Duration::from_millis(500 * (1 << (attempts - 1)));
            sleep(backoff).await;
        }
    }

    if ok {
        info!(
            account = %event.account,
            event = event.event.as_str(),
            uid = event.uid,
            attempts,
            "delivered",
        );
    } else {
        warn!(
            account = %event.account,
            event = event.event.as_str(),
            uid = event.uid,
            attempts,
            error = ?last_error,
            "delivery failed",
        );
    }

    // Publish the outcome to any live (SSE) subscribers. Ignore the
    // error: no subscribers is the normal case.
    let _ = live.send(LiveEvent::delivery(
        event.account.clone(),
        event.event.as_str(),
        event.uid,
        ok,
        last_status,
        attempts,
    ));

    let event_kind = event.event.as_str().to_owned();
    let uid = event.uid;
    let error = last_error;
    tokio::task::spawn_blocking(move || {
        store.log_delivery(&DeliveryOutcome {
            account: &account,
            event: &event_kind,
            uid,
            ok,
            status: last_status,
            error: error.as_deref(),
            attempts,
        })
    })
    .await
    .ok();
}

/// Validates a notify URL against the HTTPS-only policy. Plain `http://`
/// is refused because a leaked-in-transit signal (and, worse, an
/// attacker able to see the URL) defeats the point — with one exception:
/// a loopback host, where `http://` is safe and needed for local sinks,
/// self-host and tests. Any non-loopback `http://` (or a non-HTTP
/// scheme) is rejected.
pub fn validate_notify_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|err| anyhow::anyhow!("not a valid URL: {err}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&parsed) => {
            warn!(
                url,
                "notify URL is plain http on loopback (allowed for local use)"
            );
            Ok(())
        }
        "http" => bail!("notify URL must be https:// (plain http is only allowed to loopback)"),
        other => bail!("notify URL scheme must be https, got {other}://"),
    }
}

/// Whether a URL's host is a loopback address or `localhost`.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Stripe-style signature header over the timestamped preimage
/// `"{ts}.{body}"`, HMAC-SHA256 with each valid secret:
/// `t=<ts>,v1=<hex>[,v1=<hex>]`. The timestamp is inside the signed
/// content (replay protection); multiple `v1` values cover a rotation
/// overlap. A receiver reconstructs `"{t}.{raw body}"`, HMACs it with
/// its configured secret, and accepts if any `v1` matches.
fn sign(secrets: &[&str], ts: i64, body: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(body.len() + 16);
    preimage.extend_from_slice(ts.to_string().as_bytes());
    preimage.push(b'.');
    preimage.extend_from_slice(body);

    let mut header = format!("t={ts}");
    for secret in secrets {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&preimage);
        header.push_str(",v1=");
        header.push_str(&hex::encode(mac.finalize().into_bytes()));
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independently recompute what a receiver would, to pin the wire
    /// format of the signed preimage.
    fn expected_v1(secret: &str, ts: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{ts}.").as_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn single_secret_signature_shape() {
        let header = sign(&["s3cr3t"], 1700000000, b"{\"uid\":1}");
        let v1 = expected_v1("s3cr3t", 1700000000, b"{\"uid\":1}");
        assert_eq!(header, format!("t=1700000000,v1={v1}"));
    }

    #[test]
    fn rotation_overlap_emits_both_v1() {
        let header = sign(&["new", "old"], 42, b"body");
        let new_v1 = expected_v1("new", 42, b"body");
        let old_v1 = expected_v1("old", 42, b"body");
        assert_eq!(header, format!("t=42,v1={new_v1},v1={old_v1}"));
    }

    #[test]
    fn notify_url_policy() {
        assert!(validate_notify_url("https://example.org/hook").is_ok());
        assert!(validate_notify_url("http://127.0.0.1:9099/").is_ok());
        assert!(validate_notify_url("http://localhost:8080/x").is_ok());
        assert!(validate_notify_url("http://example.org/hook").is_err());
        assert!(validate_notify_url("ftp://example.org/hook").is_err());
        assert!(validate_notify_url("not a url").is_err());
    }
}
