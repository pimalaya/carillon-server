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
use serde_json::json;
use sha2::Sha256;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use url::{Host, Url};

use crate::event::ChangeEvent;
use crate::live::{LiveBus, LiveEvent, Routed};
use crate::store::{DeliveryOutcome, Store, Watch};
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

    // Publish the outcome to any live (SSE) subscribers, tagged with the
    // watch's billing account so the stream can scope it. Ignore the
    // error: no subscribers is the normal case.
    let _ = live.send(Routed::new(
        watch.account_id.clone(),
        LiveEvent::delivery(
            event.account.clone(),
            event.event.as_str(),
            event.uid,
            ok,
            last_status,
            attempts,
        ),
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

/// Sends a one-shot, signed **notice** webhook (low balance, exhausted,
/// auto-refilled) to a watch's notify URL. Best-effort and content-free,
/// like a change delivery, but not retried — a notice is advisory and the
/// same state recurs on the next tick. Reuses the change-delivery
/// signature scheme so receivers verify it the same way.
pub async fn deliver_notice(client: &Client, watch: &Watch, kind: &str) {
    let ts = now_secs();
    let body = serde_json::to_vec(&json!({
        "type": "notice",
        "notice": kind,
        "account": watch.id,
        "ts": ts,
    }))
    .expect("notice always serializes");
    let signature = sign(&watch.signing_secrets(ts), ts, &body);

    let result = client
        .post(&watch.notify_url)
        .header("content-type", "application/json")
        .header("x-carillon-event", "notice")
        .header("x-carillon-account", &watch.id)
        .header("x-carillon-signature", &signature)
        .body(body)
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            warn!(account = %watch.id, kind, status = %response.status(), "notice not acked")
        }
        Err(err) => warn!(account = %watch.id, kind, error = %err, "notice delivery failed"),
    }
}

/// The outcome of a one-shot webhook test: whether the endpoint acked, the
/// HTTP status (if any), and the failure reason (if any).
pub struct TestOutcome {
    /// The endpoint answered with a 2xx.
    pub ok: bool,
    /// The final HTTP status, if a response was received.
    pub status: Option<u16>,
    /// The failure reason, if the POST did not ack.
    pub error: Option<String>,
}

/// POSTs one synthetic, signed **test** event to `notify_url` — the
/// onboarding "Test webhook" button. Signed exactly like a real delivery
/// (with `secret`, so a receiver already wired to verify accepts it) but
/// carrying `{"type":"test", …}` and never retried. The caller is expected
/// to have validated the URL with [`validate_notify_url`] first.
pub async fn deliver_test(client: &Client, notify_url: &str, secret: &str) -> TestOutcome {
    let ts = now_secs();
    let body = serde_json::to_vec(&json!({
        "type": "test",
        "event": "test",
        "uid": 0,
        "ts": ts,
    }))
    .expect("test event always serializes");
    let signature = sign(&[secret], ts, &body);

    let response = client
        .post(notify_url)
        .header("content-type", "application/json")
        .header("x-carillon-event", "test")
        .header("x-carillon-signature", &signature)
        .body(body)
        .send()
        .await;

    match response {
        Ok(response) => {
            let status = response.status();
            TestOutcome {
                ok: status.is_success(),
                status: Some(status.as_u16()),
                error: (!status.is_success()).then(|| format!("endpoint returned HTTP {status}")),
            }
        }
        Err(err) => TestOutcome {
            ok: false,
            status: None,
            error: Some(err.to_string()),
        },
    }
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
