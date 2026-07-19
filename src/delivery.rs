//! Webhook delivery.
//!
//! Consumes canonical [`ChangeEvent`]s off a channel — decoupled from
//! the watchers so a slow endpoint never stalls IDLE — and POSTs each
//! as a signed, content-free JSON body. One shared, pooled
//! [`reqwest::Client`] fans out to every endpoint; failures retry with
//! bounded backoff; every outcome is logged to the store.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use sha2::Sha256;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use crate::event::ChangeEvent;
use crate::store::{DeliveryOutcome, Store};

type HmacSha256 = Hmac<Sha256>;

/// Give up after this many attempts.
const MAX_ATTEMPTS: u32 = 3;

/// Ceiling on in-flight deliveries, so a burst never spawns unbounded
/// work.
const CONCURRENCY: usize = 64;

/// Runs the delivery loop until the event channel closes.
pub async fn run(mut events: mpsc::Receiver<ChangeEvent>, store: Arc<Store>, client: Client) {
    let sem = Arc::new(Semaphore::new(CONCURRENCY));

    while let Some(event) = events.recv().await {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("delivery semaphore never closes");
        let store = store.clone();
        let client = client.clone();

        tokio::spawn(async move {
            deliver(store, client, event).await;
            drop(permit);
        });
    }
}

async fn deliver(store: Arc<Store>, client: Client, event: ChangeEvent) {
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
    let signature = sign(&watch.hmac_secret, &body);

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

/// GitHub-style HMAC-SHA256 signature: `sha256=<hex>`.
fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(digest))
}
