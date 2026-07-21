//! Entitlement — the business model made correct here, not in the payment
//! vendor (§ DECISIONS 3).
//!
//! A watch runs while its account is **entitled**, which is a boolean, not a
//! balance: either the watch's mailbox is still inside its one-time free-trial
//! **window** (wall-clock, granted once per normalised mailbox — un-farmable),
//! or the account holds an **active subscription**. There is no per-second
//! debit; a light [`run`] sweep re-checks entitlement each tick and pauses any
//! watch whose entitlement has lapsed (so it stops holding an IDLE connection),
//! emitting a notice on the live bus and as a signed webhook so a no-dashboard
//! user is never silently cut off.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::delivery::deliver_notice;
use crate::live::{LiveBus, LiveEvent, NoticeKind, Routed};
use crate::store::{Store, SubscriptionRow};
use crate::supervisor::SupervisorCmd;
use crate::util::now_secs;

/// Default free-trial window: one week of watch-time, granted once per
/// mailbox. Wall-clock from the first authentication.
const DEFAULT_TRIAL_SECS: f64 = 7.0 * 86_400.0;
/// Grace past a subscription's period end before entitlement is dropped, so a
/// delayed renewal / missed webhook does not cause a spurious outage.
pub const SUB_GRACE_SECS: i64 = 3 * 86_400;
/// Default "trial ending soon" warning lead time.
const DEFAULT_WARN_BEFORE_SECS: f64 = 3.0 * 86_400.0;
/// Default entitlement-sweep interval.
const DEFAULT_TICK_SECS: u64 = 60;

/// The one-time trial window, overridable via `CARILLON_TRIAL_SECS` (mainly to
/// exercise expiry in tests without waiting days).
pub fn trial_secs() -> f64 {
    env_f64("CARILLON_TRIAL_SECS").unwrap_or(DEFAULT_TRIAL_SECS)
}

/// The sweep interval, overridable via `CARILLON_METER_TICK_SECS`.
pub fn tick() -> Duration {
    let secs = std::env::var("CARILLON_METER_TICK_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_TICK_SECS)
        .max(1);
    Duration::from_secs(secs)
}

/// The "trial ending soon" warning lead time, overridable via
/// `CARILLON_WARN_BEFORE_SECS`.
fn warn_before_secs() -> f64 {
    env_f64("CARILLON_WARN_BEFORE_SECS").unwrap_or(DEFAULT_WARN_BEFORE_SECS)
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

/// The normalised anti-farming key for a mailbox: lowercased, plus-
/// addressing stripped, keyed on `(local, provider)`. Two logins that
/// reach the same inbox share one trial, so it cannot be farmed.
pub fn mailbox_key(login: &str, imap_host: &str) -> String {
    let login = login.trim().to_ascii_lowercase();
    let (local, domain) = match login.split_once('@') {
        Some((local, domain)) => (local.to_string(), domain.to_string()),
        None => (login.clone(), imap_host.trim().to_ascii_lowercase()),
    };
    // Strip plus-addressing (`user+tag` -> `user`).
    let local = local.split('+').next().unwrap_or(&local).to_string();
    format!("{local}@{domain}")
}

/// Whether a mailbox's subscription currently entitles its watches. Active,
/// trialing and (during dunning) past_due count, up to the period end plus a
/// grace window; a missing period end means we only just recorded it.
pub fn subscription_active(subscription: &SubscriptionRow, now: i64) -> bool {
    let paying = matches!(
        subscription.sub_status.as_deref(),
        Some("active") | Some("trialing") | Some("past_due")
    );
    if !paying {
        return false;
    }
    match subscription.sub_current_period_end {
        Some(end) => now < end + SUB_GRACE_SECS,
        None => true,
    }
}

/// Whether a mailbox's one-time free-trial window is still open.
pub fn trial_active(store: &Store, mailbox_key: &str, now: i64) -> bool {
    matches!(store.trial_expires(mailbox_key), Ok(Some(expires)) if now < expires)
}

/// Whether a mailbox is currently subscribed (its per-mailbox subscription is
/// active). Fails closed on a store error only for entitlement decisions that
/// combine it with the trial check below.
pub fn mailbox_subscribed(store: &Store, account_id: &str, mailbox_key: &str, now: i64) -> bool {
    matches!(
        store.get_mailbox_subscription(account_id, mailbox_key),
        Ok(Some(sub)) if subscription_active(&sub, now)
    )
}

/// Whether a watch may run: its mailbox is still in trial, or that mailbox's
/// subscription is active. The entitlement check the supervisor makes at
/// watch-start (the server boundary).
pub fn is_entitled(store: &Store, account_id: &str, mailbox_key: &str) -> bool {
    let now = now_secs();
    trial_active(store, mailbox_key, now) || mailbox_subscribed(store, account_id, mailbox_key, now)
}

/// Runs the entitlement sweep until cancelled: every `tick`, pause any active
/// watch whose account is no longer entitled, and warn once when a trial is
/// about to lapse with no subscription behind it.
pub async fn run(
    store: Arc<Store>,
    live: LiveBus,
    http: reqwest::Client,
    commands: mpsc::Sender<SupervisorCmd>,
    tick: Duration,
) {
    let warn_before = warn_before_secs();
    // Watches already warned this trial-ending episode, so the warning fires
    // once per crossing, not every tick.
    let mut warned: HashSet<String> = HashSet::new();

    let mut ticker = interval(tick);
    ticker.tick().await; // consume the immediate first tick

    info!(
        tick_secs = tick.as_secs(),
        warn_before_secs = warn_before,
        "entitlement sweep started"
    );

    loop {
        ticker.tick().await;

        let watches = match store.active_watches() {
            Ok(watches) => watches,
            Err(err) => {
                warn!(error = %err, "sweep: cannot read watches");
                continue;
            }
        };

        let now = now_secs();
        for watch in watches {
            let key = mailbox_key(&watch.login, &watch.imap_host);
            let subscribed = mailbox_subscribed(&store, &watch.account_id, &key, now);
            let trial_expires = store.trial_expires(&key).ok().flatten();
            let trial_ok = matches!(trial_expires, Some(expires) if now < expires);

            // Lapsed: no active trial and no subscription — pause the watch.
            if !subscribed && !trial_ok {
                let _ = store.set_active(&watch.id, false);
                warned.remove(&watch.id);
                emit_notice(
                    &store,
                    &live,
                    &http,
                    &watch.account_id,
                    &watch.id,
                    NoticeKind::WatchPaused,
                    None,
                )
                .await;
                // Drop the connection promptly rather than waiting for the
                // next periodic reconcile.
                let _ = commands.send(SupervisorCmd::Reconcile).await;
                continue;
            }

            debug!(watch = %watch.id, subscribed, trial_ok, "entitled");

            // On trial only, and it is about to lapse: warn once per crossing.
            if !subscribed {
                if let Some(expires) = trial_expires {
                    let remaining = (expires - now) as f64;
                    if remaining <= warn_before {
                        if warned.insert(watch.id.clone()) {
                            let days = (remaining / 86_400.0).ceil().max(0.0) as i64;
                            emit_notice(
                                &store,
                                &live,
                                &http,
                                &watch.account_id,
                                &watch.id,
                                NoticeKind::TrialEnding,
                                Some(format!("{days}d left")),
                            )
                            .await;
                        }
                    } else {
                        warned.remove(&watch.id);
                    }
                }
            } else {
                warned.remove(&watch.id);
            }
        }
    }
}

/// Publishes a notice on the live bus (dashboard) and as a signed webhook
/// (so a no-dashboard user is not silently cut off). `account_id` tags the
/// live event for scoped SSE fan-out; `watch_id` keys the wire payload and
/// the webhook.
async fn emit_notice(
    store: &Store,
    live: &LiveBus,
    http: &reqwest::Client,
    account_id: &str,
    watch_id: &str,
    kind: NoticeKind,
    detail: Option<String>,
) {
    info!(account = %watch_id, notice = kind.as_str(), ?detail, "notice");
    let _ = live.send(Routed::new(
        account_id,
        LiveEvent::notice(watch_id, kind, detail),
    ));
    if let Ok(Some(watch)) = store.get_watch(watch_id) {
        deliver_notice(http, &watch, kind.as_str()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(status: Option<&str>, period_end: Option<i64>) -> SubscriptionRow {
        SubscriptionRow {
            sub_status: status.map(str::to_string),
            sub_current_period_end: period_end,
            stripe_customer_id: None,
            plan: None,
        }
    }

    #[test]
    fn active_subscription_within_period_is_entitled() {
        let now = 1_000_000;
        assert!(subscription_active(
            &subscription(Some("active"), Some(now + 10)),
            now
        ));
    }

    #[test]
    fn active_subscription_keeps_grace_past_period_end() {
        let now = 1_000_000;
        // One day past the period end is still inside the 3-day grace.
        assert!(subscription_active(
            &subscription(Some("active"), Some(now - 86_400)),
            now
        ));
    }

    #[test]
    fn active_subscription_lapses_after_grace() {
        let now = 1_000_000;
        assert!(!subscription_active(
            &subscription(Some("active"), Some(now - SUB_GRACE_SECS - 1)),
            now
        ));
    }

    #[test]
    fn past_due_still_entitles_during_dunning() {
        let now = 1_000_000;
        assert!(subscription_active(
            &subscription(Some("past_due"), Some(now + 10)),
            now
        ));
    }

    #[test]
    fn canceled_or_unsubscribed_is_not_entitled() {
        let now = 1_000_000;
        assert!(!subscription_active(
            &subscription(Some("canceled"), Some(now + 10)),
            now
        ));
        assert!(!subscription_active(&subscription(None, None), now));
    }

    #[test]
    fn mailbox_key_normalises() {
        assert_eq!(
            mailbox_key("User@Example.ORG", "imap.x"),
            "user@example.org"
        );
        // Plus-addressing folds to the same key.
        assert_eq!(
            mailbox_key("user+carillon@example.org", "imap.x"),
            "user@example.org"
        );
        // No '@' falls back to the host as the provider.
        assert_eq!(
            mailbox_key("bareuser", "imap.example.org"),
            "bareuser@imap.example.org"
        );
    }
}
