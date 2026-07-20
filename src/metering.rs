//! Metering & entitlement — the business model made correct here, not in
//! the payment vendor (§ DECISIONS 3).
//!
//! A credit is watch-*time*, debited continuously as consumed. Every
//! tick, each active watch is charged the seconds it has been watching
//! against **two counters, drained in order**: first its per-mailbox
//! **trial** (non-refillable, granted once per normalised mailbox), then
//! its account's shared **paid pool** (refillable). When both run dry the
//! watch is paused (it stops debiting and the supervisor drops the
//! connection) — unless **auto-refill** tops the pool back up, killing the
//! silent-outage failure. Low-balance and exhaustion emit notices on the
//! live bus and as signed webhooks.
//!
//! Invariant: *credits spent = Σ(active watch × time)*. A paused watch is
//! not active, so it is never charged for idle it did not use.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::delivery::deliver_notice;
use crate::live::{LiveBus, LiveEvent, NoticeKind, Routed};
use crate::store::{Balance, Store};
use crate::supervisor::SupervisorCmd;
use crate::util::now_secs;

/// Default per-mailbox trial: a few days of watch-time, granted once.
const DEFAULT_TRIAL_SECS: f64 = 3.0 * 86_400.0;
/// How long a topped-up pool lasts (bounds deferred-revenue liability).
pub const POOL_TTL_SECS: i64 = 365 * 86_400;
/// Default low-balance warning threshold (of remaining watch-time).
const DEFAULT_LOW_BALANCE_SECS: f64 = 2.0 * 86_400.0;
/// Default metering tick.
const DEFAULT_TICK_SECS: u64 = 15;

/// The one-time trial length, overridable via `CARILLON_TRIAL_SECS`
/// (mainly to exercise draining in tests without waiting days).
pub fn trial_secs() -> f64 {
    env_f64("CARILLON_TRIAL_SECS").unwrap_or(DEFAULT_TRIAL_SECS)
}

/// The metering tick, overridable via `CARILLON_METER_TICK_SECS`.
pub fn tick() -> Duration {
    let secs = std::env::var("CARILLON_METER_TICK_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_TICK_SECS)
        .max(1);
    Duration::from_secs(secs)
}

/// The low-balance warning threshold, overridable via
/// `CARILLON_LOW_BALANCE_SECS`.
fn low_balance_secs() -> f64 {
    env_f64("CARILLON_LOW_BALANCE_SECS").unwrap_or(DEFAULT_LOW_BALANCE_SECS)
}

fn env_f64(name: &str) -> Option<f64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

/// The split of one debit across the two counters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Debit {
    /// Seconds taken from the mailbox trial.
    pub from_trial: f64,
    /// Seconds taken from the account paid pool.
    pub from_pool: f64,
    /// Seconds that could not be covered (the account is exhausted).
    pub shortfall: f64,
}

/// Splits `elapsed` seconds across the two counters, **trial first**,
/// then the pool, reporting any shortfall. Pure — this is the heart of
/// the model, and it is unit-tested in isolation.
pub fn split_debit(elapsed: f64, balance: Balance) -> Debit {
    let from_trial = elapsed.clamp(0.0, balance.trial.max(0.0));
    let remainder = elapsed - from_trial;
    let from_pool = remainder.clamp(0.0, balance.pool.max(0.0));
    let shortfall = (remainder - from_pool).max(0.0);
    Debit {
        from_trial,
        from_pool,
        shortfall,
    }
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

/// Whether the watch has any watch-time left to spend — the entitlement
/// check the supervisor makes at watch-start (the server boundary).
pub fn has_credit(store: &Store, account_id: &str, mailbox_key: &str) -> bool {
    match store.balance(account_id, mailbox_key, now_secs()) {
        Ok(balance) => balance.available() > 0.0,
        // Fail open on a store error rather than silently stop watching.
        Err(_) => true,
    }
}

/// Runs the metering loop until cancelled: every `tick`, debit each active
/// watch and act on the result (pause, auto-refill, warn).
pub async fn run(
    store: Arc<Store>,
    live: LiveBus,
    http: reqwest::Client,
    commands: mpsc::Sender<SupervisorCmd>,
    tick: Duration,
) {
    let max_debit = (tick.as_secs_f64() * 2.0).max(1.0);
    let low_balance = low_balance_secs();
    // Watches already warned this low-balance episode, so the warning
    // fires once per crossing, not every tick.
    let mut warned: HashSet<String> = HashSet::new();

    let mut ticker = interval(tick);
    ticker.tick().await; // consume the immediate first tick

    info!(
        tick_secs = tick.as_secs(),
        low_balance_secs = low_balance,
        "metering started"
    );

    loop {
        ticker.tick().await;

        let rows = match store.meter_rows() {
            Ok(rows) => rows,
            Err(err) => {
                warn!(error = %err, "metering: cannot read watches");
                continue;
            }
        };

        let now = now_secs();
        for row in rows {
            let key = mailbox_key(&row.login, &row.imap_host);

            // First time we see the watch: stamp the clock, do not charge
            // for time before we were watching.
            let Some(last) = row.last_metered else {
                let _ = store.mark_metered(&row.watch_id, now);
                continue;
            };

            let elapsed = ((now - last) as f64).clamp(0.0, max_debit);
            if elapsed <= 0.0 {
                let _ = store.mark_metered(&row.watch_id, now);
                continue;
            }

            let balance = match store.balance(&row.account_id, &key, now) {
                Ok(balance) => balance,
                Err(err) => {
                    warn!(watch = %row.watch_id, error = %err, "metering: balance read failed");
                    continue;
                }
            };
            let debit = split_debit(elapsed, balance);
            let _ = store.apply_debit(
                &row.watch_id,
                &row.account_id,
                &key,
                debit.from_trial,
                debit.from_pool,
                now,
            );
            debug!(
                watch = %row.watch_id,
                elapsed,
                from_trial = debit.from_trial,
                from_pool = debit.from_pool,
                "metered",
            );

            // Read the account back to decide on refill/exhaustion. The
            // proactive top-up only fires once the pool is actually in use
            // and running low (`paid_secs > 0`), never while the trial is
            // still covering the watch.
            let account = store.get_account(&row.account_id).ok().flatten();
            let below_threshold = account.as_ref().is_some_and(|a| {
                a.auto_refill && a.paid_secs > 0.0 && a.paid_secs < a.auto_refill_threshold
            });

            if debit.shortfall > 0.0 || below_threshold {
                if let Some(account) = &account
                    && account.auto_refill
                    && account.auto_refill_amount > 0.0
                {
                    let _ = store.add_credit(
                        &row.account_id,
                        account.auto_refill_amount,
                        now + POOL_TTL_SECS,
                    );
                    warned.remove(&row.watch_id);
                    emit_notice(
                        &store,
                        &live,
                        &http,
                        &row.account_id,
                        &row.watch_id,
                        NoticeKind::AutoRefilled,
                        Some(format!("+{:.0}s", account.auto_refill_amount)),
                    )
                    .await;
                    continue;
                }

                if debit.shortfall > 0.0 {
                    let _ = store.exhaust_watch(&row.watch_id);
                    warned.remove(&row.watch_id);
                    emit_notice(
                        &store,
                        &live,
                        &http,
                        &row.account_id,
                        &row.watch_id,
                        NoticeKind::CreditExhausted,
                        None,
                    )
                    .await;
                    // Drop the connection promptly rather than waiting for
                    // the next periodic reconcile.
                    let _ = commands.send(SupervisorCmd::Reconcile).await;
                    continue;
                }
            }

            // Low-balance warning, once per crossing.
            let remaining = (balance.available() - debit.from_trial - debit.from_pool).max(0.0);
            if remaining <= low_balance {
                if warned.insert(row.watch_id.clone()) {
                    emit_notice(
                        &store,
                        &live,
                        &http,
                        &row.account_id,
                        &row.watch_id,
                        NoticeKind::LowBalance,
                        Some(format!("{remaining:.0}s left")),
                    )
                    .await;
                }
            } else {
                warned.remove(&row.watch_id);
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

    fn balance(trial: f64, pool: f64) -> Balance {
        Balance { trial, pool }
    }

    #[test]
    fn trial_is_drained_before_the_pool() {
        let debit = split_debit(10.0, balance(30.0, 100.0));
        assert_eq!(debit.from_trial, 10.0);
        assert_eq!(debit.from_pool, 0.0);
        assert_eq!(debit.shortfall, 0.0);
    }

    #[test]
    fn overflow_spills_from_trial_into_pool() {
        let debit = split_debit(50.0, balance(30.0, 100.0));
        assert_eq!(debit.from_trial, 30.0);
        assert_eq!(debit.from_pool, 20.0);
        assert_eq!(debit.shortfall, 0.0);
    }

    #[test]
    fn exhaustion_is_reported_as_shortfall() {
        let debit = split_debit(50.0, balance(10.0, 5.0));
        assert_eq!(debit.from_trial, 10.0);
        assert_eq!(debit.from_pool, 5.0);
        assert_eq!(debit.shortfall, 35.0);
    }

    #[test]
    fn empty_balance_is_all_shortfall() {
        let debit = split_debit(15.0, balance(0.0, 0.0));
        assert_eq!(debit.from_trial, 0.0);
        assert_eq!(debit.from_pool, 0.0);
        assert_eq!(debit.shortfall, 15.0);
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
