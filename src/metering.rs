//! Entitlement & renewal: the business model made correct here, not in
//! the payment vendor (§ BILLING_MODEL).
//!
//! A service (watch) runs while its PIM account (mailbox membership) is
//! watching-paid: `watching_until` is in the future. Activation spends
//! one credit to set that a month ahead; the pool is the account's
//! prepaid balance. Each tick, a light [`run`] sweep, in declaration
//! order:
//!
//! - warns once when a paid month is about to end (pre-expiry), and
//! - at expiry either auto-renews (draws the next credit from the pool,
//!   if the PIM account opted in and the pool is non-empty) or stops the
//!   PIM account's watches, emitting a notice on the live bus and, per
//!   watch, as a signed webhook so a no-dashboard user is never silently
//!   cut off.
//!
//! Metering is a SaaS concern: with the keyless stub provider the whole
//! sweep is disabled and every watch is entitled, since self-host is not
//! billed.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::delivery::deliver_notice;
use crate::email::Mailer;
use crate::live::{LiveBus, LiveEvent, NoticeKind, Routed};
use crate::store::{Store, Watch};
use crate::supervisor::SupervisorCmd;
use crate::util::now_secs;

/// One watch-month: what a credit buys. Overridable via
/// `CARILLON_MONTH_SECS` (to exercise expiry/renewal in tests).
const DEFAULT_MONTH_SECS: i64 = 30 * 86_400;
/// Default pre-expiry "watch ending soon" warning lead time.
const DEFAULT_WARN_BEFORE_SECS: i64 = 3 * 86_400;
/// Default low-pool warning threshold (credits remaining).
const DEFAULT_LOW_POOL_CREDITS: i64 = 2;
/// Default renewal-sweep interval.
const DEFAULT_TICK_SECS: u64 = 60;

/// Credits granted to a Carillon account on creation: the one free
/// credit (§ BILLING_MODEL), granted once per account, gated on a
/// validated PIM account.
pub const FREE_CREDITS_ON_SIGNUP: i64 = 1;

/// The free-trial head start (§ SERVICE_MODEL v3): a newly-created
/// service auto-watches this long for free (no credit spent), granted
/// once per mailbox. Time-on-the-service can't be farmed, since a
/// leaked/farmed trial only watches a mailbox the farmer controls.
const DEFAULT_FREE_TRIAL_SECS: i64 = 7 * 86_400;

/// The free-trial length in seconds, overridable via
/// `CARILLON_FREE_TRIAL_SECS` (to exercise trial expiry in tests).
pub fn free_trial_secs() -> i64 {
    env_i64("CARILLON_FREE_TRIAL_SECS")
        .unwrap_or(DEFAULT_FREE_TRIAL_SECS)
        .max(1)
}

/// One watch-month in seconds (what one credit buys), env-overridable.
pub fn month_secs() -> i64 {
    env_i64("CARILLON_MONTH_SECS")
        .unwrap_or(DEFAULT_MONTH_SECS)
        .max(1)
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

/// The pre-expiry warning lead time, overridable via `CARILLON_WARN_BEFORE_SECS`.
fn warn_before_secs() -> i64 {
    env_i64("CARILLON_WARN_BEFORE_SECS").unwrap_or(DEFAULT_WARN_BEFORE_SECS)
}

/// The low-pool warning threshold, overridable via `CARILLON_LOW_POOL_CREDITS`.
fn low_pool_credits() -> i64 {
    env_i64("CARILLON_LOW_POOL_CREDITS").unwrap_or(DEFAULT_LOW_POOL_CREDITS)
}

fn env_i64(name: &str) -> Option<i64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

/// The normalised anti-farming key for a mailbox: lowercased,
/// plus-addressing stripped, keyed on `(local, provider)`. Two logins
/// that reach the same inbox share one PIM account, so a free credit
/// cannot be farmed with aliases.
pub fn mailbox_key(login: &str, imap_host: &str) -> String {
    let login = login.trim().to_ascii_lowercase();
    let (local, domain) = match login.split_once('@') {
        Some((local, domain)) => (local.to_string(), domain.to_string()),
        None => (login.clone(), imap_host.trim().to_ascii_lowercase()),
    };
    // NOTE: strip plus-addressing (`user+tag` -> `user`).
    let local = local.split('+').next().unwrap_or(&local).to_string();
    format!("{local}@{domain}")
}

/// The provider domain a service is grouped and trial-gated by: the
/// registrable domain (the last two dot-labels, a pragmatic eTLD+1) of
/// the server host. So an account's IMAP and CardDAV hosts collapse to
/// one provider. The one free trial is per `(Carillon account,
/// provider)`.
pub fn provider_domain(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    match labels.as_slice() {
        [.., second, last] => format!("{second}.{last}"),
        _ => host,
    }
}

/// Whether a service is currently watching-paid: `watching_until` in the
/// future.
pub fn pim_entitled(watching_until: Option<i64>, now: i64) -> bool {
    matches!(watching_until, Some(until) if now < until)
}

/// The entitlement check the supervisor makes when reconciling (the
/// server boundary): is this service's paid month still in the future?
pub fn watch_entitled(watch: &Watch, now: i64) -> bool {
    pim_entitled(watch.watching_until, now)
}

/// Runs the renewal sweep until cancelled. Disabled (returns
/// immediately) when `metered` is false, since self-host with the stub
/// provider is not billed.
pub async fn run(
    store: Arc<Store>,
    live: LiveBus,
    http: reqwest::Client,
    mailer: Arc<Mailer>,
    commands: mpsc::Sender<SupervisorCmd>,
    tick: Duration,
    metered: bool,
) {
    if !metered {
        info!("renewal sweep disabled (unmetered, stub billing / self-host)");
        return;
    }

    let month = month_secs();
    let warn_before = warn_before_secs();
    let low_pool = low_pool_credits();
    // NOTE: keyed by watch id, warned once per crossing so a warning
    // fires on the crossing, not each tick.
    let mut ending_warned: HashSet<String> = HashSet::new();
    let mut stopped_notified: HashSet<String> = HashSet::new();
    let mut low_pool_warned: HashSet<String> = HashSet::new();

    let mut ticker = interval(tick);
    // NOTE: consume the immediate first tick.
    ticker.tick().await;

    info!(
        tick_secs = tick.as_secs(),
        month_secs = month,
        warn_before_secs = warn_before,
        low_pool_credits = low_pool,
        "renewal sweep started"
    );

    loop {
        ticker.tick().await;
        if let Err(err) = sweep(
            &store,
            &live,
            &http,
            &mailer,
            &commands,
            now_secs(),
            month,
            warn_before,
            low_pool,
            &mut ending_warned,
            &mut stopped_notified,
            &mut low_pool_warned,
        )
        .await
        {
            warn!(error = %err, "renewal sweep tick failed");
        }
    }
}

/// One sweep pass, factored out so a store error aborts the tick, not
/// the loop. Iterates active services in declaration order; earlier
/// services win the shared pool when it cannot cover every auto-renew at
/// once.
#[allow(clippy::too_many_arguments)]
async fn sweep(
    store: &Store,
    live: &LiveBus,
    http: &reqwest::Client,
    mailer: &Mailer,
    commands: &mpsc::Sender<SupervisorCmd>,
    now: i64,
    month: i64,
    warn_before: i64,
    low_pool: i64,
    ending_warned: &mut HashSet<String>,
    stopped_notified: &mut HashSet<String>,
    low_pool_warned: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let watches = store.active_watches()?;

    let mut reconcile = false;
    // NOTE: accounts with an active auto-renew service, for the low-pool
    // check.
    let mut auto_renew_accounts: HashSet<String> = HashSet::new();
    let mut accounts: HashSet<String> = HashSet::new();

    for watch in &watches {
        accounts.insert(watch.account_id.clone());
        if watch.auto_renew {
            auto_renew_accounts.insert(watch.account_id.clone());
        }
        let Some(until) = watch.watching_until else {
            // NOTE: never activated, nothing to expire.
            continue;
        };

        if now < until {
            // NOTE: still watching; warn once as it nears expiry, and
            // clear any prior stop bookkeeping (it is paid again).
            stopped_notified.remove(&watch.id);
            if until - now <= warn_before {
                if ending_warned.insert(watch.id.clone()) {
                    let days = ((until - now) as f64 / 86_400.0).ceil().max(0.0) as i64;
                    emit_watch_notice(
                        store,
                        live,
                        http,
                        &watch.account_id,
                        &watch.id,
                        NoticeKind::WatchEnding,
                        Some(format!("{days}d left")),
                    )
                    .await;
                }
            } else {
                ending_warned.remove(&watch.id);
            }
            continue;
        }

        // NOTE: expired; renew from the pool (if opted in and non-empty)
        // else notify the stop once, and the reconcile below drops its
        // connection.
        ending_warned.remove(&watch.id);
        if watch.auto_renew && store.debit_credit(&watch.account_id)? {
            store.set_watch_watching_until(&watch.id, now + month)?;
            stopped_notified.remove(&watch.id);
            info!(account = %watch.account_id, watch = %watch.id, "auto-renewed");
            continue;
        }

        reconcile = true;
        if stopped_notified.insert(watch.id.clone()) {
            emit_watch_notice(
                store,
                live,
                http,
                &watch.account_id,
                &watch.id,
                NoticeKind::WatchStopped,
                None,
            )
            .await;
            email_account(
                mailer,
                store,
                &watch.account_id,
                "Carillon: a watch stopped",
                &format!(
                    "Watching {} stopped — its month ended and there were no \
                     credits to renew it. Buy credits and re-activate it to resume.",
                    mailbox_key(&watch.login, &watch.imap_host)
                ),
            )
            .await;
        }
    }

    // NOTE: low-pool warning for an account with an active auto-renew
    // service and a pool running low, once per crossing.
    for account_id in &accounts {
        let credits = store
            .get_account(account_id)?
            .map(|account| account.credits)
            .unwrap_or(0);
        let low = auto_renew_accounts.contains(account_id) && credits > 0 && credits <= low_pool;
        if low {
            if low_pool_warned.insert(account_id.clone()) {
                info!(account = %account_id, credits, "low pool");
                let _ = live.send(Routed::new(
                    account_id.clone(),
                    LiveEvent::notice(
                        account_id,
                        NoticeKind::LowPool,
                        Some(format!("{credits} left")),
                    ),
                ));
                email_account(
                    mailer,
                    store,
                    account_id,
                    "Carillon: credits running low",
                    &format!(
                        "Your credit pool is down to {credits}. Top it up so your \
                         auto-renewing services don't stop when it empties."
                    ),
                )
                .await;
            }
        } else {
            low_pool_warned.remove(account_id);
        }
    }

    if reconcile {
        let _ = commands.send(SupervisorCmd::Reconcile).await;
    }
    debug!(services = watches.len(), "sweep done");
    Ok(())
}

/// Publishes a per-watch notice on the live bus (dashboard) and as a
/// signed webhook (so a no-dashboard user is not silently cut off).
async fn emit_watch_notice(
    store: &Store,
    live: &LiveBus,
    http: &reqwest::Client,
    account_id: &str,
    watch_id: &str,
    kind: NoticeKind,
    detail: Option<String>,
) {
    info!(watch = %watch_id, notice = kind.as_str(), ?detail, "notice");
    let _ = live.send(Routed::new(
        account_id,
        LiveEvent::notice(watch_id, kind, detail),
    ));
    if let Ok(Some(watch)) = store.get_watch(watch_id) {
        deliver_notice(http, &watch, kind.as_str()).await;
    }
}

/// Emails an account-level notice to the account's magic-link address,
/// if it has one (a self-host / anonymous account has none and relies on
/// the per-watch webhook). Best-effort: a send failure is logged, not
/// fatal.
async fn email_account(
    mailer: &Mailer,
    store: &Store,
    account_id: &str,
    subject: &str,
    body: &str,
) {
    let email = store
        .get_account(account_id)
        .ok()
        .flatten()
        .and_then(|account| account.email);
    if let Some(email) = email
        && let Err(err) = mailer.send_notice(&email, subject, body).await
    {
        warn!(account = %account_id, error = %err, "notice email failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pim_entitled_tracks_watching_until() {
        let now = 1_000_000;
        assert!(pim_entitled(Some(now + 10), now));
        assert!(!pim_entitled(Some(now - 10), now));
        assert!(!pim_entitled(None, now));
    }

    #[test]
    fn provider_domain_is_the_registrable_domain() {
        // An account's mail and contacts hosts collapse to one provider.
        assert_eq!(provider_domain("imap.fastmail.com"), "fastmail.com");
        assert_eq!(provider_domain("carddav.fastmail.com"), "fastmail.com");
        assert_eq!(provider_domain("IMAP.GMail.com"), "gmail.com");
        // Already a bare registrable domain, a trailing dot, and a bare host.
        assert_eq!(provider_domain("fastmail.com"), "fastmail.com");
        assert_eq!(provider_domain("carddav.fastmail.com."), "fastmail.com");
        assert_eq!(provider_domain("localhost"), "localhost");
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
