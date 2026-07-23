//! The watcher supervisor.
//!
//! Owns one tokio task per active watch, each running an independent
//! connect → watch → reconnect loop. Reconciles the running set against
//! the store on boot, on API-triggered commands, and on a periodic
//! timer. A shared semaphore caps simultaneous TLS handshakes so a
//! restart does not fire a reconnect storm or trip per-IP provider
//! limits.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::Context;
use io_imap::types::mailbox::Mailbox;
use io_imap::types::response::Capability;
use io_imap::watch::ImapMailboxWatch;
use rand::RngExt;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval, sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::carddav::pump as carddav_pump;
use crate::carddav::session::{CardDavAccount, CardDavAuth};
use crate::crypto::Crypto;
use crate::event::ChangeEvent;
use crate::imap::pump;
use crate::imap::session::{self, ImapAccount, ImapAuth};
use crate::live::{LiveBus, LiveEvent, Routed, WatchState};
use crate::metering;
use crate::oauth;
use crate::store::{Store, Watch};
use crate::util::now_secs;

/// How a watcher authenticates each time it connects. A password is
/// constant; OAuth mints a fresh access token from the stored refresh
/// token on every connect.
enum Credential {
    Password(String),
    Oauth,
}

/// Bound on the whole TCP + TLS + greeting + login handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Reconnect backoff floor.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
/// Reconnect backoff ceiling.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// A connection that lived at least this long is considered healthy;
/// its next reconnect resets the backoff.
const HEALTHY_THRESHOLD: Duration = Duration::from_secs(60);

/// A command to the running supervisor.
pub enum SupervisorCmd {
    /// Re-read the store and reconcile running watchers.
    Reconcile,
    /// Stop every watcher and exit the loop.
    Shutdown,
}

struct WatcherHandle {
    shutdown: Arc<AtomicBool>,
    fingerprint: u64,
    /// The watch's billing account, so a stop/shutdown status event can
    /// be tagged for scoped SSE fan-out without re-reading the store.
    account_id: String,
    task: JoinHandle<()>,
}

/// The supervisor. Built with [`Supervisor::new`], consumed by
/// [`Supervisor::run`].
pub struct Supervisor {
    store: Arc<Store>,
    crypto: Arc<Crypto>,
    connector: TlsConnector,
    events: mpsc::Sender<ChangeEvent>,
    handshake_sem: Arc<Semaphore>,
    handles: HashMap<String, WatcherHandle>,
    live: LiveBus,
    /// Whether watching is credit-metered (SaaS, Stripe). When false the
    /// entitlement gate is bypassed, since self-host is not billed.
    metered: bool,
    /// Default poll interval (seconds) for CardDAV services that do not
    /// override it. IMAP services ignore it (they hold IDLE).
    carddav_poll_secs: u64,
}

impl Supervisor {
    /// Creates a supervisor. `max_handshakes` caps simultaneous TLS
    /// handshakes across all watchers. `metered` gates watches on the
    /// credit pool; unmetered self-host runs every active watch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store>,
        crypto: Arc<Crypto>,
        connector: TlsConnector,
        events: mpsc::Sender<ChangeEvent>,
        max_handshakes: usize,
        live: LiveBus,
        metered: bool,
        carddav_poll_secs: u64,
    ) -> Self {
        Self {
            store,
            crypto,
            connector,
            events,
            handshake_sem: Arc::new(Semaphore::new(max_handshakes.max(1))),
            handles: HashMap::new(),
            live,
            metered,
            carddav_poll_secs: carddav_poll_secs.max(5),
        }
    }

    /// Runs until a [`SupervisorCmd::Shutdown`] (or the command channel
    /// closes): reconciles on boot, on each command, and every
    /// `reconcile_interval` as a safety net.
    pub async fn run(
        mut self,
        mut commands: mpsc::Receiver<SupervisorCmd>,
        reconcile_interval: Duration,
    ) {
        self.reconcile().await;

        let mut ticker = interval(reconcile_interval);
        // NOTE: consume the immediate first tick.
        ticker.tick().await;

        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(SupervisorCmd::Reconcile) => self.reconcile().await,
                    Some(SupervisorCmd::Shutdown) | None => break,
                },
                _ = ticker.tick() => self.reconcile().await,
            }
        }

        self.stop_all();
    }

    /// Brings the running watcher set in line with the active watches
    /// in the store.
    async fn reconcile(&mut self) {
        let watches = match self.store.active_watches() {
            Ok(watches) => watches,
            Err(err) => {
                error!(error = %err, "reconcile: cannot read watches");
                return;
            }
        };

        // NOTE: desired = active watches also entitled (paid) when
        // metered. Filtering here (not just at spawn) makes the gate
        // continuous: a lapsed service drops out and is stopped below;
        // re-activating it brings it back on the next reconcile.
        let now = now_secs();
        let metered = self.metered;
        let desired: HashMap<String, Watch> = watches
            .into_iter()
            .filter(|watch| !metered || metering::watch_entitled(watch, now))
            .map(|watch| (watch.id.clone(), watch))
            .collect();

        // NOTE: stop watchers that vanished or whose connection
        // parameters changed.
        let stale: Vec<String> = self
            .handles
            .iter()
            .filter(|(id, handle)| match desired.get(*id) {
                None => true,
                Some(watch) => fingerprint(watch) != handle.fingerprint,
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in stale {
            if let Some(handle) = self.handles.remove(&id) {
                debug!(watch = %id, "stopping watcher");
                let account_id = handle.account_id.clone();
                stop(handle);
                let _ = self.live.send(Routed::new(
                    account_id,
                    LiveEvent::status(&id, WatchState::Stopped, None),
                ));
            }
        }

        for (id, watch) in &desired {
            if self.handles.contains_key(id) {
                continue;
            }
            match self.spawn_watcher(watch) {
                Ok(handle) => {
                    self.handles.insert(id.clone(), handle);
                }
                Err(err) => warn!(watch = %id, error = %err, "cannot start watcher"),
            }
        }

        info!(watchers = self.handles.len(), "reconciled");
    }

    fn spawn_watcher(&self, watch: &Watch) -> anyhow::Result<WatcherHandle> {
        // NOTE: entitlement (the paid-month gate) is enforced in
        // `reconcile`, which only ever hands `spawn_watcher` an entitled
        // service when metered.

        // NOTE: an OAuth watch defers to the stored `oauth_credential`,
        // minting a fresh access token per connect. A password is
        // decrypted once from the watch itself (self-host / import) or,
        // when the watch carries none, from the PIM account's stored
        // password credential, so a re-auth is picked up on reconnect.
        let credential = if watch.auth_kind == "oauth" {
            Credential::Oauth
        } else {
            let enc = if watch.enc_password.is_empty() {
                let mailbox_key = metering::mailbox_key(&watch.login, &watch.imap_host);
                self.store
                    .get_password_credential(&watch.account_id, &mailbox_key)?
                    .ok_or_else(|| anyhow::anyhow!("no password credential for the PIM account"))?
            } else {
                watch.enc_password.clone()
            };
            Credential::Password(self.crypto.decrypt(&enc)?)
        };

        let id = watch.id.clone();
        let account_id = watch.account_id.clone();
        let fingerprint = fingerprint(watch);
        let shutdown = Arc::new(AtomicBool::new(false));

        let connector = self.connector.clone();
        let events = self.events.clone();
        let handshake_sem = self.handshake_sem.clone();
        let shutdown_flag = shutdown.clone();
        let live = self.live.clone();
        let loop_account = account_id.clone();
        let store = self.store.clone();
        let crypto = self.crypto.clone();

        // NOTE: a CardDAV service is polled (no held IDLE); everything
        // else is IMAP.
        let task = if watch.source_kind == "carddav" {
            let url = watch
                .carddav_url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("carddav watch has no collection URL"))?;
            let poll = watch
                .carddav_poll_secs
                .map(|s| s.max(5) as u64)
                .unwrap_or(self.carddav_poll_secs);
            let login = watch.login.clone();
            let imap_host = watch.imap_host.clone();
            let imap_port = watch.imap_port;
            let initial_token = watch.carddav_sync_token.clone();
            tokio::spawn(async move {
                carddav_watch_loop(CardDavLoop {
                    id,
                    account_id: loop_account,
                    url,
                    login,
                    imap_host,
                    imap_port,
                    initial_token,
                    poll_secs: poll,
                    credential,
                    connector,
                    events,
                    handshake_sem,
                    shutdown: shutdown_flag,
                    live,
                    store,
                    crypto,
                })
                .await;
            })
        } else {
            let account = ImapAccount {
                host: watch.imap_host.clone(),
                port: watch.imap_port,
                login: watch.login.clone(),
                auth: ImapAuth::Password(String::new()),
                mailbox: watch.mailbox.clone(),
            };
            tokio::spawn(async move {
                watch_loop(WatchLoop {
                    id,
                    account_id: loop_account,
                    account,
                    credential,
                    connector,
                    events,
                    handshake_sem,
                    shutdown: shutdown_flag,
                    live,
                    store,
                    crypto,
                })
                .await;
            })
        };

        Ok(WatcherHandle {
            shutdown,
            fingerprint,
            account_id,
            task,
        })
    }

    fn stop_all(&mut self) {
        for (id, handle) in self.handles.drain() {
            let account_id = handle.account_id.clone();
            stop(handle);
            let _ = self.live.send(Routed::new(
                account_id,
                LiveEvent::status(&id, WatchState::Stopped, None),
            ));
        }
    }
}

fn stop(handle: WatcherHandle) {
    handle.shutdown.store(true, Ordering::SeqCst);
    handle.task.abort();
}

/// Fingerprint of the connection-relevant fields. Notify URL and HMAC
/// secret are excluded on purpose: the delivery side re-reads them, so
/// changing a webhook must not drop the connection.
fn fingerprint(watch: &Watch) -> u64 {
    let mut hasher = DefaultHasher::new();
    watch.source_kind.hash(&mut hasher);
    watch.imap_host.hash(&mut hasher);
    watch.imap_port.hash(&mut hasher);
    watch.login.hash(&mut hasher);
    watch.enc_password.hash(&mut hasher);
    watch.auth_kind.hash(&mut hasher);
    watch.mailbox.hash(&mut hasher);
    // NOTE: a CardDAV re-point or poll-rate change restarts the poller;
    // the sync-token is runtime state, deliberately not fingerprinted.
    watch.carddav_url.hash(&mut hasher);
    watch.carddav_poll_secs.hash(&mut hasher);
    hasher.finish()
}

/// Everything one watcher task needs, bundled into a struct to keep the
/// spawn site readable (and satisfy `clippy::too_many_arguments`).
struct WatchLoop {
    id: String,
    /// The billing account (for tagging live status events).
    account_id: String,
    /// Connection params; `auth` is a placeholder set before each
    /// connect.
    account: ImapAccount,
    credential: Credential,
    connector: TlsConnector,
    events: mpsc::Sender<ChangeEvent>,
    handshake_sem: Arc<Semaphore>,
    shutdown: Arc<AtomicBool>,
    live: LiveBus,
    store: Arc<Store>,
    crypto: Arc<Crypto>,
}

/// One watch's connect → watch → reconnect loop. Stopped by aborting the
/// task; the shutdown flag lets the watcher coroutine wind down cleanly
/// if resumed.
async fn watch_loop(ctx: WatchLoop) {
    let WatchLoop {
        id,
        account_id,
        mut account,
        credential,
        connector,
        events,
        handshake_sem,
        shutdown,
        live,
        store,
        crypto,
    } = ctx;

    // NOTE: tag every status change with the watch's billing account so
    // the SSE stream can scope it to the right subscriber.
    let status =
        |state, detail| Routed::new(account_id.clone(), LiveEvent::status(&id, state, detail));

    let mailbox: Mailbox<'static> = match Mailbox::try_from(account.mailbox.clone()) {
        Ok(mailbox) => mailbox,
        Err(_) => {
            error!(watch = %id, mailbox = %account.mailbox, "invalid mailbox name");
            let _ = live.send(status(
                WatchState::Error,
                Some("invalid mailbox name".into()),
            ));
            return;
        }
    };

    let mut backoff = INITIAL_BACKOFF;

    while !shutdown.load(Ordering::SeqCst) {
        // NOTE: a password is constant; OAuth mints a fresh access token
        // from the stored refresh token. A refresh failure is transient,
        // so surface it and back off like a connect failure.
        account.auth = match &credential {
            Credential::Password(password) => ImapAuth::Password(password.clone()),
            Credential::Oauth => {
                match resolve_oauth_access(&store, &crypto, &account_id, &account).await {
                    Ok(token) => ImapAuth::OauthBearer(token),
                    Err(err) => {
                        warn!(watch = %id, error = %err, "oauth token refresh failed");
                        let _ =
                            live.send(status(WatchState::Error, Some(format!("oauth: {err:#}"))));
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        let _ = live.send(status(WatchState::Reconnecting, None));
                        sleep(backoff + jitter(backoff)).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                }
            }
        };

        // NOTE: throttle simultaneous handshakes across all watchers.
        let permit = handshake_sem
            .clone()
            .acquire_owned()
            .await
            .expect("handshake semaphore never closes");
        let started = Instant::now();
        let connected = timeout(CONNECT_TIMEOUT, session::connect(&connector, &account)).await;
        drop(permit);

        match connected {
            Ok(Ok(mut session)) => {
                // NOTE: full QRESYNC deltas where supported, else the
                // IDLE-only new-mail watcher (Gmail, Yahoo, …).
                let has_qresync = session.capabilities.contains(&Capability::QResync);
                info!(
                    watch = %id,
                    host = %account.host,
                    mailbox = %account.mailbox,
                    qresync = has_qresync,
                    "watching",
                );
                let _ = live.send(status(WatchState::Watching, None));

                let outcome = if has_qresync {
                    match ImapMailboxWatch::new(
                        &session.capabilities,
                        mailbox.clone(),
                        shutdown.clone(),
                    ) {
                        Ok(watcher) => {
                            pump::run_watch(
                                &id,
                                &mut session.stream,
                                &mut session.fragmentizer,
                                watcher,
                                &events,
                            )
                            .await
                        }
                        Err(err) => {
                            error!(watch = %id, error = %err, "watcher cannot start; giving up");
                            let _ = live.send(status(WatchState::Error, Some(err.to_string())));
                            return;
                        }
                    }
                } else {
                    pump::run_watch_idle(
                        &id,
                        &mut session.stream,
                        &mut session.fragmentizer,
                        mailbox.clone(),
                        shutdown.clone(),
                        &events,
                    )
                    .await
                };

                match outcome {
                    Ok(()) => debug!(watch = %id, "session ended; reconnecting"),
                    Err(err) => warn!(watch = %id, error = %err, "session lost; reconnecting"),
                }
            }
            Ok(Err(err)) => {
                warn!(watch = %id, error = %err, "connect failed");
                let _ = live.send(status(WatchState::Error, Some(format!("{err:#}"))));
            }
            Err(_elapsed) => {
                warn!(watch = %id, "connect timed out");
                let _ = live.send(status(WatchState::Error, Some("connect timed out".into())));
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // NOTE: a connection that lasted resets the backoff; a flapping
        // one keeps growing it.
        if started.elapsed() >= HEALTHY_THRESHOLD {
            backoff = INITIAL_BACKOFF;
        }

        let _ = live.send(status(WatchState::Reconnecting, None));
        let wait = backoff + jitter(backoff);
        debug!(watch = %id, wait_ms = wait.as_millis() as u64, "backing off before reconnect");
        sleep(wait).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    debug!(watch = %id, "watch loop exited");
}

/// Everything one CardDAV poller task needs.
struct CardDavLoop {
    id: String,
    /// The billing account (for tagging live status events).
    account_id: String,
    /// The collection URL to poll.
    url: String,
    /// PIM-account login (HTTP Basic username / OAuth identity).
    login: String,
    /// PIM-account host + port: the identity the stored credential and
    /// any OAuth token are keyed by (the CardDAV host lives in `url`).
    imap_host: String,
    imap_port: u16,
    /// Last checkpoint token loaded from the store (`None` never synced).
    initial_token: Option<String>,
    /// Poll interval in seconds.
    poll_secs: u64,
    credential: Credential,
    connector: TlsConnector,
    events: mpsc::Sender<ChangeEvent>,
    handshake_sem: Arc<Semaphore>,
    shutdown: Arc<AtomicBool>,
    live: LiveBus,
    store: Arc<Store>,
    crypto: Arc<Crypto>,
}

/// One CardDAV service's poll loop: resolve the credential, run a
/// `sync-collection` round, checkpoint the returned token, sleep, repeat.
/// Transport failures back off like the IMAP reconnect loop. Stopped by
/// aborting the task; the shutdown flag lets a between-polls wait exit
/// promptly.
async fn carddav_watch_loop(ctx: CardDavLoop) {
    let CardDavLoop {
        id,
        account_id,
        url,
        login,
        imap_host,
        imap_port,
        initial_token,
        poll_secs,
        credential,
        connector,
        events,
        handshake_sem,
        shutdown,
        live,
        store,
        crypto,
    } = ctx;

    let status =
        |state, detail| Routed::new(account_id.clone(), LiveEvent::status(&id, state, detail));
    let interval = Duration::from_secs(poll_secs);
    let mut token = initial_token;
    let mut backoff = INITIAL_BACKOFF;
    let mut announced = false;

    while !shutdown.load(Ordering::SeqCst) {
        // NOTE: a password is constant; OAuth mints a fresh bearer token
        // keyed by the PIM identity (not the CardDAV host).
        let auth = match &credential {
            Credential::Password(password) => CardDavAuth::Password(password.clone()),
            Credential::Oauth => {
                let identity = ImapAccount {
                    host: imap_host.clone(),
                    port: imap_port,
                    login: login.clone(),
                    auth: ImapAuth::Password(String::new()),
                    mailbox: String::new(),
                };
                match resolve_oauth_access(&store, &crypto, &account_id, &identity).await {
                    Ok(token) => CardDavAuth::Bearer(token),
                    Err(err) => {
                        warn!(watch = %id, error = %err, "carddav oauth token refresh failed");
                        let _ =
                            live.send(status(WatchState::Error, Some(format!("oauth: {err:#}"))));
                        announced = false;
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        let _ = live.send(status(WatchState::Reconnecting, None));
                        sleep(backoff + jitter(backoff)).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                }
            }
        };
        let account = CardDavAccount {
            url: url.clone(),
            login: login.clone(),
            auth,
        };

        match carddav_pump::poll_once(
            &connector,
            &account,
            &id,
            token.clone(),
            &events,
            &handshake_sem,
        )
        .await
        {
            Ok(new_token) => {
                if !announced {
                    info!(watch = %id, url = %url, "watching (carddav)");
                    let _ = live.send(status(WatchState::Watching, None));
                    announced = true;
                }
                backoff = INITIAL_BACKOFF;
                if new_token != token {
                    token = new_token.clone();
                    let store = store.clone();
                    let (wid, checkpoint) = (id.clone(), new_token.clone());
                    let _ = tokio::task::spawn_blocking(move || {
                        store.set_carddav_sync_token(&wid, checkpoint.as_deref())
                    })
                    .await;
                }
                sleep_interruptible(interval, &shutdown).await;
            }
            Err(err) => {
                warn!(watch = %id, error = %err, "carddav poll failed");
                let _ = live.send(status(WatchState::Error, Some(format!("{err:#}"))));
                announced = false;
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let _ = live.send(status(WatchState::Reconnecting, None));
                sleep(backoff + jitter(backoff)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    debug!(watch = %id, "carddav watch loop exited");
}

/// Sleeps for `dur`, returning within ~a second once shutdown is
/// requested so a stopped poller does not linger a whole interval before
/// its task is torn down.
async fn sleep_interruptible(dur: Duration, shutdown: &Arc<AtomicBool>) {
    let step = Duration::from_secs(1);
    let mut left = dur;
    while left > Duration::ZERO {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let chunk = left.min(step);
        sleep(chunk).await;
        left = left.saturating_sub(chunk);
    }
}

fn jitter(base: Duration) -> Duration {
    let max = (base.as_millis() as u64 / 2).max(1);
    Duration::from_millis(rand::rng().random_range(0..=max))
}

/// Mints a fresh OAuth access token for a watch: loads its stored
/// credential, decrypts the refresh token, refreshes (blocking io-oauth
/// in `spawn_blocking`), and persists the refresh token if the provider
/// rotated it. Returns the access token (`OAUTHBEARER`).
pub(crate) async fn resolve_oauth_access(
    store: &Arc<Store>,
    crypto: &Arc<Crypto>,
    account_id: &str,
    account: &ImapAccount,
) -> anyhow::Result<String> {
    let mailbox_key = metering::mailbox_key(&account.login, &account.host);

    let cred = {
        let store = store.clone();
        let (owner, key) = (account_id.to_string(), mailbox_key.clone());
        tokio::task::spawn_blocking(move || store.get_oauth_credential(&owner, &key))
            .await??
            .context("no OAuth credential for this mailbox")?
    };

    let refresh_token = crypto.decrypt(&cred.enc_refresh_token)?;
    let client_secret = match &cred.enc_client_secret {
        Some(enc) => Some(crypto.decrypt(enc)?),
        None => None,
    };
    let token_endpoint: Url = cred
        .token_endpoint
        .parse()
        .context("stored token endpoint is not a valid URL")?;

    let client = oauth::ClientId::Static {
        client_id: cred.client_id.clone(),
        client_secret,
    };
    let refresh_for_call = refresh_token.clone();
    let tokens = tokio::task::spawn_blocking(move || {
        oauth::refresh(&token_endpoint, &client, &refresh_for_call)
    })
    .await??;

    // NOTE: persist a rotated refresh token so the next refresh uses the
    // current one.
    if let Some(new_refresh) = &tokens.refresh_token
        && new_refresh != &refresh_token
    {
        let enc = crypto.encrypt(new_refresh)?;
        let store = store.clone();
        let (owner, key) = (account_id.to_string(), mailbox_key.clone());
        tokio::task::spawn_blocking(move || store.update_oauth_refresh_token(&owner, &key, &enc))
            .await??;
    }

    Ok(tokens.access_token)
}
