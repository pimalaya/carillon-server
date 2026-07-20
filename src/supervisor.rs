//! The watcher supervisor.
//!
//! Owns one tokio task per active watch, each running an independent
//! connect → watch → reconnect loop. It reconciles the running set
//! against the store on boot, on API-triggered commands, and on a
//! periodic timer. A shared semaphore caps simultaneous TLS handshakes
//! so a restart (or a store full of accounts) does not fire a
//! reconnect storm or trip per-IP provider limits.

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

use crate::crypto::Crypto;
use crate::event::ChangeEvent;
use crate::imap::pump;
use crate::imap::session::{self, ImapAccount, ImapAuth};
use crate::live::{LiveBus, LiveEvent, Routed, WatchState};
use crate::metering;
use crate::oauth;
use crate::store::{Store, Watch};

/// How a watcher authenticates each time it connects. A password is
/// constant; OAuth mints a fresh access token from the stored refresh token
/// on every connect (tokens are short-lived, connections reconnect often).
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
    /// The watch's billing account, kept so a stop/shutdown status event
    /// can be tagged for scoped SSE fan-out without re-reading the store.
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
}

impl Supervisor {
    /// Creates a supervisor. `max_handshakes` caps simultaneous TLS
    /// handshakes across all watchers.
    pub fn new(
        store: Arc<Store>,
        crypto: Arc<Crypto>,
        connector: TlsConnector,
        events: mpsc::Sender<ChangeEvent>,
        max_handshakes: usize,
        live: LiveBus,
    ) -> Self {
        Self {
            store,
            crypto,
            connector,
            events,
            handshake_sem: Arc::new(Semaphore::new(max_handshakes.max(1))),
            handles: HashMap::new(),
            live,
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
        ticker.tick().await; // consume the immediate first tick

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

        let desired: HashMap<String, Watch> = watches
            .into_iter()
            .map(|watch| (watch.id.clone(), watch))
            .collect();

        // Stop watchers that vanished or whose connection parameters
        // changed.
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

        // Start watchers that are missing.
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
        // Entitlement at the server boundary: never hold a standing IDLE
        // connection for an account with no watch-time left.
        let mailbox_key = metering::mailbox_key(&watch.login, &watch.imap_host);
        if !metering::has_credit(&self.store, &watch.account_id, &mailbox_key) {
            let _ = self.live.send(Routed::new(
                &watch.account_id,
                LiveEvent::status(&watch.id, WatchState::Error, Some("no credit".into())),
            ));
            anyhow::bail!("no watch-time credit for account {}", watch.account_id);
        }

        // Resolve the credential kind. A password is decrypted once; an OAuth
        // watch defers to the stored `oauth_credential`, minting a fresh
        // access token per connect (see `watch_loop`). The auth on the
        // account is a placeholder overwritten before each connect.
        let credential = if watch.auth_kind == "oauth" {
            Credential::Oauth
        } else {
            Credential::Password(self.crypto.decrypt(&watch.enc_password)?)
        };
        let account = ImapAccount {
            host: watch.imap_host.clone(),
            port: watch.imap_port,
            login: watch.login.clone(),
            auth: ImapAuth::Password(String::new()),
            mailbox: watch.mailbox.clone(),
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

        let task = tokio::spawn(async move {
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
        });

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
/// changing a webhook must not drop the IMAP connection.
fn fingerprint(watch: &Watch) -> u64 {
    let mut hasher = DefaultHasher::new();
    watch.imap_host.hash(&mut hasher);
    watch.imap_port.hash(&mut hasher);
    watch.login.hash(&mut hasher);
    watch.enc_password.hash(&mut hasher);
    watch.auth_kind.hash(&mut hasher);
    watch.mailbox.hash(&mut hasher);
    hasher.finish()
}

/// Everything one watcher task needs. Bundled into a struct to keep the
/// spawn site readable (and satisfy `clippy::too_many_arguments`).
struct WatchLoop {
    id: String,
    /// The billing account (for tagging live status events).
    account_id: String,
    /// Connection params; `auth` is a placeholder set before each connect.
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

/// One watch's connect → watch → reconnect loop. Stopped by aborting
/// the task; the shutdown flag lets the watcher coroutine wind down
/// cleanly if it happens to be resumed.
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

    // Tag every status change with the watch's billing account so the SSE
    // stream can scope it to the right subscriber.
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
        // Resolve this attempt's credential. A password is constant; OAuth
        // mints a fresh access token from the stored refresh token. A refresh
        // failure is transient (network, provider): surface it and back off,
        // exactly like a connect failure.
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

        // Throttle simultaneous handshakes across all watchers.
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
                // Full QRESYNC deltas where the server supports it, else the
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

        // A connection that lasted resets the backoff; a flapping one
        // keeps growing it.
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

fn jitter(base: Duration) -> Duration {
    let max = (base.as_millis() as u64 / 2).max(1);
    Duration::from_millis(rand::rng().random_range(0..=max))
}

/// Mints a fresh OAuth access token for a watch: loads its stored
/// credential, decrypts the refresh token, refreshes (blocking io-oauth in
/// `spawn_blocking`), and persists the refresh token if the provider rotated
/// it. Returns the access token to authenticate with (`OAUTHBEARER`).
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

    // Persist a rotated refresh token so the next refresh uses the current one.
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
