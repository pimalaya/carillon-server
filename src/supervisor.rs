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

use io_imap::types::mailbox::Mailbox;
use io_imap::watch::ImapMailboxWatch;
use rand::RngExt;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval, sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use crate::crypto::Crypto;
use crate::event::ChangeEvent;
use crate::imap::pump;
use crate::imap::session::{self, ImapAccount};
use crate::live::{LiveBus, LiveEvent, WatchState};
use crate::metering;
use crate::store::{Store, Watch};

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
                stop(handle);
                let _ = self
                    .live
                    .send(LiveEvent::status(&id, WatchState::Stopped, None));
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
            let _ = self.live.send(LiveEvent::status(
                &watch.id,
                WatchState::Error,
                Some("no credit".into()),
            ));
            anyhow::bail!("no watch-time credit for account {}", watch.account_id);
        }

        let password = self.crypto.decrypt(&watch.enc_password)?;
        let account = ImapAccount {
            host: watch.imap_host.clone(),
            port: watch.imap_port,
            login: watch.login.clone(),
            password,
            mailbox: watch.mailbox.clone(),
        };

        let id = watch.id.clone();
        let fingerprint = fingerprint(watch);
        let shutdown = Arc::new(AtomicBool::new(false));

        let connector = self.connector.clone();
        let events = self.events.clone();
        let handshake_sem = self.handshake_sem.clone();
        let shutdown_flag = shutdown.clone();
        let live = self.live.clone();

        let task = tokio::spawn(async move {
            watch_loop(
                id,
                account,
                connector,
                events,
                handshake_sem,
                shutdown_flag,
                live,
            )
            .await;
        });

        Ok(WatcherHandle {
            shutdown,
            fingerprint,
            task,
        })
    }

    fn stop_all(&mut self) {
        for (id, handle) in self.handles.drain() {
            stop(handle);
            let _ = self
                .live
                .send(LiveEvent::status(&id, WatchState::Stopped, None));
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
    watch.mailbox.hash(&mut hasher);
    hasher.finish()
}

/// One watch's connect → watch → reconnect loop. Stopped by aborting
/// the task; the shutdown flag lets the watcher coroutine wind down
/// cleanly if it happens to be resumed.
async fn watch_loop(
    id: String,
    account: ImapAccount,
    connector: TlsConnector,
    events: mpsc::Sender<ChangeEvent>,
    handshake_sem: Arc<Semaphore>,
    shutdown: Arc<AtomicBool>,
    live: LiveBus,
) {
    let mailbox: Mailbox<'static> = match Mailbox::try_from(account.mailbox.clone()) {
        Ok(mailbox) => mailbox,
        Err(_) => {
            error!(watch = %id, mailbox = %account.mailbox, "invalid mailbox name");
            let _ = live.send(LiveEvent::status(
                &id,
                WatchState::Error,
                Some("invalid mailbox name".into()),
            ));
            return;
        }
    };

    let mut backoff = INITIAL_BACKOFF;

    while !shutdown.load(Ordering::SeqCst) {
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
                let watcher = match ImapMailboxWatch::new(
                    &session.capabilities,
                    mailbox.clone(),
                    shutdown.clone(),
                ) {
                    Ok(watcher) => watcher,
                    Err(err) => {
                        error!(watch = %id, error = %err, "watcher cannot start; giving up");
                        let _ = live.send(LiveEvent::status(
                            &id,
                            WatchState::Error,
                            Some(err.to_string()),
                        ));
                        return;
                    }
                };

                info!(watch = %id, host = %account.host, mailbox = %account.mailbox, "watching");
                let _ = live.send(LiveEvent::status(&id, WatchState::Watching, None));

                let outcome = pump::run_watch(
                    &id,
                    &mut session.stream,
                    &mut session.fragmentizer,
                    watcher,
                    &events,
                )
                .await;

                match outcome {
                    Ok(()) => debug!(watch = %id, "session ended; reconnecting"),
                    Err(err) => warn!(watch = %id, error = %err, "session lost; reconnecting"),
                }
            }
            Ok(Err(err)) => {
                warn!(watch = %id, error = %err, "connect failed");
                let _ = live.send(LiveEvent::status(
                    &id,
                    WatchState::Error,
                    Some(format!("{err:#}")),
                ));
            }
            Err(_elapsed) => {
                warn!(watch = %id, "connect timed out");
                let _ = live.send(LiveEvent::status(
                    &id,
                    WatchState::Error,
                    Some("connect timed out".into()),
                ));
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

        let _ = live.send(LiveEvent::status(&id, WatchState::Reconnecting, None));
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
