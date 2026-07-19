//! # Carillon watch server (prototype)
//!
//! Holds IMAP IDLE for many accounts on one box and, the instant a
//! mailbox changes, POSTs a small, HMAC-signed, **content-free** signal
//! to each account's notify URL. Carillon signals; it never syncs.
//!
//! Wiring: the [`supervisor`] runs one connect/watch/reconnect task per
//! active watch (over the async [`imap::pump`]) and folds every change
//! into a canonical [`event::ChangeEvent`]; those flow down a channel to
//! the [`delivery`] worker, which signs and POSTs them and logs the
//! outcome to the sqlite [`store`]. The [`api`] manages watches at
//! runtime. Passwords are encrypted at rest via [`crypto`].
//!
//! Two subcommands:
//!
//! - `carillon serve [config]` (the default) runs the daemon.
//! - `carillon import <accounts.toml> [config]` populates the store from
//!   an [`config::ImportFile`] and exits — the headless entrypoint, since
//!   accounts no longer live in the config.

mod api;
mod config;
mod crypto;
mod delivery;
mod event;
mod imap;
mod ratelimit;
mod store;
mod supervisor;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::api::AppState;
use crate::config::{Config, ImportFile};
use crate::crypto::Crypto;
use crate::ratelimit::RateLimiter;
use crate::store::{Store, Watch};
use crate::supervisor::{Supervisor, SupervisorCmd};

/// Channel depth for pending change events awaiting delivery.
const EVENT_CHANNEL: usize = 4096;
/// Channel depth for supervisor commands.
const COMMAND_CHANNEL: usize = 64;
/// `/test` limit: attempts per `(IP, login)` per window.
const TEST_MAX_ATTEMPTS: u32 = 5;
/// `/test` limit: the window over which attempts are counted.
const TEST_WINDOW: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,carillon_server=debug")),
        )
        .init();

    // One process-wide crypto provider, shared by the IMAP connector
    // and reqwest's rustls.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("import") => {
            let accounts = args
                .get(2)
                .context("usage: carillon import <accounts.toml> [config]")?;
            let config = load_config(args.get(3).map(String::as_str))?;
            import(&config, accounts.as_ref())
        }
        Some("serve") => {
            let config = load_config(args.get(2).map(String::as_str))?;
            serve(config).await
        }
        // No subcommand, or a bare config path (kept for convenience):
        // `carillon` / `carillon carillon.toml` both serve.
        Some(flag) if flag.starts_with('-') => bail!("unknown flag: {flag}"),
        other => {
            let config = load_config(other)?;
            serve(config).await
        }
    }
}

/// Resolves the config path (explicit arg → `CARILLON_CONFIG` →
/// `carillon.toml`) and loads it.
fn load_config(explicit: Option<&str>) -> Result<Config> {
    let path = explicit
        .map(String::from)
        .or_else(|| std::env::var("CARILLON_CONFIG").ok())
        .unwrap_or_else(|| String::from("carillon.toml"));
    Config::load(path.as_ref()).with_context(|| format!("Cannot load config at {path}"))
}

/// Runs the daemon: watchers, delivery worker and control API.
async fn serve(config: Config) -> Result<()> {
    let store = Arc::new(Store::open(&config.server.db_path()).context("Cannot open store")?);
    let crypto =
        Arc::new(Crypto::load_or_create(&config.server.age_key_path()).context("Cannot load key")?);

    // Shared TLS config: one verifier and one session cache for every
    // held IMAP connection, and for the read-only `/test` probe.
    let tls = Arc::new(ClientConfig::with_platform_verifier().context("Cannot build TLS config")?);
    let connector = TlsConnector::from(tls);

    // Shared, pooled HTTP client for outbound webhooks.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Cannot build HTTP client")?;

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL);

    // Delivery worker.
    tokio::spawn(delivery::run(event_rx, store.clone(), http));

    // Supervisor. Keep a clone of the connector for the `/test` probe.
    let supervisor = Supervisor::new(
        store.clone(),
        crypto.clone(),
        connector.clone(),
        event_tx,
        config.server.max_concurrent_handshakes,
    );
    let reconcile_interval = Duration::from_secs(config.server.reconcile_interval_secs.max(5));
    tokio::spawn(supervisor.run(command_rx, reconcile_interval));

    // Control API.
    let state = AppState {
        store: store.clone(),
        crypto: crypto.clone(),
        commands: command_tx.clone(),
        connector,
        test_limiter: Arc::new(RateLimiter::new(TEST_MAX_ATTEMPTS, TEST_WINDOW)),
    };
    let listener = TcpListener::bind(&config.api.listen)
        .await
        .with_context(|| format!("Cannot bind {}", config.api.listen))?;
    info!(listen = %config.api.listen, "control API listening");

    let shutdown_commands = command_tx.clone();
    let service = api::router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received");
            let _ = shutdown_commands.send(SupervisorCmd::Shutdown).await;
        })
        .await
        .context("Control API failed")?;

    Ok(())
}

/// Imports accounts from a TOML file into the store, then exits. Watches
/// are upserted (an existing id is updated in place); the running daemon,
/// if any, adopts them on its next reconcile.
fn import(config: &Config, path: &Path) -> Result<()> {
    let store = Store::open(&config.server.db_path()).context("Cannot open store")?;
    let crypto =
        Crypto::load_or_create(&config.server.age_key_path()).context("Cannot load key")?;
    let file = ImportFile::load(path)?;

    let mut imported = 0;
    for (id, account) in &file.accounts {
        let password = account
            .password
            .resolve()
            .with_context(|| format!("Cannot resolve password for account {id}"))?;
        let enc_password = crypto.encrypt(&password)?;

        let watch = Watch {
            id: id.clone(),
            imap_host: account.imap_host.clone(),
            imap_port: account.imap_port,
            login: account.login.clone(),
            enc_password,
            mailbox: account.mailbox.clone(),
            notify_url: account.notify_url.clone(),
            hmac_secret: account.hmac_secret.clone(),
            active: account.active,
        };
        store.upsert_watch(&watch)?;
        imported += 1;
        info!(watch = %id, "imported");
    }

    info!(imported, "import complete");
    Ok(())
}
