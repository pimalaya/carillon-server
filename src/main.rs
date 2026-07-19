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

mod api;
mod config;
mod crypto;
mod delivery;
mod event;
mod imap;
mod store;
mod supervisor;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::api::AppState;
use crate::config::Config;
use crate::crypto::Crypto;
use crate::store::{Store, Watch};
use crate::supervisor::{Supervisor, SupervisorCmd};

/// Channel depth for pending change events awaiting delivery.
const EVENT_CHANNEL: usize = 4096;
/// Channel depth for supervisor commands.
const COMMAND_CHANNEL: usize = 64;

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

    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CARILLON_CONFIG").ok())
        .unwrap_or_else(|| String::from("carillon.toml"));
    let config = Config::load(config_path.as_ref())
        .with_context(|| format!("Cannot load config at {config_path}"))?;

    let store = Arc::new(Store::open(&config.server.db_path()).context("Cannot open store")?);
    let crypto =
        Arc::new(Crypto::load_or_create(&config.server.age_key_path()).context("Cannot load key")?);

    let seeded = seed_accounts(&store, &crypto, &config)?;
    info!(seeded, "configuration seeded");

    // Shared TLS config: one verifier and one session cache for every
    // held IMAP connection.
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

    // Supervisor.
    let supervisor = Supervisor::new(
        store.clone(),
        crypto.clone(),
        connector,
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
    };
    let listener = TcpListener::bind(&config.api.listen)
        .await
        .with_context(|| format!("Cannot bind {}", config.api.listen))?;
    info!(listen = %config.api.listen, "control API listening");

    let shutdown_commands = command_tx.clone();
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received");
            let _ = shutdown_commands.send(SupervisorCmd::Shutdown).await;
        })
        .await
        .context("Control API failed")?;

    Ok(())
}

/// Inserts config-declared accounts that are not yet in the store,
/// leaving runtime changes (pauses, edits made via the API) untouched.
fn seed_accounts(store: &Store, crypto: &Crypto, config: &Config) -> Result<usize> {
    let mut seeded = 0;

    for (id, account) in &config.accounts {
        if store.get_watch(id)?.is_some() {
            continue;
        }

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
        seeded += 1;
        info!(watch = %id, "seeded from config");
    }

    Ok(seeded)
}
