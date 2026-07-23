//! # Carillon watch server (prototype)
//!
//! Holds IMAP IDLE for many accounts on one box and, the instant a
//! mailbox changes, POSTs a content-free, HMAC-signed signal to each
//! account's notify URL. Carillon signals; it never syncs.
//!
//! The [`supervisor`] runs one connect/watch/reconnect task per active
//! watch (over [`imap::pump`]) and folds every change into a canonical
//! [`event::ChangeEvent`]; those flow down a channel to the [`delivery`]
//! worker, which signs, POSTs and logs the outcome to the sqlite
//! [`store`]. The [`api`] manages watches at runtime; [`crypto`]
//! encrypts passwords at rest.
//!
//! Two subcommands:
//!
//! - `carillon-backend serve [config]` (the default) runs the daemon.
//! - `carillon-backend import <accounts.toml> [config]` populates the store from
//!   an [`config::ImportFile`] and exits.

mod api;
mod billing;
mod carddav;
mod config;
mod crypto;
mod delivery;
mod discover;
mod email;
mod event;
mod guard;
mod imap;
mod live;
mod metering;
mod oauth;
mod ratelimit;
mod store;
mod supervisor;
mod util;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::api::AppState;
use crate::config::{Config, ImportFile};
use crate::crypto::Crypto;
use crate::delivery::validate_notify_url;
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
/// `/discover` limit: lookups per IP per window (throttled because each
/// makes outbound DNS/HTTP requests, though unauthenticated).
const DISCOVER_MAX_ATTEMPTS: u32 = 20;
/// `/discover` limit window.
const DISCOVER_WINDOW: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,carillon_backend=debug")),
        )
        .init();

    // NOTE: one process-wide crypto provider, shared by the IMAP
    // connector and reqwest's rustls.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("import") => {
            let accounts = args
                .get(2)
                .context("usage: carillon-backend import <accounts.toml> [config]")?;
            let config = load_config(args.get(3).map(String::as_str))?;
            import(&config, accounts.as_ref())
        }
        Some("serve") => {
            let config = load_config(args.get(2).map(String::as_str))?;
            serve(config).await
        }
        // NOTE: no subcommand or a bare config path both serve, for
        // convenience (`carillon-backend` / `carillon-backend carillon.toml`).
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
    // NOTE: set egress policy first; every outbound connect (IMAP +
    // webhooks) consults it.
    guard::set_allow_private_targets(config.server.allow_private_targets);

    // NOTE: watching is credit-metered only on the SaaS (Stripe
    // configured); the keyless stub means self-host / dev, not billed.
    let metered = config.billing.stripe.is_some();

    let store = Arc::new(Store::open(&config.server.db_path()).context("Cannot open store")?);
    let crypto =
        Arc::new(Crypto::load_or_create(&config.server.age_key_path()).context("Cannot load key")?);

    // NOTE: shared TLS config, one verifier and one session cache for
    // every held IMAP connection and the read-only `/test` probe.
    let tls = Arc::new(ClientConfig::with_platform_verifier().context("Cannot build TLS config")?);
    let connector = TlsConnector::from(tls);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Cannot build HTTP client")?;

    let mailer = Arc::new(email::Mailer::new(http.clone(), &config.email));

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL);
    // NOTE: flipped on ctrl_c so held SSE streams end and do not block
    // graceful shutdown.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // NOTE: the extra receiver is dropped; the sender survives with zero
    // subscribers, and each SSE client makes its own.
    let (live_tx, _live_rx) = broadcast::channel(live::CAPACITY);

    tokio::spawn(delivery::run(
        event_rx,
        store.clone(),
        http.clone(),
        live_tx.clone(),
    ));

    // Renewal sweep: auto-renew or stop PIM accounts whose month lapsed
    // (disabled when unmetered).
    tokio::spawn(metering::run(
        store.clone(),
        live_tx.clone(),
        http.clone(),
        mailer.clone(),
        command_tx.clone(),
        metering::tick(),
        metered,
    ));

    // NOTE: keep a clone of the connector for the `/test` probe.
    let supervisor = Supervisor::new(
        store.clone(),
        crypto.clone(),
        connector.clone(),
        event_tx,
        config.server.max_concurrent_handshakes,
        live_tx.clone(),
        metered,
        config.server.carddav_poll_interval_secs,
    );
    let reconcile_interval = Duration::from_secs(config.server.reconcile_interval_secs.max(5));
    tokio::spawn(supervisor.run(command_rx, reconcile_interval));

    // NOTE: the public API base (redirect URI) and the dashboard origin
    // the OAuth callback popup posts its result back to.
    let public_url = config
        .api
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", config.api.listen));
    let dashboard_url = config
        .api
        .dashboard_url
        .clone()
        .unwrap_or_else(|| public_url.clone());
    let dashboard_origin = url::Url::parse(&dashboard_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| String::from("*"));

    // NOTE: own OAuth apps, if configured, override the built-in
    // Thunderbird clients.
    let to_client = |client: &config::OauthClientConfig| {
        (client.client_id.clone(), client.client_secret.clone())
    };
    let oauth_clients = oauth::StaticClients {
        google: config.oauth.google.as_ref().map(to_client),
        microsoft: config.oauth.microsoft.as_ref().map(to_client),
    };

    let billing: Arc<billing::Billing> = match &config.billing.stripe {
        Some(stripe) => {
            info!("billing: stripe");
            Arc::new(billing::Billing::Stripe(billing::StripeBilling::new(
                http.clone(),
                stripe,
                &dashboard_url,
            )))
        }
        None => {
            info!("billing: stub (no [billing.stripe] configured)");
            Arc::new(billing::Billing::Stub)
        }
    };

    let state = AppState {
        store: store.clone(),
        crypto: crypto.clone(),
        commands: command_tx.clone(),
        connector,
        http,
        test_limiter: Arc::new(RateLimiter::new(TEST_MAX_ATTEMPTS, TEST_WINDOW)),
        auth_limiter: Arc::new(RateLimiter::new(TEST_MAX_ATTEMPTS, TEST_WINDOW)),
        discover_limiter: Arc::new(RateLimiter::new(DISCOVER_MAX_ATTEMPTS, DISCOVER_WINDOW)),
        live: live_tx,
        shutdown: shutdown_rx,
        billing,
        mailer,
        metered,
        max_watches: config.server.max_watches_per_account.max(1),
        carddav_poll_secs: config.server.carddav_poll_interval_secs,
        admin_token: config.api.admin_token.clone(),
        public_url,
        dashboard_origin,
        oauth_clients,
    };
    let listener = TcpListener::bind(&config.api.listen)
        .await
        .with_context(|| format!("Cannot bind {}", config.api.listen))?;
    info!(listen = %config.api.listen, "control API listening");

    let shutdown_commands = command_tx.clone();
    let service = api::router(
        state,
        config.api.ui_dir.clone(),
        config.api.cors_allow_origin.clone(),
    )
    .into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received");
            // NOTE: end held SSE streams first so they don't stall
            // graceful shutdown, then stop the watchers.
            let _ = shutdown_tx.send(true);
            let _ = shutdown_commands.send(SupervisorCmd::Shutdown).await;
        })
        .await
        .context("Control API failed")?;

    Ok(())
}

/// Imports accounts from a TOML file into the store, then exits.
///
/// Watches are upserted (an existing id is updated in place); a running
/// daemon adopts them on its next reconcile.
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

        validate_notify_url(&account.notify_url)
            .with_context(|| format!("Invalid notify_url for account {id}"))?;

        let watch = Watch {
            id: id.clone(),
            imap_host: account.imap_host.clone(),
            imap_port: account.imap_port,
            login: account.login.clone(),
            enc_password,
            mailbox: account.mailbox.clone(),
            notify_url: account.notify_url.clone(),
            hmac_secret: account.hmac_secret.clone(),
            hmac_secret_prev: None,
            hmac_secret_prev_expires: None,
            // NOTE: one watch, one billing account until grouped (M7).
            account_id: id.clone(),
            provider: metering::provider_domain(&account.imap_host),
            auth_kind: String::from("password"),
            // NOTE: self-host import is unmetered, so activation is moot
            // (watches run regardless); leave the service un-activated.
            watching_until: None,
            auto_renew: false,
            active: account.active,
            // NOTE: import is IMAP-only; CardDAV services are added via
            // the API.
            source_kind: String::from("imap"),
            carddav_url: None,
            carddav_sync_token: None,
            carddav_poll_secs: None,
        };
        store.upsert_watch(&watch)?;
        store.ensure_account(id, None)?;
        store.grant_free_credit(id, metering::FREE_CREDITS_ON_SIGNUP)?;
        imported += 1;
        info!(watch = %id, "imported");
    }

    info!(imported, "import complete");
    Ok(())
}
