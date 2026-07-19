//! The HTTP control API.
//!
//! A small axum service to manage watches at runtime and inspect the
//! delivery log. It writes the store (the source of truth) and nudges
//! the supervisor to reconcile; the supervisor owns all the
//! connections. This is the prototype's stand-in for the eventual
//! dashboard and billing gate.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

use crate::billing::{self, Billing};
use crate::crypto::Crypto;
use crate::delivery::validate_notify_url;
use crate::imap::session::{self, ImapAccount};
use crate::live::LiveBus;
use crate::metering::{self, POOL_TTL_SECS};
use crate::ratelimit::RateLimiter;
use crate::store::{Store, Watch};
use crate::supervisor::SupervisorCmd;
use crate::util::now_secs;

/// Default rotation overlap: how long the previous HMAC secret keeps
/// being signed with so a receiver has time to update.
const DEFAULT_ROTATE_OVERLAP: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a capability link stays valid before it must be re-minted.
const CAPABILITY_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// This server's OpenAPI contract, embedded so it is always served in
/// sync with the binary.
const OPENAPI_YAML: &str = include_str!("../docs/openapi.yaml");

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// The store (source of truth for watches and deliveries).
    pub store: Arc<Store>,
    /// Password encryptor.
    pub crypto: Arc<Crypto>,
    /// Channel to ask the supervisor to reconcile after a mutation.
    pub commands: mpsc::Sender<SupervisorCmd>,
    /// Shared TLS connector for the read-only `/test` probe.
    pub connector: TlsConnector,
    /// Per-`(IP, login)` limiter guarding the `/test` oracle surface.
    pub test_limiter: Arc<RateLimiter>,
    /// Per-`(IP, login)` limiter guarding the `/auth` oracle surface.
    pub auth_limiter: Arc<RateLimiter>,
    /// Live bus the `/events` SSE stream subscribes to.
    pub live: LiveBus,
    /// Payment provider adapter (stubbed until keys are wired).
    pub billing: Arc<dyn Billing>,
}

/// Builds the control API router. `ui_dir`, if set, is served as static
/// files at the origin (self-host embedding a `carillon-admin` build);
/// `cors_origin`, if set, enables cross-origin access for a CDN-served
/// front.
pub fn router(state: AppState, ui_dir: Option<PathBuf>, cors_origin: Option<String>) -> Router {
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi))
        .route("/test", post(test_connect))
        .route("/auth", post(auth))
        .route("/me", get(me))
        .route("/signout", post(signout))
        .route("/watches", get(list_watches).post(create_watch))
        .route("/watches/{id}", delete(delete_watch))
        .route("/watches/{id}/pause", post(pause_watch))
        .route("/watches/{id}/resume", post(resume_watch))
        .route("/watches/{id}/rotate-secret", post(rotate_secret))
        .route("/deliveries", get(list_deliveries))
        .route("/events", get(events))
        .route("/accounts", get(list_accounts))
        .route("/accounts/{id}", get(get_account))
        .route("/accounts/{id}/credit", post(add_credit))
        .route("/accounts/{id}/auto-refill", post(set_auto_refill))
        .route("/billing/packs", get(billing_packs))
        .route("/billing/checkout", post(billing_checkout))
        .route("/billing/webhook", post(billing_webhook));

    // With a UI, static files own `/` (and unknown paths fall back to the
    // SPA entrypoint); without one, `/` returns service metadata.
    app = match &ui_dir {
        Some(_) => app,
        None => app.route("/", get(service_info)),
    };

    let mut app = app.with_state(state);

    if let Some(dir) = ui_dir {
        let index = dir.join("index.html");
        app = app.fallback_service(ServeDir::new(dir).not_found_service(ServeFile::new(index)));
    }

    if let Some(origin) = cors_origin {
        app = app.layer(cors_layer(&origin));
    }

    app
}

/// Service metadata for the root path (self-host without a UI).
async fn service_info() -> Json<serde_json::Value> {
    Json(json!({
        "name": "carillon-server",
        "version": env!("CARGO_PKG_VERSION"),
        "openapi": "/openapi.yaml",
        "docs": "https://carillon.pimalaya.org",
    }))
}

/// Serves the embedded OpenAPI spec.
async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_YAML).into_response()
}

/// A CORS layer allowing the configured origin (`*` for any) with the
/// `Authorization` bearer header — pairs with the localStorage capability
/// link, no cookies/CSRF.
fn cors_layer(origin: &str) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    match origin {
        "*" => layer.allow_origin(Any),
        origin => match origin.parse::<axum::http::HeaderValue>() {
            Ok(value) => layer.allow_origin(value),
            Err(_) => {
                warn!(origin, "invalid CORS origin; disabling CORS");
                layer
            }
        },
    }
}

async fn health() -> &'static str {
    "ok"
}

/// Body of `POST /test`: credentials to probe, read-only.
#[derive(Deserialize)]
struct TestRequest {
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
}

/// Structured verdict returned by `POST /test`. `ok` is the plan's
/// green light: reachable + authenticated + IDLE + QRESYNC — never just
/// auth, because a server can authenticate fine and still fail the watch.
#[derive(Serialize)]
struct TestVerdict {
    ok: bool,
    reachable: bool,
    authenticated: bool,
    idle: bool,
    qresync: bool,
    condstore: bool,
    missing: Vec<&'static str>,
    error: Option<String>,
}

/// Probes credentials without spending a credit: connect → auth →
/// capability check → LOGOUT. Rate-limited per `(IP, login)` so it
/// cannot be used as a credential-testing oracle. Always returns `200`
/// with the structured verdict (a failed probe is a valid answer);
/// `429` only when the caller is rate-limited.
async fn test_connect(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<TestRequest>,
) -> Response {
    let key = format!("{}|{}", peer.ip(), request.login);
    if let Err(retry_after) = state.test_limiter.check(&key) {
        warn!(login = %request.login, peer = %peer.ip(), "test rate-limited");
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    let account = ImapAccount {
        host: request.imap_host,
        port: request.imap_port,
        login: request.login,
        password: request.password,
        mailbox: request.mailbox,
    };

    let probe = session::probe(&state.connector, &account).await;
    let verdict = TestVerdict {
        ok: probe.watchable(),
        reachable: probe.reachable,
        authenticated: probe.authenticated,
        idle: probe.idle,
        qresync: probe.qresync,
        condstore: probe.condstore,
        missing: if probe.authenticated {
            probe.missing()
        } else {
            Vec::new()
        },
        error: probe.error,
    };

    info!(
        host = %account.host,
        login = %account.login,
        ok = verdict.ok,
        "test probe",
    );
    Json(verdict).into_response()
}

/// Public view of a watch: never the password or HMAC secret.
#[derive(Serialize)]
struct WatchView {
    id: String,
    imap_host: String,
    imap_port: u16,
    login: String,
    mailbox: String,
    notify_url: String,
    active: bool,
}

impl From<Watch> for WatchView {
    fn from(watch: Watch) -> Self {
        Self {
            id: watch.id,
            imap_host: watch.imap_host,
            imap_port: watch.imap_port,
            login: watch.login,
            mailbox: watch.mailbox,
            notify_url: watch.notify_url,
            active: watch.active,
        }
    }
}

async fn list_watches(State(state): State<AppState>) -> Result<Json<Vec<WatchView>>, AppError> {
    let store = state.store.clone();
    let watches = tokio::task::spawn_blocking(move || store.all_watches()).await??;
    Ok(Json(watches.into_iter().map(WatchView::from).collect()))
}

/// Body of `POST /watches`. The password is plaintext on the wire and
/// encrypted at rest.
#[derive(Deserialize)]
struct CreateWatch {
    id: String,
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
    notify_url: String,
    hmac_secret: String,
    /// Billing account to draw watch-time from. Defaults to the watch id
    /// (self-host, one watch one account); a SaaS client passes its
    /// capability-link account so the watch joins the shared pool.
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default = "default_true")]
    active: bool,
}

async fn create_watch(
    State(state): State<AppState>,
    Json(request): Json<CreateWatch>,
) -> Result<Response, AppError> {
    if let Err(err) = validate_notify_url(&request.notify_url) {
        return Ok(bad_request(&err.to_string()));
    }

    let enc_password = state.crypto.encrypt(&request.password)?;
    // Grant the mailbox its one-time trial; join the requested billing
    // account, or default to a per-watch account.
    let account_id = request
        .account_id
        .clone()
        .unwrap_or_else(|| request.id.clone());
    let mailbox_key = metering::mailbox_key(&request.login, &request.imap_host);
    let watch = Watch {
        id: request.id,
        imap_host: request.imap_host,
        imap_port: request.imap_port,
        login: request.login,
        enc_password,
        mailbox: request.mailbox,
        notify_url: request.notify_url,
        hmac_secret: request.hmac_secret,
        hmac_secret_prev: None,
        hmac_secret_prev_expires: None,
        account_id: account_id.clone(),
        active: request.active,
    };

    let id = watch.id.clone();
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        store.upsert_watch(&watch)?;
        store.ensure_account(&account_id)?;
        store.grant_trial(&mailbox_key, metering::trial_secs())?;
        Ok(())
    })
    .await??;
    info!(watch = %id, "watch created");

    state.commands.send(SupervisorCmd::Reconcile).await.ok();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "status": "ok", "id": id })),
    )
        .into_response())
}

async fn delete_watch(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let store = state.store.clone();
    let existed = tokio::task::spawn_blocking({
        let id = id.clone();
        move || store.delete_watch(&id)
    })
    .await??;

    if !existed {
        return Ok(not_found(&id));
    }

    info!(watch = %id, "watch deleted");
    state.commands.send(SupervisorCmd::Reconcile).await.ok();
    Ok(Json(json!({ "status": "ok" })).into_response())
}

async fn pause_watch(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    set_active(state, id, false).await
}

async fn resume_watch(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    set_active(state, id, true).await
}

async fn set_active(state: AppState, id: String, active: bool) -> Result<Response, AppError> {
    let store = state.store.clone();
    let matched = tokio::task::spawn_blocking({
        let id = id.clone();
        move || store.set_active(&id, active)
    })
    .await??;

    if !matched {
        return Ok(not_found(&id));
    }

    info!(watch = %id, active, "watch toggled");
    state.commands.send(SupervisorCmd::Reconcile).await.ok();
    Ok(Json(json!({ "status": "ok", "active": active })).into_response())
}

/// Body of `POST /watches/{id}/rotate-secret`. All fields optional; an
/// empty body rotates to a fresh random secret with the default overlap.
#[derive(Default, Deserialize)]
struct RotateRequest {
    /// The new secret. If omitted, a random 256-bit one is generated
    /// and returned.
    #[serde(default)]
    new_secret: Option<String>,
    /// How long (seconds) the previous secret keeps being signed with.
    #[serde(default)]
    overlap_secs: Option<u64>,
}

/// Rotates a watch's HMAC secret, keeping the old one valid for an
/// overlap window (both are signed with meanwhile). Returns the new
/// secret and the overlap expiry. The secret does not affect the IMAP
/// connection (the supervisor fingerprint excludes it), so no reconnect.
async fn rotate_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let request: RotateRequest = if body.is_empty() {
        RotateRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(err) => return Ok(bad_request(&format!("invalid body: {err}"))),
        }
    };

    let secret = request.new_secret.unwrap_or_else(random_secret);
    let overlap = request
        .overlap_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_ROTATE_OVERLAP);

    let store = state.store.clone();
    let rotate_id = id.clone();
    let rotate_secret = secret.clone();
    let expires = tokio::task::spawn_blocking(move || {
        store.rotate_secret(&rotate_id, &rotate_secret, overlap)
    })
    .await??;

    match expires {
        Some(prev_expires_at) => {
            info!(watch = %id, prev_expires_at, "hmac secret rotated");
            Ok(Json(json!({
                "status": "ok",
                "secret": secret,
                "prev_expires_at": prev_expires_at,
            }))
            .into_response())
        }
        None => Ok(not_found(&id)),
    }
}

#[derive(Deserialize)]
struct DeliveryQuery {
    account: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
}

#[derive(Serialize)]
struct DeliveryView {
    account: String,
    event: String,
    uid: u32,
    ok: bool,
    status: Option<u16>,
    error: Option<String>,
    attempts: u32,
    at: i64,
}

async fn list_deliveries(
    State(state): State<AppState>,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<Vec<DeliveryView>>, AppError> {
    let store = state.store.clone();
    let limit = query.limit.clamp(1, 1000);
    let rows = tokio::task::spawn_blocking(move || {
        store.recent_deliveries(query.account.as_deref(), limit)
    })
    .await??;

    let views = rows
        .into_iter()
        .map(|row| DeliveryView {
            account: row.account,
            event: row.event,
            uid: row.uid,
            ok: row.ok,
            status: row.status,
            error: row.error,
            attempts: row.attempts,
            at: row.at,
        })
        .collect();
    Ok(Json(views))
}

/// `GET /events` — a Server-Sent Events stream of live delivery outcomes
/// and watch connection-status changes, for the dashboard. One-way,
/// browser-native (`EventSource`), proxy-friendly. Each subscriber gets
/// its own broadcast receiver; a slow client that lags simply misses the
/// oldest events (surfaced as a `lagged` SSE event) rather than stalling
/// the bus. Purely observational and content-free.
async fn events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.live.subscribe()).map(|message| {
        let event = match message {
            Ok(live) => Event::default()
                .event(live.name())
                .data(serde_json::to_string(&live).unwrap_or_default()),
            // The subscriber fell behind and lost `skipped` events.
            Err(err) => Event::default().event("lagged").data(err.to_string()),
        };
        Ok(event)
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// A member mailbox's non-refillable trial, within an account view.
/// `watch_id` is null for a proven mailbox that has no watch yet.
#[derive(Serialize)]
struct MailboxView {
    watch_id: Option<String>,
    mailbox_key: String,
    trial_secs: f64,
}

/// Public view of a billing account: the two counters (per-mailbox trials
/// and the shared paid pool) the dashboard renders.
#[derive(Serialize)]
struct AccountView {
    id: String,
    paid_secs: f64,
    paid_expires: Option<i64>,
    pool_expired: bool,
    auto_refill: bool,
    auto_refill_threshold: f64,
    auto_refill_amount: f64,
    mailboxes: Vec<MailboxView>,
    total_available_secs: f64,
}

async fn list_accounts(State(state): State<AppState>) -> Result<Json<Vec<AccountView>>, AppError> {
    let store = state.store.clone();
    let views = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<AccountView>> {
        let now = now_secs();
        store
            .all_accounts()?
            .into_iter()
            .map(|account| account_view(&store, &account.id, now))
            .collect()
    })
    .await??;
    Ok(Json(views))
}

async fn get_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let store = state.store.clone();
    let account = tokio::task::spawn_blocking({
        let id = id.clone();
        move || store.get_account(&id)
    })
    .await??;

    if account.is_none() {
        return Ok(not_found(&id));
    }

    let store = state.store.clone();
    let view = tokio::task::spawn_blocking(move || account_view(&store, &id, now_secs())).await??;
    Ok(Json(view).into_response())
}

/// Builds an account view, reading the pool and each member mailbox's
/// trial. Blocking; call inside `spawn_blocking`.
fn account_view(store: &Store, id: &str, now: i64) -> anyhow::Result<AccountView> {
    let account = store.get_account(id)?.unwrap_or(crate::store::AccountRow {
        id: id.to_string(),
        paid_secs: 0.0,
        paid_expires: None,
        auto_refill: false,
        auto_refill_threshold: 0.0,
        auto_refill_amount: 0.0,
    });

    let pool_expired = matches!(account.paid_expires, Some(expires) if now >= expires);
    let pool = if pool_expired { 0.0 } else { account.paid_secs };

    // Union the account's mailboxes from both proven memberships (which
    // may exist before any watch) and watches (which may exist without a
    // membership, in self-host), keyed by the normalised mailbox key.
    let mut keyed: BTreeMap<String, Option<String>> = BTreeMap::new();
    for member in store.memberships(id)? {
        keyed.entry(member.mailbox_key).or_insert(None);
    }
    for watch in store.watches_by_account(id)? {
        let key = metering::mailbox_key(&watch.login, &watch.imap_host);
        keyed.insert(key, Some(watch.id));
    }

    let mut mailboxes = Vec::new();
    let mut trials_total = 0.0;
    for (key, watch_id) in keyed {
        let trial = store.balance(id, &key, now)?.trial;
        trials_total += trial;
        mailboxes.push(MailboxView {
            watch_id,
            mailbox_key: key,
            trial_secs: trial,
        });
    }

    Ok(AccountView {
        id: account.id,
        paid_secs: account.paid_secs,
        paid_expires: account.paid_expires,
        pool_expired,
        auto_refill: account.auto_refill,
        auto_refill_threshold: account.auto_refill_threshold,
        auto_refill_amount: account.auto_refill_amount,
        mailboxes,
        total_available_secs: pool + trials_total,
    })
}

/// Body of `POST /accounts/{id}/credit`: top up the paid pool. This is
/// the sole thing money touches; M7's billing calls it after a payment.
#[derive(Deserialize)]
struct CreditRequest {
    secs: f64,
    #[serde(default)]
    ttl_secs: Option<i64>,
}

async fn add_credit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<CreditRequest>,
) -> Result<Response, AppError> {
    if request.secs <= 0.0 {
        return Ok(bad_request("secs must be positive"));
    }
    let expires = now_secs() + request.ttl_secs.unwrap_or(POOL_TTL_SECS);

    let store = state.store.clone();
    let credit_id = id.clone();
    tokio::task::spawn_blocking(move || store.add_credit(&credit_id, request.secs, expires))
        .await??;
    info!(account = %id, secs = request.secs, "credit added");

    let store = state.store.clone();
    let view = tokio::task::spawn_blocking(move || account_view(&store, &id, now_secs())).await??;
    Ok(Json(view).into_response())
}

/// Body of `POST /accounts/{id}/auto-refill`.
#[derive(Deserialize)]
struct AutoRefillRequest {
    enabled: bool,
    #[serde(default)]
    threshold_secs: f64,
    #[serde(default)]
    amount_secs: f64,
}

async fn set_auto_refill(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<AutoRefillRequest>,
) -> Result<Response, AppError> {
    if request.enabled && request.amount_secs <= 0.0 {
        return Ok(bad_request(
            "amount_secs must be positive when enabling auto-refill",
        ));
    }

    let store = state.store.clone();
    let refill_id = id.clone();
    let matched = tokio::task::spawn_blocking(move || {
        store.set_auto_refill(
            &refill_id,
            request.enabled,
            request.threshold_secs,
            request.amount_secs,
        )
    })
    .await??;

    if !matched {
        return Ok(not_found(&id));
    }
    info!(account = %id, enabled = request.enabled, "auto-refill configured");
    Ok(Json(json!({ "status": "ok" })).into_response())
}

// --- Capability-link accounts & billing (M7) ---

/// The account behind a valid capability link. Extractor: reads the
/// `Authorization: Bearer <link>` header and resolves it, rejecting with
/// `401` if missing, unknown or expired. Server-validated on every call.
struct CapabilityAccount(String);

impl FromRequestParts<AppState> for CapabilityAccount {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let token = bearer(&parts.headers).ok_or_else(unauthorized)?;
        match state.store.resolve_capability(&token) {
            Ok(Some(account_id)) => Ok(CapabilityAccount(account_id)),
            _ => Err(unauthorized()),
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid or missing capability link" })),
    )
        .into_response()
}

/// Body of `POST /auth`: prove control of a mailbox.
#[derive(Deserialize)]
struct AuthRequest {
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
}

/// `POST /auth` — the login-less identity flow. Authenticating proves
/// control of a mailbox; the first auth creates an account and mints its
/// capability link, a re-auth to a member mailbox recovers (re-mints) the
/// account's link, and an auth carrying a valid link adds the mailbox to
/// that account. Rate-limited per `(IP, login)` — the one oracle surface.
async fn auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AuthRequest>,
) -> Response {
    let key = format!("{}|{}", peer.ip(), request.login);
    if let Err(retry_after) = state.auth_limiter.check(&key) {
        warn!(login = %request.login, peer = %peer.ip(), "auth rate-limited");
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    let account = ImapAccount {
        host: request.imap_host.clone(),
        port: request.imap_port,
        login: request.login.clone(),
        password: request.password,
        mailbox: request.mailbox,
    };
    let probe = session::probe(&state.connector, &account).await;
    if !probe.authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "authentication failed", "detail": probe.error })),
        )
            .into_response();
    }

    let existing = bearer(&headers);
    let store = state.store.clone();
    let login = request.login.clone();
    let host = request.imap_host.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(String, &'static str, String)> {
            let mailbox_key = metering::mailbox_key(&login, &host);
            let expires = Some(now_secs() + CAPABILITY_TTL.as_secs() as i64);

            // Join the account the presented link controls, else recover the
            // account this mailbox already belongs to, else create a new one.
            let joined = match &existing {
                Some(token) => store
                    .resolve_capability(token)?
                    .map(|id| (id, token.clone())),
                None => None,
            };
            let (account_id, action, link) = match joined {
                Some((id, token)) => (id, "joined", token),
                None => match store.account_of_mailbox(&mailbox_key)? {
                    Some(id) => {
                        let link = random_secret();
                        store.issue_capability(&id, &link, expires)?;
                        (id, "recovered", link)
                    }
                    None => {
                        let id = random_secret();
                        store.ensure_account(&id)?;
                        let link = random_secret();
                        store.issue_capability(&id, &link, expires)?;
                        (id, "created", link)
                    }
                },
            };

            store.add_membership(&account_id, &mailbox_key, &login, &host)?;
            store.grant_trial(&mailbox_key, metering::trial_secs())?;
            Ok((account_id, action, link))
        })
        .await;

    match result {
        Ok(Ok((account_id, action, link))) => {
            info!(account = %account_id, action, "auth");
            Json(json!({
                "account_id": account_id,
                "action": action,
                "link": link,
                "watchable": probe.watchable(),
                "idle": probe.idle,
                "qresync": probe.qresync,
            }))
            .into_response()
        }
        _ => AppError(anyhow::anyhow!("auth failed")).into_response(),
    }
}

/// `GET /me` — the account behind the capability link: its members,
/// watches and balance.
async fn me(
    State(state): State<AppState>,
    CapabilityAccount(account_id): CapabilityAccount,
) -> Result<Response, AppError> {
    let store = state.store.clone();
    let body = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let balance = account_view(&store, &account_id, now_secs())?;
        let mailboxes: Vec<_> = store
            .memberships(&account_id)?
            .into_iter()
            .map(|m| json!({ "mailbox_key": m.mailbox_key, "login": m.login, "imap_host": m.imap_host }))
            .collect();
        let watches: Vec<WatchView> = store
            .watches_by_account(&account_id)?
            .into_iter()
            .map(WatchView::from)
            .collect();
        Ok(json!({
            "account_id": account_id,
            "mailboxes": mailboxes,
            "watches": watches,
            "balance": balance,
        }))
    })
    .await??;
    Ok(Json(body).into_response())
}

/// `POST /signout` — revoke the presented capability link.
async fn signout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized();
    };
    let store = state.store.clone();
    let revoked = tokio::task::spawn_blocking(move || store.revoke_capability(&token))
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false);
    Json(json!({ "status": "ok", "revoked": revoked })).into_response()
}

/// `GET /billing/packs` — the credit-pack catalogue (watch-time; price is
/// set in the payment provider).
async fn billing_packs(State(state): State<AppState>) -> Json<serde_json::Value> {
    let packs: Vec<_> = billing::PACKS
        .iter()
        .map(|pack| json!({ "id": pack.id, "secs": pack.secs }))
        .collect();
    Json(json!({ "provider": state.billing.provider(), "packs": packs }))
}

/// Body of `POST /billing/checkout`.
#[derive(Deserialize)]
struct CheckoutRequest {
    pack: String,
}

/// `POST /billing/checkout` — start a purchase for the link's account.
/// Records a pending session (what to grant) and returns the provider
/// checkout URL. Payment stays stateless on our side.
async fn billing_checkout(
    State(state): State<AppState>,
    CapabilityAccount(account_id): CapabilityAccount,
    Json(request): Json<CheckoutRequest>,
) -> Result<Response, AppError> {
    let Some(pack) = billing::pack(&request.pack) else {
        return Ok(bad_request("unknown pack"));
    };

    let session_id = random_secret();
    let store = state.store.clone();
    let create_id = account_id.clone();
    let create_session = session_id.clone();
    tokio::task::spawn_blocking(move || {
        store.create_session(&create_session, &create_id, pack.secs)
    })
    .await??;

    let url = state.billing.checkout_url(&session_id, &account_id, &pack);
    info!(account = %account_id, pack = pack.id, "checkout created");
    Ok(Json(json!({
        "provider": state.billing.provider(),
        "session_id": session_id,
        "checkout_url": url,
        "pack": pack.id,
        "secs": pack.secs,
    }))
    .into_response())
}

/// Body of `POST /billing/webhook`.
#[derive(Deserialize)]
struct WebhookRequest {
    session_id: String,
}

/// `POST /billing/webhook` — the provider's payment-confirmed callback.
/// Fulfils the session exactly once (idempotent against retries),
/// crediting the account's pool. A real provider impl would verify the
/// webhook signature over the raw body before trusting it.
async fn billing_webhook(
    State(state): State<AppState>,
    Json(request): Json<WebhookRequest>,
) -> Result<Response, AppError> {
    let store = state.store.clone();
    let fulfilled =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<(String, f64)>> {
            let Some((account_id, secs)) = store.fulfill_session(&request.session_id)? else {
                return Ok(None);
            };
            store.add_credit(&account_id, secs, now_secs() + POOL_TTL_SECS)?;
            Ok(Some((account_id, secs)))
        })
        .await??;

    match fulfilled {
        Some((account_id, secs)) => {
            info!(account = %account_id, secs, "checkout fulfilled");
            Ok(Json(
                json!({ "status": "fulfilled", "account_id": account_id, "credited_secs": secs }),
            )
            .into_response())
        }
        None => Ok(
            Json(json!({ "status": "ignored", "reason": "unknown or already fulfilled" }))
                .into_response(),
        ),
    }
}

fn not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "watch not found", "id": id })),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

/// A random 256-bit hex secret, for a rotation with no supplied secret.
fn random_secret() -> String {
    format!(
        "{:032x}{:032x}",
        rand::rng().random::<u128>(),
        rand::rng().random::<u128>()
    )
}

/// anyhow-to-500 adapter for handlers.
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

fn default_port() -> u16 {
    993
}

fn default_mailbox() -> String {
    String::from("INBOX")
}

fn default_true() -> bool {
    true
}

fn default_limit() -> u32 {
    50
}
