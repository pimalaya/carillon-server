//! The HTTP control API.
//!
//! A small axum service to manage watches at runtime and inspect the
//! delivery log. It writes the store (the source of truth) and nudges
//! the supervisor to reconcile; the supervisor owns all the
//! connections. This is the prototype's stand-in for the eventual
//! dashboard and billing gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::crypto::Crypto;
use crate::delivery::validate_notify_url;
use crate::imap::session::{self, ImapAccount};
use crate::ratelimit::RateLimiter;
use crate::store::{Store, Watch};
use crate::supervisor::SupervisorCmd;

/// Default rotation overlap: how long the previous HMAC secret keeps
/// being signed with so a receiver has time to update.
const DEFAULT_ROTATE_OVERLAP: Duration = Duration::from_secs(24 * 60 * 60);

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
}

/// Builds the control API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/test", post(test_connect))
        .route("/watches", get(list_watches).post(create_watch))
        .route("/watches/{id}", delete(delete_watch))
        .route("/watches/{id}/pause", post(pause_watch))
        .route("/watches/{id}/resume", post(resume_watch))
        .route("/watches/{id}/rotate-secret", post(rotate_secret))
        .route("/deliveries", get(list_deliveries))
        .with_state(state)
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
        active: request.active,
    };

    let id = watch.id.clone();
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.upsert_watch(&watch)).await??;
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
