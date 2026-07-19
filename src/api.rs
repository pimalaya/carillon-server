//! The HTTP control API.
//!
//! A small axum service to manage watches at runtime and inspect the
//! delivery log. It writes the store (the source of truth) and nudges
//! the supervisor to reconcile; the supervisor owns all the
//! connections. This is the prototype's stand-in for the eventual
//! dashboard and billing gate.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::info;

use crate::crypto::Crypto;
use crate::store::{Store, Watch};
use crate::supervisor::SupervisorCmd;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// The store (source of truth for watches and deliveries).
    pub store: Arc<Store>,
    /// Password encryptor.
    pub crypto: Arc<Crypto>,
    /// Channel to ask the supervisor to reconcile after a mutation.
    pub commands: mpsc::Sender<SupervisorCmd>,
}

/// Builds the control API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/watches", get(list_watches).post(create_watch))
        .route("/watches/{id}", delete(delete_watch))
        .route("/watches/{id}/pause", post(pause_watch))
        .route("/watches/{id}/resume", post(resume_watch))
        .route("/deliveries", get(list_deliveries))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
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
