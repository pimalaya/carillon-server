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
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

use crate::billing::{self, Billing};
use crate::crypto::Crypto;
use crate::delivery::{self, validate_notify_url};
use crate::discover;
use crate::imap::session::{self, ImapAccount, ImapAuth};
use crate::live::LiveBus;
use crate::metering::{self, POOL_TTL_SECS};
use crate::oauth;
use crate::ratelimit::RateLimiter;
use crate::store::{OauthCredential, OauthSession, Store, Watch};
use crate::supervisor::{self, SupervisorCmd};
use crate::util::now_secs;
use url::Url;

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
    /// Shared, pooled HTTP client for the `/webhook/test` one-shot POST.
    pub http: reqwest::Client,
    /// Per-`(IP, login)` limiter guarding the `/test` oracle surface.
    pub test_limiter: Arc<RateLimiter>,
    /// Per-`(IP, login)` limiter guarding the `/auth` oracle surface.
    pub auth_limiter: Arc<RateLimiter>,
    /// Per-IP limiter throttling `/discover` (it makes outbound requests).
    pub discover_limiter: Arc<RateLimiter>,
    /// Live bus the `/events` SSE stream subscribes to.
    pub live: LiveBus,
    /// Flips to `true` when the server begins shutting down. The `/events`
    /// SSE stream watches it and ends, so a held connection cannot block
    /// graceful shutdown (an open SSE body never completes on its own, and
    /// hyper waits for every in-flight connection).
    pub shutdown: watch::Receiver<bool>,
    /// Payment provider adapter (stubbed until keys are wired).
    pub billing: Arc<dyn Billing>,
    /// Optional master token granting unscoped access to every account
    /// (ops / headless self-host). `None` = no unscoped access exists;
    /// every data route is reachable only via a capability link.
    pub admin_token: Option<String>,
    /// Public base URL of this API; the OAuth redirect URI is
    /// `{public_url}/oauth/callback`.
    pub public_url: String,
    /// Origin the OAuth-callback popup posts its result to (the dashboard).
    pub dashboard_origin: String,
    /// Config-provided OAuth client overrides (own apps) for the static
    /// providers; empty = the built-in Thunderbird public clients.
    pub oauth_clients: oauth::StaticClients,
}

/// Builds the control API router. `ui_dir`, if set, is served as static
/// files at the origin (self-host embedding a `carillon-admin` build);
/// `cors_origin`, if set, enables cross-origin access for a CDN-served
/// front.
pub fn router(state: AppState, ui_dir: Option<PathBuf>, cors_origin: Option<String>) -> Router {
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/openapi.yaml", get(openapi))
        .route("/discover", post(discover))
        .route("/oauth/start", post(oauth_start))
        .route("/oauth/callback", get(oauth_callback))
        .route("/test", post(test_connect))
        .route("/mailboxes", post(list_mailboxes))
        .route("/webhook/test", post(test_webhook))
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

/// Body of `POST /discover`: the "put anything" identifier.
#[derive(Deserialize)]
struct DiscoverRequest {
    /// An email address, or a bare domain / server host.
    input: String,
}

/// `POST /discover` — resolve an email/domain/server to IMAP onboarding
/// **choices**: each a server endpoint + one auth method (password / OAuth /
/// token), grouped across discovery mechanisms (via `io-pim-discovery`).
/// Public onboarding surface, like `/test`: no credit, no account — just a
/// hint the wizard confirms. Rate-limited per IP because it makes outbound
/// DNS/HTTP requests. Never surfaces an error for an unresolvable input;
/// it returns an empty choice list and the user types the server in.
async fn discover(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<DiscoverRequest>,
) -> Response {
    let input = request.input.trim().to_string();
    if input.is_empty() {
        return bad_request("input is required");
    }

    if let Err(retry_after) = state.discover_limiter.check(&peer.ip().to_string()) {
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    let lookup = input.clone();
    let choices = match tokio::task::spawn_blocking(move || discover::discover_imap(&lookup)).await
    {
        Ok(choices) => choices,
        Err(err) => return AppError(anyhow::anyhow!(err)).into_response(),
    };

    info!(input, count = choices.len(), "discovery");
    Json(json!({ "input": input, "choices": choices })).into_response()
}

/// How long a pending OAuth flow stays valid before it is pruned.
const OAUTH_SESSION_TTL: i64 = 15 * 60;

/// Body of `POST /oauth/start`: the discovered OAuth method (an issuer or
/// direct endpoints, from a discovery choice) plus the mailbox to watch.
#[derive(Deserialize)]
struct OauthStartRequest {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    login: String,
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    #[serde(default = "default_mailbox")]
    mailbox: String,
}

/// `POST /oauth/start` — begin an OAuth login for a mailbox. Resolves the
/// provider (dynamic registration where offered — Fastmail — else a known
/// public client for Google/Microsoft), builds the authorization URL, and
/// stashes the flow keyed by its CSRF state. The dashboard opens the URL in a
/// popup; the provider redirects the browser to `/oauth/callback`. Public
/// onboarding surface, rate-limited per `(IP, login)`.
async fn oauth_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<OauthStartRequest>,
) -> Response {
    let limit_key = format!("{}|{}", peer.ip(), request.login);
    if let Err(retry_after) = state.auth_limiter.check(&limit_key) {
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    // Join the account behind a presented capability link, if any.
    let account_id =
        bearer(&headers).and_then(|token| state.store.resolve_capability(&token).ok().flatten());

    let redirect_uri = format!("{}/oauth/callback", state.public_url.trim_end_matches('/'));
    let input = oauth::AuthInput {
        issuer: request.issuer,
        authorization_endpoint: request.authorization_endpoint,
        token_endpoint: request.token_endpoint,
        scope: request.scope,
    };

    let plan_redirect = redirect_uri.clone();
    let clients = state.oauth_clients.clone();
    let planned = match tokio::task::spawn_blocking(move || {
        oauth::plan_authorization(&input, &plan_redirect, &clients)
    })
    .await
    {
        Ok(Ok(planned)) => planned,
        Ok(Err(err)) => return bad_request(&format!("OAuth setup failed: {err:#}")),
        Err(err) => return AppError(anyhow::anyhow!(err)).into_response(),
    };

    let enc_client_secret = match &planned.client_secret {
        Some(secret) => match state.crypto.encrypt(secret) {
            Ok(enc) => Some(enc),
            Err(err) => return AppError(err).into_response(),
        },
        None => None,
    };

    let url = planned.auth.url.clone();
    let oauth_session = OauthSession {
        state: planned.auth.state,
        verifier: planned.auth.verifier,
        redirect_uri,
        token_endpoint: planned.token_endpoint,
        client_id: planned.client_id,
        enc_client_secret,
        resource: planned.resource,
        scope: planned.scope,
        account_id,
        login: request.login,
        imap_host: request.imap_host,
        imap_port: request.imap_port,
        mailbox: request.mailbox,
    };

    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.create_oauth_session(&oauth_session)).await {
        Ok(Ok(())) => Json(json!({ "authorization_url": url })).into_response(),
        _ => AppError(anyhow::anyhow!("cannot store the OAuth session")).into_response(),
    }
}

/// Query of `GET /oauth/callback`: the provider's redirect.
#[derive(Deserialize)]
struct OauthCallbackParams {
    #[serde(default)]
    state: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// `GET /oauth/callback` — the provider's redirect. Exchanges the code,
/// verifies the token actually authenticates to IMAP (`OAUTHBEARER`), mints
/// or joins the capability-link account (exactly like `/auth`), and stores the
/// encrypted refresh token as the mailbox's OAuth credential. Returns a small
/// HTML page that hands the result back to the dashboard window that opened
/// the popup and closes.
async fn oauth_callback(
    State(state): State<AppState>,
    Query(params): Query<OauthCallbackParams>,
) -> Response {
    if let Some(error) = params.error {
        let detail = params.error_description.unwrap_or(error);
        return oauth_popup(&state.dashboard_origin, oauth_err(&detail));
    }
    let Some(code) = params.code else {
        return oauth_popup(
            &state.dashboard_origin,
            oauth_err("missing authorization code"),
        );
    };
    if params.state.is_empty() {
        return oauth_popup(&state.dashboard_origin, oauth_err("missing state"));
    }

    // Consume the pending flow (single-use, CSRF-checked by the state key).
    let store = state.store.clone();
    let state_key = params.state.clone();
    let oauth_session = match tokio::task::spawn_blocking(move || {
        store.take_oauth_session(&state_key, OAUTH_SESSION_TTL)
    })
    .await
    {
        Ok(Ok(Some(session))) => session,
        Ok(Ok(None)) => {
            return oauth_popup(
                &state.dashboard_origin,
                oauth_err("unknown or expired sign-in; start again"),
            );
        }
        _ => return oauth_popup(&state.dashboard_origin, oauth_err("server error")),
    };

    // Exchange the code for tokens.
    let client_secret = match &oauth_session.enc_client_secret {
        Some(enc) => match state.crypto.decrypt(enc) {
            Ok(secret) => Some(secret),
            Err(_) => {
                return oauth_popup(
                    &state.dashboard_origin,
                    oauth_err("cannot read client secret"),
                );
            }
        },
        None => None,
    };
    let token_endpoint: Url = match oauth_session.token_endpoint.parse() {
        Ok(url) => url,
        Err(_) => return oauth_popup(&state.dashboard_origin, oauth_err("bad token endpoint")),
    };
    let client = oauth::ClientId::Static {
        client_id: oauth_session.client_id.clone(),
        client_secret,
    };
    let redirect_uri = oauth_session.redirect_uri.clone();
    let verifier = oauth_session.verifier.clone();
    let tokens = match tokio::task::spawn_blocking(move || {
        oauth::exchange_code(&token_endpoint, &client, &redirect_uri, &code, &verifier)
    })
    .await
    {
        Ok(Ok(tokens)) => tokens,
        Ok(Err(err)) => {
            return oauth_popup(
                &state.dashboard_origin,
                oauth_err(&format!("token exchange failed: {err:#}")),
            );
        }
        _ => return oauth_popup(&state.dashboard_origin, oauth_err("server error")),
    };

    let Some(refresh_token) = tokens.refresh_token.clone() else {
        return oauth_popup(
            &state.dashboard_origin,
            oauth_err("provider returned no refresh token (missing offline access)"),
        );
    };

    // Prove the token authenticates to IMAP (and check IDLE/QRESYNC).
    let probe_account = ImapAccount {
        host: oauth_session.imap_host.clone(),
        port: oauth_session.imap_port,
        login: oauth_session.login.clone(),
        auth: ImapAuth::OauthBearer(tokens.access_token.clone()),
        mailbox: oauth_session.mailbox.clone(),
    };
    let probe = session::probe(&state.connector, &probe_account).await;
    if !probe.authenticated {
        return oauth_popup(
            &state.dashboard_origin,
            oauth_err(&format!(
                "OAuth token did not authenticate to IMAP: {}",
                probe.error.unwrap_or_default()
            )),
        );
    }
    let watchable = probe.watchable();
    let missing = probe.missing();
    // QRESYNC-less providers (Gmail, Yahoo, …) are still watchable, but new
    // mail only — the UI surfaces that as a warning.
    let qresync = probe.qresync;

    let enc_refresh_token = match state.crypto.encrypt(&refresh_token) {
        Ok(enc) => enc,
        Err(_) => return oauth_popup(&state.dashboard_origin, oauth_err("server error")),
    };

    let mailbox_key = metering::mailbox_key(&oauth_session.login, &oauth_session.imap_host);
    // Advisory dedup hint for the wizard (create still enforces the 409).
    let already_watched = mailbox_already_watched(&state, &mailbox_key, None)
        .await
        .unwrap_or(false);
    let expires = Some(now_secs() + CAPABILITY_TTL.as_secs() as i64);
    // Keep the mailbox context for the success payload before the session moves.
    let login = oauth_session.login.clone();
    let imap_host = oauth_session.imap_host.clone();
    let imap_port = oauth_session.imap_port;
    let mailbox = oauth_session.mailbox.clone();

    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, String)> {
        // Join the presented account, else recover the mailbox's account, else
        // create a fresh one — the same identity flow as `/auth`.
        let (account_id, link) = match oauth_session.account_id.clone() {
            Some(id) => {
                let link = random_secret();
                store.issue_capability(&id, &link, expires)?;
                (id, link)
            }
            None => match store.account_of_mailbox(&mailbox_key)? {
                Some(id) => {
                    let link = random_secret();
                    store.issue_capability(&id, &link, expires)?;
                    (id, link)
                }
                None => {
                    let id = random_secret();
                    store.ensure_account(&id)?;
                    let link = random_secret();
                    store.issue_capability(&id, &link, expires)?;
                    (id, link)
                }
            },
        };
        store.add_membership(
            &account_id,
            &mailbox_key,
            &oauth_session.login,
            &oauth_session.imap_host,
        )?;
        store.grant_trial(&mailbox_key, metering::trial_secs())?;
        store.upsert_oauth_credential(&OauthCredential {
            account_id: account_id.clone(),
            mailbox_key,
            enc_refresh_token,
            token_endpoint: oauth_session.token_endpoint,
            client_id: oauth_session.client_id,
            enc_client_secret: oauth_session.enc_client_secret,
            resource: oauth_session.resource,
            scope: oauth_session.scope,
        })?;
        Ok((account_id, link))
    })
    .await;

    match result {
        Ok(Ok((account_id, link))) => {
            info!(account = %account_id, "oauth login");
            oauth_popup(
                &state.dashboard_origin,
                json!({
                    "type": "carillon-oauth",
                    "ok": true,
                    "link": link,
                    "account_id": account_id,
                    "watchable": watchable,
                    "missing": missing,
                    "qresync": qresync,
                    "already_watched": already_watched,
                    "login": login,
                    "imap_host": imap_host,
                    "imap_port": imap_port,
                    "mailbox": mailbox,
                }),
            )
        }
        _ => oauth_popup(&state.dashboard_origin, oauth_err("server error")),
    }
}

/// A content-free error payload for the OAuth popup.
fn oauth_err(message: &str) -> serde_json::Value {
    json!({ "type": "carillon-oauth", "ok": false, "error": message })
}

/// A tiny HTML page that hands the OAuth result to the dashboard window that
/// opened the popup (via `postMessage` to its origin) and closes. `<` is
/// escaped in the embedded JSON so a value cannot break out of the script.
fn oauth_popup(dashboard_origin: &str, payload: serde_json::Value) -> Response {
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c");
    let origin = serde_json::to_string(dashboard_origin)
        .unwrap_or_else(|_| "\"*\"".into())
        .replace('<', "\\u003c");
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Carillon</title></head>\
         <body style=\"font-family:system-ui,sans-serif;padding:2rem\">Signed in — you can close this window.\
         <script>(function(){{try{{if(window.opener){{window.opener.postMessage({json},{origin});}}}}catch(e){{}}setTimeout(function(){{window.close();}},150);}})();</script>\
         </body></html>"
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
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
    /// Advisory: this mailbox already has a watch. Onboarding surfaces it so
    /// the wizard can stop before activation (create is a hard `409`).
    already_watched: bool,
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
        auth: ImapAuth::Password(request.password),
        mailbox: request.mailbox,
    };

    let probe = session::probe(&state.connector, &account).await;
    // Advisory dedup hint (never blocks the probe itself); create enforces it.
    let mailbox_key = metering::mailbox_key(&account.login, &account.host);
    let already_watched = mailbox_already_watched(&state, &mailbox_key, None)
        .await
        .unwrap_or(false);
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
        already_watched,
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

/// Body of `POST /mailboxes`: the connection to list folders on. A
/// non-empty `password` lists via `LOGIN` (unauthenticated, rate-limited
/// like `/test`); an empty one lists an **OAuth** mailbox using the stored
/// credential — which requires a capability link scoping the caller.
#[derive(Deserialize)]
struct MailboxesRequest {
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    #[serde(default)]
    password: String,
}

/// `POST /mailboxes` — authenticate and `LIST` the account's selectable
/// mailboxes, so onboarding can offer a picker (defaulting to the inbox)
/// instead of a free-text folder field. Rate-limited per `(IP, login)`,
/// same as `/test`. Returns `{ mailboxes: [{ name, role }] }`.
async fn list_mailboxes(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MailboxesRequest>,
) -> Response {
    let key = format!("{}|{}", peer.ip(), request.login);
    if let Err(retry_after) = state.test_limiter.check(&key) {
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    let mut account = ImapAccount {
        host: request.imap_host,
        port: request.imap_port,
        login: request.login,
        auth: ImapAuth::Password(request.password.clone()),
        mailbox: default_mailbox(),
    };

    // Empty password ⇒ OAuth: resolve the stored credential for the caller's
    // account and mint a fresh access token, exactly as the watcher does.
    if request.password.is_empty() {
        let Some(token) = bearer(&headers) else {
            return unauthorized();
        };
        let account_id = match state.store.resolve_capability(&token) {
            Ok(Some(id)) => id,
            _ => return unauthorized(),
        };
        match supervisor::resolve_oauth_access(&state.store, &state.crypto, &account_id, &account)
            .await
        {
            Ok(token) => account.auth = ImapAuth::OauthBearer(token),
            Err(err) => return bad_request(&format!("cannot authenticate mailbox: {err:#}")),
        }
    }

    match session::list_mailboxes(&state.connector, &account).await {
        Ok(mailboxes) => Json(json!({ "mailboxes": mailboxes })).into_response(),
        Err(err) => bad_request(&format!("cannot list mailboxes: {err:#}")),
    }
}

/// Body of `POST /webhook/test`: where to send the one-shot test event and
/// the secret to sign it with (the wizard already holds the watch's secret).
#[derive(Deserialize)]
struct WebhookTestRequest {
    notify_url: String,
    hmac_secret: String,
}

/// `POST /webhook/test` — POST one synthetic, signed `test` event to the
/// given URL so onboarding can prove the endpoint is reachable and
/// verifying signatures **before** activating. Rate-limited per IP (it
/// makes an outbound request to a caller-supplied URL). Never retried.
async fn test_webhook(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<WebhookTestRequest>,
) -> Response {
    if let Err(retry_after) = state.discover_limiter.check(&peer.ip().to_string()) {
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    if let Err(err) = validate_notify_url(&request.notify_url) {
        return bad_request(&err.to_string());
    }

    let outcome =
        delivery::deliver_test(&state.http, &request.notify_url, &request.hmac_secret).await;
    Json(json!({
        "ok": outcome.ok,
        "status": outcome.status,
        "error": outcome.error,
    }))
    .into_response()
}

/// Whether some existing watch (other than `exclude_id`) already watches the
/// same mailbox identity (normalised `login`+`host`). The onboarding dedup
/// guard: one watch per account-mailbox, so re-onboarding a watched mailbox
/// is refused rather than silently doubled.
async fn mailbox_already_watched(
    state: &AppState,
    mailbox_key: &str,
    exclude_id: Option<&str>,
) -> Result<bool, AppError> {
    let store = state.store.clone();
    let identities = tokio::task::spawn_blocking(move || store.watch_identities()).await??;
    let exclude = exclude_id.map(str::to_owned);
    Ok(identities.iter().any(|(id, login, host)| {
        Some(id.as_str()) != exclude.as_deref() && metering::mailbox_key(login, host) == mailbox_key
    }))
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

async fn list_watches(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<WatchView>>, AppError> {
    let store = state.store.clone();
    let scope = caller.scope();
    let watches = tokio::task::spawn_blocking(move || match scope {
        Some(account_id) => store.watches_by_account(&account_id),
        None => store.all_watches(),
    })
    .await??;
    Ok(Json(watches.into_iter().map(WatchView::from).collect()))
}

/// Body of `POST /watches`. The password is plaintext on the wire and
/// encrypted at rest. Omit it to create an **OAuth** watch — the mailbox
/// must already have an OAuth credential from a completed `/oauth/callback`.
#[derive(Deserialize)]
struct CreateWatch {
    id: String,
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    #[serde(default)]
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
    caller: Caller,
    Json(request): Json<CreateWatch>,
) -> Result<Response, AppError> {
    if let Err(err) = validate_notify_url(&request.notify_url) {
        return Ok(bad_request(&err.to_string()));
    }

    let mailbox_key = metering::mailbox_key(&request.login, &request.imap_host);

    // Dedup guard: refuse to onboard a mailbox that already has a watch
    // (§ one watch per account-mailbox). An upsert of the *same* watch id is
    // still allowed (edit-in-place); a new id for a watched mailbox is not.
    if mailbox_already_watched(&state, &mailbox_key, Some(&request.id)).await? {
        return Ok(conflict("this mailbox is already being watched"));
    }

    // Resolve the billing account and enforce ownership. A scoped caller
    // watches under *its own* account (the body's account_id is ignored),
    // and only a mailbox it has proven control of via `/auth` — you cannot
    // watch what you cannot log into (the anti-farming linchpin, § DEC 3).
    // The unscoped admin may place the watch in any account (ops / import).
    let account_id = match caller.scope() {
        Some(account_id) => {
            let store = state.store.clone();
            let (owner, key) = (account_id.clone(), mailbox_key.clone());
            let proven =
                tokio::task::spawn_blocking(move || store.mailbox_belongs(&owner, &key)).await??;
            if !proven {
                return Ok(forbidden(
                    "authenticate this mailbox first (POST /auth) before watching it",
                ));
            }
            account_id
        }
        None => request
            .account_id
            .clone()
            .unwrap_or_else(|| request.id.clone()),
    };

    // Credential kind: an explicit password, else an OAuth credential the
    // caller proved earlier via `/oauth/callback` for this mailbox.
    let (auth_kind, enc_password) = if !request.password.is_empty() {
        (
            "password".to_string(),
            state.crypto.encrypt(&request.password)?,
        )
    } else {
        let store = state.store.clone();
        let (owner, key) = (account_id.clone(), mailbox_key.clone());
        let has_oauth =
            tokio::task::spawn_blocking(move || store.get_oauth_credential(&owner, &key))
                .await??
                .is_some();
        if !has_oauth {
            return Ok(bad_request(
                "no credential: provide a password, or complete OAuth for this mailbox first",
            ));
        }
        ("oauth".to_string(), String::new())
    };

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
        auth_kind,
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

/// Authorizes a caller for a watch by id. `Ok(None)` = allowed;
/// `Ok(Some(resp))` = a `404` rejection that hides the watch's existence
/// from other accounts, indistinguishable from a genuinely missing watch.
async fn authorize_watch(
    state: &AppState,
    caller: &Caller,
    id: &str,
) -> Result<Option<Response>, AppError> {
    let store = state.store.clone();
    let lookup = id.to_owned();
    let owner = tokio::task::spawn_blocking(move || store.watch_account(&lookup)).await??;
    Ok(match owner {
        Some(account_id) if caller.owns(&account_id) => None,
        _ => Some(not_found(id)),
    })
}

async fn delete_watch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }

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
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }
    set_active(state, id, false).await
}

async fn resume_watch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }
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
    caller: Caller,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }

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
    caller: Caller,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<Vec<DeliveryView>>, AppError> {
    let limit = query.limit.clamp(1, 1000);

    // Scope to the caller's account. A scoped caller may filter to one of
    // *its own* watches (`?account=<watch id>`); asking for a watch it does
    // not own yields an empty log, never another account's deliveries. The
    // unscoped admin keeps the global view with the optional filter.
    let scope = caller.scope();
    let filter = query.account.clone();
    let store = state.store.clone();
    let rows = tokio::task::spawn_blocking(move || match scope {
        None => store.recent_deliveries(filter.as_deref(), limit),
        Some(account_id) => match filter {
            Some(watch_id) => match store.watch_account(&watch_id)? {
                Some(owner) if owner == account_id => {
                    store.recent_deliveries(Some(&watch_id), limit)
                }
                _ => Ok(Vec::new()),
            },
            None => store.recent_deliveries_by_owner(&account_id, limit),
        },
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
/// browser-native (`EventSource`), proxy-friendly. A slow client that lags
/// simply misses the oldest events (surfaced as a `lagged` SSE event)
/// rather than stalling the bus. Purely observational and content-free.
///
/// A forwarding task pumps the (scoped) broadcast into a bounded channel
/// that backs the response body, and ends on **either** server shutdown or
/// client disconnect — so a held connection never blocks graceful shutdown
/// (an open SSE body never completes on its own, and hyper waits for it).
async fn events(
    State(state): State<AppState>,
    caller: Caller,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Scope the live fan-out: a capability-link subscriber sees only its
    // own account's events (delivery/status/notice all carry the billing
    // account they concern); the unscoped admin sees everything.
    let scope = caller.scope();
    let mut live = state.live.subscribe();
    let mut shutdown = state.shutdown.clone();
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                // Prefer shutdown, so it wins promptly over a busy bus.
                biased;
                _ = shutdown.wait_for(|stopping| *stopping) => break,
                message = live.recv() => match message {
                    Ok(routed) => {
                        let visible = scope.as_deref().is_none_or(|id| routed.account_id == id);
                        if !visible {
                            continue;
                        }
                        Event::default()
                            .event(routed.event.name())
                            .data(serde_json::to_string(&routed.event).unwrap_or_default())
                    }
                    // The subscriber fell behind and lost some events.
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        Event::default().event("lagged").data(skipped.to_string())
                    }
                    // The bus closed (server tearing down).
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            // A send error means the client disconnected (body dropped).
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
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

async fn list_accounts(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<AccountView>>, AppError> {
    let store = state.store.clone();
    let scope = caller.scope();
    let views = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<AccountView>> {
        let now = now_secs();
        match scope {
            // Scoped callers see only their own account (the dashboard
            // reads it via `/me`; this keeps the list route from leaking
            // the fleet).
            Some(account_id) => Ok(vec![account_view(&store, &account_id, now)?]),
            None => store
                .all_accounts()?
                .into_iter()
                .map(|account| account_view(&store, &account.id, now))
                .collect(),
        }
    })
    .await??;
    Ok(Json(views))
}

async fn get_account(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    if !caller.owns(&id) {
        return Ok(not_found(&id));
    }
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
    caller: Caller,
    Path(id): Path<String>,
    Json(request): Json<CreditRequest>,
) -> Result<Response, AppError> {
    if !caller.owns(&id) {
        return Ok(not_found(&id));
    }
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
    caller: Caller,
    Path(id): Path<String>,
    Json(request): Json<AutoRefillRequest>,
) -> Result<Response, AppError> {
    if !caller.owns(&id) {
        return Ok(not_found(&id));
    }
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

/// The authenticated caller behind a bearer token. Every data route
/// requires one — there is no unauthenticated access to watches,
/// deliveries or events (§ DECISIONS 5). A caller is either the unscoped
/// **admin** (presented the configured `admin_token` — ops / headless
/// self-host) or a single **account** (presented a valid capability link,
/// scoped to its own watches and pool).
enum Caller {
    /// The ops master token: sees and touches every account.
    Admin,
    /// A capability-link account: scoped to its own resources.
    Account(String),
}

impl Caller {
    /// The account to scope to, or `None` for the unscoped admin.
    fn scope(&self) -> Option<String> {
        match self {
            Caller::Admin => None,
            Caller::Account(id) => Some(id.clone()),
        }
    }

    /// Whether this caller may act on a resource owned by `account_id`.
    fn owns(&self, account_id: &str) -> bool {
        match self {
            Caller::Admin => true,
            Caller::Account(id) => id == account_id,
        }
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let token = bearer(&parts.headers).ok_or_else(unauthorized)?;
        // The admin token, if configured, wins. Compare digests so the
        // comparison leaks nothing exploitable about the secret.
        if let Some(admin) = &state.admin_token
            && token_matches(&token, admin)
        {
            return Ok(Caller::Admin);
        }
        match state.store.resolve_capability(&token) {
            Ok(Some(account_id)) => Ok(Caller::Account(account_id)),
            _ => Err(unauthorized()),
        }
    }
}

/// Constant-preimage token comparison: compares SHA-256 digests rather
/// than the raw strings, so a timing side-channel on the byte comparison
/// reveals nothing about the secret (digests are preimage-resistant).
fn token_matches(token: &str, expected: &str) -> bool {
    Sha256::digest(token.as_bytes()) == Sha256::digest(expected.as_bytes())
}

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
        auth: ImapAuth::Password(request.password),
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

fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response()
}

fn conflict(message: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
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
