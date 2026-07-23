//! The HTTP control API.
//!
//! A small axum service to manage watches at runtime and inspect the
//! delivery log. It writes the store (the source of truth) and nudges
//! the supervisor to reconcile; the supervisor owns all the connections.
//! The prototype's stand-in for the eventual dashboard and billing gate.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
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
use crate::carddav::session::{CardDavAccount, CardDavAuth};
use crate::crypto::Crypto;
use crate::delivery::{self, validate_notify_url};
use crate::discover;
use crate::email::Mailer;
use crate::guard;
use crate::imap::session::{self, ImapAccount, ImapAuth};
use crate::live::LiveBus;
use crate::metering;
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
const OPENAPI_YAML: &str = include_str!("../openapi.yaml");

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
    /// Flips to `true` when the server begins shutting down. The
    /// `/events` SSE stream watches it and ends, so a held connection
    /// cannot block graceful shutdown.
    pub shutdown: watch::Receiver<bool>,
    /// Payment provider adapter (stubbed until keys are wired).
    pub billing: Arc<Billing>,
    /// Transactional email sender (magic links + notices).
    pub mailer: Arc<Mailer>,
    /// Whether watching is credit-metered (SaaS), so the dashboard can
    /// hide credit UI on an unmetered self-host.
    pub metered: bool,
    /// Fair-use cap: max distinct mailboxes a scoped account may watch.
    pub max_watches: usize,
    /// Default CardDAV poll interval (seconds), surfaced on `/me`.
    pub carddav_poll_secs: u64,
    /// Optional master token granting unscoped access to every account
    /// (ops / headless self-host). `None` means no unscoped access
    /// exists; every data route is reachable only via a capability link.
    pub admin_token: Option<String>,
    /// Public base URL of this API; the OAuth redirect URI is
    /// `{public_url}/oauth/callback`.
    pub public_url: String,
    /// Origin the OAuth-callback popup posts its result to (the
    /// dashboard).
    pub dashboard_origin: String,
    /// Config-provided OAuth client overrides (own apps) for the static
    /// providers; empty uses the built-in Thunderbird public clients.
    pub oauth_clients: oauth::StaticClients,
}

/// Builds the control API router. `ui_dir`, if set, is served as static
/// files at the origin (self-host embedding a `carillon-frontend` build);
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
        .route("/addressbooks", post(list_addressbooks))
        .route("/webhook/test", post(test_webhook))
        .route("/auth", post(auth))
        .route("/forget", post(forget_account))
        .route("/auth/magic/request", post(magic_request))
        .route(
            "/auth/magic/verify",
            get(magic_verify_get).post(magic_verify),
        )
        .route("/me", get(me))
        .route("/signout", post(signout))
        .route("/watches", get(list_watches).post(create_watch))
        .route("/watches/{id}", delete(delete_watch))
        .route("/watches/{id}/pause", post(pause_watch))
        .route("/watches/{id}/resume", post(resume_watch))
        .route("/watches/{id}/rotate-secret", post(rotate_secret))
        .route("/watches/{id}/activate", post(activate_watch))
        .route("/watches/{id}/auto-renew", post(set_watch_auto_renew))
        .route("/deliveries", get(list_deliveries))
        .route("/events", get(events))
        .route("/accounts", get(list_accounts))
        .route("/accounts/{id}", get(get_account))
        .route("/billing/checkout", post(billing_checkout))
        .route("/billing/webhook", post(billing_webhook));

    // NOTE: with a UI, static files own `/` (unknown paths fall back to
    // the SPA entrypoint); without one, `/` returns service metadata.
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
        "name": "carillon-backend",
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
/// `Authorization` bearer header, pairing with the localStorage
/// capability link (no cookies/CSRF).
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

/// Body of `POST /discover`: the "put anything" identifier + what to watch.
#[derive(Deserialize)]
struct DiscoverRequest {
    /// An email address, or a bare domain / server host.
    input: String,
    /// What to watch: `email` (IMAP, the default) or `contacts`
    /// (CardDAV). The type-first wizard picks this before discovering, so
    /// only the relevant protocol is resolved.
    #[serde(default)]
    kind: Option<String>,
}

/// `POST /discover`: resolve an email/domain/server to onboarding
/// choices, each a server endpoint + one auth method (password / OAuth /
/// token), grouped across discovery mechanisms. Public onboarding
/// surface, like `/test`: no credit, no account. Rate-limited per IP
/// because it makes outbound DNS/HTTP requests. Never surfaces an error
/// for an unresolvable input; it returns an empty choice list.
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

    // NOTE: resolve only the requested protocol (Email→IMAP default,
    // Contacts→CardDAV). Both serialize to a `choices` array per kind.
    let contacts = matches!(request.kind.as_deref(), Some("contacts") | Some("carddav"));
    let kind_label = if contacts { "contacts" } else { "email" };
    let lookup = input.clone();
    let choices = match tokio::task::spawn_blocking(move || {
        if contacts {
            serde_json::to_value(discover::discover_carddav(&lookup))
        } else {
            serde_json::to_value(discover::discover_imap(&lookup))
        }
    })
    .await
    {
        Ok(Ok(choices)) => choices,
        Ok(Err(err)) => return AppError(anyhow::anyhow!(err)).into_response(),
        Err(err) => return AppError(anyhow::anyhow!(err)).into_response(),
    };

    let count = choices.as_array().map(|choices| choices.len()).unwrap_or(0);
    info!(input, kind = kind_label, count, "discovery");
    Json(json!({ "input": input, "kind": kind_label, "choices": choices })).into_response()
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
    /// For an IMAP login, the IMAP host. For a CardDAV login, the DAV
    /// host, which keys the mailbox as the poller resolves the credential
    /// by.
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    #[serde(default = "default_mailbox")]
    mailbox: String,
    /// What this OAuth login is for: `imap` (default) or `carddav`.
    #[serde(default = "default_source_kind")]
    source_kind: String,
    /// CardDAV collection context-root URL (required when
    /// `source_kind=carddav`).
    #[serde(default)]
    carddav_url: Option<String>,
}

/// `POST /oauth/start`: begin an OAuth login for a mailbox. Resolves the
/// provider (dynamic registration where offered, else a known public
/// client), builds the authorization URL, and stashes the flow keyed by
/// its CSRF state. The dashboard opens the URL in a popup; the provider
/// redirects the browser to `/oauth/callback`. Public onboarding surface,
/// rate-limited per `(IP, login)`.
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

    // NOTE: join the account behind a presented capability link, if any.
    let account_id =
        bearer(&headers).and_then(|token| state.store.resolve_capability(&token).ok().flatten());

    let redirect_uri = format!("{}/oauth/callback", state.public_url.trim_end_matches('/'));
    let input = oauth::AuthInput {
        issuer: request.issuer,
        authorization_endpoint: request.authorization_endpoint,
        token_endpoint: request.token_endpoint,
        scope: request.scope,
        contacts: request.source_kind == "carddav",
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
        source_kind: request.source_kind,
        carddav_url: request.carddav_url,
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

/// `GET /oauth/callback`: the provider's redirect. Exchanges the code,
/// verifies the token authenticates (`OAUTHBEARER`), mints or joins the
/// capability-link account (like `/auth`), and stores the encrypted
/// refresh token as the mailbox's OAuth credential. Returns a small HTML
/// page that hands the result back to the dashboard popup and closes.
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

    // NOTE: consume the pending flow (single-use, CSRF-checked by the
    // state key).
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

    // NOTE: prove the token authenticates. IMAP does a full probe (auth
    // + IDLE/QRESYNC); CardDAV does a current-user-principal PROPFIND
    // (a polled collection has no IDLE/QRESYNC to check).
    let is_carddav = oauth_session.source_kind == "carddav";
    let (watchable, missing, qresync) = if is_carddav {
        let account = CardDavAccount {
            url: oauth_session.carddav_url.clone().unwrap_or_default(),
            login: oauth_session.login.clone(),
            auth: CardDavAuth::Bearer(tokens.access_token.clone()),
        };
        let probe = crate::carddav::session::verify_auth(&state.connector, &account).await;
        if !probe.authenticated {
            return oauth_popup(
                &state.dashboard_origin,
                oauth_err(&format!(
                    "OAuth token did not authenticate to CardDAV: {}",
                    probe.error.unwrap_or_default()
                )),
            );
        }
        (true, Vec::<&'static str>::new(), false)
    } else {
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
        // NOTE: QRESYNC-less providers (Gmail, Yahoo, …) are still
        // watchable, but new mail only; the UI surfaces that as a
        // warning.
        (probe.watchable(), probe.missing(), probe.qresync)
    };

    let enc_refresh_token = match state.crypto.encrypt(&refresh_token) {
        Ok(enc) => enc,
        Err(_) => return oauth_popup(&state.dashboard_origin, oauth_err("server error")),
    };

    let mailbox_key = metering::mailbox_key(&oauth_session.login, &oauth_session.imap_host);
    let expires = Some(now_secs() + CAPABILITY_TTL.as_secs() as i64);
    // NOTE: keep the mailbox context for the success payload before the
    // session moves.
    let login = oauth_session.login.clone();
    let imap_host = oauth_session.imap_host.clone();
    let imap_port = oauth_session.imap_port;
    let mailbox = oauth_session.mailbox.clone();

    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, String)> {
        // NOTE: join the presented account, else recover the mailbox's
        // account, else create a fresh one; the same identity flow as
        // `/auth`.
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
                    store.ensure_account(&id, None)?;
                    let link = random_secret();
                    store.issue_capability(&id, &link, expires)?;
                    (id, link)
                }
            },
        };
        // NOTE: record the membership under the login's protocol
        // (CardDAV carries the context root as its base_url). The welcome
        // trial is granted per-service at create_watch, so the OAuth
        // login grants nothing; it just proves + stores the credential
        // and joins/mints the account.
        let (protocol, base_url) = if is_carddav {
            ("carddav", oauth_session.carddav_url.clone())
        } else {
            ("imap", None)
        };
        store.add_membership(
            &account_id,
            &mailbox_key,
            protocol,
            &oauth_session.login,
            &oauth_session.imap_host,
            oauth_session.imap_port,
            base_url.as_deref(),
        )?;
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

/// A tiny HTML page that hands the OAuth result to the dashboard window
/// that opened the popup (via `postMessage` to its origin) and closes.
/// `<` is escaped in the embedded JSON so a value cannot break out of the
/// script.
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

/// Body of `POST /test`: credentials to probe, read-only. `source_kind`
/// selects the protocol (`imap` default, or `carddav`, which probes the
/// `carddav_url` collection instead of an IMAP mailbox).
#[derive(Deserialize)]
struct TestRequest {
    #[serde(default = "default_source_kind")]
    source_kind: String,
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    #[serde(default)]
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
    /// CardDAV collection URL to probe (required when `source_kind=carddav`).
    #[serde(default)]
    carddav_url: Option<String>,
}

/// Structured verdict returned by `POST /test`. `ok` is the green light:
/// for IMAP, reachable + authenticated + IDLE (QRESYNC a bonus); for
/// CardDAV, reachable + authenticated + a reported `sync-token`. The
/// unused capability flags are `false` for the other protocol.
#[derive(Serialize)]
struct TestVerdict {
    ok: bool,
    reachable: bool,
    authenticated: bool,
    idle: bool,
    qresync: bool,
    condstore: bool,
    /// CardDAV: the collection reports a change token (RFC 6578
    /// sync-token or a CalendarServer ctag), so it can be watched by
    /// polling.
    sync: bool,
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
    headers: HeaderMap,
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

    // NOTE: probe the addressbook collection instead of an IMAP mailbox,
    // reusing the PIM account's stored credential when no password is
    // given (the 'Add service' flow holds a capability link).
    if request.source_kind == "carddav" {
        let Some(url) = request.carddav_url.clone() else {
            return bad_request("carddav_url is required for a CardDAV test");
        };
        let auth = if !request.password.is_empty() {
            CardDavAuth::Password(request.password.clone())
        } else {
            let Some(token) = bearer(&headers) else {
                return unauthorized();
            };
            let account_id = match state.store.resolve_capability(&token) {
                Ok(Some(id)) => id,
                _ => return unauthorized(),
            };
            let mailbox_key = metering::mailbox_key(&request.login, &request.imap_host);
            match state
                .store
                .get_password_credential(&account_id, &mailbox_key)
            {
                Ok(Some(enc)) => match state.crypto.decrypt(&enc) {
                    Ok(password) => CardDavAuth::Password(password),
                    Err(err) => return AppError(err).into_response(),
                },
                Ok(None) => return bad_request("no stored credential for this PIM account"),
                Err(err) => return AppError(err).into_response(),
            }
        };

        let account = CardDavAccount {
            url,
            login: request.login,
            auth,
        };
        let probe = crate::carddav::session::probe(&state.connector, &account).await;
        let verdict = TestVerdict {
            ok: probe.watchable(),
            reachable: probe.reachable,
            authenticated: probe.authenticated,
            idle: false,
            qresync: false,
            condstore: false,
            sync: probe.sync,
            missing: if probe.reachable && probe.authenticated && !probe.sync {
                vec!["sync-collection"]
            } else {
                Vec::new()
            },
            error: probe.error,
        };
        info!(login = %account.login, ok = verdict.ok, "carddav test probe");
        return Json(verdict).into_response();
    }

    let account = ImapAccount {
        host: request.imap_host,
        port: request.imap_port,
        login: request.login,
        auth: ImapAuth::Password(request.password),
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
        sync: false,
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

/// Body of `POST /mailboxes`: the connection to list folders on. A
/// non-empty `password` lists via `LOGIN` (unauthenticated, rate-limited
/// like `/test`); an empty one lists an OAuth mailbox using the stored
/// credential, requiring a capability link scoping the caller.
#[derive(Deserialize)]
struct MailboxesRequest {
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    #[serde(default)]
    password: String,
}

/// `POST /mailboxes`: authenticate and `LIST` the account's selectable
/// mailboxes, so onboarding can offer a picker (defaulting to the inbox)
/// instead of a free-text folder field. Rate-limited per `(IP, login)`,
/// like `/test`. Returns `{ mailboxes: [{ name, role }] }`.
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

    // NOTE: an empty password reuses the PIM account's stored credential
    // (the folder picker for 'Add service'): a password (decrypt +
    // LOGIN) or, failing that, OAuth (mint a fresh bearer token), as the
    // watcher resolves it.
    if request.password.is_empty() {
        let Some(token) = bearer(&headers) else {
            return unauthorized();
        };
        let account_id = match state.store.resolve_capability(&token) {
            Ok(Some(id)) => id,
            _ => return unauthorized(),
        };
        let mailbox_key = metering::mailbox_key(&account.login, &account.host);
        match state
            .store
            .get_password_credential(&account_id, &mailbox_key)
        {
            Ok(Some(enc)) => match state.crypto.decrypt(&enc) {
                Ok(password) => account.auth = ImapAuth::Password(password),
                Err(err) => return AppError(err).into_response(),
            },
            Ok(None) => match supervisor::resolve_oauth_access(
                &state.store,
                &state.crypto,
                &account_id,
                &account,
            )
            .await
            {
                Ok(token) => account.auth = ImapAuth::OauthBearer(token),
                Err(err) => return bad_request(&format!("cannot authenticate mailbox: {err:#}")),
            },
            Err(err) => return AppError(err).into_response(),
        }
    }

    match session::list_mailboxes(&state.connector, &account).await {
        Ok(mailboxes) => Json(json!({ "mailboxes": mailboxes })).into_response(),
        Err(err) => bad_request(&format!("cannot list mailboxes: {err:#}")),
    }
}

/// Body of `POST /webhook/test`: where to send the one-shot test event
/// and the secret to sign it with (the wizard already holds the watch's
/// secret).
#[derive(Deserialize)]
struct WebhookTestRequest {
    notify_url: String,
    hmac_secret: String,
}

/// `POST /webhook/test`: POST one synthetic, signed `test` event to the
/// given URL so onboarding can prove the endpoint is reachable and
/// verifying signatures before activating. Rate-limited per IP (it makes
/// an outbound request to a caller-supplied URL). Never retried.
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
    // NOTE: SSRF guard; refuse to POST to a private/loopback target
    // (unless opted in).
    match Url::parse(&request.notify_url) {
        Ok(url) => {
            if let Err(err) = guard::check_url_host(&url).await {
                return bad_request(&err.to_string());
            }
        }
        Err(err) => return bad_request(&format!("invalid notify URL: {err}")),
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

/// Body of `POST /addressbooks`: the CardDAV account to list collections
/// on. Like `/mailboxes`, an empty `password` reuses the account's stored
/// credential (requiring a capability link scoping the caller).
#[derive(Deserialize)]
struct AddressbooksRequest {
    /// CardDAV context-root URL (from discovery, or the account's stored
    /// one).
    carddav_url: String,
    login: String,
    #[serde(default)]
    password: String,
}

/// `POST /addressbooks`: the CardDAV target picker, listing an account's
/// addressbook collections (current-user-principal → home-set →
/// collections, following redirects). Content-free (hrefs + display
/// names only). Rate-limited per `(IP, login)`, like `/mailboxes`.
/// Returns `{ addressbooks: [{ name, url }] }`.
async fn list_addressbooks(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AddressbooksRequest>,
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

    // NOTE: an explicit password, else (empty) the account's stored one,
    // keyed by the identity (host from the DAV URL): a password
    // credential, then OAuth (mint a fresh bearer from the refresh
    // token), as the poller and `/mailboxes` do.
    let host = Url::parse(&request.carddav_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    let auth = if !request.password.is_empty() {
        CardDavAuth::Password(request.password.clone())
    } else {
        let Some(token) = bearer(&headers) else {
            return unauthorized();
        };
        let account_id = match state.store.resolve_capability(&token) {
            Ok(Some(id)) => id,
            _ => return unauthorized(),
        };
        let mailbox_key = metering::mailbox_key(&request.login, &host);
        match state
            .store
            .get_password_credential(&account_id, &mailbox_key)
        {
            Ok(Some(enc)) => match state.crypto.decrypt(&enc) {
                Ok(password) => CardDavAuth::Password(password),
                Err(err) => return AppError(err).into_response(),
            },
            Ok(None) => {
                // NOTE: OAuth account; mint a bearer from the stored
                // refresh token, keyed by the DAV identity (host from the
                // URL).
                let identity = ImapAccount {
                    host: host.clone(),
                    port: 443,
                    login: request.login.clone(),
                    auth: ImapAuth::Password(String::new()),
                    mailbox: String::new(),
                };
                match supervisor::resolve_oauth_access(
                    &state.store,
                    &state.crypto,
                    &account_id,
                    &identity,
                )
                .await
                {
                    Ok(token) => CardDavAuth::Bearer(token),
                    Err(err) => {
                        return bad_request(&format!("cannot authenticate account: {err:#}"));
                    }
                }
            }
            Err(err) => return AppError(err).into_response(),
        }
    };

    let account = CardDavAccount {
        url: request.carddav_url,
        login: request.login,
        auth,
    };
    match crate::carddav::session::list_addressbooks(&state.connector, &account).await {
        Ok(addressbooks) => Json(json!({ "addressbooks": addressbooks })).into_response(),
        Err(err) => bad_request(&format!("cannot list addressbooks: {err:#}")),
    }
}

/// Body of `POST /forget`: which PIM account to forget.
#[derive(Deserialize)]
struct ForgetRequest {
    mailbox_key: String,
    protocol: String,
}

/// `POST /forget`: forget a PIM account, removing its membership + every
/// service under it, and dropping the shared credential when no other
/// protocol of the same identity remains (§ SERVICE_MODEL). Scoped to the
/// caller's account.
async fn forget_account(
    State(state): State<AppState>,
    caller: Caller,
    Json(request): Json<ForgetRequest>,
) -> Result<Response, AppError> {
    let Some(account_id) = caller.scope() else {
        return Ok(forbidden(
            "a capability link is required to forget an account",
        ));
    };
    let store = state.store.clone();
    let removed = tokio::task::spawn_blocking(move || {
        store.forget_account(&account_id, &request.mailbox_key, &request.protocol)
    })
    .await??;
    state.commands.send(SupervisorCmd::Reconcile).await.ok();
    Ok(Json(json!({ "status": "ok", "removed": removed.len() })).into_response())
}

/// Public view of a watch: never the password or HMAC secret.
#[derive(Serialize)]
struct WatchView {
    id: String,
    /// Source protocol (`imap` or `carddav`), so a client can label the row.
    source_kind: String,
    imap_host: String,
    imap_port: u16,
    login: String,
    /// The provider domain (registrable domain of the server host), what
    /// the front end labels the service by. Falls back to the
    /// host-derived value for rows predating the column.
    provider: String,
    mailbox: String,
    notify_url: String,
    active: bool,
    /// CardDAV collection URL (`None`/absent for IMAP).
    #[serde(skip_serializing_if = "Option::is_none")]
    carddav_url: Option<String>,
}

impl From<Watch> for WatchView {
    fn from(watch: Watch) -> Self {
        let provider = if watch.provider.is_empty() {
            metering::provider_domain(&watch.imap_host)
        } else {
            watch.provider
        };
        Self {
            id: watch.id,
            source_kind: watch.source_kind,
            imap_host: watch.imap_host,
            imap_port: watch.imap_port,
            login: watch.login,
            provider,
            mailbox: watch.mailbox,
            notify_url: watch.notify_url,
            active: watch.active,
            carddav_url: watch.carddav_url,
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
/// encrypted at rest. Omit it to create an OAuth watch; the mailbox must
/// already have an OAuth credential from a completed `/oauth/callback`.
#[derive(Deserialize)]
struct CreateWatch {
    id: String,
    /// Source protocol: `imap` (default) or `carddav`. For `carddav`,
    /// `imap_host`/`login` carry the PIM-account identity (sharing the
    /// mailbox key and credential with the account's IMAP membership) and
    /// `carddav_url` is the collection actually polled.
    #[serde(default = "default_source_kind")]
    source_kind: String,
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
    /// CardDAV collection URL (required when `source_kind=carddav`).
    #[serde(default)]
    carddav_url: Option<String>,
}

async fn create_watch(
    State(state): State<AppState>,
    caller: Caller,
    Json(request): Json<CreateWatch>,
) -> Result<Response, AppError> {
    if let Err(err) = validate_notify_url(&request.notify_url) {
        return Ok(bad_request(&err.to_string()));
    }
    // NOTE: SSRF guard; the notify URL must not resolve to a
    // private/loopback target.
    match Url::parse(&request.notify_url) {
        Ok(url) => {
            if let Err(err) = guard::check_url_host(&url).await {
                return Ok(bad_request(&err.to_string()));
            }
        }
        Err(err) => return Ok(bad_request(&format!("invalid notify URL: {err}"))),
    }

    let mailbox_key = metering::mailbox_key(&request.login, &request.imap_host);

    // NOTE: the CardDAV collection URL is required + https, and is the
    // service's key (two addressbooks on one account are distinct
    // services).
    if request.source_kind == "carddav" {
        match request.carddav_url.as_deref().map(Url::parse) {
            Some(Ok(url)) if url.scheme() == "https" => {}
            Some(Ok(_)) => return Ok(bad_request("carddav_url must be https://")),
            Some(Err(err)) => return Ok(bad_request(&format!("invalid carddav_url: {err}"))),
            None => return Ok(bad_request("carddav_url is required for a CardDAV service")),
        }
    }

    // NOTE: a scoped caller watches under its own account (the body's
    // account_id is ignored). A create carrying a password is
    // self-proving (the wizard just validated it), so no prior membership
    // is required. The credential-reuse path (empty password → a stored
    // OAuth credential) still requires a recorded membership: you cannot
    // reuse a credential you never proved. The unscoped admin may place
    // the watch in any account.
    let account_id = match caller.scope() {
        Some(account_id) => {
            if request.password.is_empty() {
                let store = state.store.clone();
                let (owner, key, proto) = (
                    account_id.clone(),
                    mailbox_key.clone(),
                    request.source_kind.clone(),
                );
                let proven = tokio::task::spawn_blocking(move || {
                    store.mailbox_belongs(&owner, &key, &proto)
                })
                .await??;
                if !proven {
                    return Ok(forbidden(
                        "provide the mailbox password, or sign in with OAuth first",
                    ));
                }
            }
            account_id
        }
        None => request
            .account_id
            .clone()
            .unwrap_or_else(|| request.id.clone()),
    };

    // NOTE: no same-target dedup; a user may knowingly add the same
    // folder twice (e.g. two webhook endpoints) and pay for each. An
    // upsert of the same watch id still edits in place; only the fair-use
    // cap below bounds distinct mailboxes.

    // NOTE: fair-use cap; a scoped account may watch up to `max_watches`
    // distinct mailboxes, beyond that it needs a volume plan (the
    // ops/import path is exempt). This only stops reselling.
    if caller.scope().is_some() {
        let store = state.store.clone();
        let (owner, key, cap) = (account_id.clone(), mailbox_key.clone(), state.max_watches);
        let over_cap = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let keys: std::collections::HashSet<String> = store
                .account_watch_identities(&owner)?
                .into_iter()
                .map(|(login, host)| metering::mailbox_key(&login, &host))
                .collect();
            Ok(!keys.contains(&key) && keys.len() >= cap)
        })
        .await??;
        if over_cap {
            return Ok(fair_use(state.max_watches));
        }
    }

    // NOTE: an explicit password is stored on the watch. An empty
    // password reuses a stored OAuth credential for this `(account,
    // mailbox)` (proven at `/oauth/callback`); the supervisor resolves it
    // per connect.
    let (auth_kind, enc_password) = if !request.password.is_empty() {
        (
            "password".to_string(),
            state.crypto.encrypt(&request.password)?,
        )
    } else {
        let store = state.store.clone();
        let (owner, key) = (account_id.clone(), mailbox_key.clone());
        let has_oauth = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            Ok(store.get_oauth_credential(&owner, &key)?.is_some())
        })
        .await??;
        if has_oauth {
            ("oauth".to_string(), String::new())
        } else {
            return Ok(bad_request(
                "no credential for this service — provide a password, or sign in with OAuth first",
            ));
        }
    };

    // NOTE: the provider domain (registrable domain of the server host)
    // is stamped on the watch and reused for the trial gate + the create
    // response.
    let provider = metering::provider_domain(&request.imap_host);
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
        provider: provider.clone(),
        auth_kind,
        // NOTE: not activated yet; on the metered SaaS the service starts
        // only after `POST /watches/{id}/activate` spends a credit
        // (upsert leaves these, so an edit-in-place keeps the
        // activation).
        watching_until: None,
        auto_renew: false,
        active: request.active,
        source_kind: request.source_kind,
        carddav_url: request.carddav_url,
        // NOTE: runtime poll state, established on the first poll; the
        // default poll interval applies (no per-service override yet).
        carddav_sync_token: None,
        carddav_poll_secs: None,
    };

    let id = watch.id.clone();
    let store = state.store.clone();
    let claim_account = account_id.clone();
    // NOTE: free-trial head start; the account's first service on a
    // provider auto-watches free for a week (no credit, no separate
    // 'activate' step). Gated per (account, provider domain), so mail and
    // contacts hosts share one provider and only the first earns it.
    // `watching_until` is runtime state upsert_watch doesn't write, set
    // it after.
    let claim_provider = provider.clone();
    let free_trial = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        store.upsert_watch(&watch)?;
        store.ensure_account(&claim_account, None)?;
        let granted = store.claim_free_trial(&claim_account, &claim_provider)?;
        if granted {
            store.set_watch_watching_until(&watch.id, now_secs() + metering::free_trial_secs())?;
        }
        Ok(granted)
    })
    .await??;
    info!(watch = %id, free_trial, provider = %provider, "watch created");

    state.commands.send(SupervisorCmd::Reconcile).await.ok();
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "ok",
            "id": id,
            "free_trial": free_trial,
            "provider": provider,
        })),
    )
        .into_response())
}

/// Authorizes a caller for a watch by id. `Ok(None)` means allowed;
/// `Ok(Some(resp))` is a `404` rejection that hides the watch's existence
/// from other accounts, indistinguishable from a missing watch.
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
    /// The new secret. If omitted, a random 256-bit one is generated and
    /// returned.
    #[serde(default)]
    new_secret: Option<String>,
    /// How long (seconds) the previous secret keeps being signed with.
    #[serde(default)]
    overlap_secs: Option<u64>,
}

/// Rotates a watch's HMAC secret, keeping the old one valid for an
/// overlap window (both are signed with meanwhile). Returns the new
/// secret and the overlap expiry. The secret does not affect the
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

    // NOTE: a scoped caller may filter to one of its own watches
    // (`?account=<watch id>`); asking for a watch it does not own yields
    // an empty log, never another account's deliveries. The unscoped
    // admin keeps the global view with the optional filter.
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

/// `GET /events`: a Server-Sent Events stream of live delivery outcomes
/// and watch connection-status changes, for the dashboard. One-way,
/// browser-native (`EventSource`), proxy-friendly. A slow client that
/// lags simply misses the oldest events (surfaced as a `lagged` SSE
/// event). Purely observational and content-free.
///
/// A forwarding task pumps the (scoped) broadcast into a bounded channel
/// that backs the response body, ending on either server shutdown or
/// client disconnect, so a held connection never blocks graceful
/// shutdown.
async fn events(
    State(state): State<AppState>,
    caller: Caller,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // NOTE: scope the live fan-out; a capability-link subscriber sees
    // only its own account's events, the unscoped admin sees everything.
    let scope = caller.scope();
    let mut live = state.live.subscribe();
    let mut shutdown = state.shutdown.clone();
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                // NOTE: prefer shutdown so it wins promptly over a busy
                // bus.
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
                    // NOTE: the subscriber fell behind and lost events.
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        Event::default().event("lagged").data(skipped.to_string())
                    }
                    // NOTE: the bus closed (server tearing down).
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            // NOTE: a send error means the client disconnected (body
            // dropped).
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}

/// A slot within an account view: a service (watch) with its per-service
/// activation state, or a proven PIM account (mailbox) with no service
/// yet.
#[derive(Serialize)]
struct MailboxView {
    /// The PIM account key (normalised login) this slot belongs to.
    mailbox_key: String,
    /// Source protocol of this PIM account (`imap` / `carddav`).
    protocol: String,
    /// The service (watch) on this PIM account, or null (proven, no
    /// service yet).
    watch_id: Option<String>,
    /// The watched target (the IMAP mailbox) that distinguishes several
    /// services on one PIM account. Null for a service-less PIM account.
    mailbox: Option<String>,
    /// Unix time watching is paid up to; null/past means not currently
    /// watching.
    watching_until: Option<i64>,
    /// Whether this service currently watches (paid month in the future).
    watching: bool,
    /// Whether the next credit is drawn from the pool at expiry.
    auto_renew: bool,
}

/// Public view of a Carillon account: the credit pool and each service's
/// activation state. What the dashboard renders.
#[derive(Serialize)]
struct AccountView {
    id: String,
    /// Magic-link email identity, if any.
    email: Option<String>,
    /// Fungible credit-pool balance (1 credit = one service-month).
    credits: i64,
    /// The account's services (billed units) plus any
    /// proven-but-unwatched mailboxes, each activated independently.
    mailboxes: Vec<MailboxView>,
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
            // NOTE: scoped callers see only their own account, keeping
            // this list route from leaking the fleet.
            Some(account_id) => Ok(vec![account_view(&store, &account_id, now)?]),
            None => store
                .all_account_ids()?
                .into_iter()
                .map(|id| account_view(&store, &id, now))
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
    let exists = tokio::task::spawn_blocking({
        let id = id.clone();
        move || store.get_account(&id)
    })
    .await??
    .is_some();

    if !exists {
        return Ok(not_found(&id));
    }

    let store = state.store.clone();
    let view = tokio::task::spawn_blocking(move || account_view(&store, &id, now_secs())).await??;
    Ok(Json(view).into_response())
}

/// Builds an account view: the credit pool and each service's activation
/// state (which lives on the watch). Blocking; call inside
/// `spawn_blocking`.
fn account_view(store: &Store, id: &str, now: i64) -> anyhow::Result<AccountView> {
    let account = store.get_account(id)?.unwrap_or(crate::store::AccountRow {
        id: id.to_string(),
        email: None,
        credits: 0,
    });

    // NOTE: one slot per service (watch), carrying its activation state,
    // then any PIM account (identity+protocol) with no service yet. Keyed
    // per (mailbox_key, protocol) so a serviced Email account and a
    // service-less Contacts account both surface.
    let mut with_service: BTreeSet<(String, String)> = BTreeSet::new();
    let mut mailboxes: Vec<MailboxView> = store
        .watches_by_account(id)?
        .into_iter()
        .map(|watch| {
            let mailbox_key = metering::mailbox_key(&watch.login, &watch.imap_host);
            with_service.insert((mailbox_key.clone(), watch.source_kind.clone()));
            MailboxView {
                protocol: watch.source_kind,
                watch_id: Some(watch.id),
                mailbox: Some(watch.mailbox),
                watching_until: watch.watching_until,
                watching: metering::pim_entitled(watch.watching_until, now),
                auto_renew: watch.auto_renew,
                mailbox_key,
            }
        })
        .collect();
    for member in store.memberships(id)? {
        if !with_service.contains(&(member.mailbox_key.clone(), member.protocol.clone())) {
            mailboxes.push(MailboxView {
                protocol: member.protocol,
                watch_id: None,
                mailbox: None,
                watching_until: None,
                watching: false,
                auto_renew: false,
                mailbox_key: member.mailbox_key,
            });
        }
    }

    Ok(AccountView {
        id: account.id,
        email: account.email,
        credits: account.credits,
        mailboxes,
    })
}

/// The authenticated caller behind a bearer token. Every data route
/// requires one; there is no unauthenticated access to watches,
/// deliveries or events (§ DECISIONS 5). A caller is either the unscoped
/// admin (presented the configured `admin_token`) or a single account
/// (presented a valid capability link, scoped to its own watches and
/// pool).
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
        // NOTE: the admin token, if configured, wins. Compare digests so
        // the comparison leaks nothing exploitable about the secret.
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
/// than raw strings, so a timing side-channel on the byte comparison
/// reveals nothing about the secret.
fn token_matches(token: &str, expected: &str) -> bool {
    Sha256::digest(token.as_bytes()) == Sha256::digest(expected.as_bytes())
}

/// The account behind a valid capability link. An extractor that reads
/// the `Authorization: Bearer <link>` header and resolves it, rejecting
/// with `401` if missing, unknown or expired. Server-validated on every
/// call.
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

/// Body of `POST /auth`: prove control of a PIM account (identity + protocol).
#[derive(Deserialize)]
struct AuthRequest {
    /// `imap` (default) or `carddav`. The credential is validated the
    /// right way (IMAP LOGIN vs CardDAV PROPFIND) and the proven
    /// `(identity, protocol)` becomes a PIM account.
    #[serde(default = "default_source_kind")]
    protocol: String,
    #[serde(default)]
    imap_host: String,
    #[serde(default = "default_port")]
    imap_port: u16,
    login: String,
    password: String,
    #[serde(default = "default_mailbox")]
    mailbox: String,
    /// CardDAV context-root URL (required when `protocol=carddav`).
    #[serde(default)]
    carddav_url: Option<String>,
}

/// `POST /auth`: the login-less identity flow. Authenticating proves
/// control of a PIM account (identity + protocol); the first auth creates
/// a Carillon account and mints its capability link, a re-auth to a
/// member identity recovers the link, and an auth carrying a valid link
/// adds the PIM account to it. The credential is stored per identity.
/// Rate-limited per `(IP, login)`.
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

    // NOTE: validate the credential the right way and derive the
    // membership's server info (host/port/base_url) per protocol.
    let is_carddav = request.protocol == "carddav";
    let (authenticated, error, watchable, idle, qresync, host, port, base_url) = if is_carddav {
        let Some(url) = request.carddav_url.clone() else {
            return bad_request("carddav_url is required for a contacts account");
        };
        let account = CardDavAccount {
            url: url.clone(),
            login: request.login.clone(),
            auth: CardDavAuth::Password(request.password.clone()),
        };
        let probe = crate::carddav::session::verify_auth(&state.connector, &account).await;
        let host = Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        (
            probe.authenticated,
            probe.error.clone(),
            probe.reachable && probe.authenticated,
            false,
            false,
            host,
            443u16,
            Some(url),
        )
    } else {
        let account = ImapAccount {
            host: request.imap_host.clone(),
            port: request.imap_port,
            login: request.login.clone(),
            auth: ImapAuth::Password(request.password.clone()),
            mailbox: request.mailbox.clone(),
        };
        let probe = session::probe(&state.connector, &account).await;
        (
            probe.authenticated,
            probe.error.clone(),
            probe.watchable(),
            probe.idle,
            probe.qresync,
            request.imap_host.clone(),
            request.imap_port,
            None,
        )
    };

    if !authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "authentication failed", "detail": error })),
        )
            .into_response();
    }

    // NOTE: the proven password becomes the identity's credential
    // (shared across its protocols), reused when adding services.
    let enc_password = match state.crypto.encrypt(&request.password) {
        Ok(enc) => enc,
        Err(err) => return AppError(err).into_response(),
    };

    let existing = bearer(&headers);
    let store = state.store.clone();
    let login = request.login.clone();
    let protocol = request.protocol.clone();
    let membership_host = host;
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(String, &'static str, String)> {
            let mailbox_key = metering::mailbox_key(&login, &membership_host);
            let expires = Some(now_secs() + CAPABILITY_TTL.as_secs() as i64);

            // NOTE: join the account the presented link controls, else
            // recover the account this identity already belongs to, else
            // create a new one. Recovery is protocol-blind (any protocol
            // proves the identity).
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
                        store.ensure_account(&id, None)?;
                        let link = random_secret();
                        store.issue_capability(&id, &link, expires)?;
                        (id, "created", link)
                    }
                },
            };

            store.add_membership(
                &account_id,
                &mailbox_key,
                &protocol,
                &login,
                &membership_host,
                port,
                base_url.as_deref(),
            )?;
            store.upsert_password_credential(&account_id, &mailbox_key, &enc_password)?;
            // NOTE: no welcome credit here; the free head start is a
            // per-service trial granted at create_watch, so this endpoint
            // can't be farmed for spendable credits.
            Ok((account_id, action, link))
        })
        .await;

    match result {
        Ok(Ok((account_id, action, link))) => {
            info!(account = %account_id, action, protocol = %request.protocol, "auth");
            Json(json!({
                "account_id": account_id,
                "action": action,
                "link": link,
                "protocol": request.protocol,
                "watchable": watchable,
                "idle": idle,
                "qresync": qresync,
            }))
            .into_response()
        }
        _ => AppError(anyhow::anyhow!("auth failed")).into_response(),
    }
}

/// How long a magic-link sign-in token stays valid.
const MAGIC_LINK_TTL: i64 = 15 * 60;

/// Body of `POST /auth/magic/request`: the email to send a sign-in link to.
#[derive(Deserialize)]
struct MagicRequest {
    email: String,
}

/// `POST /auth/magic/request`: email a single-use sign-in link, the human
/// identity flow and the sybil barrier for the free credit (a new account
/// needs a real inbox). Rate-limited per `(IP, email)`. A delivery
/// failure is surfaced, since the user must receive the link to sign in.
async fn magic_request(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<MagicRequest>,
) -> Response {
    let email = request.email.trim().to_ascii_lowercase();
    if email.len() < 3 || !email.contains('@') {
        return bad_request("a valid email is required");
    }
    let key = format!("{}|{}", peer.ip(), email);
    if let Err(retry_after) = state.auth_limiter.check(&key) {
        let seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", seconds.to_string())],
            Json(json!({ "error": "too many attempts", "retry_after": seconds })),
        )
            .into_response();
    }

    let token = random_secret();
    let store = state.store.clone();
    let (store_token, store_email) = (token.clone(), email.clone());
    match tokio::task::spawn_blocking(move || store.create_magic_link(&store_token, &store_email))
        .await
    {
        Ok(Ok(())) => {}
        _ => return AppError(anyhow::anyhow!("cannot store sign-in token")).into_response(),
    }

    // NOTE: point the emailed link at the dashboard's `/verify` route,
    // falling back to the API's own GET verify endpoint when no distinct
    // dashboard origin is configured.
    let base = state.dashboard_origin.trim_end_matches('/');
    let link = if base.is_empty() || base == "*" {
        format!(
            "{}/auth/magic/verify?token={token}",
            state.public_url.trim_end_matches('/')
        )
    } else {
        format!("{base}/verify?token={token}")
    };
    match state.mailer.send_magic_link(&email, &link).await {
        Ok(()) => {
            info!(email, "magic link sent");
            Json(json!({ "status": "sent" })).into_response()
        }
        Err(err) => {
            warn!(email, error = %err, "magic link send failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "could not send the sign-in email; try again" })),
            )
                .into_response()
        }
    }
}

/// Verifies a magic-link token, minting a fresh capability link for the
/// account that owns the email, creating the account (no free credit yet,
/// that waits for a validated PIM account) on first sign-in. Blocking;
/// call inside `spawn_blocking`. `None` for an unknown or expired token.
fn verify_magic(store: &Store, token: &str) -> anyhow::Result<Option<(String, String)>> {
    let Some(email) = store.take_magic_link(token, MAGIC_LINK_TTL)? else {
        return Ok(None);
    };
    let account_id = match store.account_by_email(&email)? {
        Some(id) => id,
        None => {
            let id = random_secret();
            store.ensure_account(&id, Some(&email))?;
            id
        }
    };
    let link = random_secret();
    let expires = Some(now_secs() + CAPABILITY_TTL.as_secs() as i64);
    store.issue_capability(&account_id, &link, expires)?;
    Ok(Some((account_id, link)))
}

/// Body of `POST /auth/magic/verify`: the token from the emailed link.
#[derive(Deserialize)]
struct MagicVerifyRequest {
    token: String,
}

/// `POST /auth/magic/verify`: exchange a magic-link token for a
/// capability link (programmatic / dashboard). Returns `{ account_id,
/// link }`.
async fn magic_verify(
    State(state): State<AppState>,
    Json(request): Json<MagicVerifyRequest>,
) -> Response {
    let store = state.store.clone();
    let token = request.token;
    match tokio::task::spawn_blocking(move || verify_magic(&store, &token)).await {
        Ok(Ok(Some((account_id, link)))) => {
            info!(account = %account_id, "magic sign-in");
            Json(json!({ "account_id": account_id, "link": link })).into_response()
        }
        Ok(Ok(None)) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid or expired sign-in link" })),
        )
            .into_response(),
        _ => AppError(anyhow::anyhow!("sign-in failed")).into_response(),
    }
}

/// Query of `GET /auth/magic/verify`: the token from the emailed link.
#[derive(Deserialize)]
struct MagicVerifyQuery {
    #[serde(default)]
    token: String,
}

/// `GET /auth/magic/verify`: what the emailed link opens in the browser.
/// Mints the capability link and hands it to the dashboard window that
/// opened it (via `postMessage`), mirroring the OAuth popup.
async fn magic_verify_get(
    State(state): State<AppState>,
    Query(query): Query<MagicVerifyQuery>,
) -> Response {
    if query.token.is_empty() {
        return oauth_popup(&state.dashboard_origin, magic_err("missing token"));
    }
    let store = state.store.clone();
    let token = query.token.clone();
    match tokio::task::spawn_blocking(move || verify_magic(&store, &token)).await {
        Ok(Ok(Some((account_id, link)))) => {
            info!(account = %account_id, "magic sign-in");
            oauth_popup(
                &state.dashboard_origin,
                json!({ "type": "carillon-magic", "ok": true, "link": link, "account_id": account_id }),
            )
        }
        Ok(Ok(None)) => oauth_popup(
            &state.dashboard_origin,
            magic_err("invalid or expired sign-in link"),
        ),
        _ => oauth_popup(&state.dashboard_origin, magic_err("server error")),
    }
}

/// A content-free error payload for the magic-link popup.
fn magic_err(message: &str) -> serde_json::Value {
    json!({ "type": "carillon-magic", "ok": false, "error": message })
}

/// `GET /me`: the account behind the capability link, with its members,
/// watches and balance.
async fn me(
    State(state): State<AppState>,
    CapabilityAccount(account_id): CapabilityAccount,
) -> Result<Response, AppError> {
    let store = state.store.clone();
    let metered = state.metered;
    let carddav_poll_secs = state.carddav_poll_secs;
    let body = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let balance = account_view(&store, &account_id, now_secs())?;
        let mailboxes: Vec<_> = store
            .memberships(&account_id)?
            .into_iter()
            .map(|m| {
                json!({
                    "mailbox_key": m.mailbox_key,
                    "protocol": m.protocol,
                    "login": m.login,
                    "imap_host": m.imap_host,
                    "imap_port": m.imap_port,
                    "base_url": m.base_url,
                })
            })
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
            "metered": metered,
            "carddav_poll_secs": carddav_poll_secs,
        }))
    })
    .await??;
    Ok(Json(body).into_response())
}

/// `POST /signout`: revoke the presented capability link.
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

/// Body of `POST /watches/{id}/activate`: how many credits to spend at once.
#[derive(Deserialize)]
struct ActivateRequest {
    /// Credits to spend = months of watching to add. Defaults to 1.
    #[serde(default = "default_activate_credits")]
    credits: i64,
}

fn default_activate_credits() -> i64 {
    1
}

/// `POST /watches/{id}/activate`: spend `credits` credits (default 1) to
/// give a service that many months of watching, stacking onto any still
/// remaining. `402` when the pool can't cover it (all-or-nothing), `404`
/// when the caller does not own the service.
async fn activate_watch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    Json(request): Json<ActivateRequest>,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }

    enum Outcome {
        Gone,
        NoCredits,
        Activated { until: i64, credits: i64 },
    }

    let n = request.credits.max(1);
    let month = metering::month_secs();
    let store = state.store.clone();
    let watch_id = id.clone();
    let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<Outcome> {
        let Some(watch) = store.get_watch(&watch_id)? else {
            return Ok(Outcome::Gone);
        };
        // NOTE: all-or-nothing; never spend a partial amount the pool
        // can't cover.
        if !store.debit_credits(&watch.account_id, n)? {
            return Ok(Outcome::NoCredits);
        }
        // NOTE: stack onto any time still remaining, else start from now.
        let now = now_secs();
        let base = watch
            .watching_until
            .filter(|until| *until > now)
            .unwrap_or(now);
        let until = base + n * month;
        store.set_watch_watching_until(&watch_id, until)?;
        let credits = store
            .get_account(&watch.account_id)?
            .map(|account| account.credits)
            .unwrap_or(0);
        Ok(Outcome::Activated { until, credits })
    })
    .await??;

    Ok(match outcome {
        Outcome::Gone => not_found(&id),
        Outcome::NoCredits => no_credits(),
        Outcome::Activated { until, credits } => {
            info!(watch = %id, until, "service activated");
            // NOTE: start it now that it is paid.
            state.commands.send(SupervisorCmd::Reconcile).await.ok();
            Json(json!({
                "status": "ok",
                "id": id,
                "watching_until": until,
                "credits": credits,
            }))
            .into_response()
        }
    })
}

/// Body of `POST /watches/{id}/auto-renew`: whether to auto-renew.
#[derive(Deserialize)]
struct AutoRenewRequest {
    enabled: bool,
}

/// `POST /watches/{id}/auto-renew`: draw the next credit from the pool at
/// expiry instead of stopping. Off by default.
async fn set_watch_auto_renew(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    Json(request): Json<AutoRenewRequest>,
) -> Result<Response, AppError> {
    if let Some(reject) = authorize_watch(&state, &caller, &id).await? {
        return Ok(reject);
    }
    let enabled = request.enabled;
    let store = state.store.clone();
    let watch_id = id.clone();
    let matched =
        tokio::task::spawn_blocking(move || store.set_watch_auto_renew(&watch_id, enabled))
            .await??;
    if !matched {
        return Ok(not_found(&id));
    }
    info!(watch = %id, enabled, "auto-renew set");
    Ok(Json(json!({ "status": "ok", "id": id, "auto_renew": enabled })).into_response())
}

/// Body of `POST /billing/checkout`: how many packs to buy (min 1 pack).
#[derive(Deserialize)]
struct CheckoutRequest {
    #[serde(default = "default_packs")]
    packs: i64,
}

/// `POST /billing/checkout`: buy `packs` packs of credits in one payment
/// (the only refill unit is a pack of `PACK_SIZE`). Records a pending
/// session for the resolved credit count and returns the provider
/// checkout URL; the pool is topped up on the verified webhook.
async fn billing_checkout(
    State(state): State<AppState>,
    CapabilityAccount(account_id): CapabilityAccount,
    Json(request): Json<CheckoutRequest>,
) -> Result<Response, AppError> {
    let packs = request.packs;
    if packs < 1 {
        return Ok(bad_request("must buy at least one pack"));
    }
    let credits = packs * billing::PACK_SIZE;

    // NOTE: create the provider checkout first (it can fail / call out),
    // then record the pending session, so a failed checkout leaves no
    // orphan row.
    let session_id = random_secret();
    let url = match state
        .billing
        .create_checkout(&session_id, &account_id, packs)
        .await
    {
        Ok(url) => url,
        Err(err) => {
            warn!(account = %account_id, packs, error = %err, "checkout failed");
            return Ok(bad_request(&format!("could not start checkout: {err}")));
        }
    };

    let store = state.store.clone();
    let create_id = account_id.clone();
    let create_session = session_id.clone();
    tokio::task::spawn_blocking(move || store.create_session(&create_session, &create_id, credits))
        .await??;

    info!(account = %account_id, packs, credits, "checkout created");
    Ok(Json(json!({
        "provider": state.billing.provider(),
        "session_id": session_id,
        "checkout_url": url,
        "packs": packs,
        "credits": credits,
    }))
    .into_response())
}

/// `POST /billing/webhook`: the provider's payment callback. The raw body
/// is verified against the provider signature before it is trusted, then
/// a paid checkout tops the account's pool up by the quantity that
/// session recorded (idempotent against retried webhooks).
async fn billing_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok());
    let outcome = match state.billing.verify_webhook(signature, &body) {
        Ok(outcome) => outcome,
        Err(err) => {
            warn!(error = %err, "billing webhook rejected");
            return Ok(bad_request(&format!("webhook rejected: {err}")));
        }
    };

    let store = state.store.clone();
    let applied = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        match outcome {
            billing::WebhookOutcome::Credit { session_id } => {
                let Some((account_id, quantity)) = store.fulfill_session(&session_id)? else {
                    return Ok(
                        json!({ "status": "ignored", "reason": "unknown or already fulfilled" }),
                    );
                };
                store.add_credits(&account_id, quantity)?;
                info!(account = %account_id, quantity, "pool credited");
                Ok(json!({ "status": "credited", "account_id": account_id, "quantity": quantity }))
            }
            billing::WebhookOutcome::Ignore => Ok(json!({ "status": "ignored" })),
        }
    })
    .await??;

    Ok(Json(applied).into_response())
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

/// `402`: the pool is empty; buy a pack of credits before activating a
/// service.
fn no_credits() -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(json!({ "error": "no credits — buy a pack to activate this service" })),
    )
        .into_response()
}

/// `402`: the account hit its fair-use mailbox cap and needs a volume
/// plan.
fn fair_use(cap: usize) -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(json!({
            "error": format!(
                "fair-use limit reached ({cap} mailboxes) — get in touch for a volume plan"
            ),
            "limit": cap,
        })),
    )
        .into_response()
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

fn default_source_kind() -> String {
    String::from("imap")
}

fn default_true() -> bool {
    true
}

fn default_limit() -> u32 {
    50
}

fn default_packs() -> i64 {
    1
}
