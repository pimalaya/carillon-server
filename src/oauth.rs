//! OAuth 2.0 for watch credentials.
//!
//! The dynamic-registration path (RFC 7591) resolves an issuer's
//! endpoints from its RFC 8414 metadata, registers a public client on
//! the fly, runs authorization-code + PKCE (with the RFC 8707 `resource`
//! param where needed), and refreshes the refresh-token into short-lived
//! access tokens. The static-registration path (a config-provided
//! `client_id` per provider, for Google/Microsoft) plugs in at
//! [`ClientId`].
//!
//! Everything here is blocking (io-oauth's std client and the RFC 8414
//! fetch each open their own connection), so callers run it inside
//! `spawn_blocking`. Access and refresh tokens are secrets, returned to
//! the caller to persist encrypted, never logged.
//!
//! Wired into the watch flow through the `/oauth/*` endpoints and the
//! supervisor's per-connect token refresh.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use io_oauth::client::Oauth20ClientStd;
use io_oauth::rfc6749::access_token_request::Oauth20AccessTokenRequestParams;
use io_oauth::rfc6749::auth_request::Oauth20AuthRequestParams;
use io_oauth::rfc6749::issue_access_token::Oauth20AccessTokenSuccessParams;
use io_oauth::rfc6749::refresh_access_token::Oauth20AccessTokenRefreshParams;
use io_oauth::rfc6749::state::Oauth20State;
use io_oauth::rfc7591::register::Oauth20ClientRegisterParams;
use io_oauth::rfc7636::pkce::{Oauth20PkceCodeChallenge, Oauth20PkceCodeVerifier};
use io_pim_discovery::compose::client::DiscoveryComposeClientStd;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::discover;

/// The authorization-server endpoints a flow needs.
#[derive(Clone, Debug)]
pub struct OauthEndpoints {
    /// Where to send the user to authorize.
    pub authorization: Url,
    /// Where to exchange/refresh tokens.
    pub token: Url,
    /// RFC 7591 dynamic-registration endpoint, when the issuer offers
    /// one.
    pub registration: Option<Url>,
    /// The scopes the authorization server advertises (RFC 8414), used
    /// to pick a mail scope for a dynamically-registered client. Empty
    /// for direct endpoints with no metadata.
    pub scopes_supported: Vec<String>,
}

/// The client identity to authenticate as: registered on the fly (RFC
/// 7591) or provided by config (static registration).
#[derive(Clone, Debug)]
pub enum ClientId {
    /// A `client_id` (and optional secret) issued by dynamic registration.
    Dynamic {
        client_id: String,
        client_secret: Option<String>,
    },
    /// A `client_id` (and optional secret) from configuration.
    Static {
        client_id: String,
        client_secret: Option<String>,
    },
}

impl ClientId {
    pub fn id(&self) -> &str {
        match self {
            ClientId::Dynamic { client_id, .. } | ClientId::Static { client_id, .. } => client_id,
        }
    }

    pub fn secret(&self) -> Option<&str> {
        match self {
            ClientId::Dynamic { client_secret, .. } | ClientId::Static { client_secret, .. } => {
                client_secret.as_deref()
            }
        }
    }
}

/// A freshly built authorization request: the URL to send the user to,
/// plus the `state` and PKCE `verifier` to persist for the callback.
#[derive(Clone, Debug)]
pub struct AuthRequest {
    pub url: String,
    /// The CSRF `state` echoed back on the callback (compare as a
    /// string).
    pub state: String,
    /// The PKCE code verifier, needed to exchange the code.
    pub verifier: String,
}

/// The tokens a code-exchange or refresh yields. Secrets, persist
/// encrypted.
#[derive(Clone, Debug)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    // TODO: kept for a future access-token cache; the supervisor
    // refreshes on every connect, so these are not read yet.
    #[allow(dead_code)]
    pub expires_in: Option<usize>,
    #[allow(dead_code)]
    pub scope: Option<String>,
}

impl Tokens {
    fn from_success(success: Oauth20AccessTokenSuccessParams) -> Self {
        Tokens {
            access_token: success.access_token.expose_secret().to_string(),
            refresh_token: success
                .refresh_token
                .map(|token| token.expose_secret().to_string()),
            expires_in: success.expires_in,
            scope: success.scope,
        }
    }
}

/// Resolves an issuer's endpoints from its RFC 8414 metadata (trying the
/// OAuth then the OpenID Connect well-known URL). Fails if the issuer has
/// no discoverable metadata or lacks an authorization/token endpoint.
pub fn resolve_issuer(issuer: &str) -> Result<OauthEndpoints> {
    let issuer_url: Url = issuer.parse().context("invalid issuer URL")?;
    let client = DiscoveryComposeClientStd::new(discover::resolver(), discover::tls());
    let metadata = client
        .oauth_server(&issuer_url)
        .with_context(|| format!("no RFC 8414 metadata for issuer {issuer}"))?;
    Ok(OauthEndpoints {
        authorization: metadata
            .authorization_endpoint
            .context("issuer metadata has no authorization_endpoint")?,
        token: metadata
            .token_endpoint
            .context("issuer metadata has no token_endpoint")?,
        registration: metadata.registration_endpoint,
        scopes_supported: metadata.scopes_supported,
    })
}

/// Registers a public client (RFC 7591) for the authorization-code +
/// refresh-token grants at `registration`, returning its issued
/// identity. The auth method is `none` (public client, PKCE-protected).
pub fn register_client(
    registration: &Url,
    redirect_uri: &str,
    scope: Option<&str>,
) -> Result<ClientId> {
    let params = Oauth20ClientRegisterParams {
        redirect_uris: vec![redirect_uri.to_string()],
        token_endpoint_auth_method: Some("none".to_string()),
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        client_name: Some("Carillon".to_string()),
        scope: scope.map(str::to_string),
        ..Default::default()
    };

    let mut client = Oauth20ClientStd::connect(registration.clone(), &discover::tls(), "")
        .context("cannot connect to the registration endpoint")?;
    let info = client
        .register_client(registration, &params)
        .context("registration request failed")?
        .map_err(|err| {
            anyhow!(
                "registration rejected: {:?} {}",
                err.error,
                err.error_description.unwrap_or_default()
            )
        })?;

    Ok(ClientId::Dynamic {
        client_id: info.client_id,
        client_secret: info
            .client_secret
            .map(|secret| secret.expose_secret().to_string()),
    })
}

/// Builds the authorization URL (S256 PKCE + a random state) with extra
/// query params (an RFC 8707 `resource`, or provider-specific params).
/// Returns the URL plus the `state`/`verifier` to persist until the
/// callback.
pub fn build_authorization(
    endpoints: &OauthEndpoints,
    client_id: &str,
    redirect_uri: &str,
    scope: Option<&str>,
    extra_params: &[(String, String)],
) -> AuthRequest {
    let state = Oauth20State::default();
    let challenge = Oauth20PkceCodeChallenge::default();

    let scopes: BTreeSet<Cow<'_, str>> = scope
        .map(|scope| {
            scope
                .split_whitespace()
                .map(|s| Cow::from(s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let extras: BTreeMap<Cow<'_, str>, Cow<'_, str>> = extra_params
        .iter()
        .map(|(key, value)| (Cow::from(key.clone()), Cow::from(value.clone())))
        .collect();

    let url = Oauth20AuthRequestParams {
        client_id: client_id.into(),
        redirect_uri: Some(redirect_uri.into()),
        scope: scopes,
        state: Some(Cow::Borrowed(&state)),
        pkce_code_challenge: Some(Cow::Borrowed(&challenge)),
        extras,
    }
    .build_url(&endpoints.authorization);

    AuthRequest {
        url: url.to_string(),
        // NOTE: state/verifier bytes are printable ASCII (VSCHAR /
        // unreserved), so the from_utf8 never fails.
        state: String::from_utf8(state.expose().to_vec()).expect("state is printable ASCII"),
        verifier: String::from_utf8(challenge.verifier.expose().to_vec())
            .expect("verifier is unreserved ASCII"),
    }
}

/// Exchanges an authorization `code` for tokens, proving possession with the
/// PKCE `verifier` persisted at authorization time.
pub fn exchange_code(
    token_endpoint: &Url,
    client: &ClientId,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<Tokens> {
    let verifier = Oauth20PkceCodeVerifier::from_str(verifier)
        .map_err(|byte| anyhow!("invalid PKCE verifier byte {byte}"))?;

    let mut std_client =
        Oauth20ClientStd::connect(token_endpoint.clone(), &discover::tls(), client.id())
            .context("cannot connect to the token endpoint")?;

    let response = std_client
        .request_access_token(Oauth20AccessTokenRequestParams {
            code: code.into(),
            redirect_uri: Some(redirect_uri.into()),
            client_id: client.id().into(),
            client_secret: client.secret().map(|s| SecretString::from(s.to_string())),
            pkce_code_verifier: Some(Cow::Borrowed(&verifier)),
        })
        .context("token request failed")?
        .map_err(|err| anyhow!("token exchange rejected: {:?}", err.error))?;

    Ok(Tokens::from_success(response))
}

/// Refreshes an access token from a stored refresh token. If the provider
/// rotates the refresh token, the new one is returned; otherwise the caller
/// keeps the old one.
pub fn refresh(token_endpoint: &Url, client: &ClientId, refresh_token: &str) -> Result<Tokens> {
    let mut std_client =
        Oauth20ClientStd::connect(token_endpoint.clone(), &discover::tls(), client.id())
            .context("cannot connect to the token endpoint")?;

    let mut params = Oauth20AccessTokenRefreshParams::new(client.id(), refresh_token.to_string());
    params.client_secret = client.secret().map(|s| SecretString::from(s.to_string()));

    let response = std_client
        .refresh_access_token(params)
        .context("refresh request failed")?
        .map_err(|err| anyhow!("token refresh rejected: {:?}", err.error))?;

    Ok(Tokens::from_success(response))
}

/// A well-known public OAuth application, matched by a substring of the
/// authorization/token/issuer host.
///
/// `client_*` and `scope` apply only on the static path (Google,
/// Microsoft, which offer no dynamic registration); a
/// dynamically-registered client derives its scope from the issuer's
/// advertised `scopes_supported`. `auth_params` are extra
/// authorization-URL params the provider needs.
struct KnownProvider {
    host: &'static str,
    client_id: &'static str,
    client_secret: Option<&'static str>,
    scope: &'static str,
    auth_params: &'static [(&'static str, &'static str)],
}

/// Thunderbird's public clients (from ortie's `KNOWN_APPS`), reduced to
/// the mail-only scope needed to watch. Fastmail is registered
/// dynamically, so it has no static entry.
const KNOWN_PROVIDERS: &[KnownProvider] = &[
    KnownProvider {
        host: "google",
        client_id: "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com",
        client_secret: Some("kSmqreRr0qwBWJgbf5Y-PjSU"),
        scope: "https://mail.google.com/",
        // NOTE: Google only returns a refresh token with these.
        auth_params: &[("access_type", "offline"), ("prompt", "consent")],
    },
    KnownProvider {
        host: "microsoftonline",
        client_id: "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
        client_secret: None,
        scope: "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        auth_params: &[],
    },
];

fn provider_for(host: &str) -> Option<&'static KnownProvider> {
    KNOWN_PROVIDERS
        .iter()
        .find(|provider| host.contains(provider.host))
}

/// Picks a mail-access scope from an authorization server's advertised
/// `scopes_supported` (for a dynamically-registered client), plus
/// `offline_access` if the server uses it (needed for a refresh token).
fn mail_scope(supported: &[String]) -> Option<String> {
    scope_for(supported, |scope| {
        scope.contains("imap") || scope.contains(":mail") || scope.ends_with("/mail")
    })
}

/// Picks a contacts/CardDAV scope from advertised `scopes_supported`
/// (for a dynamically-registered client), plus `offline_access`. Without
/// it a CardDAV login gets [`mail_scope`] and the token 401s against
/// CardDAV.
///
/// Prefers a read-only contacts scope when the provider advertises one,
/// since Carillon only reads etags; falls back to a read-write CardDAV
/// scope otherwise (Fastmail offers only that).
fn contacts_scope(supported: &[String]) -> Option<String> {
    let is_contacts = |scope: &str| scope.contains("carddav") || scope.contains("contact");
    let is_readonly = |scope: &str| {
        scope.contains("readonly")
            || scope.contains("read-only")
            || scope.ends_with(".ro")
            || scope.ends_with(":ro")
    };
    scope_for(supported, |scope| is_contacts(scope) && is_readonly(scope))
        .or_else(|| scope_for(supported, is_contacts))
}

/// Shared scope picker: the first advertised scope matching `wanted`
/// (case-insensitive), plus `offline_access` when the server advertises
/// it. `None` when nothing matches, never a bare `offline_access`, so
/// callers can fall back.
fn scope_for(supported: &[String], wanted: impl Fn(&str) -> bool) -> Option<String> {
    let primary = supported
        .iter()
        .find(|scope| wanted(&scope.to_ascii_lowercase()))?;
    let mut chosen = vec![primary.clone()];
    if supported.iter().any(|scope| scope == "offline_access") {
        chosen.push("offline_access".to_string());
    }
    Some(chosen.join(" "))
}

/// Config-provided client overrides for the static providers, each
/// `(client_id, client_secret)`. Replaces the built-in Thunderbird
/// public client when set.
#[derive(Clone, Debug, Default)]
pub struct StaticClients {
    pub google: Option<(String, Option<String>)>,
    pub microsoft: Option<(String, Option<String>)>,
}

impl StaticClients {
    fn for_host(&self, host: &str) -> Option<&(String, Option<String>)> {
        match host {
            "google" => self.google.as_ref(),
            "microsoftonline" => self.microsoft.as_ref(),
            _ => None,
        }
    }
}

/// The discovered OAuth method to authorize against: an issuer (RFC
/// 8414, resolved to endpoints + a possible registration endpoint) or
/// direct endpoints, plus the scope discovery reported.
#[derive(Debug, Default)]
pub struct AuthInput {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub scope: Option<String>,
    /// Whether this login is for CardDAV (contacts): picks the contacts
    /// scope from the server's advertised metadata instead of the mail
    /// scope.
    pub contacts: bool,
}

/// The result of planning an authorization: the built request plus what
/// the callback must persist to exchange and later refresh (token
/// endpoint, client id/secret, resource, scope).
pub struct Planned {
    pub auth: AuthRequest,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

/// Plans an authorization for a discovered OAuth method: resolves
/// endpoints, chooses a client (dynamic registration where the issuer
/// offers it, else a config-provided or built-in public client),
/// requests the mail-only scope, and builds the authorization URL.
/// Blocking.
pub fn plan_authorization(
    input: &AuthInput,
    redirect_uri: &str,
    clients: &StaticClients,
) -> Result<Planned> {
    let host_of = |url: &str| {
        Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_default()
    };
    let origin_of = |url: &str| {
        Url::parse(url)
            .ok()
            .map(|url| url.origin().ascii_serialization())
    };

    let (endpoints, host) = if let Some(issuer) = &input.issuer {
        (resolve_issuer(issuer)?, host_of(issuer))
    } else {
        let authorization = input
            .authorization_endpoint
            .as_deref()
            .context("need an issuer or an authorization_endpoint")?;
        let token = input
            .token_endpoint
            .as_deref()
            .context("need a token_endpoint")?;
        let host = host_of(authorization);
        let direct = OauthEndpoints {
            authorization: authorization
                .parse()
                .context("invalid authorization_endpoint")?,
            token: token.parse().context("invalid token_endpoint")?,
            registration: None,
            scopes_supported: Vec::new(),
        };
        // NOTE: a provider can be discovered as direct endpoints yet
        // still support dynamic registration (Fastmail's per-email
        // discovery yields endpoints, not an issuer). If not a known
        // static provider, try the endpoint's origin as an issuer to
        // find a registration endpoint.
        let endpoints = if provider_for(&host).is_none() {
            origin_of(authorization)
                .and_then(|issuer| resolve_issuer(&issuer).ok())
                .filter(|metadata| metadata.registration.is_some())
                .unwrap_or(direct)
        } else {
            direct
        };
        (endpoints, host)
    };

    let provider = provider_for(&host);

    // NOTE: dynamic registration when the issuer offers it (Fastmail),
    // scope from advertised metadata; otherwise a known public client
    // (Google/Microsoft) with its hardcoded mail scope.
    let (client, scope) = if let Some(registration) = &endpoints.registration {
        let picked = if input.contacts {
            contacts_scope(&endpoints.scopes_supported)
        } else {
            mail_scope(&endpoints.scopes_supported)
        };
        let scope = picked.or_else(|| input.scope.clone());
        let client = register_client(registration, redirect_uri, scope.as_deref())?;
        (client, scope)
    } else if let Some(provider) = provider {
        // NOTE: a config-provided client (own app) overrides the
        // built-in default.
        let (client_id, client_secret) =
            clients.for_host(provider.host).cloned().unwrap_or_else(|| {
                (
                    provider.client_id.to_string(),
                    provider.client_secret.map(str::to_string),
                )
            });
        let client = ClientId::Static {
            client_id,
            client_secret,
        };
        (client, Some(provider.scope.to_string()))
    } else {
        bail!("OAuth is not configured for this provider yet");
    };

    // NOTE: extra authorization params, the provider's own plus an RFC
    // 8707 `resource` where required. Fastmail bounces the authorization
    // pre-consent with `invalid_target` unless `resource` is present;
    // discovery doesn't surface it yet, so supply the known value.
    let mut extra_params: Vec<(String, String)> = provider
        .map(|provider| {
            provider
                .auth_params
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let resource = required_resource(&host);
    if let Some(resource) = &resource {
        extra_params.push(("resource".to_string(), resource.clone()));
    }

    let auth = build_authorization(
        &endpoints,
        client.id(),
        redirect_uri,
        scope.as_deref(),
        &extra_params,
    );

    Ok(Planned {
        auth,
        token_endpoint: endpoints.token.to_string(),
        client_id: client.id().to_string(),
        client_secret: client.secret().map(str::to_string),
        resource,
        scope,
    })
}

/// The RFC 8707 `resource` indicator a provider is known to require but
/// discovery does not yet surface. Fastmail rejects the authorization
/// with `invalid_target` without it; one resource covers all its
/// protocols, so the JMAP session URL serves the mail flow too.
fn required_resource(host: &str) -> Option<String> {
    host.ends_with("fastmail.com")
        .then(|| "https://api.fastmail.com/jmap/session".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastmail_requires_a_resource() {
        assert_eq!(
            required_resource("api.fastmail.com").as_deref(),
            Some("https://api.fastmail.com/jmap/session"),
        );
        assert_eq!(
            required_resource("betty.fastmail.com").as_deref(),
            Some("https://api.fastmail.com/jmap/session")
        );
        assert_eq!(required_resource("imap.gmail.com"), None);
        assert_eq!(required_resource("outlook.office365.com"), None);
    }

    #[test]
    fn authorization_url_carries_the_resource() {
        let endpoints = OauthEndpoints {
            authorization: "https://api.fastmail.com/oauth/authorize".parse().unwrap(),
            token: "https://api.fastmail.com/oauth/refresh".parse().unwrap(),
            registration: None,
            scopes_supported: Vec::new(),
        };
        let extras = vec![(
            "resource".to_string(),
            "https://api.fastmail.com/jmap/session".to_string(),
        )];
        let request = build_authorization(
            &endpoints,
            "client-abc",
            "http://127.0.0.1:3000/oauth/callback",
            Some("urn:ietf:params:oauth:scope:mail offline_access"),
            &extras,
        );
        // The resource lands on the wire, URL-encoded.
        assert!(
            request
                .url
                .contains("resource=https%3A%2F%2Fapi.fastmail.com%2Fjmap%2Fsession"),
            "auth URL missing the RFC 8707 resource: {}",
            request.url,
        );
    }

    /// Live check: Fastmail exposes RFC 8414 metadata with a registration
    /// endpoint, and RFC 7591 dynamic registration returns a usable
    /// `client_id` from which a valid authorization URL builds. Ignored by
    /// default (hits the network); run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "hits Fastmail's live OAuth endpoints"]
    fn fastmail_dynamic_registration() {
        let endpoints = resolve_issuer("https://api.fastmail.com").expect("resolve issuer");
        let registration = endpoints
            .registration
            .clone()
            .expect("fastmail exposes a registration endpoint");

        // The mail scope Fastmail advertises for dynamic clients
        // (urn:ietf:params:oauth:scope:mail + offline_access).
        let scope = mail_scope(&endpoints.scopes_supported);
        assert!(
            scope.as_deref().is_some_and(|scope| scope.contains("mail")),
            "fastmail should advertise a mail scope, got {scope:?}",
        );

        let redirect = "http://127.0.0.1:3000/oauth/callback";
        let client =
            register_client(&registration, redirect, scope.as_deref()).expect("register client");
        assert!(
            !client.id().is_empty(),
            "issued client_id must be non-empty"
        );

        let request = build_authorization(&endpoints, client.id(), redirect, scope.as_deref(), &[]);
        assert!(
            request.url.starts_with("https://"),
            "auth URL must be https"
        );
        assert!(!request.state.is_empty() && !request.verifier.is_empty());
        // Do not print tokens/secrets; a length is enough to confirm success.
        eprintln!(
            "fastmail: client_id chars={}, scope={scope:?}, auth_url chars={}",
            client.id().len(),
            request.url.len()
        );
    }
}
