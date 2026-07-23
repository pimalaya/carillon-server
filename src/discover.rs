//! Onboarding discovery.
//!
//! Turns a "put anything" identifier (an email address or a bare
//! domain/server) into the onboarding choices a user picks from, using
//! [`io_pim_discovery`] (provider rules, PACC, Mozilla autoconfig/ISPDB,
//! RFC 6186 SRV).
//!
//! A choice is one server endpoint plus one way to authenticate; the
//! discovery mechanism that surfaced it is irrelevant to the user, so
//! results are grouped by `(host, port, security)` with auth methods
//! unioned, then split into one choice per auth category (password /
//! OAuth / token). Everything is a hint the user confirms; an
//! unresolvable input yields an empty list. The blocking std client runs
//! its own network I/O, so callers wrap [`discover_imap`] in
//! `spawn_blocking`.

use std::collections::{BTreeMap, BTreeSet};

use io_pim_discovery::compose::client::DiscoveryComposeClientStd;
use io_pim_discovery::compose::config::{
    DiscoveryAuthMethod, DiscoveryEndpoint, DiscoverySecurity, DiscoveryService,
};
use io_pim_discovery::shared::dns::system_resolver;
use pimalaya_stream::tls::{Rustls, Tls};
use serde::Serialize;
use tracing::warn;
use url::Url;

/// Fallback DNS resolver when the system one cannot be read.
const DEFAULT_RESOLVER: &str = "tcp://1.1.1.1:53";

/// One onboarding choice: an IMAP endpoint plus a single way to
/// authenticate to it. The wizard renders one card per choice, showing
/// the matching credential form on selection. Every field is a hint the
/// user confirms or overrides.
#[derive(Debug, Serialize)]
pub struct ImapChoice {
    /// IMAP server host.
    pub host: String,
    /// IMAP server port.
    pub port: u16,
    /// Connection security: `tls` | `starttls` | `plain`.
    pub security: &'static str,
    /// How to authenticate with this choice.
    pub auth: AuthMethodView,
}

/// A discovered authentication method, tagged for the client. OAuth
/// variants carry the endpoints where known.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethodView {
    /// Username + password (or an app password).
    Password,
    /// A provider-issued bearer token (an "API token").
    Bearer,
    /// OAuth 2.0 authorization-code grant (endpoints known).
    Oauth {
        authorization_endpoint: String,
        token_endpoint: String,
        scope: Option<String>,
    },
    /// OAuth 2.0 device-authorization grant.
    OauthDevice {
        device_authorization_endpoint: String,
        token_endpoint: String,
        scope: Option<String>,
    },
    /// OAuth where only the issuer is known; its endpoints are resolved
    /// later from the issuer's RFC 8414 metadata.
    OauthIssuer { issuer: String },
}

/// The three auth forms a choice maps to. Discovery may advertise
/// several concrete methods per category; the user picks a category, and
/// the best concrete method for it is kept.
#[derive(Clone, Copy, PartialEq)]
enum AuthCategory {
    Password,
    Oauth,
    Token,
}

/// One CardDAV onboarding choice: a discovered addressbook server (RFC
/// 6764 context root) plus how to authenticate. Unlike IMAP there is no
/// host/port; CardDAV is HTTP, so the endpoint is a URL the wizard
/// confirms.
#[derive(Debug, Serialize)]
pub struct CardDavChoice {
    /// CardDAV context-root URL (RFC 6764), e.g. `https://carddav.host/`.
    pub url: String,
    /// How to authenticate (password is the DAV default; a provider
    /// advertising OAuth on the endpoint surfaces it here).
    pub auth: AuthMethodView,
}

/// Discovers CardDAV onboarding choices for `input` (an email address or
/// bare domain/server) via RFC 6764 (`_carddavs._tcp` SRV +
/// `.well-known`). Never fails loudly (empty list means manual entry).
/// Blocking; call inside `spawn_blocking`.
pub fn discover_carddav(input: &str) -> Vec<CardDavChoice> {
    let input = input.trim();
    let email = if input.contains('@') {
        input.to_string()
    } else {
        format!("user@{input}")
    };

    let client = DiscoveryComposeClientStd::new(resolver(), tls());
    let configs = match client.compose_all(&email, BTreeSet::from([DiscoveryService::Carddav])) {
        Ok(configs) => configs,
        Err(err) => {
            warn!(input, error = %err, "carddav discovery failed");
            return Vec::new();
        }
    };

    // NOTE: one or two choices per distinct context-root URL. Password
    // is always offered (the DAV default, near-universal); an OAuth
    // choice is added when advertised. Emitting both (not
    // OAuth-preferred) lets a Fastmail user pick their app password.
    let mut seen = BTreeSet::new();
    let mut choices = Vec::new();
    for config in configs {
        if config.service != DiscoveryService::Carddav {
            continue;
        }
        let DiscoveryEndpoint::Http(url) = config.endpoint else {
            continue;
        };
        if !seen.insert(url.clone()) {
            continue;
        }
        choices.push(CardDavChoice {
            url: url.clone(),
            auth: AuthMethodView::Password,
        });
        if let Some(method) = best_oauth(&config.auth) {
            choices.push(CardDavChoice {
                url,
                auth: auth_view(method.clone()),
            });
        }
    }
    choices
}

/// Discovers IMAP onboarding choices for `input` (an email address or
/// bare domain/server). Never fails loudly: an unresolvable input yields
/// an empty list. Blocking; call inside `spawn_blocking`.
pub fn discover_imap(input: &str) -> Vec<ImapChoice> {
    // NOTE: `compose_all` wants a `local@domain`; for a bare
    // domain/server synthesize a local part so discovery still runs.
    let input = input.trim();
    let email = if input.contains('@') {
        input.to_string()
    } else {
        format!("user@{input}")
    };

    let client = DiscoveryComposeClientStd::new(resolver(), tls());
    let configs = match client.compose_all(&email, BTreeSet::from([DiscoveryService::Imap])) {
        Ok(configs) => configs,
        Err(err) => {
            warn!(input, error = %err, "discovery failed");
            return Vec::new();
        }
    };

    // NOTE: group by endpoint, unioning the auth methods every mechanism
    // advertised (the mechanism itself is irrelevant to the user).
    // BTreeMap keeps the output deterministic.
    let mut endpoints: BTreeMap<(String, u16, &'static str), Vec<DiscoveryAuthMethod>> =
        BTreeMap::new();
    for config in configs {
        if config.service != DiscoveryService::Imap {
            continue;
        }
        let DiscoveryEndpoint::Tcp {
            host,
            port,
            security,
        } = config.endpoint
        else {
            continue;
        };
        endpoints
            .entry((host, port, security_str(security)))
            .or_default()
            .extend(config.auth);
    }

    // NOTE: one choice per (endpoint, auth category), ordered password →
    // OAuth → token. A server discovered with no auth at all still
    // offers Password, the near-universal default.
    let mut choices = Vec::new();
    for ((host, port, security), methods) in endpoints {
        let has = |category| methods.iter().any(|method| categorize(method) == category);

        if methods.is_empty() || has(AuthCategory::Password) {
            choices.push(ImapChoice {
                host: host.clone(),
                port,
                security,
                auth: AuthMethodView::Password,
            });
        }
        if let Some(method) = best_oauth(&methods) {
            choices.push(ImapChoice {
                host: host.clone(),
                port,
                security,
                auth: auth_view(method.clone()),
            });
        }
        if has(AuthCategory::Token) {
            choices.push(ImapChoice {
                host,
                port,
                security,
                auth: AuthMethodView::Bearer,
            });
        }
    }
    choices
}

/// The category a concrete auth method falls into.
fn categorize(method: &DiscoveryAuthMethod) -> AuthCategory {
    match method {
        DiscoveryAuthMethod::Password => AuthCategory::Password,
        DiscoveryAuthMethod::Bearer => AuthCategory::Token,
        DiscoveryAuthMethod::OauthAuthorizationCodeGrant { .. }
        | DiscoveryAuthMethod::OauthDeviceAuthorizationGrant { .. }
        | DiscoveryAuthMethod::OauthIssuer(_) => AuthCategory::Oauth,
    }
}

/// Picks the single best OAuth method for an endpoint: an
/// authorization-code grant with a mail-oriented scope, else any
/// authorization-code grant, else a device grant, else a bare issuer.
/// `None` if the endpoint has no OAuth.
fn best_oauth(methods: &[DiscoveryAuthMethod]) -> Option<&DiscoveryAuthMethod> {
    let is_auth_code = |method: &&DiscoveryAuthMethod| {
        matches!(
            method,
            DiscoveryAuthMethod::OauthAuthorizationCodeGrant { .. }
        )
    };

    methods
        .iter()
        .filter(is_auth_code)
        .find(|method| match method {
            DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
                scope: Some(scope), ..
            } => {
                let scope = scope.to_ascii_lowercase();
                scope.contains("mail") || scope.contains("imap")
            }
            _ => false,
        })
        .or_else(|| methods.iter().find(is_auth_code))
        .or_else(|| {
            methods.iter().find(|method| {
                matches!(
                    method,
                    DiscoveryAuthMethod::OauthDeviceAuthorizationGrant { .. }
                )
            })
        })
        .or_else(|| {
            methods
                .iter()
                .find(|method| matches!(method, DiscoveryAuthMethod::OauthIssuer(_)))
        })
}

/// The DNS resolver to discover with: the system one, else a public
/// fallback. Shared with the OAuth module.
pub(crate) fn resolver() -> Url {
    system_resolver().unwrap_or_else(|| {
        DEFAULT_RESOLVER
            .parse()
            .expect("DEFAULT_RESOLVER must be a valid URL")
    })
}

/// TLS for the discovery HTTP fetches, pinned to HTTP/1.1 (the discovery
/// endpoints are plain HTTP/1.1 servers). Shared with the OAuth module.
pub(crate) fn tls() -> Tls {
    Tls {
        rustls: Rustls {
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn security_str(security: DiscoverySecurity) -> &'static str {
    match security {
        DiscoverySecurity::Plain => "plain",
        DiscoverySecurity::Starttls => "starttls",
        DiscoverySecurity::Tls => "tls",
    }
}

fn auth_view(method: DiscoveryAuthMethod) -> AuthMethodView {
    match method {
        DiscoveryAuthMethod::Password => AuthMethodView::Password,
        DiscoveryAuthMethod::Bearer => AuthMethodView::Bearer,
        DiscoveryAuthMethod::OauthAuthorizationCodeGrant {
            authorization_endpoint,
            token_endpoint,
            scope,
        } => AuthMethodView::Oauth {
            authorization_endpoint,
            token_endpoint,
            scope,
        },
        DiscoveryAuthMethod::OauthDeviceAuthorizationGrant {
            device_authorization_endpoint,
            token_endpoint,
            scope,
        } => AuthMethodView::OauthDevice {
            device_authorization_endpoint,
            token_endpoint,
            scope,
        },
        DiscoveryAuthMethod::OauthIssuer(issuer) => AuthMethodView::OauthIssuer { issuer },
    }
}
