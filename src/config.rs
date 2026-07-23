//! # Configuration
//!
//! TOML configuration of the watch server: **infrastructure only** —
//! server-wide settings (the sqlite database, the age key, tuning
//! knobs) and the control API listen address. Watches (accounts) do
//! **not** live here: the store is their sole source of truth, and they
//! enter it through the control API or the one-shot `carillon import`
//! command (see [`ImportFile`]). This collapses the old "config-path vs
//! API-path for accounts" duplication onto one path.

use std::{
    collections::BTreeMap,
    env, fs, mem,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Root of the daemon's TOML configuration file: infrastructure only.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    /// Server-wide settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Control API settings.
    #[serde(default)]
    pub api: ApiConfig,
    /// OAuth client overrides (own registered apps instead of the built-in
    /// Thunderbird public clients).
    #[serde(default)]
    pub oauth: OauthConfig,
    /// Payment provider (Stripe). Unset = the keyless stub provider.
    #[serde(default)]
    pub billing: BillingConfig,
    /// Transactional email provider (magic links + notices). Unset = the
    /// keyless stub mailer (logs instead of sending).
    #[serde(default)]
    pub email: EmailConfig,
}

/// Transactional email configuration. Unset (`[email]` absent) = the keyless
/// stub mailer used for local/dev (it logs the magic-link URL). Deliverability
/// guidance (authenticated sending subdomain, SPF/DKIM/DMARC, no link tracking
/// on the auth stream) lives in `docs/EMAIL.md`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EmailConfig {
    /// `[email.resend]` — the Resend adapter. Absent = the stub.
    #[serde(default)]
    pub resend: Option<ResendConfig>,
}

/// Resend configuration. `api_key` is a **secret** — inject it via systemd
/// `LoadCredential` / a secrets manager in production.
#[derive(Clone, Debug, Deserialize)]
pub struct ResendConfig {
    /// Resend API key (`re_…`). A **secret**: set it inline, or point
    /// [`ResendConfig::api_key_file`] at a file holding it.
    #[serde(default)]
    pub api_key: String,
    /// Read `api_key` from this file (trimmed) instead of inline — for systemd
    /// `LoadCredential`, sops-nix, or any secret manager. Set exactly one.
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// The `From:` header — a monitored address on your authenticated sending
    /// subdomain, e.g. `Carillon <no-reply@mail.carillon.pimalaya.org>`.
    pub from: String,
}

/// OAuth client overrides for the providers that need a pre-registered app
/// (Google, Microsoft — they offer no dynamic registration). Unset = the
/// built-in Thunderbird public clients. Provide your own to use a hosted
/// redirect URI (Thunderbird's clients only accept loopback redirects).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OauthConfig {
    /// `[oauth.google]` — your Google OAuth client.
    #[serde(default)]
    pub google: Option<OauthClientConfig>,
    /// `[oauth.microsoft]` — your Microsoft (Entra) OAuth client.
    #[serde(default)]
    pub microsoft: Option<OauthClientConfig>,
}

/// A registered OAuth client for a provider.
#[derive(Clone, Debug, Deserialize)]
pub struct OauthClientConfig {
    /// The registered client id.
    pub client_id: String,
    /// The client secret, if the app is a confidential client (public
    /// PKCE clients have none).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Read `client_secret` from this file (trimmed) instead of inline.
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
}

/// Payment provider configuration. Unset (`[billing]` absent) = the keyless
/// stub provider used for local/dev.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BillingConfig {
    /// `[billing.stripe]` — the Stripe adapter. Absent = the stub.
    #[serde(default)]
    pub stripe: Option<StripeConfig>,
}

/// Stripe configuration. `secret_key` and `webhook_secret` are **secrets** —
/// in production inject them via systemd `LoadCredential` / a secrets manager
/// rather than a world-readable file (see `docs/DEPLOY_HARDENING.md`). The
/// price *lives in Stripe*: `prices` maps the `pack` key to a **one-time**
/// Stripe Price id — the price of one credit pack (`PACK_SIZE` credits) —
/// created in the dashboard. Only the **secret** key is needed — hosted
/// Checkout needs no publishable key server-side.
#[derive(Clone, Debug, Deserialize)]
pub struct StripeConfig {
    /// Secret API key (`sk_test_…` in the sandbox, `sk_live_…` in production).
    /// A **secret**: set it inline, or via [`StripeConfig::secret_key_file`].
    #[serde(default)]
    pub secret_key: String,
    /// Read `secret_key` from this file (trimmed) instead of inline.
    #[serde(default)]
    pub secret_key_file: Option<PathBuf>,
    /// Webhook signing secret (`whsec_…`) for verifying the event signature.
    /// A **secret**: set it inline, or via [`StripeConfig::webhook_secret_file`].
    #[serde(default)]
    pub webhook_secret: String,
    /// Read `webhook_secret` from this file (trimmed) instead of inline.
    #[serde(default)]
    pub webhook_secret_file: Option<PathBuf>,
    /// Where Stripe returns the buyer after a successful payment. Optional —
    /// defaults to the dashboard URL with a `?checkout=success` marker.
    #[serde(default)]
    pub success_url: Option<String>,
    /// Where Stripe returns the buyer after a cancelled payment. Optional —
    /// defaults to the dashboard URL with a `?checkout=cancel` marker.
    #[serde(default)]
    pub cancel_url: Option<String>,
    /// Plan id (`month`, `year`, …) → recurring Stripe Price id (`price_…`).
    #[serde(default)]
    pub prices: BTreeMap<String, String>,
}

impl Config {
    /// Reads, parses and resolves the configuration at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read configuration at {}", path.display()))?;
        let mut config: Config = toml::from_str(&content).context("Cannot parse configuration")?;
        config.resolve_secrets()?;
        Ok(config)
    }

    /// Resolves every `*_file` secret pointer into its inline field by reading
    /// the file (trimmed). Keeps secrets out of the config file itself —
    /// delivered instead by systemd `LoadCredential`, sops-nix or any secret
    /// manager (see `docs/NIXOS.md`, `docs/DEPLOY_HARDENING.md`). For each
    /// secret, set the inline value OR its `*_file`, never both.
    fn resolve_secrets(&mut self) -> Result<()> {
        self.api.admin_token = resolve_optional_secret(
            "api.admin_token",
            self.api.admin_token.take(),
            self.api.admin_token_file.take(),
        )?;

        if let Some(stripe) = &mut self.billing.stripe {
            stripe.secret_key = resolve_required_secret(
                "billing.stripe.secret_key",
                mem::take(&mut stripe.secret_key),
                stripe.secret_key_file.take(),
            )?;
            stripe.webhook_secret = resolve_required_secret(
                "billing.stripe.webhook_secret",
                mem::take(&mut stripe.webhook_secret),
                stripe.webhook_secret_file.take(),
            )?;
        }

        if let Some(resend) = &mut self.email.resend {
            resend.api_key = resolve_required_secret(
                "email.resend.api_key",
                mem::take(&mut resend.api_key),
                resend.api_key_file.take(),
            )?;
        }

        if let Some(client) = &mut self.oauth.google {
            client.client_secret = resolve_optional_secret(
                "oauth.google.client_secret",
                client.client_secret.take(),
                client.client_secret_file.take(),
            )?;
        }
        if let Some(client) = &mut self.oauth.microsoft {
            client.client_secret = resolve_optional_secret(
                "oauth.microsoft.client_secret",
                client.client_secret.take(),
                client.client_secret_file.take(),
            )?;
        }

        Ok(())
    }
}

/// Resolves an **optional** secret: reads `file` (trimmed) when set, errors if
/// both an inline value and a file are given, `None` when neither is.
fn resolve_optional_secret(
    name: &str,
    inline: Option<String>,
    file: Option<PathBuf>,
) -> Result<Option<String>> {
    match (inline, file) {
        (Some(_), Some(_)) => bail!("{name}: set either the inline value or {name}_file, not both"),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => Ok(Some(read_secret_file(name, &path)?)),
        (None, None) => Ok(None),
    }
}

/// Resolves a **required** secret. The inline value arrives as a (possibly
/// empty) string; an empty inline with no file is an error.
fn resolve_required_secret(name: &str, inline: String, file: Option<PathBuf>) -> Result<String> {
    match (inline.is_empty(), file) {
        (false, Some(_)) => bail!("{name}: set either the inline value or {name}_file, not both"),
        (false, None) => Ok(inline),
        (true, Some(path)) => read_secret_file(name, &path),
        (true, None) => bail!("{name} is required: set it inline or via {name}_file"),
    }
}

/// Reads and trims a secret file, rejecting an empty result.
fn read_secret_file(name: &str, path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Cannot read {name} from {}", path.display()))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{name} file {} is empty", path.display());
    }
    Ok(trimmed.to_owned())
}

/// Server-wide settings.
#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    /// Path to the sqlite database (watches + delivery log).
    #[serde(default = "default_db")]
    pub db: PathBuf,
    /// Path to the age identity file (generated if absent) used to
    /// encrypt watch passwords at rest.
    #[serde(default = "default_age_key")]
    pub age_key_file: PathBuf,
    /// Ceiling on simultaneous TLS handshakes, to tame reconnect
    /// storms and per-IP provider limits.
    #[serde(default = "default_max_handshakes")]
    pub max_concurrent_handshakes: usize,
    /// How often the supervisor re-reads the store as a safety net,
    /// in addition to explicit API-triggered reconciles.
    #[serde(default = "default_reconcile_secs")]
    pub reconcile_interval_secs: u64,
    /// Permit outbound connections (IMAP + webhooks) to loopback / private /
    /// link-local addresses. Default `false` (the SSRF-safe posture). Set
    /// `true` for local dev or a self-host that watches a LAN mail server or
    /// posts to a loopback sink.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Fair-use cap: the most distinct mailboxes a single (SaaS) account may
    /// watch before it needs a volume plan. A generous backstop against
    /// reselling, not a product tier — the flat plan is "unlimited" below it.
    #[serde(default = "default_max_watches")]
    pub max_watches_per_account: usize,
    /// Default poll interval (seconds) for CardDAV addressbook services, which
    /// have no push and are polled for sync-token changes. A per-service
    /// override may lower it; IMAP services ignore it (they hold IDLE).
    #[serde(default = "default_carddav_poll_secs")]
    pub carddav_poll_interval_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            db: default_db(),
            age_key_file: default_age_key(),
            max_concurrent_handshakes: default_max_handshakes(),
            reconcile_interval_secs: default_reconcile_secs(),
            allow_private_targets: false,
            max_watches_per_account: default_max_watches(),
            carddav_poll_interval_secs: default_carddav_poll_secs(),
        }
    }
}

impl ServerConfig {
    /// The database path with a leading tilde expanded.
    pub fn db_path(&self) -> PathBuf {
        expand_tilde(&self.db)
    }

    /// The age key path with a leading tilde expanded.
    pub fn age_key_path(&self) -> PathBuf {
        expand_tilde(&self.age_key_file)
    }
}

/// Control API settings.
#[derive(Clone, Debug, Deserialize)]
pub struct ApiConfig {
    /// Listen address of the HTTP control API.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Optional directory of static UI assets (a built `carillon-frontend`
    /// `dist/`) to serve at the API origin. Unset = API only (the SaaS
    /// front serves the UI from a CDN instead).
    #[serde(default)]
    pub ui_dir: Option<PathBuf>,
    /// Optional CORS allow-origin for a cross-origin (CDN) front. `*`
    /// allows any origin; a URL allows exactly that one. Unset = no CORS
    /// (same-origin self-host).
    #[serde(default)]
    pub cors_allow_origin: Option<String>,
    /// Optional master bearer token granting **unscoped** access to every
    /// account's watches, deliveries and events. This is the ops /
    /// headless-self-host escape hatch: with it, a `carillon import`-only
    /// box (which has no capability link) can still be inspected, and an
    /// operator can see the whole fleet. Unset (the default) = there is no
    /// unscoped access at all; every data route is reachable only through a
    /// capability link scoped to one account (§ DECISIONS 5). Keep it long
    /// and secret; it is the whole fleet's key.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// Read `admin_token` from this file (trimmed) instead of inline — for
    /// systemd `LoadCredential`, sops-nix, etc. Set exactly one of the two.
    #[serde(default)]
    pub admin_token_file: Option<PathBuf>,
    /// Public base URL of this API, used to build the OAuth redirect URI
    /// (`{public_url}/oauth/callback`). Defaults to `http://{listen}` — fine
    /// for local self-host; set it to the externally reachable URL when
    /// exposed (the provider redirects the browser here).
    #[serde(default)]
    pub public_url: Option<String>,
    /// Base URL of the dashboard the OAuth popup posts its result back to; its
    /// origin is the `postMessage` target. Defaults to `public_url`.
    #[serde(default)]
    pub dashboard_url: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            ui_dir: None,
            cors_allow_origin: None,
            admin_token: None,
            admin_token_file: None,
            public_url: None,
            dashboard_url: None,
        }
    }
}

/// A file of accounts to import into the store, consumed by the
/// `carillon import` command. This is the headless self-host entrypoint
/// for populating the DB out-of-band; the running daemon picks the new
/// watches up on its next reconcile. Distinct from [`Config`] on
/// purpose: the daemon config is infra, this is data.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ImportFile {
    /// Accounts to import, keyed by watch id.
    #[serde(default)]
    pub accounts: BTreeMap<String, ImportAccount>,
}

impl ImportFile {
    /// Reads and parses an import file at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read import file at {}", path.display()))?;
        toml::from_str(&content).context("Cannot parse import file")
    }
}

/// One account (watch) to import into the store.
#[derive(Clone, Debug, Deserialize)]
pub struct ImportAccount {
    /// IMAP server host.
    pub imap_host: String,
    /// IMAP server port.
    #[serde(default = "default_port")]
    pub imap_port: u16,
    /// Login (authentication identity).
    pub login: String,
    /// Password source (inline or command).
    pub password: PasswordConfig,
    /// Mailbox to watch.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    /// Where to POST the signed, content-free change events.
    pub notify_url: String,
    /// Shared secret used to HMAC-sign deliveries.
    pub hmac_secret: String,
    /// Whether the watch starts enabled.
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Password source: inline (testing) or the output of a shell command.
#[derive(Clone, Debug, Deserialize)]
pub struct PasswordConfig {
    /// Inline password (testing only).
    pub raw: Option<String>,
    /// Command whose stdout is the password (keyring CLIs).
    pub command: Option<String>,
}

impl PasswordConfig {
    /// Resolves the password, trimming trailing newlines of command
    /// outputs.
    pub fn resolve(&self) -> Result<String> {
        if let Some(raw) = &self.raw {
            return Ok(raw.clone());
        }

        let Some(command) = &self.command else {
            bail!("Account password requires either raw or command");
        };

        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .context("Cannot run the password command")?;

        if !output.status.success() {
            bail!("Password command exited with {}", output.status);
        }

        let password = String::from_utf8(output.stdout)
            .context("Password command output is not valid UTF-8")?;

        Ok(password.trim_end().to_owned())
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
    let Ok(rest) = path.strip_prefix("~") else {
        return path.to_path_buf();
    };

    match env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(rest),
        None => path.to_path_buf(),
    }
}

fn default_db() -> PathBuf {
    PathBuf::from("~/.local/share/carillon/carillon.db")
}

fn default_age_key() -> PathBuf {
    PathBuf::from("~/.local/share/carillon/age.key")
}

fn default_max_handshakes() -> usize {
    50
}

fn default_reconcile_secs() -> u64 {
    60
}

fn default_max_watches() -> usize {
    25
}

fn default_carddav_poll_secs() -> u64 {
    300
}

fn default_listen() -> String {
    String::from("127.0.0.1:3000")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("carillon-secret-test-{name}"));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn inline_optional_secret_passes_through() {
        assert_eq!(
            resolve_optional_secret("x", Some("v".into()), None).unwrap(),
            Some("v".to_owned())
        );
        assert_eq!(resolve_optional_secret("x", None, None).unwrap(), None);
    }

    #[test]
    fn file_secret_is_read_and_trimmed() {
        let path = write_temp("read", "  sk_live_abc\n");
        assert_eq!(
            resolve_required_secret("x", String::new(), Some(path.clone())).unwrap(),
            "sk_live_abc"
        );
        assert_eq!(
            resolve_optional_secret("x", None, Some(path.clone())).unwrap(),
            Some("sk_live_abc".to_owned())
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn both_inline_and_file_is_rejected() {
        let path = write_temp("both", "v");
        assert!(resolve_optional_secret("x", Some("v".into()), Some(path.clone())).is_err());
        assert!(resolve_required_secret("x", "v".into(), Some(path.clone())).is_err());
        fs::remove_file(path).ok();
    }

    #[test]
    fn missing_required_secret_is_rejected() {
        assert!(resolve_required_secret("x", String::new(), None).is_err());
    }

    #[test]
    fn empty_secret_file_is_rejected() {
        let path = write_temp("empty", "   \n");
        assert!(resolve_required_secret("x", String::new(), Some(path.clone())).is_err());
        fs::remove_file(path).ok();
    }

    #[test]
    fn stripe_secret_key_resolves_from_file_on_load() {
        let key = write_temp("stripe-sk", "sk_live_fromfile\n");
        let toml = format!(
            r#"
            [billing.stripe]
            secret_key_file = "{}"
            webhook_secret = "whsec_inline"
            [billing.stripe.prices]
            pack = "price_1"
            "#,
            key.display()
        );
        let cfg_path = write_temp("cfg.toml", &toml);
        let config = Config::load(&cfg_path).unwrap();
        let stripe = config.billing.stripe.unwrap();
        assert_eq!(stripe.secret_key, "sk_live_fromfile");
        assert_eq!(stripe.webhook_secret, "whsec_inline");
        fs::remove_file(key).ok();
        fs::remove_file(cfg_path).ok();
    }
}
