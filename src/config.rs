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
    env, fs,
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
}

impl Config {
    /// Reads and parses the configuration at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Cannot read configuration at {}", path.display()))?;
        toml::from_str(&content).context("Cannot parse configuration")
    }
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            db: default_db(),
            age_key_file: default_age_key(),
            max_concurrent_handshakes: default_max_handshakes(),
            reconcile_interval_secs: default_reconcile_secs(),
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
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
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
