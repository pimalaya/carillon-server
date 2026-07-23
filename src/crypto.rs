//! Password encryption at rest.
//!
//! Carillon holds credentials in order to watch; they must never sit in
//! the database as plaintext. Each password is encrypted to a per-box
//! age (x25519) identity kept in a `0600` key file. Production would
//! move that key into a KMS without changing this interface.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, str::FromStr};

use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;

/// Symmetric self-recipient encryptor backed by a persisted age
/// identity.
pub struct Crypto {
    identity: Identity,
    recipient: Recipient,
}

impl Crypto {
    /// Loads the age identity at `path`, generating and persisting a
    /// fresh one (mode `0600`) if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let identity = if path.exists() {
            let text = fs::read_to_string(path)
                .with_context(|| format!("Cannot read age key at {}", path.display()))?;
            Identity::from_str(text.trim()).map_err(|e| anyhow!("Invalid age key: {e}"))?
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Cannot create {}", parent.display()))?;
            }

            let identity = Identity::generate();
            let secret = identity.to_string();
            fs::write(path, secret.expose_secret())
                .with_context(|| format!("Cannot write age key at {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .context("Cannot restrict age key permissions")?;
            identity
        };

        let recipient = identity.to_public();
        Ok(Self {
            identity,
            recipient,
        })
    }

    /// Encrypts a password into a base64 blob for the database.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let bytes = age::encrypt(&self.recipient, plaintext.as_bytes())
            .context("Cannot encrypt password")?;
        Ok(STANDARD.encode(bytes))
    }

    /// Decrypts a base64 blob produced by [`Crypto::encrypt`].
    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<String> {
        let bytes = STANDARD
            .decode(ciphertext_b64)
            .context("Stored password is not valid base64")?;
        let plaintext = age::decrypt(&self.identity, &bytes).context("Cannot decrypt password")?;
        String::from_utf8(plaintext).context("Decrypted password is not valid UTF-8")
    }
}
