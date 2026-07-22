//! # Store
//!
//! The source of truth for watches and the delivery log, a local
//! sqlite database behind a mutex. Passwords are stored encrypted (see
//! [`crate::crypto`]); everything else is plain. Blocking rusqlite
//! calls are cheap and infrequent here (boot-time loads, one small row
//! per delivery); the hot delivery path wraps them in
//! `spawn_blocking`.

use std::{path::Path, sync::Mutex, time::Duration};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};

use crate::util::now_secs;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS watch (
  id           TEXT PRIMARY KEY,
  imap_host    TEXT NOT NULL,
  imap_port    INTEGER NOT NULL,
  login        TEXT NOT NULL,
  enc_password TEXT NOT NULL,
  mailbox      TEXT NOT NULL,
  notify_url   TEXT NOT NULL,
  hmac_secret  TEXT NOT NULL,
  hmac_secret_prev         TEXT,
  hmac_secret_prev_expires INTEGER,
  account_id   TEXT NOT NULL DEFAULT '',
  -- The provider domain this service is grouped + trial-gated under: the
  -- registrable domain of the server host (e.g. `fastmail.com` for both an
  -- account's imap. and carddav. hosts). Stamped at create; the front end uses
  -- it for every provider label. Empty on rows predating the column.
  provider     TEXT NOT NULL DEFAULT '',
  last_metered INTEGER,
  -- 'password' (enc_password) or 'oauth' (the oauth_credential for the
  -- watch's (account_id, mailbox_key)).
  auth_kind    TEXT NOT NULL DEFAULT 'password',
  -- Per-service billing (§ BILLING_MODEL): the watch is the billed unit.
  -- `watching_until` is the paid-through time — activation spends one credit to
  -- set it a month ahead, and the service runs (when metered) only while it is
  -- in the future. `auto_renew` (off by default) draws the next credit from the
  -- pool at expiry instead of stopping.
  watching_until INTEGER,
  auto_renew   INTEGER NOT NULL DEFAULT 0,
  active       INTEGER NOT NULL DEFAULT 1,
  -- Source protocol: 'imap' (a held IDLE connection, the default) or
  -- 'carddav' (a polled addressbook). CardDAV columns are null for IMAP.
  source_kind  TEXT NOT NULL DEFAULT 'imap',
  -- CardDAV: the full collection URL the poller connects to (imap_host/login
  -- still carry the PIM-account identity, so the mailbox key and stored
  -- credential are shared with the account's IMAP membership).
  carddav_url  TEXT,
  -- CardDAV: the last RFC 6578 sync-token checkpoint (runtime state, kept
  -- across edits, reset on re-baseline). Null until the first poll.
  carddav_sync_token TEXT,
  -- CardDAV: poll interval override in seconds; null uses the server default.
  carddav_poll_secs INTEGER
);

-- Pending OAuth authorization flows: the short-lived state carried between
-- /oauth/start and /oauth/callback. Consumed (deleted) on use; aged out by
-- created_at. The verifier is ephemeral and single-use; a client secret (if
-- the provider issued one) is age-encrypted.
CREATE TABLE IF NOT EXISTS oauth_session (
  state          TEXT PRIMARY KEY,
  verifier       TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  token_endpoint TEXT NOT NULL,
  client_id      TEXT NOT NULL,
  enc_client_secret TEXT,
  resource       TEXT,
  scope          TEXT,
  account_id     TEXT,
  login          TEXT NOT NULL,
  imap_host      TEXT NOT NULL,
  imap_port      INTEGER NOT NULL,
  mailbox        TEXT NOT NULL,
  -- Source protocol this OAuth login is for: 'imap' (default) or 'carddav'. For
  -- carddav, `imap_host` carries the DAV host (so the mailbox key matches what
  -- the poller resolves) and `carddav_url` the collection context root.
  source_kind    TEXT NOT NULL DEFAULT 'imap',
  carddav_url    TEXT,
  created_at     INTEGER NOT NULL
);

-- The OAuth credential for a proven mailbox: the age-encrypted refresh token
-- plus everything needed to mint fresh access tokens. Keyed by (account,
-- mailbox); every watch on that mailbox authenticates through it. This is the
-- long-term secret (the /oauth/callback stores it; the supervisor refreshes).
CREATE TABLE IF NOT EXISTS oauth_credential (
  account_id        TEXT NOT NULL,
  mailbox_key       TEXT NOT NULL,
  enc_refresh_token TEXT NOT NULL,
  token_endpoint    TEXT NOT NULL,
  client_id         TEXT NOT NULL,
  enc_client_secret TEXT,
  resource          TEXT,
  scope             TEXT,
  updated_at        INTEGER NOT NULL,
  PRIMARY KEY (account_id, mailbox_key)
);

-- The password credential for a proven PIM account (§ BILLING_MODEL: the
-- credential lives on the PIM account, not the service). Age-encrypted; every
-- password service under this (account, mailbox) authenticates through it, so a
-- re-auth updates them all at once. Stored at 'Add account' (POST /auth); reused
-- when adding services. Self-host import instead carries the password on the
-- watch (watch.enc_password), which takes precedence when present.
CREATE TABLE IF NOT EXISTS password_credential (
  account_id   TEXT NOT NULL,
  mailbox_key  TEXT NOT NULL,
  enc_password TEXT NOT NULL,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (account_id, mailbox_key)
);

CREATE TABLE IF NOT EXISTS delivery (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  account  TEXT NOT NULL,
  event    TEXT NOT NULL,
  uid      INTEGER NOT NULL,
  ok       INTEGER NOT NULL,
  status   INTEGER,
  error    TEXT,
  attempts INTEGER NOT NULL,
  at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS delivery_account_at ON delivery (account, at DESC);

-- The Carillon account (§ BILLING_MODEL): a magic-link-verified email plus a
-- prepaid, fungible **credit pool**. One credit buys one PIM account one month
-- of watching. Payment is stateless on our side: a one-shot purchase tops the
-- pool up; we persist only the integer balance, never card/PII. `email` is the
-- magic-link identity (null for a self-host / import account, which is keyed by
-- the watch id and never billed).
CREATE TABLE IF NOT EXISTS account (
  id            TEXT PRIMARY KEY,
  email         TEXT,
  credits       INTEGER NOT NULL DEFAULT 0,
  -- Set once the account's one free credit has been granted (on its first
  -- validated PIM account), so it is never granted twice.
  free_credited INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS account_email ON account (email);

-- Sybil barrier for the free credit (§ BILLING_MODEL): the one welcome credit
-- for a given PIM account (its normalised mailbox key) is claimable ONCE
-- globally — by the first Carillon account to validate it. A second account may
-- still watch the same mailbox, but earns no free credit for it. Keyed by
-- mailbox_key so it can't be farmed by re-adding the same mailbox everywhere.
CREATE TABLE IF NOT EXISTS free_credit_claim (
  mailbox_key TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  claimed_at  INTEGER NOT NULL
);

-- Pending magic-link sign-ins: a short-lived, single-use token e-mailed to an
-- address to prove control of it (the human identity flow). Only the SHA-256
-- hash is stored; consumed on verify, aged out by created_at.
CREATE TABLE IF NOT EXISTS magic_link (
  token_hash TEXT PRIMARY KEY,
  email      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Capability links: the login-less bearer credential for an account
-- (M7). Only the SHA-256 hash is stored, so a DB leak hands out no valid
-- links. Sign-out deletes the row; expiry ages links out.
CREATE TABLE IF NOT EXISTS capability (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

-- A **PIM account** (§ SERVICE_MODEL): a proven `(identity, protocol, server)`
-- connection under one Carillon account, keyed by `(account_id, mailbox_key,
-- protocol)`. The **credential** is keyed to the identity (mailbox_key) and
-- SHARED across an identity's protocols (one Fastmail app-password serves IMAP +
-- CardDAV) — see password_credential / oauth_credential. Billing is per
-- **service** (watch) under it, not per membership. For CardDAV, `imap_host` is
-- the DAV host and `base_url` the RFC 6764 context root (used to list
-- addressbooks); for IMAP, `base_url` is null.
CREATE TABLE IF NOT EXISTS account_mailbox (
  account_id  TEXT NOT NULL,
  mailbox_key TEXT NOT NULL,
  protocol    TEXT NOT NULL DEFAULT 'imap',
  login       TEXT NOT NULL,
  imap_host   TEXT NOT NULL,
  imap_port   INTEGER NOT NULL DEFAULT 993,
  base_url    TEXT,
  added_at    INTEGER NOT NULL,
  PRIMARY KEY (account_id, mailbox_key, protocol)
);

-- Pending checkout sessions: payment is stateless on our side — we keep only
-- what to credit on fulfilment (the account and the number of credits bought),
-- never card/PII (the provider owns the customer + receipt). Fulfilment is
-- once-only (idempotent against retried payment webhooks).
CREATE TABLE IF NOT EXISTS checkout_session (
  session_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  quantity   INTEGER NOT NULL DEFAULT 0,
  fulfilled  INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
";

/// A full watch row, including the encrypted password and the shared
/// HMAC secret. Used by the supervisor and the delivery worker.
#[derive(Clone, Debug)]
pub struct Watch {
    /// Watch identifier (the API key and the `account` field of events).
    pub id: String,
    /// IMAP server host.
    pub imap_host: String,
    /// IMAP server port.
    pub imap_port: u16,
    /// Login (authentication identity).
    pub login: String,
    /// Base64 age-encrypted password.
    pub enc_password: String,
    /// Mailbox to watch.
    pub mailbox: String,
    /// Notify URL to POST signed events to.
    pub notify_url: String,
    /// Shared secret used to HMAC-sign deliveries.
    pub hmac_secret: String,
    /// The previous HMAC secret during a rotation overlap, still
    /// accepted by receivers until it expires.
    pub hmac_secret_prev: Option<String>,
    /// Unix time (seconds) at which `hmac_secret_prev` stops being
    /// signed with.
    pub hmac_secret_prev_expires: Option<i64>,
    /// The billing account this watch draws watch-time from. Defaults to
    /// the watch id (one watch, one account) until grouped under a shared
    /// account (M7).
    pub account_id: String,
    /// The provider domain this service is grouped + trial-gated under (the
    /// registrable domain of the server host, e.g. `fastmail.com`). Stamped at
    /// create; empty on rows predating the column.
    pub provider: String,
    /// `password` (uses `enc_password`) or `oauth` (authenticates via the
    /// `oauth_credential` for this watch's `(account_id, mailbox_key)`).
    pub auth_kind: String,
    /// Paid-through time (§ BILLING_MODEL): the service runs, when metered, only
    /// while this is in the future. `None` = never activated.
    pub watching_until: Option<i64>,
    /// Whether the next credit is drawn from the pool at expiry.
    pub auto_renew: bool,
    /// Whether the watch is enabled (the user's pause toggle, independent of
    /// billing).
    pub active: bool,
    /// Source protocol: `imap` (held IDLE) or `carddav` (polled addressbook).
    pub source_kind: String,
    /// CardDAV collection URL the poller connects to (`None` for IMAP).
    pub carddav_url: Option<String>,
    /// CardDAV last sync-token checkpoint (`None` until the first poll).
    pub carddav_sync_token: Option<String>,
    /// CardDAV poll-interval override in seconds (`None` = server default).
    pub carddav_poll_secs: Option<i64>,
}

impl Watch {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            imap_host: row.get("imap_host")?,
            imap_port: row.get("imap_port")?,
            login: row.get("login")?,
            enc_password: row.get("enc_password")?,
            mailbox: row.get("mailbox")?,
            notify_url: row.get("notify_url")?,
            hmac_secret: row.get("hmac_secret")?,
            hmac_secret_prev: row.get("hmac_secret_prev")?,
            hmac_secret_prev_expires: row.get("hmac_secret_prev_expires")?,
            account_id: row.get("account_id")?,
            provider: row.get("provider")?,
            auth_kind: row.get("auth_kind")?,
            watching_until: row.get("watching_until")?,
            auto_renew: row.get::<_, i64>("auto_renew")? != 0,
            active: row.get::<_, i64>("active")? != 0,
            source_kind: row.get("source_kind")?,
            carddav_url: row.get("carddav_url")?,
            carddav_sync_token: row.get("carddav_sync_token")?,
            carddav_poll_secs: row.get("carddav_poll_secs")?,
        })
    }

    /// The secrets a delivery should be signed with right now: always
    /// the current one, plus the previous one while its overlap window
    /// is open. Returning both lets a receiver mid-rotation validate
    /// against either.
    pub fn signing_secrets(&self, now: i64) -> Vec<&str> {
        let mut secrets = vec![self.hmac_secret.as_str()];
        if let (Some(prev), Some(expires)) = (&self.hmac_secret_prev, self.hmac_secret_prev_expires)
            && now < expires
        {
            secrets.push(prev.as_str());
        }
        secrets
    }
}

/// A recorded delivery attempt outcome.
#[derive(Clone, Debug)]
pub struct DeliveryRow {
    /// Owning watch id.
    pub account: String,
    /// Event kind (`new`, `flags_added`, ...).
    pub event: String,
    /// Affected UID.
    pub uid: u32,
    /// Whether the endpoint acknowledged (2xx).
    pub ok: bool,
    /// Final HTTP status, if any response was received.
    pub status: Option<u16>,
    /// Final error message, if the delivery failed.
    pub error: Option<String>,
    /// Number of attempts made.
    pub attempts: u32,
    /// Unix timestamp (seconds) of the final attempt.
    pub at: i64,
}

impl DeliveryRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            account: row.get("account")?,
            event: row.get("event")?,
            uid: row.get("uid")?,
            ok: row.get::<_, i64>("ok")? != 0,
            status: row.get::<_, Option<i64>>("status")?.map(|s| s as u16),
            error: row.get("error")?,
            attempts: row.get("attempts")?,
            at: row.get("at")?,
        })
    }
}

/// The outcome of a delivery attempt, to be logged.
pub struct DeliveryOutcome<'a> {
    /// Owning watch id.
    pub account: &'a str,
    /// Event kind (`new`, `flags_added`, ...).
    pub event: &'a str,
    /// Affected UID.
    pub uid: u32,
    /// Whether the endpoint acknowledged (2xx).
    pub ok: bool,
    /// Final HTTP status, if any response was received.
    pub status: Option<u16>,
    /// Final error message, if the delivery failed.
    pub error: Option<&'a str>,
    /// Number of attempts made.
    pub attempts: u32,
}

/// A Carillon account: the magic-link email identity and the prepaid credit
/// pool every PIM account draws its watch-months from.
#[derive(Clone, Debug)]
pub struct AccountRow {
    /// Account id.
    pub id: String,
    /// Magic-link email identity. `None` for a self-host / import account.
    pub email: Option<String>,
    /// Fungible credit-pool balance (one credit = one PIM-account-month).
    pub credits: i64,
}

impl AccountRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            email: row.get("email")?,
            credits: row.get("credits")?,
        })
    }
}

/// A PIM account (§ SERVICE_MODEL): a proven `(identity, protocol, server)`
/// connection. Ownership/credential unit; services (watches) under it are the
/// billed unit. The credential is identity-keyed and shared across protocols.
#[derive(Clone, Debug)]
pub struct MembershipRow {
    /// Normalised mailbox key (the identity).
    pub mailbox_key: String,
    /// Source protocol: `imap` or `carddav`.
    pub protocol: String,
    /// Login used to prove control.
    pub login: String,
    /// IMAP host, or (for CardDAV) the DAV host.
    pub imap_host: String,
    /// Server port (993 for IMAP; 443 for CardDAV).
    pub imap_port: u16,
    /// CardDAV context-root URL used to list addressbooks (`None` for IMAP).
    pub base_url: Option<String>,
}

impl MembershipRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            mailbox_key: row.get("mailbox_key")?,
            protocol: row.get("protocol")?,
            login: row.get("login")?,
            imap_host: row.get("imap_host")?,
            imap_port: row.get("imap_port")?,
            base_url: row.get("base_url")?,
        })
    }
}

/// A pending OAuth authorization flow, carried between `/oauth/start` and
/// `/oauth/callback` and consumed on the callback.
#[derive(Clone, Debug)]
pub struct OauthSession {
    /// CSRF state (the primary key; echoed back on the callback).
    pub state: String,
    /// PKCE code verifier for the token exchange.
    pub verifier: String,
    /// Redirect URI the flow was started with (must match on exchange).
    pub redirect_uri: String,
    /// Token endpoint to exchange the code at.
    pub token_endpoint: String,
    /// Client id (dynamically registered or from config).
    pub client_id: String,
    /// Age-encrypted client secret, if the provider issued one.
    pub enc_client_secret: Option<String>,
    /// RFC 8707 resource, if the provider needs it.
    pub resource: Option<String>,
    /// Scope requested (stored on the credential for refresh).
    pub scope: Option<String>,
    /// The capability-link account to join, if the flow carried one.
    pub account_id: Option<String>,
    /// Mailbox context, so the callback can build the credential + watch. For a
    /// CardDAV login, `imap_host` is the DAV host (keying the mailbox) and
    /// `mailbox` is unused; `carddav_url` carries the collection context root.
    pub login: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub mailbox: String,
    /// Source protocol: `imap` (default) or `carddav`.
    pub source_kind: String,
    /// CardDAV context-root URL (`Some` only when `source_kind` is `carddav`).
    pub carddav_url: Option<String>,
}

/// The stored OAuth credential for a proven mailbox: an age-encrypted refresh
/// token plus what is needed to mint fresh access tokens.
#[derive(Clone, Debug)]
pub struct OauthCredential {
    pub account_id: String,
    pub mailbox_key: String,
    pub enc_refresh_token: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub enc_client_secret: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

/// The sqlite-backed store, cheap to clone via `Arc`.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Opens (or creates) the database at `path` and ensures the
    /// schema exists.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Cannot open database at {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("Cannot enable WAL")?;
        conn.execute_batch(SCHEMA).context("Cannot create schema")?;
        migrate(&conn).context("Cannot migrate schema")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    /// Inserts or replaces a watch. Rotation state is left to
    /// [`Store::rotate_secret`]; an upsert resets it (a redefine of the
    /// watch drops any in-flight overlap).
    pub fn upsert_watch(&self, watch: &Watch) -> Result<()> {
        // `carddav_sync_token` is deliberately not written here: it is runtime
        // checkpoint state (like `watching_until`), preserved across an
        // edit-in-place and set only by `set_carddav_sync_token`.
        self.lock().execute(
            "INSERT INTO watch
               (id, imap_host, imap_port, login, enc_password, mailbox, notify_url,
                hmac_secret, hmac_secret_prev, hmac_secret_prev_expires, account_id,
                auth_kind, active, source_kind, carddav_url, carddav_poll_secs, provider)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
               imap_host=?2, imap_port=?3, login=?4, enc_password=?5,
               mailbox=?6, notify_url=?7, hmac_secret=?8,
               hmac_secret_prev=?9, hmac_secret_prev_expires=?10,
               account_id=?11, auth_kind=?12, active=?13,
               source_kind=?14, carddav_url=?15, carddav_poll_secs=?16, provider=?17",
            params![
                watch.id,
                watch.imap_host,
                watch.imap_port,
                watch.login,
                watch.enc_password,
                watch.mailbox,
                watch.notify_url,
                watch.hmac_secret,
                watch.hmac_secret_prev,
                watch.hmac_secret_prev_expires,
                watch.account_id,
                watch.auth_kind,
                watch.active as i64,
                watch.source_kind,
                watch.carddav_url,
                watch.carddav_poll_secs,
                watch.provider,
            ],
        )?;
        Ok(())
    }

    /// Rotates a watch's HMAC secret, keeping the current one as the
    /// previous secret for an `overlap` window so a receiver can update
    /// without dropping events. Returns the expiry of the overlap, or
    /// `None` if no watch matched.
    pub fn rotate_secret(
        &self,
        id: &str,
        new_secret: &str,
        overlap: Duration,
    ) -> Result<Option<i64>> {
        let now = now_secs();
        let expires = now + overlap.as_secs() as i64;
        let n = self.lock().execute(
            "UPDATE watch
               SET hmac_secret_prev = hmac_secret,
                   hmac_secret_prev_expires = ?2,
                   hmac_secret = ?3
             WHERE id = ?1",
            params![id, expires, new_secret],
        )?;
        Ok((n > 0).then_some(expires))
    }

    /// Returns every active watch, in **declaration order** (`rowid` =
    /// insertion order) — the order the renewal sweep debits the shared pool in.
    pub fn active_watches(&self) -> Result<Vec<Watch>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM watch WHERE active = 1 ORDER BY rowid")?;
        let rows = stmt.query_map([], Watch::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Returns every watch, ordered by id.
    pub fn all_watches(&self) -> Result<Vec<Watch>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM watch ORDER BY id")?;
        let rows = stmt.query_map([], Watch::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Returns every watch belonging to an account, ordered by id.
    pub fn watches_by_account(&self, account_id: &str) -> Result<Vec<Watch>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM watch WHERE account_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map([account_id], Watch::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Looks up a single watch by id.
    pub fn get_watch(&self, id: &str) -> Result<Option<Watch>> {
        let conn = self.lock();
        let watch = conn
            .query_row("SELECT * FROM watch WHERE id = ?1", [id], Watch::from_row)
            .optional()?;
        Ok(watch)
    }

    /// The billing account a watch belongs to, if the watch exists. Cheap
    /// authorization check for the scoped watch routes (no decrypt, no full
    /// row): `None` means no such watch.
    pub fn watch_account(&self, id: &str) -> Result<Option<String>> {
        let conn = self.lock();
        let account = conn
            .query_row("SELECT account_id FROM watch WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(account)
    }

    /// Enables or disables a watch. Returns whether a row matched.
    pub fn set_active(&self, id: &str, active: bool) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE watch SET active = ?2 WHERE id = ?1",
            params![id, active as i64],
        )?;
        Ok(n > 0)
    }

    /// Deletes a watch. Returns whether a row matched.
    pub fn delete_watch(&self, id: &str) -> Result<bool> {
        let n = self
            .lock()
            .execute("DELETE FROM watch WHERE id = ?1", [id])?;
        Ok(n > 0)
    }

    /// Records the outcome of a delivery attempt.
    pub fn log_delivery(&self, outcome: &DeliveryOutcome) -> Result<()> {
        let at = now_secs();
        self.lock().execute(
            "INSERT INTO delivery (account, event, uid, ok, status, error, attempts, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                outcome.account,
                outcome.event,
                outcome.uid,
                outcome.ok as i64,
                outcome.status.map(|s| s as i64),
                outcome.error,
                outcome.attempts,
                at
            ],
        )?;
        Ok(())
    }

    /// The most recent deliveries across every watch owned by a billing
    /// account, newest first — the scoped counterpart of
    /// [`Store::recent_deliveries`]. Joins on the watch so a capability
    /// link only ever sees its own account's log. (A delivery whose watch
    /// was since deleted drops out of the join; that is acceptable — the
    /// live log is a recent-activity view, not an audit trail.)
    pub fn recent_deliveries_by_owner(
        &self,
        account_id: &str,
        limit: u32,
    ) -> Result<Vec<DeliveryRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT d.* FROM delivery d
               JOIN watch w ON w.id = d.account
             WHERE w.account_id = ?1
             ORDER BY d.at DESC, d.id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![account_id, limit], DeliveryRow::from_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Returns the most recent deliveries, optionally filtered by
    /// account, newest first.
    pub fn recent_deliveries(&self, account: Option<&str>, limit: u32) -> Result<Vec<DeliveryRow>> {
        let conn = self.lock();
        let rows = match account {
            Some(account) => {
                let mut stmt = conn.prepare(
                    "SELECT * FROM delivery WHERE account = ?1 ORDER BY at DESC, id DESC LIMIT ?2",
                )?;
                stmt.query_map(params![account, limit], DeliveryRow::from_row)?
                    .collect::<rusqlite::Result<_>>()?
            }
            None => {
                let mut stmt =
                    conn.prepare("SELECT * FROM delivery ORDER BY at DESC, id DESC LIMIT ?1")?;
                stmt.query_map(params![limit], DeliveryRow::from_row)?
                    .collect::<rusqlite::Result<_>>()?
            }
        };
        Ok(rows)
    }

    // --- Carillon accounts & the credit pool ---

    /// Creates the account row if it does not exist yet (with an empty pool).
    /// The free credit is granted separately by [`Store::grant_free_credit`], on
    /// the first validated PIM account — not here, so a magic-link signup with no
    /// mailbox cannot claim it. Returns whether the account was newly created.
    pub fn ensure_account(&self, id: &str, email: Option<&str>) -> Result<bool> {
        let created = self.lock().execute(
            "INSERT OR IGNORE INTO account (id, email) VALUES (?1, ?2)",
            params![id, email],
        )?;
        Ok(created > 0)
    }

    /// Grants the one free credit (§ BILLING_MODEL) to an account exactly once,
    /// on its first validated PIM account. Idempotent (guarded by
    /// `free_credited`); returns whether the grant fired this call. Used by the
    /// self-host / admin-import paths, which have no sybil concern; the SaaS
    /// `/auth` + OAuth paths use [`Store::claim_free_credit`] instead.
    pub fn grant_free_credit(&self, account_id: &str, amount: i64) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE account SET credits = credits + ?2, free_credited = 1
             WHERE id = ?1 AND free_credited = 0",
            params![account_id, amount],
        )?;
        Ok(n > 0)
    }

    /// Claims the one-time welcome **trial** for a `(Carillon account, provider
    /// domain)` (§ SERVICE_MODEL v3). The account's FIRST service on a provider
    /// (its `metering::provider_domain`, e.g. `fastmail.com` for both its IMAP
    /// and CardDAV hosts) earns a free head start of watch-time on that service;
    /// the caller sets the new watch's `watching_until` when this returns `true`.
    /// Recorded per account+provider (the `free_credit_claim` ledger, reused with
    /// a composite key), so a second service on the same provider — or a
    /// delete+recreate — does not renew it. The trial is time-on-the-service, not
    /// a fungible credit, so per-account (not global) gating is safe. Atomic.
    pub fn claim_free_trial(&self, account_id: &str, provider_domain: &str) -> Result<bool> {
        let key = format!("{account_id}|{provider_domain}");
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let claimed = tx
            .query_row(
                "SELECT 1 FROM free_credit_claim WHERE mailbox_key = ?1",
                [&key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if claimed {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO free_credit_claim (mailbox_key, account_id, claimed_at)
             VALUES (?1, ?2, ?3)",
            params![key, account_id, now_secs()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The account bearing a magic-link email, if one exists.
    pub fn account_by_email(&self, email: &str) -> Result<Option<String>> {
        let conn = self.lock();
        let id = conn
            .query_row(
                "SELECT id FROM account WHERE email = ?1 ORDER BY rowid LIMIT 1",
                [email],
                |row| row.get(0),
            )
            .optional()?;
        Ok(id)
    }

    /// Looks up an account's pool state.
    pub fn get_account(&self, id: &str) -> Result<Option<AccountRow>> {
        let conn = self.lock();
        let account = conn
            .query_row(
                "SELECT id, email, credits FROM account WHERE id = ?1",
                [id],
                AccountRow::from_row,
            )
            .optional()?;
        Ok(account)
    }

    /// Every account id, ordered.
    pub fn all_account_ids(&self) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT id FROM account ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The `(login, imap_host)` of every watch owned by an account — cheap
    /// input to the fair-use cap, which normalises them into mailbox keys.
    pub fn account_watch_identities(&self, account_id: &str) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT login, imap_host FROM watch WHERE account_id = ?1")?;
        let rows = stmt.query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds `n` credits to an account's pool (a fulfilled purchase). Ensures the
    /// account exists first.
    pub fn add_credits(&self, account_id: &str, n: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO account (id) VALUES (?1)",
            [account_id],
        )?;
        conn.execute(
            "UPDATE account SET credits = credits + ?2 WHERE id = ?1",
            params![account_id, n],
        )?;
        Ok(())
    }

    /// Spends one credit from an account's pool, atomically (only when the
    /// balance is positive). Returns whether a credit was drawn.
    pub fn debit_credit(&self, account_id: &str) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE account SET credits = credits - 1 WHERE id = ?1 AND credits > 0",
            [account_id],
        )?;
        Ok(n > 0)
    }

    /// Spends `n` credits at once, atomically and all-or-nothing (only when the
    /// balance covers them). Returns whether the debit happened. `n <= 0` is a
    /// no-op that fails.
    pub fn debit_credits(&self, account_id: &str, n: i64) -> Result<bool> {
        if n <= 0 {
            return Ok(false);
        }
        let rows = self.lock().execute(
            "UPDATE account SET credits = credits - ?2 WHERE id = ?1 AND credits >= ?2",
            params![account_id, n],
        )?;
        Ok(rows > 0)
    }

    // --- Magic-link sign-in ---

    /// Stores a pending magic-link token (by hash) for an email address.
    pub fn create_magic_link(&self, token: &str, email: &str) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO magic_link (token_hash, email, created_at)
             VALUES (?1, ?2, ?3)",
            params![token_hash(token), email, now_secs()],
        )?;
        Ok(())
    }

    /// Consumes a magic-link token (single-use), returning the email it proves,
    /// and prunes tokens older than `max_age_secs`. `None` if unknown/expired.
    pub fn take_magic_link(&self, token: &str, max_age_secs: i64) -> Result<Option<String>> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM magic_link WHERE created_at < ?1",
            [now_secs() - max_age_secs],
        )?;
        let hash = token_hash(token);
        let email: Option<String> = conn
            .query_row(
                "SELECT email FROM magic_link WHERE token_hash = ?1",
                [&hash],
                |row| row.get(0),
            )
            .optional()?;
        if email.is_some() {
            conn.execute("DELETE FROM magic_link WHERE token_hash = ?1", [&hash])?;
        }
        Ok(email)
    }

    // --- Services (watch activation) ---

    /// Sets a service's (watch's) paid-through time (activation / renewal).
    /// Returns whether the watch matched.
    pub fn set_watch_watching_until(&self, watch_id: &str, until: i64) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE watch SET watching_until = ?2 WHERE id = ?1",
            params![watch_id, until],
        )?;
        Ok(n > 0)
    }

    /// Checkpoints a CardDAV service's RFC 6578 sync-token after a poll
    /// (`None` resets it, forcing a fresh baseline on the next poll). Returns
    /// whether the watch matched.
    pub fn set_carddav_sync_token(&self, watch_id: &str, token: Option<&str>) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE watch SET carddav_sync_token = ?2 WHERE id = ?1",
            params![watch_id, token],
        )?;
        Ok(n > 0)
    }

    /// Turns auto-renew on or off for a service (watch). Returns whether the
    /// watch matched.
    pub fn set_watch_auto_renew(&self, watch_id: &str, on: bool) -> Result<bool> {
        let n = self.lock().execute(
            "UPDATE watch SET auto_renew = ?2 WHERE id = ?1",
            params![watch_id, on as i64],
        )?;
        Ok(n > 0)
    }

    // --- Capability links, membership & checkout (M7) ---

    /// Stores a capability link (by hash) for an account.
    pub fn issue_capability(
        &self,
        account_id: &str,
        token: &str,
        expires: Option<i64>,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO capability (token_hash, account_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![token_hash(token), account_id, now_secs(), expires],
        )?;
        Ok(())
    }

    /// Resolves a capability link to its account, honouring expiry.
    pub fn resolve_capability(&self, token: &str) -> Result<Option<String>> {
        let conn = self.lock();
        let row: Option<(String, Option<i64>)> = conn
            .query_row(
                "SELECT account_id, expires_at FROM capability WHERE token_hash = ?1",
                [token_hash(token)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        Ok(match row {
            Some((account_id, expires)) => match expires {
                Some(expires) if now_secs() >= expires => None,
                _ => Some(account_id),
            },
            None => None,
        })
    }

    /// Revokes a capability link (sign-out). Returns whether one matched.
    pub fn revoke_capability(&self, token: &str) -> Result<bool> {
        let n = self.lock().execute(
            "DELETE FROM capability WHERE token_hash = ?1",
            [token_hash(token)],
        )?;
        Ok(n > 0)
    }

    /// Records that an account controls a `(mailbox_key, protocol)` endpoint (a
    /// PIM account). Re-auth updates the server info (host/port/base_url) in
    /// place; `added_at` (declaration order) is preserved.
    #[allow(clippy::too_many_arguments)]
    pub fn add_membership(
        &self,
        account_id: &str,
        mailbox_key: &str,
        protocol: &str,
        login: &str,
        imap_host: &str,
        imap_port: u16,
        base_url: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO account_mailbox
               (account_id, mailbox_key, protocol, login, imap_host, imap_port, base_url, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(account_id, mailbox_key, protocol) DO UPDATE SET
               login=?4, imap_host=?5, imap_port=?6, base_url=?7",
            params![
                account_id,
                mailbox_key,
                protocol,
                login,
                imap_host,
                imap_port,
                base_url,
                now_secs()
            ],
        )?;
        Ok(())
    }

    /// The account a mailbox already belongs to, if any (for recovery: a
    /// re-auth to a member mailbox re-mints that account's link).
    pub fn account_of_mailbox(&self, mailbox_key: &str) -> Result<Option<String>> {
        let conn = self.lock();
        let account = conn
            .query_row(
                "SELECT account_id FROM account_mailbox WHERE mailbox_key = ?1
                 ORDER BY added_at LIMIT 1",
                [mailbox_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(account)
    }

    /// Whether an account has proven control of a `(mailbox_key, protocol)`
    /// endpoint. The create-watch gate: a scoped caller may only watch a PIM
    /// account it authenticated (which recorded the membership) — you cannot
    /// watch what you cannot log into.
    pub fn mailbox_belongs(
        &self,
        account_id: &str,
        mailbox_key: &str,
        protocol: &str,
    ) -> Result<bool> {
        let conn = self.lock();
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM account_mailbox
                 WHERE account_id = ?1 AND mailbox_key = ?2 AND protocol = ?3",
                params![account_id, mailbox_key, protocol],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    /// The PIM accounts a Carillon account controls, in declaration order.
    pub fn memberships(&self, account_id: &str) -> Result<Vec<MembershipRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT mailbox_key, protocol, login, imap_host, imap_port, base_url
             FROM account_mailbox WHERE account_id = ?1 ORDER BY added_at",
        )?;
        let rows = stmt.query_map([account_id], MembershipRow::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forgets a PIM account: removes the `(mailbox_key, protocol)` membership
    /// and every service (watch) under it, then drops the **shared** credential
    /// only when no other membership of the same identity remains (another
    /// protocol may still be using it). Returns the ids of the deleted watches
    /// (so the supervisor can be reconciled). All in one transaction.
    pub fn forget_account(
        &self,
        account_id: &str,
        mailbox_key: &str,
        protocol: &str,
    ) -> Result<Vec<String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;

        // Services under this PIM account: same account + protocol, whose
        // (login, host) normalises to this mailbox_key.
        let watch_ids: Vec<(String, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, login, imap_host FROM watch
                 WHERE account_id = ?1 AND source_kind = ?2",
            )?;
            let rows = stmt.query_map(params![account_id, protocol], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let deleted: Vec<String> = watch_ids
            .into_iter()
            .filter(|(_, login, host)| crate::metering::mailbox_key(login, host) == mailbox_key)
            .map(|(id, _, _)| id)
            .collect();
        for id in &deleted {
            tx.execute("DELETE FROM watch WHERE id = ?1", [id])?;
        }

        tx.execute(
            "DELETE FROM account_mailbox
             WHERE account_id = ?1 AND mailbox_key = ?2 AND protocol = ?3",
            params![account_id, mailbox_key, protocol],
        )?;

        // Shared credential: drop it only if no protocol of this identity
        // remains under the account.
        let remaining: i64 = tx.query_row(
            "SELECT COUNT(*) FROM account_mailbox WHERE account_id = ?1 AND mailbox_key = ?2",
            params![account_id, mailbox_key],
            |row| row.get(0),
        )?;
        if remaining == 0 {
            tx.execute(
                "DELETE FROM password_credential WHERE account_id = ?1 AND mailbox_key = ?2",
                params![account_id, mailbox_key],
            )?;
            tx.execute(
                "DELETE FROM oauth_credential WHERE account_id = ?1 AND mailbox_key = ?2",
                params![account_id, mailbox_key],
            )?;
        }

        tx.commit()?;
        Ok(deleted)
    }

    /// Records a pending checkout session: the account and the number of
    /// credits to add to its pool on fulfilment.
    pub fn create_session(&self, session_id: &str, account_id: &str, quantity: i64) -> Result<()> {
        self.lock().execute(
            "INSERT INTO checkout_session (session_id, account_id, quantity, fulfilled, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![session_id, account_id, quantity, now_secs()],
        )?;
        Ok(())
    }

    /// Fulfils a session exactly once, returning `(account_id, quantity)`.
    /// `None` if the session is unknown or already fulfilled (idempotency
    /// against retried payment webhooks).
    pub fn fulfill_session(&self, session_id: &str) -> Result<Option<(String, i64)>> {
        let conn = self.lock();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT account_id, quantity FROM checkout_session
                 WHERE session_id = ?1 AND fulfilled = 0",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if row.is_some() {
            conn.execute(
                "UPDATE checkout_session SET fulfilled = 1 WHERE session_id = ?1",
                [session_id],
            )?;
        }
        Ok(row)
    }

    // --- OAuth flows & credentials (M10) ---

    /// Stores a pending OAuth flow, keyed by its CSRF state.
    pub fn create_oauth_session(&self, session: &OauthSession) -> Result<()> {
        self.lock().execute(
            "INSERT INTO oauth_session
               (state, verifier, redirect_uri, token_endpoint, client_id,
                enc_client_secret, resource, scope, account_id, login,
                imap_host, imap_port, mailbox, source_kind, carddav_url, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                session.state,
                session.verifier,
                session.redirect_uri,
                session.token_endpoint,
                session.client_id,
                session.enc_client_secret,
                session.resource,
                session.scope,
                session.account_id,
                session.login,
                session.imap_host,
                session.imap_port,
                session.mailbox,
                session.source_kind,
                session.carddav_url,
                now_secs(),
            ],
        )?;
        Ok(())
    }

    /// Consumes a pending OAuth flow by its state (single-use), also pruning
    /// any sessions older than `max_age_secs`. `None` if the state is unknown.
    pub fn take_oauth_session(
        &self,
        state: &str,
        max_age_secs: i64,
    ) -> Result<Option<OauthSession>> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM oauth_session WHERE created_at < ?1",
            [now_secs() - max_age_secs],
        )?;
        let session = conn
            .query_row(
                "SELECT state, verifier, redirect_uri, token_endpoint, client_id,
                        enc_client_secret, resource, scope, account_id, login,
                        imap_host, imap_port, mailbox, source_kind, carddav_url
                 FROM oauth_session WHERE state = ?1",
                [state],
                |row| {
                    Ok(OauthSession {
                        state: row.get(0)?,
                        verifier: row.get(1)?,
                        redirect_uri: row.get(2)?,
                        token_endpoint: row.get(3)?,
                        client_id: row.get(4)?,
                        enc_client_secret: row.get(5)?,
                        resource: row.get(6)?,
                        scope: row.get(7)?,
                        account_id: row.get(8)?,
                        login: row.get(9)?,
                        imap_host: row.get(10)?,
                        imap_port: row.get(11)?,
                        mailbox: row.get(12)?,
                        source_kind: row.get(13)?,
                        carddav_url: row.get(14)?,
                    })
                },
            )
            .optional()?;

        if session.is_some() {
            conn.execute("DELETE FROM oauth_session WHERE state = ?1", [state])?;
        }
        Ok(session)
    }

    /// Stores (or replaces) the OAuth credential for a mailbox.
    pub fn upsert_oauth_credential(&self, cred: &OauthCredential) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO oauth_credential
               (account_id, mailbox_key, enc_refresh_token, token_endpoint,
                client_id, enc_client_secret, resource, scope, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                cred.account_id,
                cred.mailbox_key,
                cred.enc_refresh_token,
                cred.token_endpoint,
                cred.client_id,
                cred.enc_client_secret,
                cred.resource,
                cred.scope,
                now_secs(),
            ],
        )?;
        Ok(())
    }

    /// The OAuth credential for a mailbox, if any.
    pub fn get_oauth_credential(
        &self,
        account_id: &str,
        mailbox_key: &str,
    ) -> Result<Option<OauthCredential>> {
        let conn = self.lock();
        let cred = conn
            .query_row(
                "SELECT account_id, mailbox_key, enc_refresh_token, token_endpoint,
                        client_id, enc_client_secret, resource, scope
                 FROM oauth_credential WHERE account_id = ?1 AND mailbox_key = ?2",
                params![account_id, mailbox_key],
                |row| {
                    Ok(OauthCredential {
                        account_id: row.get(0)?,
                        mailbox_key: row.get(1)?,
                        enc_refresh_token: row.get(2)?,
                        token_endpoint: row.get(3)?,
                        client_id: row.get(4)?,
                        enc_client_secret: row.get(5)?,
                        resource: row.get(6)?,
                        scope: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(cred)
    }

    /// Updates the stored refresh token for a mailbox (the provider rotated
    /// it on a refresh).
    pub fn update_oauth_refresh_token(
        &self,
        account_id: &str,
        mailbox_key: &str,
        enc_refresh_token: &str,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE oauth_credential
               SET enc_refresh_token = ?3, updated_at = ?4
             WHERE account_id = ?1 AND mailbox_key = ?2",
            params![account_id, mailbox_key, enc_refresh_token, now_secs()],
        )?;
        Ok(())
    }

    // --- Password credentials (per PIM account) ---

    /// Stores (or replaces) the password credential for a PIM account. Called at
    /// 'Add account' (auth); a re-auth updates it for every service under it.
    pub fn upsert_password_credential(
        &self,
        account_id: &str,
        mailbox_key: &str,
        enc_password: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO password_credential
               (account_id, mailbox_key, enc_password, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![account_id, mailbox_key, enc_password, now_secs()],
        )?;
        Ok(())
    }

    /// The age-encrypted password for a PIM account, if one is stored.
    pub fn get_password_credential(
        &self,
        account_id: &str,
        mailbox_key: &str,
    ) -> Result<Option<String>> {
        let conn = self.lock();
        let enc = conn
            .query_row(
                "SELECT enc_password FROM password_credential
                 WHERE account_id = ?1 AND mailbox_key = ?2",
                params![account_id, mailbox_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(enc)
    }
}

/// SHA-256 hex of a capability token — what we persist, so a DB leak
/// never yields a usable link.
fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Adds columns introduced after the initial schema to a pre-existing
/// database. `CREATE TABLE IF NOT EXISTS` never alters an existing
/// table, so older stores need their new columns backfilled here.
fn migrate(conn: &Connection) -> Result<()> {
    // account_mailbox gained a protocol axis (§ SERVICE_MODEL): its primary key
    // is now (account_id, mailbox_key, protocol). SQLite cannot ALTER a primary
    // key, so rebuild the table when the `protocol` column is absent (an old
    // store), backfilling every existing membership as an IMAP one.
    if !column_exists(conn, "account_mailbox", "protocol")? {
        conn.execute_batch(
            "CREATE TABLE account_mailbox_new (
               account_id  TEXT NOT NULL,
               mailbox_key TEXT NOT NULL,
               protocol    TEXT NOT NULL DEFAULT 'imap',
               login       TEXT NOT NULL,
               imap_host   TEXT NOT NULL,
               imap_port   INTEGER NOT NULL DEFAULT 993,
               base_url    TEXT,
               added_at    INTEGER NOT NULL,
               PRIMARY KEY (account_id, mailbox_key, protocol)
             );
             INSERT INTO account_mailbox_new
               (account_id, mailbox_key, protocol, login, imap_host, imap_port, base_url, added_at)
               SELECT account_id, mailbox_key, 'imap', login, imap_host, 993, NULL, added_at
               FROM account_mailbox;
             DROP TABLE account_mailbox;
             ALTER TABLE account_mailbox_new RENAME TO account_mailbox;",
        )?;
    }

    for (table, column, decl) in [
        ("watch", "hmac_secret_prev", "TEXT"),
        ("watch", "hmac_secret_prev_expires", "INTEGER"),
        ("watch", "account_id", "TEXT NOT NULL DEFAULT ''"),
        ("watch", "provider", "TEXT NOT NULL DEFAULT ''"),
        ("watch", "last_metered", "INTEGER"),
        ("watch", "auth_kind", "TEXT NOT NULL DEFAULT 'password'"),
        // Credit-pool accounts (§ BILLING_MODEL). Any older subscription / trial
        // columns from an intermediate build are simply left inert.
        ("account", "email", "TEXT"),
        ("account", "credits", "INTEGER NOT NULL DEFAULT 0"),
        ("account", "free_credited", "INTEGER NOT NULL DEFAULT 0"),
        // Per-service activation state lives on the watch (the billed unit).
        ("watch", "watching_until", "INTEGER"),
        ("watch", "auto_renew", "INTEGER NOT NULL DEFAULT 0"),
        ("checkout_session", "quantity", "INTEGER NOT NULL DEFAULT 0"),
        // CardDAV source support: a second service kind alongside IMAP.
        ("watch", "source_kind", "TEXT NOT NULL DEFAULT 'imap'"),
        ("watch", "carddav_url", "TEXT"),
        ("watch", "carddav_sync_token", "TEXT"),
        ("watch", "carddav_poll_secs", "INTEGER"),
        // CardDAV OAuth logins carry their protocol + collection through the
        // pending-flow row.
        (
            "oauth_session",
            "source_kind",
            "TEXT NOT NULL DEFAULT 'imap'",
        ),
        ("oauth_session", "carddav_url", "TEXT"),
    ] {
        if !column_exists(conn, table, column)? {
            conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
                [],
            )?;
        }
    }
    // Backfill the billing account for pre-metering rows: one watch, one
    // account, sharing the id.
    conn.execute("UPDATE watch SET account_id = id WHERE account_id = ''", [])?;
    Ok(())
}

/// Whether `table` has a column named `column`. Both are internal
/// constants, never user input.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    Ok(names.any(|name| matches!(name, Ok(name) if name == column)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A fresh store on a unique temp-file path (each test isolated).
    fn temp_store() -> Store {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("carillon-test-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Store::open(&path).unwrap()
    }

    #[test]
    fn free_credit_is_granted_exactly_once() {
        let store = temp_store();
        store.ensure_account("acc", Some("a@b.test")).unwrap();
        assert_eq!(store.get_account("acc").unwrap().unwrap().credits, 0);

        assert!(store.grant_free_credit("acc", 1).unwrap()); // fires
        assert!(!store.grant_free_credit("acc", 1).unwrap()); // idempotent
        assert_eq!(store.get_account("acc").unwrap().unwrap().credits, 1);
    }

    #[test]
    fn free_trial_claimed_once_per_account_provider() {
        let store = temp_store();
        store.ensure_account("a", Some("a@x.test")).unwrap();
        store.ensure_account("b", Some("b@x.test")).unwrap();

        // First service on a provider earns the trial for that account.
        assert!(store.claim_free_trial("a", "fastmail.com").unwrap());

        // A second service on the SAME provider (e.g. contacts after mail, or a
        // delete+recreate) earns nothing — no renewal.
        assert!(!store.claim_free_trial("a", "fastmail.com").unwrap());

        // …but the same account still earns a trial on a *different* provider.
        assert!(store.claim_free_trial("a", "gmail.com").unwrap());

        // Gating is per Carillon account (time-on-service is non-fungible), so a
        // different account earns its own trial on the same provider.
        assert!(store.claim_free_trial("b", "fastmail.com").unwrap());
    }

    #[test]
    fn credits_add_and_debit() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store.add_credits("acc", 3).unwrap();
        assert_eq!(store.get_account("acc").unwrap().unwrap().credits, 3);

        assert!(store.debit_credit("acc").unwrap());
        assert!(store.debit_credit("acc").unwrap());
        assert!(store.debit_credit("acc").unwrap());
        assert!(!store.debit_credit("acc").unwrap()); // empty pool refuses
        assert_eq!(store.get_account("acc").unwrap().unwrap().credits, 0);
    }

    /// A minimal watch for activation tests.
    fn watch(id: &str, account_id: &str) -> Watch {
        Watch {
            id: id.into(),
            imap_host: "imap.x".into(),
            imap_port: 993,
            login: "u@x".into(),
            enc_password: String::new(),
            mailbox: "INBOX".into(),
            notify_url: "https://x/hook".into(),
            hmac_secret: "s".into(),
            hmac_secret_prev: None,
            hmac_secret_prev_expires: None,
            account_id: account_id.into(),
            provider: "x".into(),
            auth_kind: "password".into(),
            watching_until: None,
            auto_renew: false,
            active: true,
            source_kind: "imap".into(),
            carddav_url: None,
            carddav_sync_token: None,
            carddav_poll_secs: None,
        }
    }

    #[test]
    fn service_activation_state_round_trips() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store.upsert_watch(&watch("w1", "acc")).unwrap();

        // Never activated: no watching_until, auto_renew off.
        let w = store.get_watch("w1").unwrap().unwrap();
        assert_eq!(w.watching_until, None);
        assert!(!w.auto_renew);

        assert!(store.set_watch_watching_until("w1", 5_000).unwrap());
        assert!(store.set_watch_auto_renew("w1", true).unwrap());
        let w = store.get_watch("w1").unwrap().unwrap();
        assert_eq!(w.watching_until, Some(5_000));
        assert!(w.auto_renew);

        // A missing watch does not match.
        assert!(!store.set_watch_watching_until("nope", 1).unwrap());
    }

    #[test]
    fn upsert_preserves_activation_across_edits() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store.upsert_watch(&watch("w1", "acc")).unwrap();
        store.set_watch_watching_until("w1", 9_000).unwrap();

        // Re-upsert (an edit-in-place, e.g. a new notify_url) must not wipe the
        // paid-through time.
        let mut edited = watch("w1", "acc");
        edited.notify_url = "https://x/new".into();
        store.upsert_watch(&edited).unwrap();

        let w = store.get_watch("w1").unwrap().unwrap();
        assert_eq!(w.watching_until, Some(9_000));
        assert_eq!(w.notify_url, "https://x/new");
    }

    #[test]
    fn carddav_service_round_trips_and_checkpoints() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        let mut w = watch("cd1", "acc");
        w.source_kind = "carddav".into();
        w.carddav_url = Some("https://dav.x/addressbooks/u/Default/".into());
        w.mailbox = "Personal".into();
        store.upsert_watch(&w).unwrap();

        let got = store.get_watch("cd1").unwrap().unwrap();
        assert_eq!(got.source_kind, "carddav");
        assert_eq!(
            got.carddav_url.as_deref(),
            Some("https://dav.x/addressbooks/u/Default/")
        );
        assert_eq!(got.carddav_sync_token, None);

        // The sync-token checkpoint survives an edit-in-place (like activation).
        assert!(
            store
                .set_carddav_sync_token("cd1", Some("sync-42"))
                .unwrap()
        );
        let mut edited = w.clone();
        edited.notify_url = "https://x/new".into();
        store.upsert_watch(&edited).unwrap();
        assert_eq!(
            store
                .get_watch("cd1")
                .unwrap()
                .unwrap()
                .carddav_sync_token
                .as_deref(),
            Some("sync-42")
        );

        // Resetting to None forces a fresh baseline on the next poll.
        assert!(store.set_carddav_sync_token("cd1", None).unwrap());
        assert_eq!(
            store.get_watch("cd1").unwrap().unwrap().carddav_sync_token,
            None
        );
    }

    #[test]
    fn pim_accounts_are_per_protocol_and_share_a_credential() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store
            .add_membership("acc", "u@x", "imap", "u@x", "imap.x", 993, None)
            .unwrap();
        store
            .add_membership(
                "acc",
                "u@x",
                "carddav",
                "u@x",
                "dav.x",
                443,
                Some("https://dav.x/"),
            )
            .unwrap();
        store
            .upsert_password_credential("acc", "u@x", "enc")
            .unwrap();

        // One identity, two protocol-accounts.
        assert_eq!(store.memberships("acc").unwrap().len(), 2);
        assert!(store.mailbox_belongs("acc", "u@x", "imap").unwrap());
        assert!(store.mailbox_belongs("acc", "u@x", "carddav").unwrap());
        assert!(!store.mailbox_belongs("acc", "u@x", "jmap").unwrap());

        // Forget CardDAV: its membership goes, the shared credential stays (IMAP
        // still uses it).
        store.forget_account("acc", "u@x", "carddav").unwrap();
        assert!(!store.mailbox_belongs("acc", "u@x", "carddav").unwrap());
        assert!(store.mailbox_belongs("acc", "u@x", "imap").unwrap());
        assert_eq!(
            store
                .get_password_credential("acc", "u@x")
                .unwrap()
                .as_deref(),
            Some("enc")
        );

        // Forget the last protocol: the shared credential is dropped.
        store.forget_account("acc", "u@x", "imap").unwrap();
        assert_eq!(store.get_password_credential("acc", "u@x").unwrap(), None);
    }

    #[test]
    fn active_watches_are_in_declaration_order() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store.upsert_watch(&watch("first", "acc")).unwrap();
        store.upsert_watch(&watch("second", "acc")).unwrap();
        let ids: Vec<String> = store
            .active_watches()
            .unwrap()
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn magic_link_is_single_use_and_maps_email() {
        let store = temp_store();
        store.create_magic_link("tok", "user@x.test").unwrap();
        assert_eq!(
            store.take_magic_link("tok", 900).unwrap().as_deref(),
            Some("user@x.test")
        );
        // Consumed: a second take finds nothing.
        assert_eq!(store.take_magic_link("tok", 900).unwrap(), None);
    }

    #[test]
    fn account_looked_up_by_email() {
        let store = temp_store();
        store.ensure_account("acc", Some("me@x.test")).unwrap();
        assert_eq!(
            store.account_by_email("me@x.test").unwrap().as_deref(),
            Some("acc")
        );
        assert_eq!(store.account_by_email("nobody@x.test").unwrap(), None);
    }

    #[test]
    fn one_shot_session_fulfils_once() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        store.create_session("sess", "acc", 10).unwrap();
        assert_eq!(
            store.fulfill_session("sess").unwrap(),
            Some(("acc".to_string(), 10))
        );
        // Idempotent against a retried webhook.
        assert_eq!(store.fulfill_session("sess").unwrap(), None);
    }

    #[test]
    fn password_credential_lives_on_the_pim_account() {
        let store = temp_store();
        store.ensure_account("acc", None).unwrap();
        assert_eq!(store.get_password_credential("acc", "u@p").unwrap(), None);

        store
            .upsert_password_credential("acc", "u@p", "enc-1")
            .unwrap();
        assert_eq!(
            store
                .get_password_credential("acc", "u@p")
                .unwrap()
                .as_deref(),
            Some("enc-1")
        );

        // A re-auth replaces it (one credential per PIM account, shared by every
        // service under it).
        store
            .upsert_password_credential("acc", "u@p", "enc-2")
            .unwrap();
        assert_eq!(
            store
                .get_password_credential("acc", "u@p")
                .unwrap()
                .as_deref(),
            Some("enc-2")
        );
    }
}
