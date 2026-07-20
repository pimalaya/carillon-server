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
  last_metered INTEGER,
  -- 'password' (enc_password) or 'oauth' (the oauth_credential for the
  -- watch's (account_id, mailbox_key)).
  auth_kind    TEXT NOT NULL DEFAULT 'password',
  active       INTEGER NOT NULL DEFAULT 1
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

-- The billing account: one shared, refillable paid pool of watch-seconds
-- (§ DECISIONS 3). Watches draw from their account_id's pool.
CREATE TABLE IF NOT EXISTS account (
  id                    TEXT PRIMARY KEY,
  paid_secs             REAL NOT NULL DEFAULT 0,
  paid_expires          INTEGER,
  auto_refill           INTEGER NOT NULL DEFAULT 0,
  auto_refill_threshold REAL NOT NULL DEFAULT 0,
  auto_refill_amount    REAL NOT NULL DEFAULT 0
);

-- Per-mailbox free trial: non-refillable once emptied, granted once ever,
-- keyed on the normalised (login, provider). Drained BEFORE the pool, so
-- a dead trial is dead forever and money only ever touches the pool.
CREATE TABLE IF NOT EXISTS mailbox_trial (
  mailbox_key TEXT PRIMARY KEY,
  trial_secs  REAL NOT NULL,
  granted_at  INTEGER NOT NULL
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

-- Mailbox membership of an account: the mailboxes a user has proven
-- control of (by authenticating), grouped under one account.
CREATE TABLE IF NOT EXISTS account_mailbox (
  account_id  TEXT NOT NULL,
  mailbox_key TEXT NOT NULL,
  login       TEXT NOT NULL,
  imap_host   TEXT NOT NULL,
  added_at    INTEGER NOT NULL,
  PRIMARY KEY (account_id, mailbox_key)
);

-- Pending checkout sessions: payment is stateless on our side — we keep
-- only what to grant on fulfilment, never card/PII (the provider owns
-- the customer + receipt).
CREATE TABLE IF NOT EXISTS checkout_session (
  session_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  secs       REAL NOT NULL,
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
    /// `password` (uses `enc_password`) or `oauth` (authenticates via the
    /// `oauth_credential` for this watch's `(account_id, mailbox_key)`).
    pub auth_kind: String,
    /// Whether the watch is enabled.
    pub active: bool,
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
            auth_kind: row.get("auth_kind")?,
            active: row.get::<_, i64>("active")? != 0,
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

/// A billing account: one shared, refillable pool of watch-seconds plus
/// its auto-refill settings.
#[derive(Clone, Debug)]
pub struct AccountRow {
    /// Account id.
    pub id: String,
    /// Remaining paid watch-seconds (the refillable pool).
    pub paid_secs: f64,
    /// Unix time the pool expires (bounds deferred-revenue liability).
    pub paid_expires: Option<i64>,
    /// Whether auto-refill is enabled.
    pub auto_refill: bool,
    /// Refill when the pool falls below this many seconds.
    pub auto_refill_threshold: f64,
    /// Seconds to add on each auto-refill.
    pub auto_refill_amount: f64,
}

impl AccountRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            paid_secs: row.get("paid_secs")?,
            paid_expires: row.get("paid_expires")?,
            auto_refill: row.get::<_, i64>("auto_refill")? != 0,
            auto_refill_threshold: row.get("auto_refill_threshold")?,
            auto_refill_amount: row.get("auto_refill_amount")?,
        })
    }
}

/// The metering-relevant fields of one active watch.
#[derive(Clone, Debug)]
pub struct MeterRow {
    /// Watch id.
    pub watch_id: String,
    /// Billing account the watch draws from.
    pub account_id: String,
    /// Login, for the mailbox-trial key.
    pub login: String,
    /// IMAP host, for the mailbox-trial key.
    pub imap_host: String,
    /// When this watch was last debited (`None` before its first tick).
    pub last_metered: Option<i64>,
}

impl MeterRow {
    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            watch_id: row.get("id")?,
            account_id: row.get("account_id")?,
            login: row.get("login")?,
            imap_host: row.get("imap_host")?,
            last_metered: row.get("last_metered")?,
        })
    }
}

/// The two counters available to a watch right now: its per-mailbox trial
/// and its account's paid pool (already zeroed here if expired).
#[derive(Clone, Copy, Debug, Default)]
pub struct Balance {
    /// Remaining trial seconds for the mailbox.
    pub trial: f64,
    /// Remaining paid pool seconds for the account (0 if expired).
    pub pool: f64,
}

impl Balance {
    /// Total watch-seconds the watch can still spend.
    pub fn available(&self) -> f64 {
        self.trial + self.pool
    }
}

/// A mailbox an account has proven control of.
#[derive(Clone, Debug)]
pub struct MembershipRow {
    /// Normalised mailbox key.
    pub mailbox_key: String,
    /// Login used to prove control.
    pub login: String,
    /// IMAP host.
    pub imap_host: String,
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
    /// Mailbox context, so the callback can build the credential + watch.
    pub login: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub mailbox: String,
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
        self.lock().execute(
            "INSERT INTO watch
               (id, imap_host, imap_port, login, enc_password, mailbox, notify_url,
                hmac_secret, hmac_secret_prev, hmac_secret_prev_expires, account_id,
                auth_kind, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
               imap_host=?2, imap_port=?3, login=?4, enc_password=?5,
               mailbox=?6, notify_url=?7, hmac_secret=?8,
               hmac_secret_prev=?9, hmac_secret_prev_expires=?10,
               account_id=?11, auth_kind=?12, active=?13",
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

    /// Returns every active watch, ordered by id.
    pub fn active_watches(&self) -> Result<Vec<Watch>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM watch WHERE active = 1 ORDER BY id")?;
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

    /// The `(id, login, imap_host)` of every watch — the cheap input to the
    /// onboarding dedup guard, which normalises `(login, host)` into a
    /// mailbox key (that normalisation lives in `metering`, not here). No
    /// decrypt, no full row.
    pub fn watch_identities(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT id, login, imap_host FROM watch")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
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

    // --- Metering & accounts (M5) ---

    /// Creates the account row if it does not exist yet (no-op if it
    /// does). Called when a watch is created so its pool exists.
    pub fn ensure_account(&self, id: &str) -> Result<()> {
        self.lock()
            .execute("INSERT OR IGNORE INTO account (id) VALUES (?1)", [id])?;
        Ok(())
    }

    /// Looks up an account.
    pub fn get_account(&self, id: &str) -> Result<Option<AccountRow>> {
        let conn = self.lock();
        let account = conn
            .query_row(
                "SELECT * FROM account WHERE id = ?1",
                [id],
                AccountRow::from_row,
            )
            .optional()?;
        Ok(account)
    }

    /// Every account, ordered by id.
    pub fn all_accounts(&self) -> Result<Vec<AccountRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM account ORDER BY id")?;
        let rows = stmt.query_map([], AccountRow::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds paid watch-seconds to an account's pool and sets its expiry.
    /// Ensures the account exists. This is the sole thing money touches
    /// (top-up and auto-refill both land here).
    pub fn add_credit(&self, id: &str, secs: f64, expires: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute("INSERT OR IGNORE INTO account (id) VALUES (?1)", [id])?;
        conn.execute(
            "UPDATE account SET paid_secs = paid_secs + ?2, paid_expires = ?3 WHERE id = ?1",
            params![id, secs, expires],
        )?;
        Ok(())
    }

    /// Configures auto-refill for an account.
    pub fn set_auto_refill(
        &self,
        id: &str,
        enabled: bool,
        threshold: f64,
        amount: f64,
    ) -> Result<bool> {
        let conn = self.lock();
        conn.execute("INSERT OR IGNORE INTO account (id) VALUES (?1)", [id])?;
        let n = conn.execute(
            "UPDATE account
               SET auto_refill = ?2, auto_refill_threshold = ?3, auto_refill_amount = ?4
             WHERE id = ?1",
            params![id, enabled as i64, threshold, amount],
        )?;
        Ok(n > 0)
    }

    /// Grants a mailbox its one-time trial, keyed on the normalised
    /// mailbox key. A no-op if the key was ever granted before — this is
    /// the anti-farming linchpin (a dead trial stays dead).
    pub fn grant_trial(&self, mailbox_key: &str, secs: f64) -> Result<()> {
        self.lock().execute(
            "INSERT OR IGNORE INTO mailbox_trial (mailbox_key, trial_secs, granted_at)
             VALUES (?1, ?2, ?3)",
            params![mailbox_key, secs, now_secs()],
        )?;
        Ok(())
    }

    /// The metering rows for every active watch.
    pub fn meter_rows(&self) -> Result<Vec<MeterRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, account_id, login, imap_host, last_metered FROM watch WHERE active = 1",
        )?;
        let rows = stmt.query_map([], MeterRow::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The two counters available to a watch right now. The pool reads as
    /// `0` (with `pool_expired`) once its expiry has passed.
    pub fn balance(&self, account_id: &str, mailbox_key: &str, now: i64) -> Result<Balance> {
        let conn = self.lock();
        let trial: f64 = conn
            .query_row(
                "SELECT trial_secs FROM mailbox_trial WHERE mailbox_key = ?1",
                [mailbox_key],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0.0);

        let account = conn
            .query_row(
                "SELECT * FROM account WHERE id = ?1",
                [account_id],
                AccountRow::from_row,
            )
            .optional()?;

        let pool = match account {
            Some(account) => match account.paid_expires {
                Some(expires) if now >= expires => 0.0,
                _ => account.paid_secs,
            },
            None => 0.0,
        };

        Ok(Balance { trial, pool })
    }

    /// Debits a watch's consumed time: `from_trial` off the mailbox trial
    /// and `from_pool` off the account pool, and stamps `last_metered`.
    /// Clamped at zero so rounding never drives a balance negative.
    pub fn apply_debit(
        &self,
        watch_id: &str,
        account_id: &str,
        mailbox_key: &str,
        from_trial: f64,
        from_pool: f64,
        now: i64,
    ) -> Result<()> {
        let conn = self.lock();
        if from_trial > 0.0 {
            conn.execute(
                "UPDATE mailbox_trial SET trial_secs = MAX(0, trial_secs - ?2) WHERE mailbox_key = ?1",
                params![mailbox_key, from_trial],
            )?;
        }
        if from_pool > 0.0 {
            conn.execute(
                "UPDATE account SET paid_secs = MAX(0, paid_secs - ?2) WHERE id = ?1",
                params![account_id, from_pool],
            )?;
        }
        conn.execute(
            "UPDATE watch SET last_metered = ?2 WHERE id = ?1",
            params![watch_id, now],
        )?;
        Ok(())
    }

    /// Stamps `last_metered` without debiting (first observation of a
    /// watch, so it is not charged for downtime before the daemon saw it).
    pub fn mark_metered(&self, watch_id: &str, now: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE watch SET last_metered = ?2 WHERE id = ?1",
            params![watch_id, now],
        )?;
        Ok(())
    }

    /// Deactivates a watch whose credit ran out and clears its metering
    /// clock, so it stops debiting and reconcile stops the connection.
    pub fn exhaust_watch(&self, watch_id: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE watch SET active = 0, last_metered = NULL WHERE id = ?1",
            [watch_id],
        )?;
        Ok(())
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

    /// Records that an account controls a mailbox (idempotent).
    pub fn add_membership(
        &self,
        account_id: &str,
        mailbox_key: &str,
        login: &str,
        imap_host: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT OR IGNORE INTO account_mailbox
               (account_id, mailbox_key, login, imap_host, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account_id, mailbox_key, login, imap_host, now_secs()],
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

    /// Whether an account has proven control of a mailbox (its
    /// membership exists). The create-watch gate: a scoped caller may only
    /// watch a mailbox it authenticated to via `/auth`, which is what
    /// recorded the membership — you cannot watch what you cannot log into.
    pub fn mailbox_belongs(&self, account_id: &str, mailbox_key: &str) -> Result<bool> {
        let conn = self.lock();
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM account_mailbox WHERE account_id = ?1 AND mailbox_key = ?2",
                params![account_id, mailbox_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    /// The mailboxes an account controls.
    pub fn memberships(&self, account_id: &str) -> Result<Vec<MembershipRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT mailbox_key, login, imap_host FROM account_mailbox
             WHERE account_id = ?1 ORDER BY added_at",
        )?;
        let rows = stmt.query_map([account_id], |row| {
            Ok(MembershipRow {
                mailbox_key: row.get(0)?,
                login: row.get(1)?,
                imap_host: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records a pending checkout session (what to grant on fulfilment).
    pub fn create_session(&self, session_id: &str, account_id: &str, secs: f64) -> Result<()> {
        self.lock().execute(
            "INSERT INTO checkout_session (session_id, account_id, secs, fulfilled, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![session_id, account_id, secs, now_secs()],
        )?;
        Ok(())
    }

    /// Fulfils a session exactly once, returning `(account_id, secs)` to
    /// credit. `None` if the session is unknown or already fulfilled
    /// (idempotency against retried payment webhooks).
    pub fn fulfill_session(&self, session_id: &str) -> Result<Option<(String, f64)>> {
        let conn = self.lock();
        let row: Option<(String, f64)> = conn
            .query_row(
                "SELECT account_id, secs FROM checkout_session
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
                imap_host, imap_port, mailbox, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                        imap_host, imap_port, mailbox
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
    for (column, decl) in [
        ("hmac_secret_prev", "TEXT"),
        ("hmac_secret_prev_expires", "INTEGER"),
        ("account_id", "TEXT NOT NULL DEFAULT ''"),
        ("last_metered", "INTEGER"),
        ("auth_kind", "TEXT NOT NULL DEFAULT 'password'"),
    ] {
        if !column_exists(conn, "watch", column)? {
            conn.execute(&format!("ALTER TABLE watch ADD COLUMN {column} {decl}"), [])?;
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
