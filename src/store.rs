//! # Store
//!
//! The source of truth for watches and the delivery log, a local
//! sqlite database behind a mutex. Passwords are stored encrypted (see
//! [`crate::crypto`]); everything else is plain. Blocking rusqlite
//! calls are cheap and infrequent here (boot-time loads, one small row
//! per delivery); the hot delivery path wraps them in
//! `spawn_blocking`.

use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};

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
  active       INTEGER NOT NULL DEFAULT 1
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
            active: row.get::<_, i64>("active")? != 0,
        })
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

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    /// Inserts or replaces a watch.
    pub fn upsert_watch(&self, watch: &Watch) -> Result<()> {
        self.lock().execute(
            "INSERT INTO watch
               (id, imap_host, imap_port, login, enc_password, mailbox, notify_url, hmac_secret, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               imap_host=?2, imap_port=?3, login=?4, enc_password=?5,
               mailbox=?6, notify_url=?7, hmac_secret=?8, active=?9",
            params![
                watch.id,
                watch.imap_host,
                watch.imap_port,
                watch.login,
                watch.enc_password,
                watch.mailbox,
                watch.notify_url,
                watch.hmac_secret,
                watch.active as i64,
            ],
        )?;
        Ok(())
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

    /// Looks up a single watch by id.
    pub fn get_watch(&self, id: &str) -> Result<Option<Watch>> {
        let conn = self.lock();
        let watch = conn
            .query_row("SELECT * FROM watch WHERE id = ?1", [id], Watch::from_row)
            .optional()?;
        Ok(watch)
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
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
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
}
