//! The live event bus for the SSE stream.
//!
//! A process-wide broadcast channel over which the delivery worker and
//! the supervisor publish what a dashboard wants to watch in real time:
//! each delivery outcome and each change in a watch's connection status.
//! The `/events` SSE endpoint subscribes and forwards them. This is
//! purely observational — it carries no message content, only the same
//! content-free signal the rest of Carillon deals in.

use serde::Serialize;
use tokio::sync::broadcast;

use crate::util::now_secs;

/// The sender half of the live bus, cloned to every publisher and to
/// the API state. Subscribers call [`broadcast::Sender::subscribe`].
pub type LiveBus = broadcast::Sender<Routed>;

/// Channel depth: how many live events buffer before a slow SSE
/// subscriber starts lagging (dropping the oldest). Deliveries and
/// status changes are small and infrequent per box, so this is ample.
pub const CAPACITY: usize = 1024;

/// A live event tagged with the billing **account** it belongs to, so the
/// `/events` SSE stream can scope each subscriber to its own account
/// (§ DECISIONS 5). The routing tag is server-side only — the wire
/// payload a client receives is just the inner [`LiveEvent`], unchanged.
#[derive(Clone, Debug)]
pub struct Routed {
    /// The billing account this event concerns; the SSE handler forwards
    /// an event to a subscriber only when it matches (or the subscriber is
    /// the unscoped admin).
    pub account_id: String,
    /// The event to serialize and deliver.
    pub event: LiveEvent,
}

impl Routed {
    /// Tags a live event with its billing account for scoped fan-out.
    pub fn new(account_id: impl Into<String>, event: LiveEvent) -> Self {
        Self {
            account_id: account_id.into(),
            event,
        }
    }
}

/// One thing worth showing on a live dashboard.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// A delivery attempt completed (success or final failure).
    Delivery {
        account: String,
        event: &'static str,
        uid: u32,
        ok: bool,
        status: Option<u16>,
        attempts: u32,
        at: i64,
    },
    /// A watch's connection status changed.
    Status {
        account: String,
        state: WatchState,
        detail: Option<String>,
        at: i64,
    },
    /// An entitlement / billing notice (trial ending, watch paused).
    Notice {
        account: String,
        kind: NoticeKind,
        detail: Option<String>,
        at: i64,
    },
}

/// An entitlement / billing notice. Delivered on the SSE bus and, so a
/// no-dashboard user is not silently cut off, also as a signed webhook.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    /// A mailbox's free trial is about to end with no subscription behind it.
    TrialEnding,
    /// Entitlement lapsed (trial ended, no active subscription); the watch
    /// was paused.
    WatchPaused,
}

impl NoticeKind {
    /// The wire string for the webhook `notice` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            NoticeKind::TrialEnding => "trial_ending",
            NoticeKind::WatchPaused => "watch_paused",
        }
    }
}

/// The connection state of a single watch, as surfaced to the UI.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchState {
    /// Connected, authenticated and holding IDLE.
    Watching,
    /// Between connections (backing off before a reconnect).
    Reconnecting,
    /// The last connection attempt failed.
    Error,
    /// The watcher was stopped (paused, removed or shutting down).
    Stopped,
}

impl LiveEvent {
    /// The SSE `event:` name for this variant.
    pub fn name(&self) -> &'static str {
        match self {
            LiveEvent::Delivery { .. } => "delivery",
            LiveEvent::Status { .. } => "status",
            LiveEvent::Notice { .. } => "notice",
        }
    }

    /// A delivery-outcome event stamped now.
    pub fn delivery(
        account: impl Into<String>,
        event: &'static str,
        uid: u32,
        ok: bool,
        status: Option<u16>,
        attempts: u32,
    ) -> Self {
        LiveEvent::Delivery {
            account: account.into(),
            event,
            uid,
            ok,
            status,
            attempts,
            at: now_secs(),
        }
    }

    /// A status-change event stamped now.
    pub fn status(account: impl Into<String>, state: WatchState, detail: Option<String>) -> Self {
        LiveEvent::Status {
            account: account.into(),
            state,
            detail,
            at: now_secs(),
        }
    }

    /// A metering notice stamped now.
    pub fn notice(account: impl Into<String>, kind: NoticeKind, detail: Option<String>) -> Self {
        LiveEvent::Notice {
            account: account.into(),
            kind,
            detail,
            at: now_secs(),
        }
    }
}
