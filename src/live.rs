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
pub type LiveBus = broadcast::Sender<LiveEvent>;

/// Channel depth: how many live events buffer before a slow SSE
/// subscriber starts lagging (dropping the oldest). Deliveries and
/// status changes are small and infrequent per box, so this is ample.
pub const CAPACITY: usize = 1024;

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
}
