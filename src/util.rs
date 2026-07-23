//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in whole seconds, saturating to `0` before the
/// epoch.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
