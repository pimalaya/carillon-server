//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in whole seconds. Saturates to `0` before the
/// epoch (never happens on a sane clock), keeping callers total.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
