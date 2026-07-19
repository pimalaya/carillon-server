//! A small fixed-window rate limiter.
//!
//! The `/test` endpoint authenticates arbitrary credentials against
//! arbitrary servers on request — an open credential-testing oracle if
//! left ungated. This caps attempts per key (we key on `(client IP,
//! login)`) so Carillon adds no meaningful guessing power beyond what
//! the target IMAP server already exposes: the server *is* the oracle;
//! we only refuse to parallelise it.
//!
//! Fixed windows are coarse (a caller can burst at a boundary) but
//! simple, allocation-light and adequate for an anti-oracle guard.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-key counter within the current window.
struct Window {
    /// Attempts charged in the current window.
    count: u32,
    /// When the current window ends and the count resets.
    reset_at: Instant,
}

/// A fixed-window limiter: at most `max` charges per `window` per key.
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
    max: u32,
    window: Duration,
}

impl RateLimiter {
    /// Builds a limiter allowing `max` charges per `window` per key.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max: max.max(1),
            window,
        }
    }

    /// Charges one attempt against `key`. Returns `Ok(())` if under the
    /// limit, or `Err(retry_after)` with the time until the window
    /// resets if the key is exhausted.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut windows = self.windows.lock().expect("rate limiter mutex poisoned");

        // Opportunistic prune so a churn of distinct keys does not grow
        // the map without bound.
        if windows.len() > 4096 {
            windows.retain(|_, window| window.reset_at > now);
        }

        let window = windows.entry(key.to_owned()).or_insert(Window {
            count: 0,
            reset_at: now + self.window,
        });

        if window.reset_at <= now {
            window.count = 0;
            window.reset_at = now + self.window;
        }

        if window.count >= self.max {
            return Err(window.reset_at.saturating_duration_since(now));
        }

        window.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));

        assert!(limiter.check("a|user").is_ok());
        assert!(limiter.check("a|user").is_ok());
        assert!(limiter.check("a|user").is_ok());
        assert!(limiter.check("a|user").is_err(), "4th attempt blocked");
    }

    #[test]
    fn keys_are_independent() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));

        assert!(limiter.check("a|user").is_ok());
        assert!(limiter.check("a|user").is_err());
        // A different key (different IP or login) is unaffected.
        assert!(limiter.check("b|user").is_ok());
    }

    #[test]
    fn window_resets_after_expiry() {
        let limiter = RateLimiter::new(1, Duration::from_millis(1));

        assert!(limiter.check("a|user").is_ok());
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("a|user").is_ok(), "resets after the window");
    }
}
