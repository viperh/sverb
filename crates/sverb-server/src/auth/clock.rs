//! Injectable time source, so token expiry can be tested by time travel
//! [`Clock`] in [`super::AuthRuntime`], also for SQL (bound as a parameter
//! instead of `now()`).

use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};

/// A source of the current time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current time.
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct ManualClock(Mutex<DateTime<Utc>>);

impl ManualClock {
    /// Starts at the current system time.
    #[must_use]
    pub fn new() -> Self {
        Self(Mutex::new(Utc::now()))
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: TimeDelta) {
        if let Ok(mut t) = self.0.lock() {
            *t += by;
        }
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        self.0.lock().map_or_else(|_| Utc::now(), |t| *t)
    }
}
