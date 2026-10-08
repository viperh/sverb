//! Injectable wall clock (M1-03 §2.5). All store timestamps are UNIX milliseconds.

use std::fmt::Debug;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of "now" in UNIX milliseconds.
pub trait Clock: Send + Sync + Debug {
    /// The current time in UNIX milliseconds.
    fn now_millis(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

/// A clock that only moves when told to; for tests.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// Starts at `millis`.
    pub fn new(millis: i64) -> Self {
        Self(AtomicI64::new(millis))
    }

    /// Sets the time.
    pub fn set(&self, millis: i64) {
        self.0.store(millis, Ordering::SeqCst);
    }

    /// Moves the time forward by `millis`.
    pub fn advance(&self, millis: i64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
