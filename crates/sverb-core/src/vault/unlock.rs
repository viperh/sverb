//! The persisted unlock backoff (SPEC §5.3).
//!
//! have no delay. From the 5th consecutive failure on, the delays are 1 s, 2 s, 4 s,
//! 8 s, 16 s, then 30 s (cap). Success resets the counter. The counter and the
//! earliest next attempt are stored in `meta` (`unlock_failures`,
//! `unlock_next_allowed_at`), so restarting does not reset them.

use std::time::Duration;

/// Failures without any delay.
pub const FREE_ATTEMPTS: u32 = 4;

/// The longest delay.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// The delay after the `failures`-th consecutive failure.
pub fn backoff_delay(failures: u32) -> Duration {
    if failures <= FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let exp = failures - FREE_ATTEMPTS - 1;
    if exp >= 5 {
        return MAX_DELAY;
    }
    Duration::from_secs(1u64 << exp).min(MAX_DELAY)
}

/// The persisted backoff: consecutive failures and the earliest next attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackoffState {
    /// Consecutive failed attempts.
    pub failures: u32,
    /// Earliest time (UNIX ms) the next attempt is allowed; 0 = now.
    pub next_allowed_at: i64,
}

impl BackoffState {
    /// Decodes the two `meta` values (missing or malformed values count as zero, so a
    /// damaged row can never lock the user out for longer than one cap).
    pub fn decode(failures: Option<&[u8]>, next_allowed_at: Option<&[u8]>) -> Self {
        let failures = failures
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map_or(0, u32::from_be_bytes);
        let next_allowed_at = next_allowed_at
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(0, i64::from_be_bytes);
        Self {
            failures,
            next_allowed_at,
        }
    }

    /// `meta.unlock_failures` (u32 BE).
    pub fn failures_bytes(&self) -> [u8; 4] {
        self.failures.to_be_bytes()
    }

    /// `meta.unlock_next_allowed_at` (i64 BE, UNIX ms).
    pub fn next_allowed_at_bytes(&self) -> [u8; 8] {
        self.next_allowed_at.to_be_bytes()
    }

    /// `Err(remaining)` if an attempt at `now_ms` must be refused (without running
    /// Argon2). A next-allowed time absurdly far ahead (clock moved back) is clamped
    /// to [`MAX_DELAY`].
    pub fn check(&self, now_ms: i64) -> Result<(), Duration> {
        let wait = self.next_allowed_at.saturating_sub(now_ms);
        if wait <= 0 {
            return Ok(());
        }
        let wait = Duration::from_millis(u64::try_from(wait).unwrap_or(0));
        Err(wait.min(MAX_DELAY))
    }

    /// The state after one more failure at `now_ms`.
    #[must_use]
    pub fn after_failure(&self, now_ms: i64) -> Self {
        let failures = self.failures.saturating_add(1);
        let delay = i64::try_from(backoff_delay(failures).as_millis()).unwrap_or(i64::MAX);
        Self {
            failures,
            next_allowed_at: now_ms.saturating_add(delay),
        }
    }

    /// The delay the last failure imposed, if any.
    pub fn current_delay(&self) -> Option<Duration> {
        let d = backoff_delay(self.failures);
        (!d.is_zero()).then_some(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule() {
        let table = [
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
            (5, 1),
            (6, 2),
            (7, 4),
            (8, 8),
            (9, 16),
            (10, 30),
            (11, 30),
            (20, 30),
            (u32::MAX, 30),
        ];
        for (failures, secs) in table {
            assert_eq!(
                backoff_delay(failures),
                Duration::from_secs(secs),
                "failures = {failures}"
            );
        }
        assert_eq!(backoff_delay(0), Duration::ZERO);
    }

    #[test]
    fn state_roundtrip_and_gate() {
        let mut s = BackoffState::default();
        for _ in 0..4 {
            s = s.after_failure(1_000);
            assert_eq!(s.check(1_000), Ok(()));
        }
        s = s.after_failure(1_000);
        assert_eq!(s.failures, 5);
        assert_eq!(s.check(1_000), Err(Duration::from_secs(1)));
        assert_eq!(s.check(2_000), Ok(()));
        let back =
            BackoffState::decode(Some(&s.failures_bytes()), Some(&s.next_allowed_at_bytes()));
        assert_eq!(back, s);
        assert_eq!(
            BackoffState::decode(None, Some(b"xx")),
            BackoffState::default()
        );
        // Clock moved back a long way: the wait is clamped to the cap.
        let far = BackoffState {
            failures: 10,
            next_allowed_at: i64::MAX,
        };
        assert_eq!(far.check(0), Err(MAX_DELAY));
    }
}
