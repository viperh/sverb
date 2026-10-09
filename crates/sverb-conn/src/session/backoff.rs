//! The auto-reconnect schedule (SPEC §6.1.2), as pure functions.
//!
//! Attempt `n` (1-based) waits `min(2^(n-1), 30)` seconds: 1, 2, 4, 8, 16, 30, 30, …,
//! up to [`MAX_ATTEMPTS`] tries, each with ±[`JITTER`] jitter so many sessions dropped
//! by the same outage don't reconnect in lockstep. There is no attempt after the last.
//!
//! Auto-reconnect is never tried for `HostKey` or `Auth` (it would hit the same wall)
//! nor for a remote exit (`Exited`, §6.1.9): see [`retries`].
//!
//! The randomness comes from a caller-supplied [`SplitMix64`], so tests (and the
//! reducer, which must stay deterministic) seed it.

use std::time::Duration;

use crate::session::state::DisconnectReason;

/// Tries before giving up.
pub const MAX_ATTEMPTS: u32 = 10;

/// The longest base delay.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// Relative jitter: each delay is scaled by a factor in `[1 - JITTER, 1 + JITTER]`.
pub const JITTER: f64 = 0.2;

/// Whether a session that disconnected for `reason` may be reconnected automatically.
pub fn retries(reason: DisconnectReason) -> bool {
    !matches!(
        reason,
        DisconnectReason::HostKey | DisconnectReason::Auth | DisconnectReason::Exited(_)
    )
}

/// The base delay before attempt `attempt` (1-based), or `None` past [`MAX_ATTEMPTS`]
/// (and for attempt 0).
pub fn base_delay(attempt: u32) -> Option<Duration> {
    if attempt == 0 || attempt > MAX_ATTEMPTS {
        return None;
    }
    let secs = 1_u64
        .checked_shl(attempt - 1)
        .unwrap_or(u64::MAX)
        .min(MAX_DELAY.as_secs());
    Some(Duration::from_secs(secs))
}

/// The jittered delay before attempt `attempt`: [`base_delay`] scaled by a factor in
/// `[1 - JITTER, 1 + JITTER]` drawn from `rng`. `None` past [`MAX_ATTEMPTS`].
pub fn delay(attempt: u32, rng: &mut SplitMix64) -> Option<Duration> {
    let base = base_delay(attempt)?;
    let factor = 1.0 + JITTER * (2.0 * rng.next_unit() - 1.0);
    Some(base.mul_f64(factor))
}

/// A tiny seeded PRNG (SplitMix64): enough for jitter, deterministic in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// A generator seeded with `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniform value in `[0, 1)`.
    pub fn next_unit(&mut self) -> f64 {
        // 53 random bits → an exactly representable fraction.
        #[allow(clippy::cast_precision_loss)]
        let v = (self.next_u64() >> 11) as f64;
        v / (1_u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // 1, 2, 4, 8, 16, 30, 30, 30, 30, 30 with ±20% jitter; no 11th attempt.
    #[test]
    fn t01_backoff_schedule() {
        let bases: Vec<u64> = (1..=MAX_ATTEMPTS)
            .map(|n| base_delay(n).unwrap().as_secs())
            .collect();
        assert_eq!(bases, [1, 2, 4, 8, 16, 30, 30, 30, 30, 30]);
        assert_eq!(base_delay(0), None);
        assert_eq!(base_delay(11), None);
        assert_eq!(base_delay(u32::MAX), None);

        for seed in 0..200 {
            let mut rng = SplitMix64::new(seed);
            for n in 1..=MAX_ATTEMPTS {
                let base = base_delay(n).unwrap().as_secs_f64();
                let d = delay(n, &mut rng).unwrap().as_secs_f64();
                assert!(
                    d >= base * 0.8 - 1e-9 && d <= base * 1.2 + 1e-9,
                    "seed {seed} attempt {n}: {d} vs {base}"
                );
            }
            assert_eq!(delay(MAX_ATTEMPTS + 1, &mut rng), None);
        }
        // The jitter actually varies, and a seed reproduces it.
        let a = delay(5, &mut SplitMix64::new(1)).unwrap();
        let b = delay(5, &mut SplitMix64::new(2)).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, delay(5, &mut SplitMix64::new(1)).unwrap());
    }

    // No auto-reconnect for HostKey, Auth or Exited.
    #[test]
    fn t02_no_auto_reconnect_for_hostkey_auth_exited() {
        for reason in [
            DisconnectReason::HostKey,
            DisconnectReason::Auth,
            DisconnectReason::Exited(0),
            DisconnectReason::Exited(130),
        ] {
            assert!(!retries(reason), "{reason:?}");
        }
        for reason in [
            DisconnectReason::Resolve,
            DisconnectReason::Connect,
            DisconnectReason::Negotiation,
            DisconnectReason::Timeout,
            DisconnectReason::Closed,
            DisconnectReason::Internal,
        ] {
            assert!(retries(reason), "{reason:?}");
        }
    }
}
