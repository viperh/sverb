//! Hybrid Logical Clock (SPEC §4, §12.4).
//!
//! An [`Hlc`] is a `uhlc` [`NTP64`]: 32 bits of seconds since the Unix epoch, 32 bits of
//! fraction, of which the low [`uhlc::CSIZE`] bits are the logical counter (the same
//! layout `uhlc::HLC` uses). Order is plain `u64` order, which is `(time, logical)`.
//! Ties between devices are broken by [`DeviceId`] in [`Stamped`](super::Stamped)
//! ordering, not here.
//!
//! [`HlcClock`] implements the HLC algorithm with an injectable [`PhysicalClock`], and a
//! skew clamp: a remote stamp more than [`MAX_SKEW`] ahead of local physical time only
//! advances the local clock to `physical + MAX_SKEW`, and [`HlcClock::observe`] returns
//! [`ClockSkew`] so the UI can warn. The remote stamp itself is **not** rewritten: the
//! value stored in the item keeps its original stamp, so every replica still converges
//! (decision of M1-02, see `docs/data-model.md`).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uhlc::NTP64;

use super::ids::DeviceId;

/// Remote stamps further ahead of local physical time than this are clamped (§12.4).
pub const MAX_SKEW: Duration = Duration::from_secs(5 * 60);

/// Mask clearing the logical counter bits of an [`NTP64`].
const LMASK: u64 = !((1_u64 << uhlc::CSIZE) - 1);

/// A Hybrid Logical Clock timestamp. Serialized as a CBOR unsigned integer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc(NTP64);

impl Hlc {
    /// The smallest stamp.
    pub const ZERO: Hlc = Hlc(NTP64(0));

    /// From the raw 64-bit NTP representation.
    pub const fn from_u64(raw: u64) -> Self {
        Self(NTP64(raw))
    }

    /// The raw 64-bit NTP representation.
    pub const fn as_u64(&self) -> u64 {
        self.0.0
    }

    /// A stamp at the given time since the Unix epoch, with logical counter 0.
    pub fn from_duration(since_epoch: Duration) -> Self {
        Self(NTP64(NTP64::from(since_epoch).0 & LMASK))
    }

    /// The physical part (time since the Unix epoch, logical counter dropped).
    pub fn physical(&self) -> Duration {
        NTP64(self.0.0 & LMASK).to_duration()
    }

    /// The logical counter (low bits).
    pub const fn logical(&self) -> u64 {
        self.0.0 & !LMASK
    }

    /// The wrapped `uhlc` value.
    pub const fn ntp64(&self) -> NTP64 {
        self.0
    }
}

impl From<NTP64> for Hlc {
    fn from(t: NTP64) -> Self {
        Self(t)
    }
}

impl fmt::Debug for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.physical();
        write!(
            f,
            "Hlc({}.{:09}+{})",
            p.as_secs(),
            p.subsec_nanos(),
            self.logical()
        )
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Hlc {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.as_u64())
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        u64::deserialize(d).map(Self::from_u64)
    }
}

/// Source of physical time, injectable for tests.
pub trait PhysicalClock: Send + Sync + fmt::Debug {
    /// Current time since the Unix epoch.
    fn now(&self) -> Duration;
}

/// The system wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl PhysicalClock for SystemClock {
    fn now(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }
}

/// A manually driven clock for tests. Clones share the same time.
#[derive(Debug, Default, Clone)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    /// A clock frozen at `since_epoch`.
    pub fn new(since_epoch: Duration) -> Self {
        let clock = Self::default();
        clock.set(since_epoch);
        clock
    }

    /// Sets the time.
    pub fn set(&self, since_epoch: Duration) {
        let nanos = u64::try_from(since_epoch.as_nanos()).unwrap_or(u64::MAX);
        self.0.store(nanos, Ordering::SeqCst);
    }

    /// Moves the time forward.
    pub fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.0.fetch_add(by, Ordering::SeqCst);
    }
}

impl PhysicalClock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

/// A received stamp was too far ahead of local physical time (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("clock skew detected on device {device}: {}s ahead", ahead_by.as_secs())]
pub struct ClockSkew {
    /// The device whose stamp was ahead.
    pub device: DeviceId,
    /// How far ahead of local physical time the stamp was.
    pub ahead_by: Duration,
}

/// The per-device HLC. Owned by the store layer; one instance per device.
#[derive(Debug)]
pub struct HlcClock {
    last: u64,
    physical: Box<dyn PhysicalClock>,
    max_skew: Duration,
}

impl Default for HlcClock {
    fn default() -> Self {
        Self::new(SystemClock)
    }
}

impl HlcClock {
    /// A clock reading physical time from `physical`, with the §12.4 skew limit.
    pub fn new(physical: impl PhysicalClock + 'static) -> Self {
        Self {
            last: 0,
            physical: Box::new(physical),
            max_skew: MAX_SKEW,
        }
    }

    /// Resumes from a persisted last stamp (so stamps stay monotonic across restarts).
    pub fn with_last(mut self, last: Hlc) -> Self {
        self.last = last.as_u64();
        self
    }

    /// The last stamp issued or observed.
    pub fn last(&self) -> Hlc {
        Hlc::from_u64(self.last)
    }

    fn physical_now(&self) -> u64 {
        Hlc::from_duration(self.physical.now()).as_u64()
    }

    /// A new stamp, strictly greater than every stamp issued or observed before.
    pub fn now(&mut self) -> Hlc {
        let pt = self.physical_now();
        self.last = if pt > (self.last & LMASK) {
            pt
        } else {
            // Same (or earlier) physical tick: advance the logical counter. On overflow
            // it carries into the time bits, which keeps the order strict.
            self.last.saturating_add(1)
        };
        Hlc::from_u64(self.last)
    }

    /// Updates the clock with a stamp received from `from`.
    ///
    /// A stamp more than [`MAX_SKEW`] ahead of local physical time advances the local
    /// clock only to `physical + MAX_SKEW` and returns [`ClockSkew`]. The caller keeps
    /// the original stamp on the received value.
    pub fn observe(&mut self, remote: Hlc, from: DeviceId) -> Result<(), ClockSkew> {
        let pt = self.physical_now();
        let limit = Hlc::from_duration(self.physical.now() + self.max_skew).as_u64();
        let (effective, skew) = if remote.as_u64() > limit {
            let ahead_by = remote
                .physical()
                .saturating_sub(Hlc::from_u64(pt).physical());
            (
                limit,
                Some(ClockSkew {
                    device: from,
                    ahead_by,
                }),
            )
        } else {
            (remote.as_u64(), None)
        };
        self.last = self.last.max(effective).max(pt);
        match skew {
            Some(skew) => Err(skew),
            None => Ok(()),
        }
    }

    /// [`HlcClock::observe`] for a received [`Stamped`](super::Stamped) value.
    pub fn observe_stamp<T>(&mut self, stamped: &super::Stamped<T>) -> Result<(), ClockSkew> {
        self.observe(stamped.hlc, stamped.device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Duration = Duration::from_secs(1_800_000_000);

    fn dev() -> DeviceId {
        DeviceId::from_bytes([9; 16])
    }

    // T-02
    #[test]
    fn now_is_strictly_increasing_with_frozen_clock() {
        let mut clock = HlcClock::new(ManualClock::new(T0));
        let mut prev = clock.now();
        for _ in 0..10_000 {
            let next = clock.now();
            assert!(next > prev, "{next:?} <= {prev:?}");
            prev = next;
        }
    }

    #[test]
    fn now_follows_physical_time() {
        let pc = ManualClock::new(T0);
        let mut clock = HlcClock::new(pc.clone());
        let a = clock.now();
        assert_eq!(a.physical().as_secs(), T0.as_secs());
        assert_eq!(a.logical(), 0);
        let b = clock.now();
        assert_eq!(b.logical(), 1);
        pc.advance(Duration::from_secs(1));
        let c = clock.now();
        assert!(c > b);
        assert_eq!(c.logical(), 0);
        assert_eq!(c.physical().as_secs(), T0.as_secs() + 1);
    }

    // T-03
    #[test]
    fn observe_moves_clock_past_remote() {
        let mut clock = HlcClock::new(ManualClock::new(T0));
        let remote = Hlc::from_duration(T0 + Duration::from_secs(10));
        assert_eq!(clock.observe(remote, dev()), Ok(()));
        assert!(clock.now() > remote);
    }

    // T-04
    #[test]
    fn skew_is_clamped_and_reported() {
        let mut clock = HlcClock::new(ManualClock::new(T0));
        let remote = Hlc::from_duration(T0 + Duration::from_secs(600));
        let err = clock.observe(remote, dev());
        let skew = match err {
            Err(skew) => skew,
            Ok(()) => panic!("expected ClockSkew"),
        };
        assert_eq!(skew.device, dev());
        assert!(skew.ahead_by >= Duration::from_secs(599));
        let now = clock.now();
        let eps = Duration::from_millis(1);
        assert!(now.physical() < T0 + MAX_SKEW + eps, "{now:?}");
        assert!(now < remote);
        // Still beyond anything observed below the limit.
        assert!(now.physical() >= T0 + MAX_SKEW - eps);
    }

    #[test]
    fn hlc_serializes_as_integer() -> Result<(), Box<dyn std::error::Error>> {
        let h = Hlc::from_u64(0x1234_5678_9abc_def0);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf)?;
        assert_eq!(buf[0], 0x1b); // unsigned 64-bit
        let back: Hlc = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(back, h);
        Ok(())
    }
}
