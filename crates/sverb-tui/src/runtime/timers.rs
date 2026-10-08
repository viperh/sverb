//! The timer service (M0-09): `Effect::ScheduleTimer` / `CancelTimer` → `UiEvent::Timer`.
//!
//! [`Timers`] owns a `tokio_util::time::DelayQueue<TimerKind>`. Scheduling a kind that
//! is already pending replaces its deadline; cancelling a kind that is not pending is a
//! no-op. Every scheduled timer fires at most once.
//!
//! There is no periodic `Tick`: everything time-based in the UI is an explicit timer.

use std::{collections::HashMap, future::poll_fn, time::Duration};

use tokio_util::time::{DelayQueue, delay_queue};

use crate::app::{TimerFired, TimerKind};

/// Pending one-shot timers, keyed by [`TimerKind`].
#[derive(Debug, Default)]
pub struct Timers {
    queue: DelayQueue<TimerKind>,
    keys: HashMap<TimerKind, delay_queue::Key>,
}

impl Timers {
    /// No timers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire `kind` after `after`, replacing a pending timer of the same kind.
    pub fn schedule(&mut self, kind: TimerKind, after: Duration) {
        match self.keys.get(&kind) {
            Some(key) => self.queue.reset(key, after),
            None => {
                let key = self.queue.insert(kind, after);
                self.keys.insert(kind, key);
            }
        }
    }

    /// Cancel `kind` if it is pending.
    pub fn cancel(&mut self, kind: TimerKind) {
        if let Some(key) = self.keys.remove(&kind) {
            self.queue.remove(&key);
        }
    }

    /// Whether `kind` is pending.
    pub fn is_pending(&self, kind: TimerKind) -> bool {
        self.keys.contains_key(&kind)
    }

    /// Whether no timer is pending. The loop only polls [`Timers::next`] when this is false.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Wait for the next timer. Never resolves while no timer is pending.
    pub async fn next(&mut self) -> TimerFired {
        loop {
            let expired = poll_fn(|cx| self.queue.poll_expired(cx)).await;
            match expired {
                Some(expired) => {
                    let kind = expired.into_inner();
                    self.keys.remove(&kind);
                    return TimerFired {
                        kind,
                        // tokio's clock, so paused-time tests see virtual time.
                        at: tokio::time::Instant::now().into_std(),
                    };
                }
                // Empty queue: wait forever (the select! re-polls after a schedule).
                None => std::future::pending::<()>().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::Instant;

    use super::*;
    use crate::app::ToastId;

    const TOAST: TimerKind = TimerKind::ToastExpiry(ToastId(0));

    // T-08
    #[tokio::test(start_paused = true)]
    async fn timer_fires_exactly_once_at_its_deadline() {
        let start = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(TOAST, Duration::from_secs(4));
        let fired = timers.next().await;
        assert_eq!(fired.kind, TOAST);
        assert_eq!(Instant::now() - start, Duration::from_secs(4));
        assert_eq!(fired.at, (start + Duration::from_secs(4)).into_std());
        assert!(timers.is_empty());
        // Nothing fires again.
        let again = tokio::time::timeout(Duration::from_secs(60), timers.next()).await;
        assert!(again.is_err());
    }

    // T-08
    #[tokio::test(start_paused = true)]
    async fn cancel_before_deadline_suppresses_the_timer() {
        let mut timers = Timers::new();
        timers.schedule(TOAST, Duration::from_secs(4));
        tokio::time::sleep(Duration::from_secs(1)).await;
        timers.cancel(TOAST);
        assert!(!timers.is_pending(TOAST));
        let fired = tokio::time::timeout(Duration::from_secs(10), timers.next()).await;
        assert!(fired.is_err());
        // Cancelling again is a no-op.
        timers.cancel(TOAST);
    }

    #[tokio::test(start_paused = true)]
    async fn rescheduling_replaces_the_deadline() {
        let start = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(TimerKind::WhichKey, Duration::from_secs(1));
        timers.schedule(TimerKind::LeaderTimeout, Duration::from_secs(2));
        timers.schedule(TimerKind::WhichKey, Duration::from_secs(3));
        let first = timers.next().await;
        assert_eq!(first.kind, TimerKind::LeaderTimeout);
        let second = timers.next().await;
        assert_eq!(second.kind, TimerKind::WhichKey);
        assert_eq!(Instant::now() - start, Duration::from_secs(3));
    }
}
