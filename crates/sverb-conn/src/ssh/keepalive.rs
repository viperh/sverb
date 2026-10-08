//! Keepalive and latency (SPEC §6.1.1 step 7).
//!
//! - Dead-link detection is russh's: `Config { keepalive_interval, keepalive_max: 3 }`
//!   sends `keepalive@openssh.com` when the link is idle and gives up after 3 unanswered
//!   ones; the transport then ends with `Disconnected { Timeout }`.
//! - russh doesn't expose the keepalive RTT, so sverb measures it itself: every
//!   interval it sends its own `keepalive@openssh.com` global request with `want_reply`
//!   (`Handle::send_ping`) and times the reply, emitting `SessionEvent::Latency`.
//! - `keepalive_secs = 0` disables both (the status bar shows `–`).

use std::{sync::Arc, time::Duration};

use russh::client::Handle;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::trace;

use super::handler::ClientHandler;
use crate::{session::SessionEvent, transport::SessionEmitter};

/// Unanswered keepalives before the connection is considered dead.
pub const KEEPALIVE_MAX: usize = 3;

/// The russh keepalive settings for an interval in seconds (`None`: disabled).
pub fn keepalive_interval(secs: u32) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(u64::from(secs)))
}

/// Something that answers pings (the russh handle; a fake in tests).
pub(crate) trait Pinger: Send + Sync + 'static {
    /// Send a ping and wait for the reply.
    fn ping(&self) -> impl std::future::Future<Output = Result<(), ()>> + Send;
}

impl Pinger for Handle<ClientHandler> {
    async fn ping(&self) -> Result<(), ()> {
        self.send_ping().await.map_err(|_| ())
    }
}

/// Measure the RTT every `interval` (the first one right away) and emit `Latency`.
/// A ping without a reply within `interval` is skipped (russh's keepalive decides
/// whether the link is dead). Ends when a ping can't be sent (connection gone).
pub(crate) async fn measure_latency<P: Pinger>(
    pinger: Arc<P>,
    interval: Duration,
    emitter: SessionEmitter,
) {
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let t0 = Instant::now();
        match tokio::time::timeout(interval, pinger.ping()).await {
            Ok(Ok(())) => emitter.emit(SessionEvent::Latency(t0.elapsed())),
            Ok(Err(())) => return,
            Err(_) => trace!(session = %emitter.id(), "ping unanswered"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::session::SessionId;
    use tokio::sync::mpsc;

    struct SlowPinger(Duration);

    impl Pinger for SlowPinger {
        async fn ping(&self) -> Result<(), ()> {
            tokio::time::sleep(self.0).await;
            Ok(())
        }
    }

    #[test]
    fn zero_disables_keepalive() {
        assert_eq!(keepalive_interval(0), None);
        assert_eq!(keepalive_interval(30), Some(Duration::from_secs(30)));
    }

    /// The RTT is measured and reported (virtual time).
    #[tokio::test(start_paused = true)]
    async fn latency_is_the_ping_round_trip() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let emitter = SessionEmitter::new(SessionId(3), Arc::new(tx));
        let task = tokio::spawn(measure_latency(
            Arc::new(SlowPinger(Duration::from_millis(23))),
            Duration::from_secs(1),
            emitter,
        ));
        let (id, ev) = rx.recv().await.unwrap();
        assert_eq!(id, SessionId(3));
        assert_eq!(ev, SessionEvent::Latency(Duration::from_millis(23)));
        // Within 2 × keepalive, a second one.
        let t0 = Instant::now();
        rx.recv().await.unwrap();
        assert!(t0.elapsed() <= Duration::from_secs(2));
        task.abort();
    }
}
