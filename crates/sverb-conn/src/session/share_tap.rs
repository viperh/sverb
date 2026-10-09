//! The share tap, an observer of a session's output (SPEC §14.1 step 7).
//!
//! A terminal share copies every output chunk to its viewers **after** the session
//! fed it to the emulator, so a snapshot of the emulator plus the chunks that follow
//! it reproduce the screen. The actor calls the attached [`OutputObserver`] while it
//! holds the emulator lock:
//!
//! - [`OutputObserver::output`] right after each chunk is fed,
//! - [`OutputObserver::resize`] right after each resize, and once with the current
//!   size when the observer is attached (the "attached" mark),
//! - [`OutputObserver::ended`] once, when the connection ends (exit, drop or close);
//!   the observer is detached then (a reconnected session is not shared).
//!
//! Because both callbacks run under the emulator lock, an observer that takes a
//! snapshot under the same lock knows exactly which chunks the snapshot already
//! contains: everything it received before. Observers must never block or take the
//! emulator lock themselves (a bounded `try_send` is the intended body).

use std::{fmt, sync::Arc};

/// Receives a session's output (see the module docs for the locking rules).
pub trait OutputObserver: Send + Sync + 'static {
    /// `bytes` were just fed to the emulator (the emulator is locked).
    fn output(&self, bytes: &[u8]);

    /// The emulator now has this size (the emulator is locked). Also called once on
    /// attach.
    fn resize(&self, cols: u16, rows: u16);

    /// The session's connection ended; the observer was detached.
    fn ended(&self);
}

/// An attached observer (`SessionCmd::AttachShareTap`). Cheap to clone.
#[derive(Clone)]
pub struct ShareTap(pub Arc<dyn OutputObserver>);

impl ShareTap {
    /// Wrap an observer.
    pub fn new(observer: Arc<dyn OutputObserver>) -> Self {
        Self(observer)
    }
}

impl fmt::Debug for ShareTap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShareTap")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use bytes::Bytes;
    use parking_lot::Mutex;

    use super::*;
    use crate::{
        MockSpec, SessionCmd, SessionEvent, SessionId, SessionManager, SessionSpec,
        mock::MockTransport,
    };

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);

    impl OutputObserver for Log {
        fn output(&self, bytes: &[u8]) {
            self.0
                .lock()
                .push(format!("out:{}", String::from_utf8_lossy(bytes)));
        }
        fn resize(&self, cols: u16, rows: u16) {
            self.0.lock().push(format!("size:{cols}x{rows}"));
        }
        fn ended(&self) {
            self.0.lock().push("ended".to_owned());
        }
    }

    async fn wait_for(log: &Log, what: &str) {
        for _ in 0..200 {
            if log.0.lock().iter().any(|l| l == what) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{what} not seen: {:?}", log.0.lock());
    }

    #[tokio::test]
    async fn tap_sees_output_resizes_and_end() {
        let (sink, mut events) =
            tokio::sync::mpsc::unbounded_channel::<(SessionId, SessionEvent)>();
        let manager = SessionManager::new(sink);
        let (transport, mut remote) = MockTransport::pair();
        let handle = manager
            .open(SessionSpec::Mock(MockSpec::new(Box::new(transport))))
            .unwrap();
        let log = Arc::new(Log::default());
        handle
            .cmd_tx
            .send(SessionCmd::AttachShareTap(ShareTap::new(log.clone())))
            .await
            .unwrap();
        wait_for(&log, "size:80x24").await;
        remote.send(b"hello").await.unwrap();
        wait_for(&log, "out:hello").await;
        handle
            .cmd_tx
            .send(SessionCmd::Resize {
                cols: 100,
                rows: 30,
                px_w: 0,
                px_h: 0,
            })
            .await
            .unwrap();
        wait_for(&log, "size:100x30").await;
        // The output reached the emulator before the tap saw it.
        assert!(
            handle
                .term
                .lock()
                .snapshot_vt()
                .windows(5)
                .any(|w| w == b"hello")
        );
        handle
            .cmd_tx
            .send(SessionCmd::Input(Bytes::from_static(b"x")))
            .await
            .unwrap();
        remote.finish(Some(0));
        wait_for(&log, "ended").await;
        // Detached: nothing after the end.
        let n = log.0.lock().len();
        assert_eq!(log.0.lock().last().unwrap(), "ended");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(log.0.lock().len(), n);
        while events.try_recv().is_ok() {}
    }
}
