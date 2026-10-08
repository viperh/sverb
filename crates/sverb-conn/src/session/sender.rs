//! [`UiSender`]: how the UI sends commands to a session without ever waiting
//! (SPEC §2.1, M0-09 backpressure contract).
//!
//! The UI only uses `try_send`. When the bounded queue (capacity 256) is full:
//! - **input bytes are never dropped**: they go to a per-session overflow queue, in
//!   order, which a small drainer task feeds into the channel as the actor makes room.
//!   While the overflow is non-empty, new input is appended to it, so ordering holds.
//!   The UI shows an error once the overflow exceeds [`OVERFLOW_WARN_BYTES`];
//! - other commands are dropped with a `warn!` (a later `Resize` supersedes the
//!   dropped one; `Close` goes through the manager, which falls back to cancelling).

use std::{collections::VecDeque, fmt, sync::Arc};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::warn;

use super::{SessionCmd, SessionId};

/// Overflow size above which the UI shows an error toast (1 MiB).
pub const OVERFLOW_WARN_BYTES: usize = 1024 * 1024;

/// What happened to a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Queued in the session's channel.
    Sent,
    /// The channel was full; the input waits in the overflow queue, which now holds
    /// `overflow_bytes` bytes.
    Overflowed {
        /// Bytes waiting in the overflow queue.
        overflow_bytes: usize,
    },
    /// The channel was full and the (non-input) command was dropped.
    Dropped,
    /// The session is gone.
    Closed,
}

#[derive(Default)]
struct Overflow {
    // M1-11: input commands (`Input`, `Key`, `Paste`), in order.
    queue: VecDeque<SessionCmd>,
    bytes: usize,
    draining: bool,
}

/// The UI's sender for one session. Cheap to clone.
#[derive(Clone)]
pub struct UiSender {
    id: SessionId,
    tx: mpsc::Sender<SessionCmd>,
    overflow: Arc<Mutex<Overflow>>,
}

impl fmt::Debug for UiSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UiSender")
            .field("id", &self.id)
            .field("overflow_bytes", &self.overflow_bytes())
            .finish_non_exhaustive()
    }
}

impl UiSender {
    /// Wrap a session's command sender.
    pub fn new(id: SessionId, tx: mpsc::Sender<SessionCmd>) -> Self {
        Self {
            id,
            tx,
            overflow: Arc::new(Mutex::new(Overflow::default())),
        }
    }

    /// Bytes waiting in the overflow queue.
    pub fn overflow_bytes(&self) -> usize {
        self.overflow.lock().bytes
    }

    /// Send input bytes; never drops them while the session lives. Must be called
    /// inside a tokio runtime (the overflow drainer is a task).
    pub fn send_input(&self, bytes: Bytes) -> SendOutcome {
        if bytes.is_empty() {
            return SendOutcome::Sent;
        }
        self.send_ordered(SessionCmd::Input(bytes))
    }

    // M1-11
    /// Send an input command (`Input`, `Key`, `Paste`): never dropped while the session
    /// lives, and kept in order with other input. Must be called inside a tokio runtime.
    pub fn send_ordered(&self, cmd: SessionCmd) -> SendOutcome {
        let mut overflow = self.overflow.lock();
        if overflow.queue.is_empty() {
            match self.tx.try_send(cmd) {
                Ok(()) => return SendOutcome::Sent,
                Err(TrySendError::Closed(_)) => return SendOutcome::Closed,
                Err(TrySendError::Full(cmd)) => {
                    warn!(session = %self.id, "session input queue full; buffering input");
                    overflow.bytes += input_size(&cmd);
                    overflow.queue.push_back(cmd);
                }
            }
        } else {
            overflow.bytes += input_size(&cmd);
            overflow.queue.push_back(cmd);
        }
        if !overflow.draining {
            overflow.draining = true;
            tokio::spawn(drain(self.tx.clone(), Arc::clone(&self.overflow)));
        }
        SendOutcome::Overflowed {
            overflow_bytes: overflow.bytes,
        }
    }

    /// Send any other command with `try_send`; dropped (with a warning) when full.
    pub fn send_cmd(&self, cmd: SessionCmd) -> SendOutcome {
        // M1-11: keys and pastes are input too.
        if matches!(
            cmd,
            SessionCmd::Input(_)
                | SessionCmd::Key(_)
                | SessionCmd::Paste { .. }
                | SessionCmd::Mouse(_)
        ) {
            return self.send_ordered(cmd);
        }
        match self.tx.try_send(cmd) {
            Ok(()) => SendOutcome::Sent,
            Err(TrySendError::Full(cmd)) => {
                warn!(session = %self.id, cmd = cmd.name(), "session queue full; command dropped");
                SendOutcome::Dropped
            }
            Err(TrySendError::Closed(_)) => SendOutcome::Closed,
        }
    }
}

/// Move the overflow into the channel as room appears, in order.
async fn drain(tx: mpsc::Sender<SessionCmd>, overflow: Arc<Mutex<Overflow>>) {
    loop {
        let Ok(permit) = tx.reserve().await else {
            let mut o = overflow.lock();
            o.queue.clear();
            o.bytes = 0;
            o.draining = false;
            return;
        };
        let mut o = overflow.lock();
        let Some(cmd) = o.queue.pop_front() else {
            o.draining = false;
            return;
        };
        o.bytes -= input_size(&cmd);
        // Sent while holding the lock: new input can't overtake it.
        permit.send(cmd);
    }
}

// M1-11
/// Bytes an input command accounts for in the overflow (a key counts as one).
fn input_size(cmd: &SessionCmd) -> usize {
    match cmd {
        SessionCmd::Input(bytes) => bytes.len(),
        SessionCmd::Paste { text, .. } => text.len(),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use super::*;
    use crate::{
        manager::SessionManager,
        mock::MockTransport,
        session::{CMD_CAPACITY, MockSpec, SessionEvent, SessionSpec, SessionState},
    };

    /// T-07: with the actor not running (current-thread runtime, no yield), 256
    /// commands fill the queue, `try_send` reports Full, the rest of the input waits in
    /// the overflow, and everything arrives in order once the actor runs.
    #[tokio::test]
    async fn t07_command_channel_capacity_and_overflow() {
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let mgr = SessionManager::new(ev_tx);
        let (transport, mut remote) = MockTransport::pair();
        let h = mgr
            .open(SessionSpec::Mock(MockSpec::new(transport.boxed())))
            .unwrap();
        // Let it connect, so it is parked in its select loop.
        loop {
            let (_, ev) = ev_rx.recv().await.unwrap();
            if matches!(ev, SessionEvent::State(SessionState::Connected { .. })) {
                break;
            }
        }
        let sender = UiSender::new(h.id, h.cmd_tx.clone());
        let mut expected = Vec::new();
        let mut outcomes = Vec::new();
        for i in 0..300_u32 {
            let msg = format!("<{i}>");
            expected.extend_from_slice(msg.as_bytes());
            outcomes.push(sender.send_input(Bytes::from(msg)));
        }
        assert!(
            outcomes[..CMD_CAPACITY]
                .iter()
                .all(|o| *o == SendOutcome::Sent)
        );
        assert!(
            outcomes[CMD_CAPACITY..]
                .iter()
                .all(|o| matches!(o, SendOutcome::Overflowed { .. }))
        );
        assert!(matches!(
            h.cmd_tx.try_send(SessionCmd::StartRecording),
            Err(TrySendError::Full(_))
        ));
        assert_eq!(
            sender.send_cmd(SessionCmd::StopRecording),
            SendOutcome::Dropped
        );
        let overflow: usize = (CMD_CAPACITY..300).map(|i| format!("<{i}>").len()).sum();
        assert_eq!(sender.overflow_bytes(), overflow);

        // The actor resumes.
        let got =
            tokio::time::timeout(Duration::from_secs(10), remote.read_written(expected.len()))
                .await
                .unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            String::from_utf8(expected).unwrap()
        );
        assert_eq!(sender.overflow_bytes(), 0);
        assert_eq!(
            sender.send_input(Bytes::from_static(b"!")),
            SendOutcome::Sent
        );
    }

    #[tokio::test]
    async fn closed_session_reports_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let sender = UiSender::new(SessionId(1), tx);
        assert_eq!(
            sender.send_input(Bytes::from_static(b"x")),
            SendOutcome::Closed
        );
        assert_eq!(sender.send_cmd(SessionCmd::Close), SendOutcome::Closed);
    }
}
