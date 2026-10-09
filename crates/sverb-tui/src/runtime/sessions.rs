//! The session → UI seam and dirty tracking (SPEC §2.1).
//!
//!
//! **Session → UI** ([`SessionNotice`]; The session manager's events arrive as
//! `SessionNotice::Dirty` and `SessionNotice::Event`, translated by
//! `services::sessions::NoticeSink`): an **unbounded** `mpsc`, kept small by coalescing.
//! - Each session owns an `Arc<AtomicBool>` dirty flag, shared with the UI through
//!   [`SessionNotice::Opened`] (the `SessionRegistry`).
//! - After feeding output into its emulator, the session does
//!   `if !dirty.swap(true, AcqRel) { send(Dirty(id)) }`, so there is **at most one
//!   outstanding `Dirty` per session** until the UI acknowledges it. A flood of
//!   output produces one event per rendered frame, not thousands.
//! - The UI acknowledges with `dirty.store(false, Release)` for every session whose pane
//!   is part of the frame it is about to draw ([`DirtyTracker::ack_visible`]). It does
//!   so right **before** drawing, so output that arrives while the frame is being drawn
//!   sends a fresh `Dirty` instead of being lost. A hidden pane is never acknowledged:
//!   its flag stays `true`, it sends nothing more, and it is drawn (and re-armed) as
//!   soon as it becomes visible, because the focus/layout change sets `needs_redraw`.
//! - Other session events (title, bell, state, prompts) are rare and not coalesced.
//! - A session never waits for the UI: it keeps parsing while the UI is behind, and SSH
//!   flow control is never blocked on rendering.
//!
//! **UI → session** (`SessionCmd`, bounded, capacity 256): the UI never `await`s a
//! session's command channel, because the session may be blocked on the UI. It uses
//! `try_send` only. On a full queue:
//! - `Resize` is dropped (a later one supersedes it) with a `warn!`,
//! - `Input` bytes are **never dropped**: they go to a per-session overflow queue that
//!   is retried on the next loop iteration, and the pane shows "input queue full",
//!   which is a bug indicator, not a normal state.
//!
//! **Terminal input** has its own bounded channel (see [`super::input`]) with the
//! highest priority in the loop, and all queued input is applied before each frame,
//! so output floods can delay a keystroke by at most one frame.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::mpsc;

use crate::app::SessionId;

/// A notification from a session to the UI loop. `Opened`, `Dirty` and `Closed`
/// drive the [`DirtyTracker`]; `Event` goes to the reducer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionNotice {
    /// A session exists; `dirty` is its coalescing flag.
    Opened {
        /// The session.
        id: SessionId,
        /// Set by the session when it has undrawn output; cleared by the UI.
        dirty: Arc<AtomicBool>,
    },
    /// The session has undrawn output (at most one outstanding per session).
    Dirty(SessionId),
    /// The session is gone.
    Closed(SessionId),
    /// Any other session event (title, bell, state, prompts, errors), for the reducer.
    Event(SessionId, sverb_conn::SessionEvent),
}

/// Sender half of the session channel (unbounded, coalesced: see the module docs).
pub type SessionSender = mpsc::UnboundedSender<SessionNotice>;

/// Receiver half of the session channel.
pub type SessionReceiver = mpsc::UnboundedReceiver<SessionNotice>;

/// A new session channel.
pub fn channel() -> (SessionSender, SessionReceiver) {
    mpsc::unbounded_channel()
}

/// The loop's view of session dirty flags.
#[derive(Debug, Default)]
pub struct DirtyTracker {
    flags: HashMap<SessionId, Arc<AtomicBool>>,
    /// Visible sessions with undrawn output.
    pending: BTreeSet<SessionId>,
}

impl DirtyTracker {
    /// No sessions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a notice. `visible` are the sessions whose panes the next frame draws.
    pub fn on_notice(&mut self, notice: SessionNotice, visible: &[SessionId]) {
        match notice {
            SessionNotice::Opened { id, dirty } => {
                if dirty.load(Ordering::Acquire) && visible.contains(&id) {
                    self.pending.insert(id);
                }
                self.flags.insert(id, dirty);
            }
            SessionNotice::Dirty(id) => {
                // Hidden panes don't schedule frames; their flag stays set until shown.
                if visible.contains(&id) {
                    self.pending.insert(id);
                }
            }
            SessionNotice::Closed(id) => {
                self.flags.remove(&id);
                self.pending.remove(&id);
            }
            // Routed to the reducer by the loop, not dirty tracking.
            SessionNotice::Event(..) => {}
        }
    }

    /// Whether a visible session has undrawn output.
    pub fn any_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Acknowledge every visible session (its pane is in the frame about to be drawn).
    /// Hidden sessions keep their flag.
    pub fn ack_visible(&mut self, visible: &[SessionId]) {
        self.pending.clear();
        for id in visible {
            if let Some(flag) = self.flags.get(id) {
                flag.store(false, Ordering::Release);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_dirty_neither_schedules_nor_acks() {
        let mut t = DirtyTracker::new();
        let a = SessionId(1);
        let b = SessionId(2);
        let fa = Arc::new(AtomicBool::new(false));
        let fb = Arc::new(AtomicBool::new(false));
        t.on_notice(
            SessionNotice::Opened {
                id: a,
                dirty: Arc::clone(&fa),
            },
            &[a],
        );
        t.on_notice(
            SessionNotice::Opened {
                id: b,
                dirty: Arc::clone(&fb),
            },
            &[a],
        );
        fb.store(true, Ordering::Release);
        t.on_notice(SessionNotice::Dirty(b), &[a]);
        assert!(!t.any_pending());
        fa.store(true, Ordering::Release);
        t.on_notice(SessionNotice::Dirty(a), &[a]);
        assert!(t.any_pending());
        t.ack_visible(&[a]);
        assert!(!t.any_pending());
        assert!(!fa.load(Ordering::Acquire));
        assert!(fb.load(Ordering::Acquire));
        t.on_notice(SessionNotice::Closed(b), &[a]);
    }
}
