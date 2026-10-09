//! The session service. Executes `Effect::OpenSession`, `SendToSession` and
//! `CloseSession` through the [`SessionManager`] (sverb-conn), and adapts the manager's
//! events to the loop's session channel ([`NoticeSink`]).
//!
//! # Backpressure
//! The UI never waits on a session: commands go through a per-session [`UiSender`]
//! (`try_send` only). Input bytes that don't fit wait in an ordered overflow queue and
//! are never dropped; once the overflow exceeds [`OVERFLOW_WARN_BYTES`] the session
//! reports an error (a toast). Other commands are dropped with a warning when the
//! queue is full (see `runtime::sessions` for the whole contract).
//!
//! # Keys and pastes
//! Terminal-mode keys arrive as `SessionInput::Key(KeyChord)` and go to the
//! session as `SessionCmd::Key(KeyInput)`; pastes as `SessionCmd::Paste`. The session
//! actor encodes them with **its own** emulator's modes (DECCKM, DECKPAM,
//! modifyOtherKeys, remote kitty flags, bracketed paste: `sverb_term` input encoding),
//! so broadcast targets each get their own encoding (SPEC §9.8).
//!
//! # Panics in session tasks
//! [`in_contained_task`] is re-exported for the binary's panic hook: a panic inside a
//! session actor is contained by the manager, so the hook must not restore the
//! terminal for it.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use sverb_conn::{
    EventSink, OVERFLOW_WARN_BYTES, OpenOptions, SendOutcome, SessionCmd, SessionEvent,
    SessionManager, SessionRegistry, SessionSpec, SessionState, UiSender,
};
use sverb_conn::{LocalConnector, LocalOptions, TransportKind};
use sverb_core::error_report::ErrorReport;
use tracing::{debug, warn};

pub use sverb_conn::panic_scope::in_contained_task;

use crate::{
    app::{SessionId, SessionInput, UiEvent},
    runtime::sessions::{SessionNotice, SessionSender},
};

fn conn_id(id: SessionId) -> sverb_conn::SessionId {
    sverb_conn::SessionId(id.0)
}

fn ui_id(id: sverb_conn::SessionId) -> SessionId {
    SessionId(id.0)
}

/// Turns the manager's events into [`SessionNotice`]s on the loop's session channel:
/// `Dirty` → `Dirty`, `State(Closed)` → `Event` then `Closed`, everything else →
/// `Event`.
#[derive(Debug, Clone)]
pub struct NoticeSink(pub SessionSender);

impl EventSink for NoticeSink {
    fn send(&self, id: sverb_conn::SessionId, ev: SessionEvent) {
        let id = ui_id(id);
        // A closed channel means the UI is shutting down.
        let _ = match ev {
            SessionEvent::Dirty => self.0.send(SessionNotice::Dirty(id)),
            SessionEvent::State(SessionState::Closed) => {
                let _ = self.0.send(SessionNotice::Event(id, ev));
                self.0.send(SessionNotice::Closed(id))
            }
            ev => self.0.send(SessionNotice::Event(id, ev)),
        };
    }
}

/// The reducer event for a session event (`Dirty` never gets here: the loop's dirty
/// tracker handles it).
pub(crate) fn to_ui_event(id: SessionId, ev: SessionEvent) -> Option<UiEvent> {
    Some(UiEvent::Session(id, ev))
}

/// Executes session effects. Owned by [`Services`](super::Services).
#[derive(Debug)]
pub struct SessionService {
    manager: SessionManager,
    notices: SessionSender,
    senders: HashMap<SessionId, UiSender>,
    overflow_warned: HashSet<SessionId>,
}

impl SessionService {
    /// A service whose sessions report on `notices` (the loop's session channel).
    pub fn new(notices: SessionSender) -> Self {
        let service = Self {
            manager: SessionManager::new(NoticeSink(notices.clone())),
            notices,
            senders: HashMap::new(),
            overflow_warned: HashSet::new(),
        };
        // Local shells (`leader t`), with default options until the runtime
        // passes `[terminal]`.
        service.set_local_options(LocalOptions::default());
        // SSH with the default config and no vault (unsaved targets only) until
        // the runtime registers the real one.
        service.set_ssh_connector(super::ssh::ssh_connector(None, Arc::default()));
        service
    }

    /// Options for local shells opened from now on (`terminal.term`).
    pub fn set_local_options(&self, opts: LocalOptions) {
        self.manager
            .register_connector(TransportKind::Local, Arc::new(LocalConnector::new(opts)));
    }

    /// Use `connector` for SSH sessions opened from now on.
    pub fn set_ssh_connector(&self, connector: sverb_conn::SshConnector) {
        self.manager
            .register_connector(TransportKind::Ssh, Arc::new(connector));
    }

    /// The manager (register connectors; `shutdown` on quit).
    pub fn manager(&self) -> &SessionManager {
        &self.manager
    }

    /// The read-only view for rendering.
    pub fn registry(&self) -> SessionRegistry {
        self.manager.registry()
    }

    fn notify_error(&self, id: SessionId, msg: impl Into<String>) {
        let _ = self.notices.send(SessionNotice::Event(
            id,
            SessionEvent::Error(ErrorReport::msg(msg)),
        ));
    }

    /// `Effect::OpenSession`.
    pub fn open(&mut self, id: SessionId, spec: SessionSpec, cols: u16, rows: u16) {
        let mut opts = OpenOptions {
            id: Some(conn_id(id)),
            cols,
            rows,
            ..OpenOptions::default()
        };
        // The host's `backspace` for the key encoder.
        if let SessionSpec::Ssh(ssh) = &spec
            && let Some(backspace) = ssh.backspace
        {
            opts.encode.backspace = backspace.into();
        }
        match self.manager.open_with(spec, opts) {
            Ok(handle) => {
                let _ = self.notices.send(SessionNotice::Opened {
                    id,
                    dirty: handle.dirty,
                });
                self.senders
                    .insert(id, UiSender::new(handle.id, handle.cmd_tx));
            }
            Err(err) => {
                warn!(session = id.0, %err, "cannot open session");
                self.notify_error(id, format!("cannot open session: {err}"));
            }
        }
    }

    /// A standalone port-forward tunnel (SPEC §9.6): SSH without a shell channel and
    /// without a tab. It is reachable like other sessions (host-key and auth answers,
    /// reconnect, close), but the runtime gets no `Opened` notice (nothing to draw).
    /// Returns whether it opened.
    pub fn open_tunnel(&mut self, id: SessionId, spec: SessionSpec) -> bool {
        let opts = OpenOptions {
            id: Some(conn_id(id)),
            tunnel_only: true,
            ..OpenOptions::default()
        };
        match self.manager.open_with(spec, opts) {
            Ok(handle) => {
                self.senders
                    .insert(id, UiSender::new(handle.id, handle.cmd_tx));
                true
            }
            Err(err) => {
                warn!(session = id.0, %err, "cannot open the tunnel");
                self.notify_error(id, format!("cannot open the tunnel: {err}"));
                false
            }
        }
    }

    /// `Effect::SendToSession`.
    pub fn send(&mut self, id: SessionId, input: SessionInput) {
        let Some(sender) = self.senders.get(&id) else {
            debug!(session = id.0, "input for an unknown session dropped");
            return;
        };
        // The actor encodes with its own emulator's modes (per pane, SPEC §9.8);
        // keys and pastes share the ordered, never-dropped input queue.
        let cmd = match input {
            SessionInput::Key(chord) => match chord.to_key_input() {
                Some(key) => SessionCmd::Key(key),
                None => {
                    debug!(session = id.0, "key has no encoding");
                    return;
                }
            },
            SessionInput::Paste(text) => SessionCmd::Paste {
                text,
                confirm_multiline: true,
            },
            SessionInput::PasteUnchecked(text) => SessionCmd::Paste {
                text,
                confirm_multiline: false,
            },
            // Pane-relative mouse events (the actor routes them).
            SessionInput::Mouse(ev) => SessionCmd::Mouse(ev),
            // A snippet's Paste & execute lines, typed as is.
            SessionInput::Raw(bytes) => SessionCmd::Input(sverb_conn::Bytes::from(bytes)),
        };
        match sender.send_ordered(cmd) {
            SendOutcome::Sent => {
                self.overflow_warned.remove(&id);
            }
            SendOutcome::Overflowed { overflow_bytes } => {
                if overflow_bytes > OVERFLOW_WARN_BYTES && self.overflow_warned.insert(id) {
                    self.notify_error(id, "input queue full: the session is not reading input");
                }
            }
            SendOutcome::Dropped => {}
            SendOutcome::Closed => {
                self.senders.remove(&id);
            }
        }
    }

    /// Any other command (resize, recording, prompt answers): `try_send`, dropped with
    /// a warning when the queue is full.
    pub fn command(&mut self, id: SessionId, cmd: SessionCmd) -> SendOutcome {
        match self.senders.get(&id) {
            Some(sender) => sender.send_cmd(cmd),
            None => SendOutcome::Closed,
        }
    }

    /// Deliver `ev` as if session `id` had sent it (the recording service reports
    /// `SessionEvent::Recording` this way, in order with the session's own events).
    pub fn notify(&self, id: SessionId, ev: SessionEvent) {
        let _ = self.notices.send(SessionNotice::Event(id, ev));
    }

    /// [`SessionService::notify`] for a background task.
    pub fn clone_notifier(&self) -> impl Fn(SessionId, SessionEvent) + Send + 'static {
        let notices = self.notices.clone();
        move |id, ev| {
            let _ = notices.send(SessionNotice::Event(id, ev));
        }
    }

    /// `Effect::ResizeSession`: `SessionCmd::Resize` with the pane's pixel size from the
    /// outer terminal's cell size (0 when unknown). Dropped when the queue is full (the
    /// next resize supersedes it).
    pub fn resize(&mut self, id: SessionId, cols: u16, rows: u16) {
        let cell = crate::widgets::terminal_pane::cell_pixel_size();
        let (px_w, px_h) = crate::widgets::terminal_pane::pane_pixel_size(cols, rows, cell);
        let cmd = SessionCmd::Resize {
            cols,
            rows,
            px_w: u16::try_from(px_w).unwrap_or(u16::MAX),
            px_h: u16::try_from(px_h).unwrap_or(u16::MAX),
        };
        if self.command(id, cmd) == SendOutcome::Dropped {
            warn!(session = id.0, "resize dropped: session queue full");
        }
    }

    /// `Effect::CloseSession`.
    pub fn close(&mut self, id: SessionId) {
        self.senders.remove(&id);
        self.overflow_warned.remove(&id);
        if !self.manager.close(conn_id(id)) {
            // Already gone (e.g. crashed): let the UI forget it too.
            let _ = self.notices.send(SessionNotice::Closed(id));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use super::*;
    use crate::runtime::sessions;

    use crate::keymap::chord::KeyChord;

    fn key(s: &str) -> KeyChord {
        s.parse().unwrap()
    }

    /// The service opens a session, routes input and close, and translates events.
    #[tokio::test]
    async fn open_send_close() {
        let (tx, mut rx) = sessions::channel();
        let mut svc = SessionService::new(tx);
        let id = SessionId(7);
        // A shell that can't start: it opens and then disconnects.
        let broken = sverb_conn::LocalSpec {
            shell: Some("/nonexistent/sverb-no-such-shell".to_owned()),
            ..sverb_conn::LocalSpec::default()
        };
        svc.open(id, SessionSpec::Local(broken.clone()), 80, 24);
        let mut saw_opened = false;
        let mut saw_disconnect = false;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !(saw_opened && saw_disconnect) {
                match rx.recv().await.unwrap() {
                    SessionNotice::Opened { id: got, .. } => {
                        assert_eq!(got, id);
                        saw_opened = true;
                    }
                    SessionNotice::Event(
                        got,
                        SessionEvent::State(SessionState::Disconnected { .. }),
                    ) => {
                        assert_eq!(got, id);
                        saw_disconnect = true;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        // Same id again is refused with an error event.
        svc.open(id, SessionSpec::Local(broken), 80, 24);
        svc.send(id, SessionInput::Key(key("a")));
        svc.close(id);
        let mut saw_error = false;
        let mut saw_closed = false;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !(saw_error && saw_closed) {
                match rx.recv().await.unwrap() {
                    SessionNotice::Event(_, SessionEvent::Error(_)) => saw_error = true,
                    SessionNotice::Closed(got) => {
                        assert_eq!(got, id);
                        saw_closed = true;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        let report = svc.manager().shutdown(Duration::from_secs(1)).await;
        assert_eq!(report.aborted, 0);
    }
}
