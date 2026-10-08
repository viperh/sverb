//! The [`Transport`] trait (SPEC §6): what the session actor reads from and writes to.
//!
//! Implementations: SSH (M1-13), local PTY (M1-12), and `MockTransport`
//! (in-memory duplex, `test-util` feature) for tests.
//!
//! A [`Connector`] turns a [`SessionSpec`] into a transport, driving
//! the state machine through a [`ConnectCtx`] on the way (resolving, hops, host-key and
//! auth prompts). The [`SessionManager`](crate::SessionManager) picks the connector by
//! [`TransportKind`].

use std::{io, sync::Arc, time::Instant};

use async_trait::async_trait;
use sverb_core::error_report::ErrorReport;
use tokio::{io::AsyncRead, sync::mpsc};

use crate::session::{
    DisconnectReason, EventSink, SessionCmd, SessionEvent, SessionId, SessionSpec, SessionState,
    StateInput,
};

/// What is underneath a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// SSH (russh).
    Ssh,
    /// Local PTY.
    Local,
    /// In-memory, for tests.
    Mock,
}

/// A byte stream to a remote shell or a local PTY (SPEC §6).
#[async_trait]
pub trait Transport: Send {
    /// Write bytes to the remote side.
    async fn write(&mut self, data: &[u8]) -> io::Result<()>;

    /// Tell the remote side the terminal size changed.
    async fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;

    /// The output stream. Reads must be cancel-safe (the actor `select!`s on them).
    /// `Ok(0)` means the remote side closed.
    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send);

    /// Close gracefully.
    async fn close(&mut self) -> io::Result<()>;

    /// What this is.
    fn kind(&self) -> TransportKind;

    /// M1-08: the remote process's exit status, asked after the reader hit EOF.
    /// `None` means the connection closed without one. Not in SPEC §6's listing;
    /// provided so the default keeps the required methods exactly as specified.
    async fn exit_status(&mut self) -> Option<i32> {
        None
    }
}

/// Why connecting failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    /// The user-facing reason (SPEC §6.1.9).
    pub reason: DisconnectReason,
    /// Details for the toast / detail view, if any.
    pub report: Option<ErrorReport>,
}

impl ConnectError {
    /// An error with a reason and no details.
    pub fn new(reason: DisconnectReason) -> Self {
        Self {
            reason,
            report: None,
        }
    }

    /// An error with a reason and a report.
    pub fn with_report(reason: DisconnectReason, report: ErrorReport) -> Self {
        Self {
            reason,
            report: Some(report),
        }
    }

    /// The session was closed by the user while connecting.
    pub fn closed() -> Self {
        Self::new(DisconnectReason::Closed)
    }
}

// M1-13
/// A transport failure with a specific [`DisconnectReason`] (e.g. `Timeout` when the
/// SSH keepalive gave up), carried inside the `io::Error` a transport returns from a
/// read or write. The actor uses `reason` and `report` instead of the generic
/// `Connect`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", report.short)]
pub struct TransportFailure {
    /// The user-facing reason.
    pub reason: DisconnectReason,
    /// The message and detail chain.
    pub report: ErrorReport,
}

// M1-13
impl TransportFailure {
    /// A failure with `reason` and `report`.
    pub fn new(reason: DisconnectReason, report: ErrorReport) -> Self {
        Self { reason, report }
    }

    /// Wrap into an `io::Error` (kind `Other`).
    pub fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// The failure inside `err`, if it carries one.
    pub fn from_io(err: &io::Error) -> Option<&Self> {
        err.get_ref().and_then(|e| e.downcast_ref::<Self>())
    }
}

// M1-13
/// A `'static` handle to emit [`SessionEvent`]s for one session from a background
/// task (the SSH latency pinger). Cheap to clone.
#[derive(Clone)]
pub struct SessionEmitter {
    id: SessionId,
    sink: Arc<dyn EventSink>,
}

// M1-13
impl SessionEmitter {
    /// An emitter for session `id` over `sink`.
    pub fn new(id: SessionId, sink: Arc<dyn EventSink>) -> Self {
        Self { id, sink }
    }

    /// The session.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Emit `ev`.
    pub fn emit(&self, ev: SessionEvent) {
        self.sink.send(self.id, ev);
    }
}

// M1-13
impl std::fmt::Debug for SessionEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEmitter")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Builds transports for one [`TransportKind`] (M1-12: local PTY, M1-13: SSH).
#[async_trait]
pub trait Connector: Send + Sync {
    /// Connect `spec` and return the open transport.
    ///
    /// Report progress with [`ConnectCtx::input`] (`Resolved`, `TcpConnected`,
    /// `HostKeyNeeded`, `AuthStarted`, …). Do **not** send `ChannelOpened`: the actor
    /// does that once this returns `Ok`. When an input is illegal, `ctx.input` returns
    /// an error with reason `Internal`; return it. Wait for user decisions with
    /// [`ConnectCtx::next_cmd`]; it returns `None` when the user closed the session,
    /// in which case return [`ConnectError::closed`].
    async fn connect(
        &self,
        spec: &SessionSpec,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError>;
}

/// What a [`Connector`] can do while connecting: move the state machine, emit events,
/// and wait for the user's answers.
pub struct ConnectCtx<'a> {
    pub(crate) id: SessionId,
    pub(crate) state: &'a mut SessionState,
    pub(crate) sink: &'a dyn EventSink,
    pub(crate) cmd_rx: &'a mut mpsc::Receiver<SessionCmd>,
    pub(crate) size: (u16, u16),
    /// Commands that arrived while waiting for a decision but are meant for the
    /// connected session (input typed ahead, resizes). Replayed after connecting.
    pub(crate) deferred: &'a mut Vec<SessionCmd>,
    // M1-13: for [`ConnectCtx::emitter`].
    pub(crate) owned_sink: Arc<dyn EventSink>,
    // M2-08
    /// Told about the connection once it is up (port forwards ride on it).
    pub(crate) forwards: Option<Arc<dyn crate::forward::ForwardHook>>,
    /// Standalone tunnel: no shell channel (SSH stops after authentication).
    pub(crate) tunnel_only: bool,
}

impl std::fmt::Debug for ConnectCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectCtx")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl ConnectCtx<'_> {
    /// The session.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// The current state.
    pub fn state(&self) -> &SessionState {
        self.state
    }

    // M2-08
    /// A tunnel-only (standalone forwards) connection: no shell channel.
    pub fn tunnel_only(&self) -> bool {
        self.tunnel_only
    }

    /// The terminal size to request (cols, rows).
    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    /// Apply a state input and emit `State`. An illegal input is logged at `error`,
    /// the session moves to `Disconnected { Internal }`, and this returns that error.
    pub fn input(&mut self, input: StateInput) -> Result<(), ConnectError> {
        if apply_input(self.id, self.state, self.sink, input, Instant::now()) {
            Ok(())
        } else {
            Err(ConnectError::new(DisconnectReason::Internal))
        }
    }

    // M1-13
    /// A `'static` emitter for this session, for tasks that outlive the connect call
    /// (keepalive latency).
    pub fn emitter(&self) -> SessionEmitter {
        SessionEmitter::new(self.id, Arc::clone(&self.owned_sink))
    }

    /// Emit an event (`HostKey`, `Prompt`, `Error`, …).
    pub fn emit(&self, ev: SessionEvent) {
        self.sink.send(self.id, ev);
    }

    /// The next command relevant while connecting (`HostKeyDecision`, `AuthAnswer`).
    /// `Input` and `Resize` are deferred until connected (M3-05: so are
    /// `AttachRecorder` and `StopRecording`), and `Close` (or a dropped sender) returns
    /// `None`.
    pub async fn next_cmd(&mut self) -> Option<SessionCmd> {
        loop {
            match self.cmd_rx.recv().await? {
                SessionCmd::Close => {
                    // The command loop sees it again through the deferred list.
                    self.deferred.push(SessionCmd::Close);
                    return None;
                }
                cmd @ (SessionCmd::Input(_) | SessionCmd::Resize { .. }) => {
                    if let SessionCmd::Resize { cols, rows, .. } = cmd {
                        self.size = (cols, rows);
                    }
                    self.deferred.push(cmd);
                }
                cmd @ (SessionCmd::HostKeyDecision(_) | SessionCmd::AuthAnswer(_)) => {
                    return Some(cmd);
                }
                // M3-05: a recording started while connecting begins once connected.
                cmd @ (SessionCmd::AttachRecorder(_) | SessionCmd::StopRecording) => {
                    self.deferred.push(cmd);
                }
                other => {
                    tracing::debug!(session = %self.id, cmd = other.name(), "ignored while connecting")
                }
            }
        }
    }
}

/// Apply `input` to `state`, emit the new state, and return whether it was legal.
/// An illegal input is logged at `error` and moves to `Disconnected { Internal }`
/// (SPEC §2.1.1).
pub(crate) fn apply_input(
    id: SessionId,
    state: &mut SessionState,
    sink: &dyn EventSink,
    input: StateInput,
    now: Instant,
) -> bool {
    match state.transition(input, now) {
        Ok(next) => {
            *state = next;
            sink.send(id, SessionEvent::State(state.clone()));
            true
        }
        Err(err) => {
            tracing::error!(session = %id, %err, "illegal session state transition");
            if !state.is_closed() {
                *state = SessionState::Disconnected {
                    reason: DisconnectReason::Internal,
                    at: now,
                };
                sink.send(id, SessionEvent::State(state.clone()));
            }
            false
        }
    }
}
