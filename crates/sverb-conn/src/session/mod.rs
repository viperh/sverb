//! Sessions (SPEC §2.1): one actor task per session, owning its transport and its
//! terminal emulator.
//!
//! - [`cmd`]: [`SessionCmd`], UI → session (bounded, capacity 256),
//! - [`event`]: [`SessionEvent`], session → UI (unbounded, coalesced) through an
//!   [`EventSink`],
//! - [`state`]: the state machine (SPEC §2.1.1),
//! - [`actor`]: the actor itself (read loop, command loop, dirty coalescing).
//!
//! The [`SessionManager`](crate::SessionManager) spawns actors and contains their panics.

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use parking_lot::Mutex;
use sverb_term::Emulator;
use tokio::sync::mpsc;

use crate::transport::{Transport, TransportKind};

pub mod actor;
pub mod cmd;
pub mod event;
pub mod sender;
// Output observers for terminal sharing.
pub mod share_tap;
pub mod state;

#[cfg(test)]
mod tests;

pub use cmd::{AuthAnswer, CMD_CAPACITY, Decision, SessionCmd};
pub use event::SshSessionInfo;
pub use event::{MAX_TITLE_CHARS, SessionEvent, sanitize_title};
pub use sender::{OVERFLOW_WARN_BYTES, SendOutcome, UiSender};
pub use share_tap::{OutputObserver, ShareTap};
pub use state::PromptKind;
pub use state::{
    AuthMethod, AuthPrompt, DisconnectReason, HostKeyDetails, IllegalTransition, PromptLine,
    SessionState, StateInput, Verification,
};

/// Identifies a session for its whole life (reconnects keep the id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// The shared emulator. Locked by the actor for at most one 64 KiB chunk and by the
/// renderer for one draw; never across an `.await`.
pub type SharedEmulator = Arc<Mutex<Box<dyn Emulator>>>;

/// Where session events go. The UI implements it over its own channel; the plain
/// `(SessionId, SessionEvent)` channel of SPEC §2.1 implements it too.
///
/// `send` is called from the actor task and must not block.
pub trait EventSink: Send + Sync + 'static {
    /// Deliver `ev` from session `id`. A closed receiver drops the event.
    fn send(&self, id: SessionId, ev: SessionEvent);
}

impl EventSink for mpsc::UnboundedSender<(SessionId, SessionEvent)> {
    fn send(&self, id: SessionId, ev: SessionEvent) {
        let _ = mpsc::UnboundedSender::send(self, (id, ev));
    }
}

/// What to open (SPEC §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionSpec {
    /// An SSH session.
    Ssh(SshSpec),
    /// A local terminal.
    Local(LocalSpec),
    Mock(MockSpec),
}

impl SessionSpec {
    /// Which connector handles this spec.
    pub fn kind(&self) -> TransportKind {
        match self {
            Self::Ssh(_) => TransportKind::Ssh,
            Self::Local(_) => TransportKind::Local,
            Self::Mock(_) => TransportKind::Mock,
        }
    }
}

/// What SSH target to open. The SSH connector resolves it into a
/// [`SshTarget`](crate::ssh::SshTarget) in the `Resolving` state, through its
/// [`HostResolver`](crate::ssh::HostResolver) (the saved host's settings, read fresh
/// on every connect and reconnect). An unsaved target (quick connect) resolves from
/// these fields and the global config alone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshSpec {
    /// Host name or address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name, if set.
    pub user: Option<String>,
    /// The saved host item (`None` for an unsaved target).
    pub host_id: Option<sverb_core::model::ItemId>,
    /// What the session is shown as (the host's label), if not `host`.
    pub label: Option<String>,
    /// The host's `backspace` setting, for the key encoder (`OpenOptions::encode`).
    pub backspace: Option<sverb_core::model::Backspace>,
}

/// A local terminal (SPEC §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalSpec {
    /// Working directory (default: the user's home).
    pub cwd: Option<PathBuf>,
    /// Shell (default: `$SHELL`, `/bin/sh`; `pwsh` or `ComSpec` on Windows).
    pub shell: Option<String>,
    /// Extra environment variables.
    pub env: Vec<(String, String)>,
}

/// A session over a transport that already exists. Taken once by the built-in mock
/// connector: a reconnect of a mock session fails with `Connect`.
#[derive(Clone)]
pub struct MockSpec {
    transport: Arc<Mutex<Option<Box<dyn Transport>>>>,
    /// State inputs the mock connector applies before opening the channel (to drive
    /// the state machine in tests). An illegal one fails the connection.
    pub script: Vec<StateInput>,
}

impl MockSpec {
    /// Wrap a transport.
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport: Arc::new(Mutex::new(Some(transport))),
            script: Vec::new(),
        }
    }

    /// Apply `script` before opening the channel.
    #[must_use]
    pub fn with_script(mut self, script: Vec<StateInput>) -> Self {
        self.script = script;
        self
    }

    /// Take the transport (once).
    pub fn take(&self) -> Option<Box<dyn Transport>> {
        self.transport.lock().take()
    }
}

impl PartialEq for MockSpec {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.transport, &other.transport) && self.script == other.script
    }
}

impl Eq for MockSpec {}

impl fmt::Debug for MockSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockSpec")
            .field("script", &self.script)
            .finish_non_exhaustive()
    }
}

/// What the opener of a session holds (SPEC §2.1).
#[derive(Clone)]
pub struct SessionHandle {
    /// The session.
    pub id: SessionId,
    /// Bounded command channel (capacity [`CMD_CAPACITY`]). The UI uses `try_send` only.
    pub cmd_tx: mpsc::Sender<SessionCmd>,
    /// The emulator, for rendering.
    pub term: SharedEmulator,
    /// Set by the session when it has undrawn output; cleared by the UI before drawing.
    pub dirty: Arc<AtomicBool>,
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}
