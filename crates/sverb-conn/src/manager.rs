//! The session manager (M1-08 §2.4): opens, tracks, closes and shuts down session
//! actors, and contains their panics.
//!
//! Each session is two tasks: the actor (wrapped in
//! [`Contained`]) and a small supervisor that awaits the
//! actor's `JoinHandle`. When the actor panics, the supervisor reports
//! `State(Disconnected { Internal })` and an error ("session crashed (see log)"); the
//! app keeps running. When the actor ends (normally or aborted by
//! [`SessionManager::shutdown`]) the supervisor removes the session.
//!
//! [`SessionRegistry`] is the read-only view the renderer uses (emulator and dirty flag
//! by id).

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use sverb_core::error_report::ErrorReport;
use sverb_term::{AlacrittyEmulator, DEFAULT_SCROLLBACK, Emulator, EmulatorConfig};
// M1-11
use sverb_term::modes::input::EncodeOpts;
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::{
    panic_scope::Contained,
    session::{
        CMD_CAPACITY, DisconnectReason, EventSink, SessionCmd, SessionEvent, SessionHandle,
        SessionId, SessionSpec, SessionState, SharedEmulator,
        actor::{Actor, READ_BUFFER},
    },
    transport::{ConnectCtx, ConnectError, Connector, Transport, TransportKind},
};
// M3-06
use crate::connlog::{AttemptEnd, AttemptOutcome, ConnLogSink, NoConnLog};
use sverb_core::model::UnixMillis;

/// Builds the emulator for a new session.
pub type EmulatorFactory = Arc<dyn Fn(EmulatorConfig) -> Box<dyn Emulator> + Send + Sync>;

/// Per-session options for [`SessionManager::open_with`].
pub struct OpenOptions {
    /// Use this id (the UI allocates ids so it can focus the pane at once). `None`
    /// lets the manager pick one.
    pub id: Option<SessionId>,
    /// Initial columns.
    pub cols: u16,
    /// Initial rows.
    pub rows: u16,
    /// Scrollback lines.
    pub scrollback: usize,
    /// Use this emulator instead of the factory's (tests).
    pub emulator: Option<Box<dyn Emulator>>,
    /// Transport read buffer size (default [`READ_BUFFER`]).
    pub read_buffer: usize,
    // M1-11
    /// Key encoding options (the host's `backspace`), used by `SessionCmd::Key`.
    pub encode: EncodeOpts,
    // M2-08
    /// A standalone tunnel (SPEC §9.6): SSH without a shell channel; the session only
    /// carries port forwards.
    pub tunnel_only: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            id: None,
            cols: 80,
            rows: 24,
            scrollback: DEFAULT_SCROLLBACK,
            emulator: None,
            read_buffer: READ_BUFFER,
            // M1-11
            encode: EncodeOpts::default(),
            // M2-08
            tunnel_only: false,
        }
    }
}

impl fmt::Debug for OpenOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenOptions")
            .field("id", &self.id)
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("scrollback", &self.scrollback)
            .field("read_buffer", &self.read_buffer)
            .field("encode", &self.encode)
            .field("tunnel_only", &self.tunnel_only)
            .finish_non_exhaustive()
    }
}

/// Why a session could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// The requested id belongs to a live session.
    #[error("session {0} already exists")]
    IdInUse(SessionId),
    /// Not called from inside a tokio runtime.
    #[error("no tokio runtime")]
    NoRuntime,
}

/// What [`SessionManager::shutdown`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShutdownReport {
    /// Sessions that closed in time.
    pub closed: usize,
    /// Sessions aborted after the timeout.
    pub aborted: usize,
}

struct Entry {
    handle: SessionHandle,
    cancel: CancellationToken,
    abort: AbortHandle,
    supervisor: Option<JoinHandle<()>>,
}

struct Sessions {
    map: HashMap<SessionId, Entry>,
    next_id: u64,
}

struct Inner {
    sink: Arc<dyn EventSink>,
    sessions: Mutex<Sessions>,
    connectors: Mutex<HashMap<TransportKind, Arc<dyn Connector>>>,
    factory: Mutex<EmulatorFactory>,
    // M3-06
    connlog: Mutex<Arc<dyn ConnLogSink>>,
    // M2-08
    forwards: Mutex<Option<Arc<dyn crate::forward::ForwardHook>>>,
}

/// Opens and tracks sessions. Cheap to clone (shared state).
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Inner>,
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("sessions", &self.ids())
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// A manager whose sessions report to `sink`. The mock connector is registered;
    /// M1-12 and M1-13 register the local and SSH connectors.
    pub fn new(sink: impl EventSink) -> Self {
        let mut connectors: HashMap<TransportKind, Arc<dyn Connector>> = HashMap::new();
        connectors.insert(TransportKind::Mock, Arc::new(MockConnector));
        let factory: EmulatorFactory =
            Arc::new(|config| Box::new(AlacrittyEmulator::new(config)) as Box<dyn Emulator>);
        Self {
            inner: Arc::new(Inner {
                sink: Arc::new(sink),
                sessions: Mutex::new(Sessions {
                    map: HashMap::new(),
                    next_id: 1,
                }),
                connectors: Mutex::new(connectors),
                factory: Mutex::new(factory),
                // M3-06
                connlog: Mutex::new(Arc::new(NoConnLog)),
                // M2-08
                forwards: Mutex::new(None),
            }),
        }
    }

    /// Use `connector` for sessions of `kind` (replaces a previous one).
    pub fn register_connector(&self, kind: TransportKind, connector: Arc<dyn Connector>) {
        self.inner.connectors.lock().insert(kind, connector);
    }

    // M3-06
    /// Report connection attempts of sessions opened from now on to `sink` (default:
    /// [`NoConnLog`]).
    pub fn set_connlog_sink(&self, sink: Arc<dyn ConnLogSink>) {
        *self.inner.connlog.lock() = sink;
    }

    // M2-08
    /// Report the connections of sessions opened from now on to `hook` (port
    /// forwards: auto-start, restart on reconnect, stop on connection loss).
    pub fn set_forward_hook(&self, hook: Arc<dyn crate::forward::ForwardHook>) {
        *self.inner.forwards.lock() = Some(hook);
    }

    /// Build emulators with `factory` (default: [`AlacrittyEmulator`]).
    pub fn set_emulator_factory(&self, factory: EmulatorFactory) {
        *self.inner.factory.lock() = factory;
    }

    /// Open a session with default options.
    pub fn open(&self, spec: SessionSpec) -> Result<SessionHandle, OpenError> {
        self.open_with(spec, OpenOptions::default())
    }

    /// Open a session. Spawns the actor; must be called inside a tokio runtime.
    pub fn open_with(
        &self,
        spec: SessionSpec,
        opts: OpenOptions,
    ) -> Result<SessionHandle, OpenError> {
        let rt = tokio::runtime::Handle::try_current().map_err(|_| OpenError::NoRuntime)?;
        let mut sessions = self.inner.sessions.lock();
        let id = match opts.id {
            Some(id) if sessions.map.contains_key(&id) => return Err(OpenError::IdInUse(id)),
            Some(id) => {
                sessions.next_id = sessions.next_id.max(id.0.saturating_add(1));
                id
            }
            None => loop {
                let id = SessionId(sessions.next_id);
                sessions.next_id = sessions.next_id.wrapping_add(1);
                if !sessions.map.contains_key(&id) {
                    break id;
                }
            },
        };

        let emulator = opts.emulator.unwrap_or_else(|| {
            let factory = self.inner.factory.lock().clone();
            factory(EmulatorConfig {
                cols: opts.cols,
                rows: opts.rows,
                scrollback: opts.scrollback,
            })
        });
        let term: SharedEmulator = Arc::new(Mutex::new(emulator));
        let dirty = Arc::new(AtomicBool::new(false));
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CAPACITY);
        let cancel = CancellationToken::new();
        let connector = self.inner.connectors.lock().get(&spec.kind()).cloned();
        // M3-06
        let connlog = Arc::clone(&*self.inner.connlog.lock());
        let handle = SessionHandle {
            id,
            cmd_tx,
            term: Arc::clone(&term),
            dirty: Arc::clone(&dirty),
        };
        let actor = Actor {
            id,
            spec,
            connector,
            term,
            dirty,
            cmd_rx,
            sink: Arc::clone(&self.inner.sink),
            cancel: cancel.clone(),
            read_buffer: opts.read_buffer,
            state: SessionState::Resolving,
            last_title: None,
            deferred: Vec::new(),
            // M1-11
            encode: opts.encode,
            // M3-05
            recorder: None,
            // M3-06
            connlog: Arc::clone(&connlog),
            attempt: None,
            // M2-08
            forwards: self.inner.forwards.lock().clone(),
            tunnel_only: opts.tunnel_only,
        };
        let task = rt.spawn(Contained::new(actor.run()));
        let abort = task.abort_handle();
        let supervisor = rt.spawn(supervise(
            id,
            task,
            Arc::clone(&self.inner.sink),
            Arc::downgrade(&self.inner),
            // M3-06
            connlog,
        ));
        sessions.map.insert(
            id,
            Entry {
                handle: handle.clone(),
                cancel,
                abort,
                supervisor: Some(supervisor),
            },
        );
        debug!(session = %id, "session opened");
        Ok(handle)
    }

    /// The handle of a live session.
    pub fn get(&self, id: SessionId) -> Option<SessionHandle> {
        self.inner
            .sessions
            .lock()
            .map
            .get(&id)
            .map(|e| e.handle.clone())
    }

    /// Ask a session to close gracefully. Returns `false` if it does not exist.
    /// Uses `try_send(Close)`; on a full queue it cancels the session instead, which
    /// takes the same graceful path.
    pub fn close(&self, id: SessionId) -> bool {
        let sessions = self.inner.sessions.lock();
        let Some(entry) = sessions.map.get(&id) else {
            return false;
        };
        if entry.handle.cmd_tx.try_send(SessionCmd::Close).is_err() {
            entry.cancel.cancel();
        }
        true
    }

    /// Live session ids, sorted.
    pub fn ids(&self) -> Vec<SessionId> {
        let mut ids: Vec<_> = self.inner.sessions.lock().map.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Number of live sessions.
    pub fn len(&self) -> usize {
        self.inner.sessions.lock().map.len()
    }

    /// Whether there are no live sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The read-only view for rendering.
    pub fn registry(&self) -> SessionRegistry {
        SessionRegistry {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Close every session, wait up to `timeout`, then abort the rest (Quit, M0-09).
    pub async fn shutdown(&self, timeout: Duration) -> ShutdownReport {
        let mut tasks: Vec<(AbortHandle, JoinHandle<()>)> = Vec::new();
        {
            let mut sessions = self.inner.sessions.lock();
            for entry in sessions.map.values_mut() {
                entry.cancel.cancel();
                if let Some(sup) = entry.supervisor.take() {
                    tasks.push((entry.abort.clone(), sup));
                }
            }
        }
        let total = tasks.len();
        let all = futures::future::join_all(tasks.iter_mut().map(|(_, sup)| sup));
        if tokio::time::timeout(timeout, all).await.is_ok() {
            return ShutdownReport {
                closed: total,
                aborted: 0,
            };
        }
        let mut aborted = 0;
        for (abort, sup) in &tasks {
            if !sup.is_finished() {
                abort.abort();
                aborted += 1;
            }
        }
        warn!(aborted, "sessions did not close in time; aborted");
        for (_, sup) in tasks {
            if !sup.is_finished() {
                let _ = sup.await;
            }
        }
        ShutdownReport {
            closed: total - aborted,
            aborted,
        }
    }
}

/// Await the actor; report panics; forget the session.
async fn supervise(
    id: SessionId,
    task: JoinHandle<()>,
    sink: Arc<dyn EventSink>,
    inner: Weak<Inner>,
    // M3-06
    connlog: Arc<dyn ConnLogSink>,
) {
    let result: Result<(), JoinError> = task.await;
    match result {
        Ok(()) => debug!(session = %id, "session ended"),
        Err(err) if err.is_panic() => {
            let payload = err.into_panic();
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_owned());
            error!(session = %id, "session task panicked: {msg}");
            sink.send(
                id,
                SessionEvent::State(SessionState::Disconnected {
                    reason: DisconnectReason::Internal,
                    at: Instant::now(),
                }),
            );
            sink.send(
                id,
                SessionEvent::Error(ErrorReport::msg(DisconnectReason::Internal.message())),
            );
            // M3-06: a crashed attempt still ends its ConnLog entry (ignored if the
            // actor had already ended it).
            connlog.attempt_ended(
                id,
                AttemptEnd {
                    outcome: AttemptOutcome::Disconnected(DisconnectReason::Internal),
                    ended_at: UnixMillis::now(),
                    bytes_in: 0,
                    bytes_out: 0,
                    error: Some(ErrorReport::msg(format!("session task panicked: {msg}"))),
                },
            );
        }
        Err(_) => {
            debug!(session = %id, "session aborted");
            // M3-06: aborted on quit: the attempt ends now (`ended_at` = quit time).
            connlog.attempt_ended(
                id,
                AttemptEnd {
                    outcome: AttemptOutcome::UserClosed { connected: true },
                    ended_at: UnixMillis::now(),
                    bytes_in: 0,
                    bytes_out: 0,
                    error: None,
                },
            );
            sink.send(id, SessionEvent::State(SessionState::Closed));
        }
    }
    if let Some(inner) = inner.upgrade() {
        inner.sessions.lock().map.remove(&id);
    }
}

/// Read-only access to live sessions' emulators and dirty flags (for rendering).
#[derive(Clone)]
pub struct SessionRegistry {
    inner: Arc<Inner>,
}

impl fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRegistry").finish_non_exhaustive()
    }
}

impl SessionRegistry {
    /// The emulator of a live session.
    pub fn term(&self, id: SessionId) -> Option<SharedEmulator> {
        self.inner
            .sessions
            .lock()
            .map
            .get(&id)
            .map(|e| Arc::clone(&e.handle.term))
    }

    /// The dirty flag of a live session.
    pub fn dirty(&self, id: SessionId) -> Option<Arc<AtomicBool>> {
        self.inner
            .sessions
            .lock()
            .map
            .get(&id)
            .map(|e| Arc::clone(&e.handle.dirty))
    }

    /// Whether a live session has undrawn output.
    pub fn is_dirty(&self, id: SessionId) -> bool {
        self.dirty(id).is_some_and(|d| d.load(Ordering::Acquire))
    }
}

/// The built-in connector for [`SessionSpec::Mock`]: applies the script, then hands
/// out the wrapped transport.
#[derive(Debug)]
struct MockConnector;

#[async_trait]
impl Connector for MockConnector {
    async fn connect(
        &self,
        spec: &SessionSpec,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError> {
        let SessionSpec::Mock(mock) = spec else {
            return Err(ConnectError::new(DisconnectReason::Connect));
        };
        for input in &mock.script {
            ctx.input(input.clone())?;
        }
        mock.take().ok_or_else(|| {
            ConnectError::with_report(
                DisconnectReason::Connect,
                ErrorReport::msg("the mock transport was already used"),
            )
        })
    }
}
