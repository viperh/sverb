//! [`ForwardManager`]: the rules, their live status, and the connections carrying
//! them (§9.6 lifecycle).
//!
//! - Every SSH connection made by a session manager with this hook
//!   ([`ForwardHook::connected`]) is registered with its token. On connect (and on
//!   every reconnect) the host's **auto-start** rules start; a standalone connection
//!   starts the rules that asked for it ([`ForwardManager::start_standalone`]).
//! - Each running rule's task runs under a child of the connection's token: when the
//!   connection goes away the rule stops with state `stopped (connection lost)`.
//! - Starting needs the rule's locally-acting values confirmed
//!   ([`approval`](super::approval)); otherwise [`StartError::NeedsApproval`], and an
//!   auto-start rule waits in state `needs approval`.

use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use sverb_core::model::{ForwardKind, ItemId};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{
    ConnInfo, ForwardHook, ForwardRule, ForwardState, ForwardStatus, Live, RiskyValue, RuleError,
    Tunnel,
    approval::{ApprovalStore, needs_confirmation},
    bind_error_text, bind_socket_addr, dynamic, local, remote, remote_bind_addr,
};
use crate::{
    SessionHandle, SessionId,
    manager::{OpenError, OpenOptions, SessionManager},
    session::{SessionSpec, SshSpec},
};

/// Why a rule did not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    /// No such rule.
    #[error("no such forward")]
    UnknownRule,
    /// The rule is invalid.
    #[error("{0}")]
    Invalid(#[from] RuleError),
    /// Values that act locally need confirmation first (§9.6, §17.1).
    #[error("needs approval: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
    NeedsApproval(Vec<RiskyValue>),
    /// The user denied one of these values in this session (§17.1): not asked again
    /// until the next start of sverb.
    #[error("blocked by approval policy: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
    Blocked(Vec<RiskyValue>),
    /// The rule's host has no live connection (start a session or a standalone
    /// tunnel).
    #[error("the host is not connected")]
    NotConnected,
}

struct Conn {
    id: u64,
    host_id: Option<ItemId>,
    session: SessionId,
    standalone: bool,
    tunnel: Arc<dyn Tunnel>,
    token: CancellationToken,
}

struct Run {
    conn: u64,
    token: CancellationToken,
}

struct Entry {
    rule: ForwardRule,
    live: Arc<Live>,
    run: Option<Run>,
    /// "Start without terminal" was asked: start on the host's standalone
    /// connection(s), and again after a reconnect, until stopped.
    standalone: bool,
}

#[derive(Default)]
struct State {
    rules: BTreeMap<ItemId, Entry>,
    conns: Vec<Conn>,
    next_conn: u64,
    /// Standalone sessions opened per host (connecting, connected or failed).
    pending: std::collections::HashMap<ItemId, SessionId>,
}

struct Inner {
    state: Mutex<State>,
    // Replaceable (the TUI attaches the store's approvals once it has them).
    approvals: parking_lot::RwLock<Arc<dyn ApprovalStore>>,
}

/// Rules, live status and connections. Cheap to clone (shared state).
#[derive(Clone)]
pub struct ForwardManager {
    inner: Arc<Inner>,
}

impl fmt::Debug for ForwardManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.state.lock();
        f.debug_struct("ForwardManager")
            .field("rules", &state.rules.len())
            .field("connections", &state.conns.len())
            .finish_non_exhaustive()
    }
}

impl Default for ForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardManager {
    /// A manager with in-memory approvals (nothing persisted; Attach the
    /// store's with [`ForwardManager::set_approvals`]).
    pub fn new() -> Self {
        Self::with_approvals(Arc::new(
            sverb_core::resolve::approval::DeviceApprovals::new(),
        ))
    }

    pub fn with_approvals(approvals: Arc<dyn ApprovalStore>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                approvals: parking_lot::RwLock::new(approvals),
            }),
        }
    }

    /// The approval store.
    pub fn approvals(&self) -> Arc<dyn ApprovalStore> {
        Arc::clone(&self.inner.approvals.read())
    }

    /// Use `approvals` from now on (the device's `local_approvals`).
    pub fn set_approvals(&self, approvals: Arc<dyn ApprovalStore>) {
        *self.inner.approvals.write() = approvals;
    }

    /// Record the user's confirmation of `values`.
    pub fn approve(&self, values: &[RiskyValue]) {
        let store = self.approvals();
        for v in values {
            store.approve(v);
        }
    }

    /// Record the user's denial of `values` for this session.
    pub fn deny(&self, values: &[RiskyValue]) {
        let store = self.approvals();
        for v in values {
            store.deny(v);
        }
    }

    /// `Ok` when nothing needs confirmation; else `NeedsApproval`, or `Blocked` when
    /// one of the values was denied in this session.
    fn check_approvals(&self, rule: &ForwardRule) -> Result<(), StartError> {
        let store = self.approvals();
        let pending = needs_confirmation(rule, store.as_ref());
        if pending.is_empty() {
            Ok(())
        } else if pending.iter().any(|v| store.is_denied(v)) {
            Err(StartError::Blocked(pending))
        } else {
            Err(StartError::NeedsApproval(pending))
        }
    }

    /// Values of rule `id` that still need confirmation.
    pub fn pending_approval(&self, id: ItemId) -> Vec<RiskyValue> {
        let state = self.inner.state.lock();
        state
            .rules
            .get(&id)
            .map(|e| needs_confirmation(&e.rule, self.approvals().as_ref()))
            .unwrap_or_default()
    }

    /// Replace the rule set (from the vault). Unchanged rules keep running; changed
    /// running rules are stopped; removed rules are stopped and dropped.
    pub fn set_rules(&self, rules: impl IntoIterator<Item = ForwardRule>) {
        let mut state = self.inner.state.lock();
        let mut next = BTreeMap::new();
        for rule in rules {
            let entry = match state.rules.remove(&rule.id) {
                Some(mut old) => {
                    if old.rule != rule {
                        if let Some(run) = old.run.take() {
                            run.token.cancel();
                            old.live.set_state(ForwardState::Stopped);
                        }
                        old.rule = rule;
                    }
                    old
                }
                None => Entry {
                    rule,
                    live: Arc::default(),
                    run: None,
                    standalone: false,
                },
            };
            next.insert(entry.rule.id, entry);
        }
        for (_, old) in std::mem::take(&mut state.rules) {
            if let Some(run) = old.run {
                run.token.cancel();
            }
        }
        state.rules = next;
    }

    /// Add or replace one rule.
    pub fn upsert(&self, rule: ForwardRule) {
        let rules: Vec<ForwardRule> = {
            let state = self.inner.state.lock();
            let mut v: Vec<_> = state
                .rules
                .values()
                .filter(|e| e.rule.id != rule.id)
                .map(|e| e.rule.clone())
                .collect();
            v.push(rule);
            v
        };
        self.set_rules(rules);
    }

    /// Remove a rule (stopping it).
    pub fn remove(&self, id: ItemId) {
        let mut state = self.inner.state.lock();
        if let Some(entry) = state.rules.remove(&id)
            && let Some(run) = entry.run
        {
            run.token.cancel();
        }
    }

    /// The rule `id`.
    pub fn rule(&self, id: ItemId) -> Option<ForwardRule> {
        self.inner
            .state
            .lock()
            .rules
            .get(&id)
            .map(|e| e.rule.clone())
    }

    /// Every rule's status, in id order.
    pub fn statuses(&self) -> Vec<ForwardStatus> {
        let state = self.inner.state.lock();
        state
            .rules
            .values()
            .map(|e| {
                let standalone =
                    e.run.as_ref().is_some_and(|r| {
                        state.conns.iter().any(|c| c.id == r.conn && c.standalone)
                    }) || (e.run.is_none() && e.standalone);
                ForwardStatus::snapshot(&e.rule, &e.live, standalone)
            })
            .collect()
    }

    /// One rule's status.
    pub fn status(&self, id: ItemId) -> Option<ForwardStatus> {
        self.statuses().into_iter().find(|s| s.rule.id == id)
    }

    /// Whether `host` has a live connection.
    pub fn is_connected(&self, host: ItemId) -> bool {
        self.inner
            .state
            .lock()
            .conns
            .iter()
            .any(|c| c.host_id == Some(host) && !c.token.is_cancelled())
    }

    /// Start rule `id` on a live connection of its host.
    ///
    /// # Errors
    /// Unknown or invalid rule, values needing approval, or no connection.
    pub fn start(&self, id: ItemId) -> Result<(), StartError> {
        let mut state = self.inner.state.lock();
        let entry = state.rules.get(&id).ok_or(StartError::UnknownRule)?;
        if entry.run.is_some() {
            return Ok(());
        }
        entry.rule.validate()?;
        // Session denials fail without asking again.
        if let Err(e) = self.check_approvals(&entry.rule) {
            entry.live.set_state(ForwardState::NeedsApproval);
            return Err(e);
        }
        let host = entry.rule.host_id;
        // Prefer a terminal session's connection, else a standalone one.
        let conn = state
            .conns
            .iter()
            .filter(|c| c.host_id == Some(host) && !c.token.is_cancelled())
            .min_by_key(|c| c.standalone)
            .map(|c| c.id)
            .ok_or(StartError::NotConnected)?;
        start_on(&mut state, id, conn);
        Ok(())
    }

    /// "Start without terminal": validate and check approvals, then mark the rule to
    /// start on the host's standalone connection (now if one is up). The caller opens
    /// the tunnel-only session when [`ForwardManager::has_standalone`] is false
    /// (see [`open_standalone`]).
    ///
    /// # Errors
    /// Unknown or invalid rule, or values needing approval.
    pub fn start_standalone(&self, id: ItemId) -> Result<(), StartError> {
        let mut state = self.inner.state.lock();
        let entry = state.rules.get_mut(&id).ok_or(StartError::UnknownRule)?;
        entry.rule.validate()?;
        // Session denials fail without asking again.
        if let Err(e) = self.check_approvals(&entry.rule) {
            entry.live.set_state(ForwardState::NeedsApproval);
            return Err(e);
        }
        entry.standalone = true;
        if entry.run.is_some() {
            return Ok(());
        }
        let host = entry.rule.host_id;
        let conn = state
            .conns
            .iter()
            .find(|c| c.host_id == Some(host) && c.standalone && !c.token.is_cancelled())
            .map(|c| c.id);
        match conn {
            Some(conn) => start_on(&mut state, id, conn),
            None => {
                if let Some(e) = state.rules.get(&id) {
                    e.live.set_state(ForwardState::Connecting);
                }
            }
        }
        Ok(())
    }

    /// Whether `host` has a live standalone connection.
    pub fn has_standalone(&self, host: ItemId) -> bool {
        self.inner
            .state
            .lock()
            .conns
            .iter()
            .any(|c| c.host_id == Some(host) && c.standalone && !c.token.is_cancelled())
    }

    /// Stop rule `id`. Returns the standalone session that no longer carries any rule
    /// (the caller closes it).
    pub fn stop(&self, id: ItemId) -> Option<SessionId> {
        let mut state = self.inner.state.lock();
        let entry = state.rules.get_mut(&id)?;
        entry.standalone = false;
        let run = entry.run.take();
        entry.live.set_state(ForwardState::Stopped);
        let host = entry.rule.host_id;
        if let Some(run) = &run {
            run.token.cancel();
        }
        // A standalone connection of this host with nothing left to carry.
        let busy = |conn: u64, state: &State| {
            state.rules.values().any(|e| {
                e.run.as_ref().is_some_and(|r| r.conn == conn)
                    || (e.standalone && e.rule.host_id == host)
            })
        };
        let idle = state
            .conns
            .iter()
            .filter(|c| c.standalone && c.host_id == Some(host))
            .find(|c| !busy(c.id, &state))
            .map(|c| c.session);
        let wanted = state
            .rules
            .values()
            .any(|e| e.standalone && e.rule.host_id == host);
        let pending = if wanted {
            None
        } else {
            state.pending.remove(&host)
        };
        idle.or(pending)
    }

    /// Wait until rule `id` leaves `starting`/`connecting` (or `timeout`). Returns
    /// the state then.
    pub async fn wait_started(&self, id: ItemId, timeout: Duration) -> Option<ForwardState> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = self.status(id)?.state;
            if !matches!(state, ForwardState::Starting | ForwardState::Connecting)
                || Instant::now() >= deadline
            {
                return Some(state);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn connection_lost(&self, conn: u64) {
        let mut state = self.inner.state.lock();
        state.conns.retain(|c| c.id != conn);
        for entry in state.rules.values_mut() {
            if entry.run.as_ref().is_some_and(|r| r.conn == conn) {
                entry.run = None;
                entry.live.set_state(ForwardState::ConnectionLost);
            }
        }
    }
}

/// Spawn rule `id` on connection `conn`. The state lock is held (no awaits).
fn start_on(state: &mut State, id: ItemId, conn: u64) {
    let Some(c) = state.conns.iter().find(|c| c.id == conn) else {
        return;
    };
    let tunnel = Arc::clone(&c.tunnel);
    let token = c.token.child_token();
    let Some(entry) = state.rules.get_mut(&id) else {
        return;
    };
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        entry
            .live
            .set_state(ForwardState::Error("no async runtime".to_owned()));
        return;
    };
    entry.live.set_state(ForwardState::Starting);
    entry.live.set_port(0);
    entry.run = Some(Run {
        conn,
        token: token.clone(),
    });
    rt.spawn(run_rule(
        entry.rule.clone(),
        tunnel,
        Arc::clone(&entry.live),
        token,
    ));
}

/// One rule's task: bind or request, then the accept loop.
async fn run_rule(
    rule: ForwardRule,
    tunnel: Arc<dyn Tunnel>,
    live: Arc<Live>,
    token: CancellationToken,
) {
    let fail = |live: &Live, msg: String| {
        if !token.is_cancelled() {
            live.set_state(ForwardState::Error(msg));
        }
    };
    match rule.kind {
        ForwardKind::Local | ForwardKind::Dynamic => {
            let addr = match bind_socket_addr(&rule.bind_addr, rule.bind_port) {
                Ok(a) => a,
                Err(e) => return fail(&live, e.to_string()),
            };
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => return fail(&live, bind_error_text(&e)),
            };
            if let Ok(local) = listener.local_addr() {
                live.set_port(local.port());
            }
            if token.is_cancelled() {
                return;
            }
            live.set_state(ForwardState::Listening);
            debug!(rule = %rule.id, "forward listening");
            if rule.kind == ForwardKind::Local {
                let (Some(host), Some(port)) = (rule.dest_host.clone(), rule.dest_port) else {
                    return fail(&live, RuleError::MissingDest.to_string());
                };
                local::run(listener, host, port, tunnel, live, token).await;
            } else {
                dynamic::run(listener, tunnel, live, token).await;
            }
        }
        ForwardKind::Remote => {
            let (Some(host), Some(port)) = (rule.dest_host.clone(), rule.dest_port) else {
                return fail(&live, RuleError::MissingDest.to_string());
            };
            let addr = remote_bind_addr(&rule.bind_addr);
            let listener = tokio::select! {
                () = token.cancelled() => return,
                l = tunnel.listen_remote(&addr, rule.bind_port) => l,
            };
            let listener = match listener {
                Ok(l) => l,
                Err(e) => return fail(&live, e.to_string()),
            };
            live.set_port(listener.port);
            if token.is_cancelled() {
                return;
            }
            live.set_state(ForwardState::Listening);
            remote::run(listener, host, port, live, token).await;
        }
    }
}

impl ForwardHook for ForwardManager {
    fn connected(&self, info: ConnInfo) {
        let id = {
            let mut state = self.inner.state.lock();
            state.next_conn += 1;
            let id = state.next_conn;
            state.conns.push(Conn {
                id,
                host_id: info.host_id,
                session: info.session,
                standalone: info.standalone,
                tunnel: Arc::clone(&info.tunnel),
                token: info.token.clone(),
            });
            // Auto-start on a terminal session's connection; "start without terminal"
            // rules on a standalone one.
            let start: Vec<ItemId> = state
                .rules
                .values()
                .filter(|e| {
                    Some(e.rule.host_id) == info.host_id
                        && e.run.is_none()
                        && if info.standalone {
                            e.standalone
                        } else {
                            e.rule.auto_start
                        }
                })
                .map(|e| e.rule.id)
                .collect();
            for rule in start {
                let Some(entry) = state.rules.get(&rule) else {
                    continue;
                };
                if entry.rule.validate().is_err() {
                    continue;
                }
                if !needs_confirmation(&entry.rule, self.approvals().as_ref()).is_empty() {
                    entry.live.set_state(ForwardState::NeedsApproval);
                    continue;
                }
                start_on(&mut state, rule, id);
            }
            id
        };
        let this = self.clone();
        let token = info.token;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                token.cancelled().await;
                this.connection_lost(id);
            });
        }
    }
}

/// What "start without terminal" needs from the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandalonePlan {
    /// The host's standalone connection is up; the rule started (or starts) on it.
    Connected,
    /// A standalone session of the host exists but is not connected (connecting, or
    /// failed): ask it to reconnect instead of opening another one.
    Pending(SessionId),
    /// Open a tunnel-only session for the host, then report it with
    /// [`ForwardManager::note_standalone_session`].
    Open {
        /// The host to connect.
        host: ItemId,
    },
}

impl ForwardManager {
    /// "Start without terminal" (§9.6): mark rule `id` standalone (it starts on the
    /// host's standalone connection now or once it is up, and again after a
    /// reconnect) and say what the caller must do about the connection.
    ///
    /// # Errors
    /// Unknown or invalid rule, or values needing approval.
    pub fn plan_standalone(&self, id: ItemId) -> Result<StandalonePlan, StartError> {
        self.start_standalone(id)?;
        let host = self.rule(id).ok_or(StartError::UnknownRule)?.host_id;
        if self.has_standalone(host) {
            return Ok(StandalonePlan::Connected);
        }
        if let Some(session) = self.inner.state.lock().pending.get(&host).copied() {
            return Ok(StandalonePlan::Pending(session));
        }
        Ok(StandalonePlan::Open { host })
    }

    /// The caller opened tunnel-only session `session` for `host`.
    pub fn note_standalone_session(&self, host: ItemId, session: SessionId) {
        self.inner.state.lock().pending.insert(host, session);
    }

    /// A standalone session is gone (closed): forget it.
    pub fn forget_standalone_session(&self, session: SessionId) {
        self.inner.state.lock().pending.retain(|_, s| *s != session);
    }
}

/// "Start without terminal" (§9.6) through a [`SessionManager`] whose forward hook is
/// `forwards`: [`ForwardManager::plan_standalone`], then reconnect the pending session
/// or open a tunnel-only one (no shell channel, no tab) with id `session`. Returns the
/// new session's handle, if one was opened.
///
/// # Errors
/// The rule could not start, or the session could not be opened.
pub fn open_standalone(
    sessions: &SessionManager,
    forwards: &ForwardManager,
    id: ItemId,
    spec: SshSpec,
    session: Option<SessionId>,
) -> Result<Option<SessionHandle>, StandaloneError> {
    match forwards.plan_standalone(id)? {
        StandalonePlan::Connected => Ok(None),
        StandalonePlan::Pending(sid) => match sessions.get(sid) {
            Some(handle) => {
                let _ = handle.cmd_tx.try_send(crate::SessionCmd::Reconnect);
                Ok(None)
            }
            None => {
                forwards.forget_standalone_session(sid);
                open_standalone(sessions, forwards, id, spec, session)
            }
        },
        StandalonePlan::Open { host } => {
            let handle = sessions.open_with(
                SessionSpec::Ssh(spec),
                OpenOptions {
                    id: session,
                    tunnel_only: true,
                    ..OpenOptions::default()
                },
            )?;
            forwards.note_standalone_session(host, handle.id);
            Ok(Some(handle))
        }
    }
}

/// Why a standalone tunnel did not open.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StandaloneError {
    /// The rule cannot start.
    #[error("{0}")]
    Start(#[from] StartError),
    /// The session could not be opened.
    #[error("{0}")]
    Open(#[from] OpenError),
}
