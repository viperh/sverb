//! Non-interactive exec channels (SPEC §6.1.7).
//!
//! - [`SshConnection::open`] gets a connection for exec runs without a shell channel.
//!   Through the connector's pool (`ssh.multiplex`): a run shares a tab's (or
//!   another run's) connection to the same key, and jump chains work as for sessions;
//!   with sharing off it is a dedicated connection (resolve → first hop or jump chain →
//!   handshake with the host-key seam → the authentication chain), closed afterwards.
//!   Exec connections never forward the agent, so they share only with sessions that
//!   don't either. Host-key and auth
//!   prompts go out through [`ExecPrompts`] as ordinary [`SessionEvent`]s under the
//!   run's own [`SessionId`], and answers come back as [`SessionCmd`]s, so the UI can
//!   show its usual dialogs attributed to the run.
//! - [`exec`] runs one command on a session channel: no PTY unless asked
//!   ([`ExecOpts::request_pty`], else the host's `request_pty_for_exec`); with a PTY
//!   stdout and stderr are merged (as with `ssh -t`). Each stream keeps at most
//!   [`OUTPUT_CAP`] bytes; past it the output is read and dropped (the remote never
//!   blocks on window space) and [`ExecResult::truncated`] is set. On timeout the
//!   channel gets `signal TERM`, [`TERM_GRACE`] to finish, then is closed; the result
//!   has `exit = None`, `signal = "TERM (timeout)"`.
//! - [`for_each_concurrent`]: run work for many targets, at most `limit` at a time
//!   ([`DEFAULT_CONCURRENCY`]).
//!
//! The connection comes from the same flow as sessions (`mux_ssh::connect`).
//! A run refused by the server's `MaxSessions` on a shared connection fails like any
//! refused channel (sessions fall back to a new connection; runs don't).

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use russh::{ChannelMsg, Sig, client};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::{
    SshConnector,
    channel::pty_modes,
    connect::jump::mux_ssh::{self, SshLease},
    errors::{SshError, from_russh},
    handler::ClientHandler,
    resolved::SshTarget,
};
use crate::{
    session::{
        DisconnectReason, EventSink, SessionCmd, SessionEvent, SessionId, SessionState, SshSpec,
    },
    transport::{ConnectCtx, ConnectError},
};

// Multi-host snippet runs on top of exec channels (SPEC §9.7, §16).
pub mod snippets;

/// Output kept per stream (1 MiB, §6.1.7).
pub const OUTPUT_CAP: usize = 1 << 20;

/// How long a timed-out command gets after `signal TERM` before the channel is closed.
pub const TERM_GRACE: Duration = Duration::from_secs(2);

/// The default number of hosts worked on at once (install key, snippet runs).
pub const DEFAULT_CONCURRENCY: usize = 10;

/// The `signal` of a run that hit its timeout.
pub const TIMEOUT_SIGNAL: &str = "TERM (timeout)";

/// How a command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOpts {
    /// Give up after this long (`ssh.exec_timeout_secs`, default 60 s).
    pub timeout: Duration,
    /// Request a PTY (`None`: the host's `request_pty_for_exec`).
    pub request_pty: Option<bool>,
    /// Sent to the command's stdin, then EOF. Without it stdin is closed at once.
    pub stdin: Option<Bytes>,
}

impl Default for ExecOpts {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            request_pty: None,
            stdin: None,
        }
    }
}

impl ExecOpts {
    /// Options with `timeout`.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Self::default()
        }
    }
}

/// What a command did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecResult {
    /// Standard output (with a PTY: both streams), at most [`OUTPUT_CAP`] bytes.
    pub stdout: Bytes,
    /// Standard error (empty with a PTY), at most [`OUTPUT_CAP`] bytes.
    pub stderr: Bytes,
    /// The exit status, if the server sent one.
    pub exit: Option<u32>,
    /// The signal that ended the command (`TERM`, …), or [`TIMEOUT_SIGNAL`].
    pub signal: Option<String>,
    /// A stream went over [`OUTPUT_CAP`].
    pub truncated: bool,
    /// From the channel request to the end.
    pub duration: Duration,
}

impl ExecResult {
    /// Exited with status 0.
    pub fn success(&self) -> bool {
        self.exit == Some(0) && self.signal.is_none()
    }

    /// Ended by the timeout.
    pub fn timed_out(&self) -> bool {
        self.signal.as_deref() == Some(TIMEOUT_SIGNAL)
    }
}

/// Where the connection's host-key and auth prompts go, and where answers come from.
pub struct ExecPrompts {
    /// The run's id in events (pick one that no session uses).
    pub id: SessionId,
    /// Receives `HostKey`, `Prompt`, `PromptAccepted` and `State` events.
    pub events: Arc<dyn EventSink>,
    /// `HostKeyDecision` and `AuthAnswer` commands; `Close` (or a dropped sender)
    /// aborts the connection.
    pub answers: mpsc::Receiver<SessionCmd>,
}

impl std::fmt::Debug for ExecPrompts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecPrompts")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Drops every event.
struct NoEvents;

impl EventSink for NoEvents {
    fn send(&self, _id: SessionId, _ev: SessionEvent) {}
}

impl ExecPrompts {
    /// No prompts can be answered (non-interactive use): a host-key or auth prompt
    /// fails the connection as if the user cancelled it.
    pub fn none() -> Self {
        let (_tx, answers) = mpsc::channel(1);
        Self {
            id: SessionId(0),
            events: Arc::new(NoEvents),
            answers,
        }
    }
}

/// An authenticated connection for exec runs (no shell channel). Shared
/// through the connector's pool when `ssh.multiplex` is on.
pub struct SshConnection {
    handle: Arc<client::Handle<ClientHandler>>,
    target: SshTarget,
    // This run's lease on the (possibly shared) connection.
    lease: SshLease,
    pooled: bool,
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("label", &self.target.label)
            .finish_non_exhaustive()
    }
}

fn fail(err: SshError) -> ConnectError {
    err.into_connect_error()
}

impl SshConnection {
    /// Connect and authenticate `spec` through `connector` (its resolver, host-key
    /// verifier and authenticator), asking through `prompts`.
    ///
    /// # Errors
    /// As a session connect (§6.1.9): resolve, TCP, host key, auth; `Closed` when a
    /// prompt was cancelled by closing.
    pub async fn open(
        connector: &SshConnector,
        spec: &SshSpec,
        prompts: ExecPrompts,
    ) -> Result<Self, ConnectError> {
        let ExecPrompts {
            id,
            events,
            mut answers,
        } = prompts;
        let mut state = SessionState::Resolving;
        let mut deferred = Vec::new();
        let mut ctx = ConnectCtx {
            id,
            state: &mut state,
            sink: events.as_ref(),
            cmd_rx: &mut answers,
            size: (80, 24),
            deferred: &mut deferred,
            owned_sink: Arc::clone(&events),
            forwards: None,
            tunnel_only: true,
        };
        dial(connector, spec, &mut ctx).await
    }

    /// The resolved target.
    pub fn target(&self) -> &SshTarget {
        &self.target
    }

    /// Disconnect. A shared connection is only released (it stays up for its
    /// other users, or lingers 10 s).
    pub async fn close(self) {
        if !self.pooled {
            let _ = self
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
        }
        drop(self.lease);
    }
}

/// Resolve → the pool (a shared connection, or first hop / jump chain → handshake →
/// auth; connect.rs steps 1–4).
async fn dial(
    conn: &SshConnector,
    spec: &SshSpec,
    ctx: &mut ConnectCtx<'_>,
) -> Result<SshConnection, ConnectError> {
    let mut host = conn.resolver.resolve(spec).await.map_err(fail)?;
    // Exec channels never forward the agent (and so don't share a connection that
    // serves forwarded agent channels for a session).
    host.agent_forwarding = false;
    let connected = mux_ssh::connect(conn, conn.pool(), spec, &host, None, ctx).await?;
    info!(session = %ctx.id(), channels = connected.channels(), "exec connection open");
    Ok(SshConnection {
        handle: Arc::clone(connected.handle()),
        pooled: connected.pooled(),
        lease: connected.lease,
        target: host,
    })
}

/// A capped output buffer.
#[derive(Default)]
struct Capped {
    buf: BytesMut,
    over: bool,
}

impl Capped {
    fn push(&mut self, data: &[u8]) {
        let room = OUTPUT_CAP.saturating_sub(self.buf.len());
        if data.len() > room {
            self.over = true;
        }
        self.buf.extend_from_slice(&data[..data.len().min(room)]);
    }
}

fn signal_name(sig: &Sig) -> String {
    match sig {
        Sig::ABRT => "ABRT".to_owned(),
        Sig::ALRM => "ALRM".to_owned(),
        Sig::FPE => "FPE".to_owned(),
        Sig::HUP => "HUP".to_owned(),
        Sig::ILL => "ILL".to_owned(),
        Sig::INT => "INT".to_owned(),
        Sig::KILL => "KILL".to_owned(),
        Sig::PIPE => "PIPE".to_owned(),
        Sig::QUIT => "QUIT".to_owned(),
        Sig::SEGV => "SEGV".to_owned(),
        Sig::TERM => "TERM".to_owned(),
        Sig::USR1 => "USR1".to_owned(),
        Sig::Custom(s) => s.clone(),
    }
}

/// Run `command` on `conn` (SPEC §6.1.7; see the module docs).
///
/// # Errors
/// The channel could not be opened, or the server refused the PTY or exec request.
/// A timeout is not an error: the result says `TERM (timeout)`.
pub async fn exec(
    conn: &SshConnection,
    command: &str,
    opts: ExecOpts,
) -> Result<ExecResult, SshError> {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let host = &conn.target;
    let russh_err = |e: &russh::Error| from_russh(e, host.keepalive_secs, &host.display_addr());
    let mut channel = tokio::time::timeout_at(deadline, conn.handle.channel_open_session())
        .await
        .map_err(|_| SshError::Channel("no reply to the channel request".to_owned()))?
        .map_err(|e| russh_err(&e))?;
    let pty = opts.request_pty.unwrap_or(host.request_pty_for_exec);
    if pty {
        channel
            .request_pty(
                true,
                &host.term,
                80,
                24,
                0,
                0,
                &pty_modes(host.backspace, host.is_utf8()),
            )
            .await
            .map_err(|e| russh_err(&e))?;
    }
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| russh_err(&e))?;
    // Replies arrive in request order: the PTY's (if any), then the exec's.
    let mut replies_due = if pty { 2 } else { 1 };
    let mut stdin = opts.stdin;

    let mut out = Capped::default();
    let mut err = Capped::default();
    let mut result = ExecResult::default();
    let mut timed_out = false;
    loop {
        let msg = if timed_out {
            match tokio::time::timeout_at(deadline + TERM_GRACE, channel.wait()).await {
                Ok(msg) => msg,
                Err(_) => {
                    debug!("exec: no close after TERM; closing the channel");
                    let _ = channel.close().await;
                    break;
                }
            }
        } else {
            match tokio::time::timeout_at(deadline, channel.wait()).await {
                Ok(msg) => msg,
                Err(_) => {
                    debug!("exec: timeout; sending TERM");
                    timed_out = true;
                    let _ = channel.signal(Sig::TERM).await;
                    continue;
                }
            }
        };
        let Some(msg) = msg else { break };
        match msg {
            ChannelMsg::Data { data } => out.push(&data),
            ChannelMsg::ExtendedData { data, ext } => {
                if pty || ext != 1 {
                    out.push(&data);
                } else {
                    err.push(&data);
                }
            }
            ChannelMsg::Success if replies_due > 0 => {
                replies_due -= 1;
                if replies_due == 0 {
                    // The command runs: feed stdin, then EOF.
                    if let Some(data) = stdin.take() {
                        channel.data_bytes(data).await.map_err(|e| russh_err(&e))?;
                    }
                    let _ = channel.eof().await;
                }
            }
            ChannelMsg::Failure if replies_due > 0 => {
                let what = if pty && replies_due == 2 {
                    "the server refused the PTY request"
                } else {
                    "the server refused the exec request"
                };
                let _ = channel.close().await;
                return Err(SshError::Channel(what.to_owned()));
            }
            ChannelMsg::ExitStatus { exit_status } => result.exit = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name: s, .. } => {
                result.signal = Some(signal_name(&s));
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if timed_out {
        result.exit = None;
        result.signal = Some(TIMEOUT_SIGNAL.to_owned());
    }
    result.truncated = out.over || err.over;
    result.stdout = out.buf.freeze();
    result.stderr = err.buf.freeze();
    result.duration = started.elapsed();
    Ok(result)
}

/// Run `work` for every item, at most `limit` (≥ 1) at a time; returns when all are
/// done. Results are reported by `work` itself (in completion order).
pub async fn for_each_concurrent<T, F, Fut>(items: Vec<T>, limit: usize, work: F)
where
    F: Fn(T) -> Fut,
    Fut: Future<Output = ()>,
{
    use futures::StreamExt as _;
    futures::stream::iter(items)
        .for_each_concurrent(limit.max(1), work)
        .await;
}

/// The message for a failed connection (the report's short text, else the reason).
pub fn connect_error_text(err: &ConnectError) -> String {
    match &err.report {
        Some(report) => report.short.clone(),
        None if err.reason == DisconnectReason::Closed => "cancelled".to_owned(),
        None => err.reason.to_string(),
    }
}
