//! Port forwarding (SPEC §9.6, §4.8): Local (`-L`), Remote (`-R`, including
//! server-allocated ports) and Dynamic (`-D`, a SOCKS5/SOCKS4a server with remote DNS).
//!
//! # Layout
//! - [`socks`]: the pure SOCKS wire format (fuzz target); `socks_server`: the
//!   handshake over a stream.
//! - `local`, `remote`, `dynamic`: one task per running rule.
//! - [`ForwardManager`]: rules, their live status, the connections that carry them,
//!   auto-start on connect and reconnect, and stopping on connection loss.
//! - [`approval`]: which rule values act locally (§17.1) and the first-time
//!   confirmation of non-loopback binds (§9.6); M2-10 replaces the in-memory store.
//! - `ssh_glue`: the only russh-facing part ([`Tunnel`] over a russh client handle,
//!   `forwarded-tcpip` routing, the tunnel-only transport). The hooks into
//!   `ssh/connect.rs` and `ssh/handler.rs` are a few lines that call into it.
//!
//! # Connections and lifetimes
//! Every SSH connection made with a forward hook ([`ConnectCtx`](crate::ConnectCtx)'s,
//! set through [`SessionManager::set_forward_hook`](crate::SessionManager)) reports a
//! [`ConnInfo`] to the hook: a [`Tunnel`] and a per-connection `CancellationToken`
//! that is cancelled when the transport is dropped (the session disconnected, closed,
//! or is about to reconnect). Each rule task runs under a **child** of that token.
//! Reconnecting produces a new `ConnInfo`, and the manager restarts the host's
//! auto-start rules on it. Standalone tunnels are sessions opened with
//! `OpenOptions::tunnel_only` (no shell channel, no tab).
//!
//! # Splicing and half-close
//! Streams are spliced with `tokio::io::copy_bidirectional`: EOF on one side shuts the
//! other side's write half down (TCP FIN ⇄ channel `eof`) while the other direction
//! keeps flowing. Bytes are counted live in atomics ([`Live`]).

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use sverb_core::model::{DeviceId, ForwardKind, ItemBody, ItemId, PortForward};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub mod approval;
mod dynamic;
mod local;
mod manager;
mod remote;
pub mod socks;
mod socks_server;
pub(crate) mod ssh_glue;
#[cfg(test)]
mod tests;

pub use approval::{ApprovalStore, MemoryApprovals, RiskyValue, needs_confirmation, risky_values};
pub use manager::{ForwardManager, StandaloneError, StandalonePlan, StartError, open_standalone};
pub use remote::RemoteRoutes;
pub use socks_server::{SocksError, handshake as socks_handshake};

/// At most this many concurrent channels per rule (SPEC §9.6, §19).
pub const MAX_CHANNELS: usize = 256;

/// SOCKS request parsing must finish within this time (§9.6).
pub const SOCKS_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- rules

/// A rule as the forwarding runtime sees it: the §4.8 fields plus its item id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    /// The `PortForward` item.
    pub id: ItemId,
    /// Display name.
    pub label: String,
    /// `-L`, `-R` or `-D`.
    pub kind: ForwardKind,
    /// The host whose connection carries the tunnel.
    pub host_id: ItemId,
    /// Listen address (`127.0.0.1` by default; `*` means all interfaces).
    pub bind_addr: String,
    /// Listen port (`0` for a remote rule: server-allocated).
    pub bind_port: u16,
    /// Destination host (`None` for Dynamic).
    pub dest_host: Option<String>,
    /// Destination port (`None` for Dynamic).
    pub dest_port: Option<u16>,
    /// Start when the host connects.
    pub auto_start: bool,
    /// The values that act locally were last written by this device. M2-10:
    /// informational only (dialog wording); approval is an explicit
    /// `local_approvals` row, created when the rule is saved on this device.
    pub typed_here: bool,
}

impl ForwardRule {
    /// The runtime rule for item `id` (`typed_here` = false: callers that know
    /// better use [`ForwardRule::from_body`]).
    pub fn from_item(id: ItemId, pf: &PortForward) -> Self {
        Self {
            id,
            label: pf.label.clone(),
            kind: pf.kind,
            host_id: pf.host_id,
            bind_addr: pf.bind_addr.clone(),
            bind_port: pf.bind_port,
            dest_host: pf.dest_host.clone(),
            dest_port: pf.dest_port,
            auto_start: pf.auto_start,
            typed_here: false,
        }
    }

    /// The runtime rule for item `id`; `typed_here` when every locally-acting field
    /// (`bind_addr`, `bind_port`, `dest_host`, `dest_port`) present in `body` was last
    /// written by `this_device`.
    pub fn from_body(id: ItemId, pf: &PortForward, body: &ItemBody, this_device: DeviceId) -> Self {
        let mut rule = Self::from_item(id, pf);
        rule.typed_here = ["bind_addr", "bind_port", "dest_host", "dest_port"]
            .iter()
            .filter_map(|f| body.get_stamped(f))
            .all(|s| s.device == this_device);
        rule
    }

    /// `bind_addr:bind_port` (IPv6 in brackets).
    pub fn bind_display(&self) -> String {
        host_port(&self.bind_addr, self.bind_port)
    }

    /// `dest_host:dest_port`, or `SOCKS` for a dynamic rule.
    pub fn dest_display(&self) -> String {
        match (&self.dest_host, self.dest_port) {
            (Some(h), Some(p)) => host_port(h, p),
            (Some(h), None) => h.clone(),
            _ => "SOCKS".to_owned(),
        }
    }

    /// Compact form for the status bar: `L:5432→db:5432`, `R:8080→localhost:3000`,
    /// `D:1080`.
    pub fn summary(&self) -> String {
        let letter = kind_letter(self.kind);
        match self.kind {
            ForwardKind::Dynamic => format!("{letter}:{}", self.bind_port),
            _ => format!("{letter}:{}→{}", self.bind_port, self.dest_display()),
        }
    }

    /// Validate the rule (§2.1 of the task): ports 1–65535 (a remote `bind_port` may
    /// be 0), a destination for Local and Remote, and a valid bind address.
    ///
    /// # Errors
    /// The first problem found.
    pub fn validate(&self) -> Result<(), RuleError> {
        validate_fields(
            self.kind,
            &self.bind_addr,
            self.bind_port,
            self.dest_host.as_deref(),
            self.dest_port,
        )
    }
}

/// `L`, `R` or `D`.
pub fn kind_letter(kind: ForwardKind) -> char {
    match kind {
        ForwardKind::Local => 'L',
        ForwardKind::Remote => 'R',
        ForwardKind::Dynamic => 'D',
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Why a rule is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// Port 0 where it is not allowed.
    #[error("{0} must be between 1 and 65535")]
    Port(&'static str),
    /// Local and Remote rules need `dest_host` and `dest_port`.
    #[error("a destination host and port are required")]
    MissingDest,
    /// Not an IP, `localhost`, `*`, `0.0.0.0` or `::`.
    #[error("bind address must be an IP address, localhost or *")]
    BindAddr,
    /// The destination host is empty or contains spaces or control characters.
    #[error("invalid destination host")]
    DestHost,
}

/// Field-level validation shared by the runtime and the form.
///
/// # Errors
/// The first problem found.
pub fn validate_fields(
    kind: ForwardKind,
    bind_addr: &str,
    bind_port: u16,
    dest_host: Option<&str>,
    dest_port: Option<u16>,
) -> Result<(), RuleError> {
    if bind_port == 0 && kind != ForwardKind::Remote {
        return Err(RuleError::Port("bind port"));
    }
    if !valid_bind_addr(bind_addr) {
        return Err(RuleError::BindAddr);
    }
    if kind != ForwardKind::Dynamic {
        let (Some(host), Some(port)) = (dest_host, dest_port) else {
            return Err(RuleError::MissingDest);
        };
        if port == 0 {
            return Err(RuleError::Port("destination port"));
        }
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(RuleError::DestHost);
        }
    }
    Ok(())
}

/// A valid IP, `localhost`, or one of the wildcards `*`, `0.0.0.0`, `::`.
pub fn valid_bind_addr(addr: &str) -> bool {
    addr == "*" || addr.eq_ignore_ascii_case("localhost") || parse_ip(addr).is_some()
}

fn parse_ip(addr: &str) -> Option<IpAddr> {
    addr.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// 127.0.0.0/8, `::1` or `localhost`. Binding anything else needs a first-time
/// confirmation (§9.6).
pub fn is_loopback(addr: &str) -> bool {
    addr.eq_ignore_ascii_case("localhost") || parse_ip(addr).is_some_and(|ip| ip.is_loopback())
}

/// The socket address to bind for a local listener.
///
/// # Errors
/// An invalid bind address.
pub fn bind_socket_addr(addr: &str, port: u16) -> Result<SocketAddr, RuleError> {
    let ip = if addr == "*" {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else if addr.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        parse_ip(addr).ok_or(RuleError::BindAddr)?
    };
    Ok(SocketAddr::new(ip, port))
}

/// The address string sent in a `tcpip-forward` request (`*` → `""`… OpenSSH
/// treats `""`, `0.0.0.0` and `*` as all interfaces; `localhost` stays as is).
pub fn remote_bind_addr(addr: &str) -> String {
    if addr == "*" {
        String::new()
    } else {
        addr.to_owned()
    }
}

// ---------------------------------------------------------------- live state

/// A rule's state (§9.6 status table).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ForwardState {
    /// Not running.
    #[default]
    Stopped,
    /// Waiting for the host's connection (standalone tunnel connecting).
    Connecting,
    /// Binding the listener / requesting the remote forward.
    Starting,
    /// Accepting connections.
    Listening,
    /// The connection carrying it dropped (restarts on reconnect if auto-start).
    ConnectionLost,
    /// Waiting for the user's approval or confirmation (§9.6, §17.1).
    NeedsApproval,
    /// Failed (`address in use`, the OS's message, `remote forward refused`, …).
    Error(String),
}

impl fmt::Display for ForwardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("stopped"),
            Self::Connecting => f.write_str("connecting"),
            Self::Starting => f.write_str("starting"),
            Self::Listening => f.write_str("listening"),
            Self::ConnectionLost => f.write_str("stopped (connection lost)"),
            Self::NeedsApproval => f.write_str("needs approval"),
            Self::Error(msg) => write!(f, "error: {msg}"),
        }
    }
}

impl ForwardState {
    /// Listening (or about to).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Listening | Self::Starting | Self::Connecting)
    }
}

/// The user-facing text for a bind failure (`address in use`, else the OS message).
pub fn bind_error_text(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::AddrInUse => "address in use".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        io::ErrorKind::AddrNotAvailable => "address not available".to_owned(),
        _ => err.to_string(),
    }
}

/// Live counters of one rule, shared with its tasks (atomics; the UI samples them at
/// ≤ 2 Hz).
#[derive(Debug, Default)]
pub struct Live {
    state: Mutex<ForwardState>,
    /// The bound or server-allocated port (0 until known).
    port: AtomicU16,
    active: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    refused: AtomicU64,
    total: AtomicU64,
}

impl Live {
    pub(crate) fn set_state(&self, state: ForwardState) {
        *self.state.lock() = state;
    }

    pub(crate) fn state(&self) -> ForwardState {
        self.state.lock().clone()
    }

    pub(crate) fn set_port(&self, port: u16) {
        self.port.store(port, Ordering::Relaxed);
    }

    pub(crate) fn refuse(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    fn opened(self: &Arc<Self>) -> ActiveGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(Arc::clone(self))
    }
}

/// Decrements the active count when a spliced connection ends.
#[derive(Debug)]
pub(crate) struct ActiveGuard(Arc<Live>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A snapshot of one rule for the Forwards view and the status bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    /// The rule.
    pub rule: ForwardRule,
    /// Its state.
    pub state: ForwardState,
    /// Bound / server-allocated port, once known.
    pub port: Option<u16>,
    /// Concurrent channels.
    pub active: usize,
    /// Bytes from the tunnel to the local side.
    pub bytes_in: u64,
    /// Bytes from the local side into the tunnel.
    pub bytes_out: u64,
    /// Connections refused at the cap.
    pub refused: u64,
    /// Connections accepted since the rule started.
    pub total: u64,
    /// Carried by a standalone (tunnel-only) connection.
    pub standalone: bool,
}

impl ForwardStatus {
    pub(crate) fn snapshot(rule: &ForwardRule, live: &Live, standalone: bool) -> Self {
        let port = live.port.load(Ordering::Relaxed);
        Self {
            rule: rule.clone(),
            state: live.state(),
            port: (port != 0).then_some(port),
            active: live.active.load(Ordering::Relaxed),
            bytes_in: live.bytes_in.load(Ordering::Relaxed),
            bytes_out: live.bytes_out.load(Ordering::Relaxed),
            refused: live.refused.load(Ordering::Relaxed),
            total: live.total.load(Ordering::Relaxed),
            standalone,
        }
    }

    /// At the channel cap (`256/256` in the UI).
    pub fn saturated(&self) -> bool {
        self.active >= MAX_CHANNELS
    }

    /// `bind → dest` with the allocated port for a remote rule with `bind_port = 0`.
    pub fn route(&self) -> String {
        let port = self.port.unwrap_or(self.rule.bind_port);
        format!(
            "{} → {}",
            host_port(&self.rule.bind_addr, port),
            self.rule.dest_display()
        )
    }

    /// The line `sverb forward` prints: `listening on 127.0.0.1:5432 → db:5432`.
    pub fn listening_line(&self) -> String {
        format!("listening on {}", self.route())
    }
}

// ---------------------------------------------------------------- tunnels

/// A bidirectional byte stream (a TCP socket or an SSH channel).
pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}

/// A boxed stream.
pub type TunnelStream = Box<dyn TunnelIo>;

/// Why a channel could not be opened (`direct-tcpip` failures, §2.4 mapping).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenFailure {
    /// `connect failed` (SOCKS `0x05`).
    #[error("connection refused: {0}")]
    Refused(String),
    /// `administratively prohibited` (SOCKS `0x02`).
    #[error("administratively prohibited: {0}")]
    Prohibited(String),
    /// Host or network unreachable (SOCKS `0x04`).
    #[error("host unreachable: {0}")]
    Unreachable(String),
    /// The connection is gone, or anything else (SOCKS `0x01`).
    #[error("{0}")]
    Other(String),
}

impl OpenFailure {
    /// The SOCKS5 reply for this failure.
    pub fn socks_reply(&self) -> socks::Reply {
        match self {
            Self::Refused(_) => socks::Reply::ConnectionRefused,
            Self::Prohibited(_) => socks::Reply::NotAllowed,
            Self::Unreachable(_) => socks::Reply::HostUnreachable,
            Self::Other(_) => socks::Reply::GeneralFailure,
        }
    }
}

/// A channel the server opened for a remote forward.
pub struct Incoming {
    /// The channel.
    pub stream: TunnelStream,
    /// `originator_address:originator_port`, for logs.
    pub originator: String,
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("originator", &self.originator)
            .finish_non_exhaustive()
    }
}

/// An active remote forward: the port the server listens on and the channels it
/// opens. Dropping it cancels the forward (`cancel-tcpip-forward`).
pub struct RemoteListener {
    /// The port the server listens on (allocated when 0 was requested).
    pub port: u16,
    /// Channels for this forward.
    pub incoming: mpsc::Receiver<Incoming>,
    cancel: Option<Box<dyn FnOnce() + Send>>,
}

impl RemoteListener {
    /// A listener whose drop runs `cancel`.
    pub fn new(
        port: u16,
        incoming: mpsc::Receiver<Incoming>,
        cancel: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            port,
            incoming,
            cancel: Some(Box::new(cancel)),
        }
    }
}

impl Drop for RemoteListener {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

impl fmt::Debug for RemoteListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteListener")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// What a connection offers to forwards: `direct-tcpip` channels and remote
/// (`tcpip-forward`) listeners. Implemented over russh by `ssh_glue`, and by mocks in
/// tests.
#[async_trait]
pub trait Tunnel: Send + Sync + fmt::Debug {
    /// Open a `direct-tcpip` channel to `host:port` (the host is passed unresolved).
    async fn open_direct(
        &self,
        host: &str,
        port: u16,
        originator: SocketAddr,
    ) -> Result<TunnelStream, OpenFailure>;

    /// Ask the server to listen on `addr:port` (`port = 0`: server-allocated).
    async fn listen_remote(&self, addr: &str, port: u16) -> Result<RemoteListener, OpenFailure>;
}

/// A connection that came up (first connect or reconnect), as reported to the hook.
#[derive(Clone)]
pub struct ConnInfo {
    /// The saved host (`None` for an unsaved target: no rules apply).
    pub host_id: Option<ItemId>,
    /// The session carrying it.
    pub session: crate::SessionId,
    /// Tunnel-only (standalone) connection.
    pub standalone: bool,
    /// Channels and listeners.
    pub tunnel: Arc<dyn Tunnel>,
    /// Cancelled when the connection goes away.
    pub token: CancellationToken,
}

impl fmt::Debug for ConnInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnInfo")
            .field("host_id", &self.host_id)
            .field("session", &self.session)
            .field("standalone", &self.standalone)
            .finish_non_exhaustive()
    }
}

/// Told about every SSH connection made by sessions of a
/// [`SessionManager`](crate::SessionManager) with a hook set.
pub trait ForwardHook: Send + Sync + fmt::Debug {
    /// A connection is up. Rules started on it stop when `info.token` is cancelled.
    fn connected(&self, info: ConnInfo);
}

// ---------------------------------------------------------------- splicing

/// Counts bytes through a tunnel stream: reads are `bytes_in`, writes `bytes_out`.
struct Counted {
    inner: TunnelStream,
    live: Arc<Live>,
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.live.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.live.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Splice `local` and `tunnel` until both directions finished (half-close propagated)
/// or `token` is cancelled. `early` is written into the tunnel first (bytes the
/// client sent along with its SOCKS request).
pub(crate) async fn splice(
    mut local: impl AsyncRead + AsyncWrite + Unpin,
    tunnel: TunnelStream,
    early: &[u8],
    live: &Arc<Live>,
    token: &CancellationToken,
) {
    use tokio::io::AsyncWriteExt;
    let mut tunnel = Counted {
        inner: tunnel,
        live: Arc::clone(live),
    };
    if !early.is_empty() && tunnel.write_all(early).await.is_err() {
        return;
    }
    tokio::select! {
        () = token.cancelled() => {}
        res = tokio::io::copy_bidirectional(&mut local, &mut tunnel) => {
            if let Err(err) = res {
                tracing::trace!(%err, "forwarded connection ended with an error");
            }
        }
    }
}
