//! The russh side of connection sharing (SPEC §6.1.3, §6.1.4).
//!
//! [`connect`] reaches the target through the pool: every hop of the jump chain and
//! the target itself is a pooled [`SshConn`] under its [`MuxKey`] (a hop's key holds
//! the previous hop's key, so the chain is part of the key). A hop's connection holds
//! a lease on the hop before it (its stream is a `direct-tcpip` channel there), so a
//! session's lease on the target keeps the whole chain up, and two targets behind the
//! same bastion share the bastion connection.
//!
//! - **Plan.** The deepest live connection along the chain is looked up first (the
//!   target itself: nothing to dial; a hop: dial only what follows it). The rest is
//!   claimed hop by hop ([`Pool::claim`]): concurrent sessions dial each key once.
//! - **State.** A reused connection skips its states. The flow reports
//!   `Resolved { hops: m }` (`m`: the connections left to dial) and, per dialed
//!   connection, `TcpConnected { hop: i }`, the handshake and `AuthSucceeded`, with `i`
//!   counting dialed connections only. A fully shared target goes from `Resolving`
//!   straight to `Connected`; a connection another session finished dialing while
//!   this one waited leaves the state at `Connecting`, which `ChannelOpened` also
//!   accepts (state.rs). Errors keep the absolute hop labels (`hop 2/3 (bastion)`).
//! - **Channels.** [`open_session`] opens the shell channel. When the server refuses
//!   it on a shared connection (OpenSSH `MaxSessions`: `open failed`,
//!   administratively prohibited), the connection is marked full and a new connection
//!   to the target is dialed for this session (over the same hops); later sessions
//!   prefer the newer one.
//! - **Failure.** Every channel of a connection sees the same `Shared::end` (the
//!   handler records why the connection ended), so all sessions on it disconnect with
//!   the same reason; [`SshConn`]'s [`MuxConn::down`] reports it to the pool (and a
//!   hop's failure takes the connections behind it down too).
//! - **`ssh.multiplex = false`:** a private pool per connect; only the hops of one
//!   chain share (there is nothing to share within one chain), and closing the
//!   session disconnects at once.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use russh::{
    Channel, ChannelOpenFailure, Disconnect,
    client::{Handle, Msg},
};
use sverb_core::error_report::ErrorReport;
use tokio::task::AbortHandle;
use tracing::{debug, info};

use super::{
    Chain, HopConn, label_error,
    mux::{Lease, MuxConn, MuxKey, Pool, Slot},
    open_direct, resolve_hops,
};
use crate::{
    proxy::ProxyConfig,
    session::{DisconnectReason, SshSpec, StateInput},
    ssh::{
        SshConnector,
        connect::establish,
        errors::{SshError, from_russh},
        first_hop,
        handler::{ClientHandler, EndCause, Shared},
        resolved::SshTarget,
    },
    transport::{ConnectCtx, ConnectError, TransportFailure},
};

/// The connector's pool of SSH connections.
pub(crate) type SshPool = Pool<SshConn>;
/// One user of a pooled SSH connection.
pub(crate) type SshLease = Lease<SshConn>;

fn fail(err: SshError) -> ConnectError {
    err.into_connect_error()
}

/// One pooled SSH connection: a hop or a target.
pub(crate) struct SshConn {
    pub(crate) handle: Arc<Handle<ClientHandler>>,
    pub(crate) shared: Arc<Shared>,
    /// The hop this connection runs over (kept up while this connection lives).
    pub(crate) parent: Option<SshLease>,
    /// Position in its chain (1 for a direct connection).
    pub(crate) index: usize,
    /// The host's label (hop error messages).
    pub(crate) label: String,
    /// The socket address of the chain's first connection.
    pub(crate) root_peer: String,
    keepalive_secs: u32,
}

impl std::fmt::Debug for SshConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConn")
            .field("index", &self.index)
            .field("closed", &self.handle.is_closed())
            .finish_non_exhaustive()
    }
}

impl MuxConn for SshConn {
    fn down(&self) -> Option<TransportFailure> {
        if let Some(parent) = &self.parent
            && let Some(failure) = parent.failure()
        {
            return Some(failure);
        }
        let end = self.shared.end.lock().clone();
        if end.is_none() && !self.handle.is_closed() {
            return None;
        }
        Some(match end {
            Some(EndCause::KeepaliveTimeout) => TransportFailure::new(
                DisconnectReason::Timeout,
                SshError::KeepaliveTimeout {
                    interval_secs: self.keepalive_secs,
                }
                .report(),
            ),
            Some(EndCause::Error(msg)) => TransportFailure::new(
                DisconnectReason::Connect,
                ErrorReport::from_messages(["SSH connection failed".to_owned(), msg]),
            ),
            Some(EndCause::Remote(msg)) => {
                let mut report = ErrorReport::msg("Connection closed by the remote host");
                report.chain.extend(Some(msg).filter(|m| !m.is_empty()));
                TransportFailure::new(DisconnectReason::Connect, report)
            }
            None => TransportFailure::new(
                DisconnectReason::Connect,
                ErrorReport::msg("Connection lost"),
            ),
        })
    }

    fn close(&self) {
        let handle = Arc::clone(&self.handle);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            });
        }
    }
}

/// The pool key of `host`, reached through `via` (`None`: directly).
pub(crate) fn key_for(host: &SshTarget, via: Option<&MuxKey>) -> MuxKey {
    let mut key = MuxKey::new(&host.address, host.port, &host.username)
        .identity(identity_of(host))
        .options(format!(
            "agent={}:{:?};algorithms={:?}",
            host.agent_forwarding, host.agent_source, host.algorithms
        ));
    match via {
        Some(prev) => key = key.via(prev),
        // Behind a chain the host's own proxy is not used, so it is not part
        // of the key there.
        None => {
            if let Some(proxy) = &host.proxy {
                key = key.proxy(proxy_of(proxy));
            }
        }
    }
    key
}

/// The proxy as it identifies the path (never its password).
fn proxy_of(proxy: &ProxyConfig) -> String {
    match proxy {
        ProxyConfig::Socks5 { addr, auth } => format!(
            "socks5 {addr} {}",
            auth.as_ref().map(|a| a.user.as_str()).unwrap_or_default()
        ),
        ProxyConfig::Http { addr, auth } => format!(
            "http {addr} {}",
            auth.as_ref().map(|a| a.user.as_str()).unwrap_or_default()
        ),
        ProxyConfig::Command { command, .. } => format!("command {command}"),
    }
}

/// The authentication identity: the key item (or a digest of an inline key), the
/// identity item, certificates, and whether the system agent may be used. No secret.
fn identity_of(host: &SshTarget) -> String {
    let auth = &host.auth;
    let key = match &auth.key {
        Some(material) => match material.key_id {
            Some(id) => format!("{id:?}"),
            None => {
                let mut h = DefaultHasher::new();
                material.private_key.expose().hash(&mut h);
                material.certificates.hash(&mut h);
                format!("inline:{:016x}", h.finish())
            }
        },
        None => format!("{:?}", auth.key_id),
    };
    format!(
        "key={key};identity={:?};agent={}",
        auth.identity_id, auth.use_system_agent
    )
}

/// Connections dialed by one connect, for the state inputs.
#[derive(Debug)]
struct Progress {
    /// `Resolved { hops: plan }`.
    plan: usize,
    /// Connections dialed so far.
    dialed: usize,
    /// `Resolved` was reported.
    resolved: bool,
}

/// The target's connection, ready for channels.
pub(crate) struct Connected {
    /// This session's lease on the target connection.
    pub(crate) lease: SshLease,
    /// The hops (for hop failure messages); `None`: direct.
    pub(crate) chain: Option<Arc<Chain>>,
    /// The peer shown in the session info.
    pub(crate) peer: String,
    key: MuxKey,
    pool: SshPool,
    of: usize,
    target_addr: String,
    progress: Progress,
    agent: Option<crate::agent::AgentServer>,
}

impl std::fmt::Debug for Connected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connected")
            .field("lease", &self.lease)
            .field("of", &self.of)
            .finish_non_exhaustive()
    }
}

impl Connected {
    /// The russh handle of the target connection.
    pub(crate) fn handle(&self) -> &Arc<Handle<ClientHandler>> {
        &self.lease.conn().handle
    }

    /// The target connection's shared state.
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.lease.conn().shared
    }

    /// Whether the connection is shared with other sessions (`ssh.multiplex`): closing
    /// this session must then not disconnect it.
    pub(crate) fn pooled(&self) -> bool {
        self.pool.is_enabled()
    }

    /// The connection's channels (users), for the session info panel.
    pub(crate) fn channels(&self) -> usize {
        self.lease.users()
    }

    /// The token cancelled when the connection closes (the parent of its forwards).
    pub(crate) fn token(&self) -> &tokio_util::sync::CancellationToken {
        self.lease.token()
    }

    fn rebuild(&mut self) {
        let (chain, peer) = describe(&self.lease, self.of, self.target_addr.clone());
        self.chain = chain;
        self.peer = peer;
    }
}

/// The chain under `lease` and the peer text.
fn describe(lease: &SshLease, of: usize, target_addr: String) -> (Option<Arc<Chain>>, String) {
    let root = lease.conn().root_peer.clone();
    if of <= 1 {
        return (None, root);
    }
    let mut hops = Vec::with_capacity(of - 1);
    let mut next = lease.conn().parent.as_ref();
    while let Some(hop) = next {
        let c = hop.conn();
        hops.push(HopConn {
            index: c.index,
            label: c.label.clone(),
            handle: Arc::clone(&c.handle),
            shared: Arc::clone(&c.shared),
        });
        next = c.parent.as_ref();
    }
    hops.reverse();
    (
        Some(Arc::new(Chain { hops, of })),
        format!("{target_addr} via {root}"),
    )
}

/// Connect to `host` through `pool` (see the module docs): the target's connection,
/// shared or new. `agent` serves the forwarded agent channels of a new connection.
///
/// # Errors
/// Chain expansion and every dialed connection's failures (labelled with the hop).
pub(crate) async fn connect(
    conn: &SshConnector,
    pool: &SshPool,
    spec: &SshSpec,
    host: &SshTarget,
    mut agent: Option<crate::agent::AgentServer>,
    ctx: &mut ConnectCtx<'_>,
) -> Result<Connected, ConnectError> {
    let session = ctx.id();
    let pool = if pool.is_enabled() {
        pool.clone()
    } else {
        SshPool::private()
    };
    let hops = if host.jump_chain.is_empty() {
        Vec::new()
    } else {
        resolve_hops(conn, spec, host).await?
    };
    let of = hops.len() + 1;
    let mut keys: Vec<MuxKey> = Vec::with_capacity(of);
    for target in hops.iter().chain(std::iter::once(host)) {
        let key = key_for(target, keys.last());
        keys.push(key);
    }
    let target_addr = host.display_addr();
    let finish = |lease: SshLease, progress, agent| {
        let (chain, peer) = describe(&lease, of, target_addr.clone());
        Connected {
            lease,
            chain,
            peer,
            key: keys[of - 1].clone(),
            pool: pool.clone(),
            of,
            target_addr: target_addr.clone(),
            progress,
            agent,
        }
    };

    // The deepest live connection along the chain.
    if let Some(lease) = pool.lookup(&keys[of - 1]) {
        info!(%session, channels = lease.users(), "ssh connection shared");
        let progress = Progress {
            plan: 1,
            dialed: 0,
            resolved: false,
        };
        return Ok(finish(lease, progress, agent));
    }
    let (mut start, mut prev) = (0, None);
    for i in (0..of - 1).rev() {
        if let Some(lease) = pool.lookup(&keys[i]) {
            debug!(%session, hop = i + 1, "jump hop connection shared");
            (start, prev) = (i + 1, Some(lease));
            break;
        }
    }
    if of > 1 && start == 0 {
        info!(%session, hops = of - 1, "connecting through jump hosts");
    }
    let mut progress = Progress {
        plan: of - start,
        dialed: 0,
        resolved: false,
    };
    for i in start..of {
        let is_target = i + 1 == of;
        let target = if is_target { host } else { &hops[i] };
        let lease = match pool.claim(&keys[i]).await {
            Slot::Found(lease) => {
                debug!(%session, hop = i + 1, "connection shared (dialed meanwhile)");
                lease
            }
            Slot::Vacant(guard) => {
                let agent = if is_target { agent.take() } else { None };
                let dialed = dial(
                    conn,
                    target,
                    i + 1,
                    of,
                    prev.take(),
                    agent,
                    &mut progress,
                    ctx,
                )
                .await?;
                guard.register(dialed)
            }
        };
        prev = Some(lease);
    }
    let Some(lease) = prev else {
        // Unreachable: the loop ran at least for the target.
        return Err(ConnectError::new(DisconnectReason::Internal));
    };
    Ok(finish(lease, progress, agent))
}

/// Dial one connection: the first hop's stream (direct or proxy) or `direct-tcpip`
/// on `parent`, then the handshake and authentication.
#[allow(clippy::too_many_arguments)]
async fn dial(
    conn: &SshConnector,
    target: &SshTarget,
    index: usize,
    of: usize,
    parent: Option<SshLease>,
    agent: Option<crate::agent::AgentServer>,
    progress: &mut Progress,
    ctx: &mut ConnectCtx<'_>,
) -> Result<SshConn, ConnectError> {
    let label = |e: ConnectError| {
        if of > 1 {
            label_error(e, index, of, &target.label)
        } else {
            e
        }
    };
    let step = progress.dialed + 1;
    let (stream, root_peer) = match &parent {
        None => first_hop::open_first_of(conn, target, progress.plan, ctx)
            .await
            .map_err(label)?,
        Some(hop) => {
            if !progress.resolved {
                ctx.input(StateInput::Resolved {
                    hops: progress.plan,
                })?;
            }
            let hop = hop.conn();
            let stream = open_direct(&hop.handle, &hop.label, target)
                .await
                .map_err(label)?;
            debug!(session = %ctx.id(), hop = index, "direct-tcpip channel open");
            ctx.input(StateInput::TcpConnected { hop: step })?;
            (stream, hop.root_peer.clone())
        }
    };
    progress.resolved = true;
    let (handle, shared) = establish(conn, target, stream, ctx).await.map_err(label)?;
    progress.dialed = step;
    // The agent server of the session that dialed.
    *shared.agent.lock() = agent;
    Ok(SshConn {
        handle: Arc::new(handle),
        shared,
        parent,
        index,
        label: target.label.clone(),
        root_peer,
        keepalive_secs: target.keepalive_secs,
    })
}

/// The server refused a session channel because of a limit (OpenSSH `MaxSessions`
/// answers `open failed`, administratively prohibited).
pub(crate) fn is_session_limit(err: &russh::Error) -> bool {
    matches!(
        err,
        russh::Error::ChannelOpenFailure(
            ChannelOpenFailure::AdministrativelyProhibited
                | ChannelOpenFailure::ResourceShortage
                | ChannelOpenFailure::ConnectFailed
        )
    ) || matches!(
        err,
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::Other { reason, .. })
            if reason.to_ascii_lowercase().contains("open failed")
    )
}

async fn try_open(
    handle: &Handle<ClientHandler>,
    host: &SshTarget,
) -> Result<Result<Channel<Msg>, russh::Error>, ConnectError> {
    tokio::time::timeout(host.connect_timeout, handle.channel_open_session())
        .await
        .map_err(|_| {
            fail(SshError::HandshakeTimeout {
                addr: host.display_addr(),
            })
        })
}

/// Open a session channel on the target connection; on a shared connection the
/// server refused (`MaxSessions`), dial a new connection for this session and retry
/// once (see the module docs).
///
/// # Errors
/// The channel could not be opened (§6.1.9), or the new connection failed.
pub(crate) async fn open_session(
    conn: &SshConnector,
    host: &SshTarget,
    connected: &mut Connected,
    ctx: &mut ConnectCtx<'_>,
) -> Result<Channel<Msg>, ConnectError> {
    let russh_err =
        |e: &russh::Error| fail(from_russh(e, host.keepalive_secs, &host.display_addr()));
    let err = match try_open(connected.handle(), host).await? {
        Ok(channel) => return Ok(channel),
        Err(err) => err,
    };
    if !is_session_limit(&err) || connected.lease.fresh() {
        return Err(russh_err(&err));
    }
    info!(
        session = %ctx.id(),
        channels = connected.lease.users(),
        "the server refused another session on the shared connection; opening a new connection"
    );
    connected.lease.mark_full();
    let guard = connected.pool.claim_fresh(&connected.key);
    let parent = connected.lease.conn().parent.clone();
    let agent = connected.agent.take();
    let of = connected.of;
    let dialed = dial(
        conn,
        host,
        of,
        of,
        parent,
        agent,
        &mut connected.progress,
        ctx,
    )
    .await?;
    connected.lease = guard.register(dialed);
    connected.rebuild();
    try_open(connected.handle(), host)
        .await?
        .map_err(|e| russh_err(&e))
}

/// A task that keeps `lease` (and `guard`'s task) until it is aborted.
pub(crate) fn hold(lease: SshLease, guard: Option<AbortHandle>) -> AbortHandle {
    struct AbortOnDrop(Option<AbortHandle>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            if let Some(task) = self.0.take() {
                task.abort();
            }
        }
    }
    let inner = AbortOnDrop(guard);
    let task = tokio::spawn(async move {
        let _keep = (lease, inner);
        std::future::pending::<()>().await;
    });
    task.abort_handle()
}
