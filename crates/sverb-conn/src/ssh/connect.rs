//! The connection flow (SPEC §6.1.1): resolve → DNS → TCP (Happy Eyeballs) →
//! handshake (host-key seam) → authentication (seam) → session channel → keepalive.
//!
//! State inputs, in order: `Resolved { hops: 1 }`, `TcpConnected { hop: 1 }`,
//! [`HostKeyNeeded`/`HostKeyAccepted` when the verifier asks], `AuthStarted(m)` (by the
//! authenticator), `AuthSucceeded`; the actor sends `ChannelOpened` once the transport
//! is returned. Failures are returned as [`ConnectError`]s (reason + report, §6.1.9) and
//! the actor moves to `Disconnected`.
//!
//! Hostnames and addresses are logged at `debug` only (§17); `info` logs carry the
//! session id.
//!
//! Hooks for later tasks, in flow order: the first hop's stream comes from
//! forwarding in
//! `channel::open_shell`; auto-start forwards after the shell opens.
//!
//! Steps 2–4 go through the connector's pool (`jump::mux_ssh::connect`): a live
//! connection to the same key is shared (no handshake, no auth; the state goes from
//! `Resolving` to `Connected`), and jump hops are pooled too. The session then holds
//! a lease on the connection; closing it releases the lease (the connection lingers
//! 10 s) instead of disconnecting, unless sharing is off.

use std::{borrow::Cow, sync::Arc, time::Duration};

use bytes::Bytes;
use russh::{SshId, client};
use tokio::{sync::mpsc, time::Instant};
use tracing::{debug, info};

use super::{
    SshConnector, algorithms,
    auth_stub::AuthSession,
    channel::{PumpParts, SshTransport, open_shell},
    errors::{SshError, from_russh},
    handler::{ClientHandler, HostKeyRequest, HostKeyTarget, Shared},
    keepalive::{KEEPALIVE_MAX, keepalive_interval, measure_latency},
    resolved::SshTarget,
};
// Jump chains. Declared here because `ssh/mod.rs` is held by another task;
// the merge moves this to `ssh/mod.rs` as `mod jump;` (see the merge notes).
#[path = "jump.rs"]
pub(super) mod jump;
use crate::forward as fwd;
use crate::proxy::BoxedIo;
use crate::{
    session::{Decision, SessionCmd, SessionEvent, SessionState, SshSpec, StateInput},
    transport::{ConnectCtx, ConnectError, Transport},
};

/// How long a host-key prompt may stay open (§6.1.1 step 3); then the key is rejected.
pub const HOST_KEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

fn fail(err: SshError) -> ConnectError {
    err.into_connect_error()
}

/// The client identification string.
fn client_id() -> SshId {
    SshId::Standard(Cow::Owned(format!(
        "SSH-2.0-sverb_{}",
        env!("CARGO_PKG_VERSION")
    )))
}

/// The russh client config for `host`.
pub(crate) fn client_config(host: &SshTarget, known_key_types: &[String]) -> client::Config {
    let table = algorithms::preferences(&host.algorithms, known_key_types);
    client::Config {
        client_id: client_id(),
        preferred: algorithms::to_russh(&table),
        keepalive_interval: keepalive_interval(host.keepalive_secs),
        keepalive_max: KEEPALIVE_MAX,
        nodelay: true,
        ..client::Config::default()
    }
}

/// Connect `spec` (the [`Connector`](crate::Connector) entry point).
pub(crate) async fn connect(
    conn: &SshConnector,
    spec: &SshSpec,
    ctx: &mut ConnectCtx<'_>,
) -> Result<Box<dyn Transport>, ConnectError> {
    let session = ctx.id();

    // 1. Resolve settings, then DNS (never cached).
    let mut host = conn.resolver.resolve(spec).await.map_err(fail)?;
    // Agent forwarding needs a server for the channels, and forwarding the
    // system agent for a host configured on another device needs approval (§17.1).
    let agent = agent_server(conn, &mut host, session).map_err(fail)?;
    // 2–4. Through the pool: a shared connection, or the first hop's stream
    // (direct TCP with DNS and Happy Eyeballs, or the proxy), the jump chain
    // , handshake and authentication (`agent` serves a new connection's
    // forwarded agent channels).
    let mut connected = jump::mux_ssh::connect(conn, conn.pool(), spec, &host, agent, ctx).await?;

    // A standalone tunnel has no shell channel; forwards ride on the handle.
    if ctx.tunnel_only() {
        let handle = Arc::clone(connected.handle());
        let shared = Arc::clone(connected.shared());
        let guard = fwd::ssh_glue::attach_under(
            ctx,
            spec,
            &handle,
            &shared.forwards,
            Some(connected.token()),
        );
        // The lease (and through it the hops) lives as long as the tunnel.
        let pooled = connected.pooled();
        let guard = jump::mux_ssh::hold(connected.lease, guard);
        info!(%session, "ssh tunnel open");
        let tunnel = fwd::ssh_glue::TunnelTransport::new(handle, Some(guard))
            .with_end(shared, host.keepalive_secs);
        return Ok(Box::new(if pooled {
            tunnel.shared_connection()
        } else {
            tunnel
        }));
    }

    // 5. Session channel: env, pty, shell. A server refusing another session
    // on a shared connection (`MaxSessions`) gets a new connection for this one.
    let timeout = host.connect_timeout;
    let channel = jump::mux_ssh::open_session(conn, &host, &mut connected, ctx).await?;
    let (mut read, write) = channel.split();
    let early = tokio::time::timeout(timeout, open_shell(&mut read, &write, &host, ctx.size()))
        .await
        .map_err(|_| {
            fail(SshError::Channel(
                "no reply to the shell request".to_owned(),
            ))
        })?
        .map_err(fail)?;

    let handle = Arc::clone(connected.handle());
    let shared = Arc::clone(connected.shared());
    let chain = connected.chain.clone();
    let mut info = shared.info.lock().clone();
    info.peer = connected.peer.clone();
    info.keepalive_secs = host.keepalive_secs;
    info.connected_at = Some(sverb_core::model::UnixMillis::now());
    // "shared connection (N channels)" in the info panel.
    info.shared_channels = connected.pooled().then(|| connected.channels());
    ctx.emit(SessionEvent::SshInfo(info));

    // 6–8. Data path, startup input, keepalive latency. (auto-start forwards.)
    let shared_forwards = Arc::clone(&shared.forwards);
    let mut transport = SshTransport::start(
        write,
        Arc::clone(&handle),
        PumpParts {
            read,
            early,
            startup: host.startup_input.clone().map(Bytes::from),
            shared,
            keepalive_secs: host.keepalive_secs,
            chain: chain.clone(),
        },
    );
    // the forwards also stop when the shared connection closes.
    if let Some(guard) = fwd::ssh_glue::attach_under(
        ctx,
        spec,
        &handle,
        &shared_forwards,
        Some(connected.token()),
    ) {
        transport.own_task(guard);
    }
    // The session's lease (and through it the jump hops) lives as long as the
    // transport; closing a shared connection's session only closes its channel.
    transport.set_shared_connection(connected.pooled());
    transport.own_task(jump::mux_ssh::hold(connected.lease, None));
    if let Some(interval) = keepalive_interval(host.keepalive_secs) {
        let pinger = tokio::spawn(measure_latency(handle, interval, ctx.emitter()));
        transport.own_task(pinger.abort_handle());
    }
    info!(%session, "ssh session open");
    Ok(Box::new(transport))
}

/// The agent server for `host`'s forwarded channels; clears `host.agent_forwarding`
/// when there is nothing to serve them with.
fn agent_server(
    conn: &SshConnector,
    host: &mut SshTarget,
    session: crate::SessionId,
) -> Result<Option<crate::agent::AgentServer>, SshError> {
    use crate::{agent, proxy::Approval};
    use sverb_core::model::WireEnum;
    if !host.agent_forwarding {
        return Ok(None);
    }
    let Some(forwarding) = conn.agent_forwarding() else {
        debug!(%session, "agent forwarding configured but not available here");
        host.agent_forwarding = false;
        return Ok(None);
    };
    if agent::needs_approval(true, host.agent_source) {
        let value = host.agent_source.as_wire();
        if conn
            .local_approvals()
            .check(agent::APPROVAL_FIELD, value, &host.agent_origin)
            != Approval::Approved
        {
            return Err(SshError::AgentNeedsApproval {
                host: host.label.clone(),
                source: value.to_owned(),
            });
        }
    }
    Ok(Some(forwarding.for_session(
        host.agent_source,
        &host.label,
        &session.to_string(),
    )))
}

/// Steps 3–4 over `stream`: the SSH handshake (the handler asks the verifier and,
/// through us, the user) and authentication, ending with `AuthSucceeded` (which moves
/// a jump chain on to its next hop). Run once per hop.
pub(super) async fn establish(
    conn: &SshConnector,
    host: &SshTarget,
    stream: BoxedIo,
    ctx: &mut ConnectCtx<'_>,
) -> Result<(client::Handle<ClientHandler>, Arc<Shared>), ConnectError> {
    let target = HostKeyTarget {
        host: host.address.clone(),
        port: host.port,
    };
    // The verifier reloads the known hosts first.
    conn.verifier.prepare(&target).await;
    let config = Arc::new(client_config(host, &conn.verifier.known_key_types(&target)));
    let shared = Arc::new(Shared::default());
    let (prompt_tx, mut prompt_rx) = mpsc::channel::<HostKeyRequest>(1);
    let handler = ClientHandler {
        verifier: Arc::clone(&conn.verifier),
        target,
        prompts: prompt_tx,
        shared: Arc::clone(&shared),
    };
    let handshake = client::connect_stream(config, stream, handler);
    tokio::pin!(handshake);
    let timeout = host.connect_timeout;
    let mut deadline = Instant::now() + timeout;
    let mut handle = loop {
        tokio::select! {
            res = &mut handshake => match res {
                Ok(handle) => break handle,
                Err(err) => return Err(fail(handshake_error(&err.0, &shared, host))),
            },
            Some(request) = prompt_rx.recv() => {
                ask_host_key(ctx, request).await?;
                // The prompt doesn't count against the handshake timeout.
                deadline = Instant::now() + timeout;
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(fail(SshError::HandshakeTimeout { addr: host.display_addr() }));
            }
        }
    };

    conn.auth
        .authenticate(
            &mut AuthSession {
                handle: &mut handle,
            },
            host,
            ctx,
        )
        .await
        .map_err(fail)?;
    ctx.input(StateInput::AuthSucceeded)?;
    Ok((handle, shared))
}

/// Why the handshake failed: a host-key rejection the handler recorded, else russh's
/// error.
fn handshake_error(err: &russh::Error, shared: &Shared, host: &SshTarget) -> SshError {
    if let Some(detail) = shared.host_key_rejection.lock().clone() {
        return SshError::HostKey { detail };
    }
    from_russh(err, host.keepalive_secs, &host.display_addr())
}

/// Ask the user about a host key: `AwaitingHostKey`, `SessionEvent::HostKey`, then wait
/// for `HostKeyDecision` (at most [`HOST_KEY_PROMPT_TIMEOUT`]).
async fn ask_host_key(
    ctx: &mut ConnectCtx<'_>,
    request: HostKeyRequest,
) -> Result<(), ConnectError> {
    let HostKeyRequest {
        verification,
        reply,
    } = request;
    ctx.input(StateInput::HostKeyNeeded(verification.clone()))?;
    let shown = match ctx.state() {
        SessionState::AwaitingHostKey(v) => v.clone(),
        _ => verification,
    };
    ctx.emit(SessionEvent::HostKey(shown));
    let wait = async {
        loop {
            match ctx.next_cmd().await {
                Some(SessionCmd::HostKeyDecision(decision)) => break Some(decision),
                Some(other) => debug!(
                    cmd = other.name(),
                    "ignored while asking about the host key"
                ),
                None => break None,
            }
        }
    };
    match tokio::time::timeout(HOST_KEY_PROMPT_TIMEOUT, wait).await {
        Ok(Some(decision @ (Decision::AcceptAndSave | Decision::AcceptOnce))) => {
            ctx.input(StateInput::HostKeyAccepted)?;
            let _ = reply.send(decision);
            Ok(())
        }
        // Rejected: the handshake fails with a host-key error.
        Ok(Some(decision)) => {
            let _ = reply.send(decision);
            Ok(())
        }
        Ok(None) => {
            let _ = reply.send(Decision::Reject);
            Err(ConnectError::closed())
        }
        Err(_) => {
            let _ = reply.send(Decision::Reject);
            Err(fail(SshError::HostKey {
                detail: "no decision within 120 s".to_owned(),
            }))
        }
    }
}
