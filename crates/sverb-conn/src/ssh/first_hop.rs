//! The first hop's stream (SPEC §6.1.1 step 2, §6.1.5) — the stream factory
//! `connect.rs` asks for the byte stream the SSH handshake runs over.
//!
//! - **Direct:** DNS (never cached), then TCP with Happy Eyeballs under the connect
//!   timeout.
//! - **Proxy:** [`crate::proxy::open_first_hop`] (SOCKS5 with remote DNS, HTTP
//!   CONNECT, ProxyCommand behind the §17.1 approval check). No local DNS of the
//!   target. Jump chains use this for their first hop only.
//!
//! State inputs: `Resolved { hops: 1 }` then `TcpConnected { hop: 1 }`, either way.

use tracing::{debug, info};

use super::{
    SshConnector,
    errors::SshError,
    resolved::SshTarget,
    tcp::{TcpError, connect_tcp, lookup},
};
use crate::{
    proxy::{BoxedIo, HopTarget, open_first_hop},
    session::StateInput,
    transport::{ConnectCtx, ConnectError},
};

fn fail(err: SshError) -> ConnectError {
    err.into_connect_error()
}

/// The first hop to `host`: its stream and the peer shown in the session info.
///
/// # Errors
/// DNS, TCP or proxy failures as [`ConnectError`]s (§6.1.9).
pub async fn open(
    conn: &SshConnector,
    host: &SshTarget,
    ctx: &mut ConnectCtx<'_>,
) -> Result<(BoxedIo, String), ConnectError> {
    open_first_of(conn, host, 1, ctx).await
}

/// [`open`] for the first hop of a chain of `hops` hops (`Resolved { hops }`): a jump
/// chain's first hop is reached directly or through *its* proxy, like any host.
///
/// # Errors
/// As [`open`].
pub async fn open_first_of(
    conn: &SshConnector,
    host: &SshTarget,
    hops: usize,
    ctx: &mut ConnectCtx<'_>,
) -> Result<(BoxedIo, String), ConnectError> {
    let session = ctx.id();
    if let Some(proxy) = &host.proxy {
        ctx.input(StateInput::Resolved { hops })?;
        info!(%session, kind = proxy.kind(), "connecting through a proxy");
        let hop = open_first_hop(
            proxy,
            HopTarget {
                host: &host.address,
                port: host.port,
                user: &host.username,
                label: &host.label,
            },
            host.connect_timeout,
            conn.local_approvals(),
        )
        .await
        .map_err(fail)?;
        debug!(%session, peer = %hop.peer, "proxy connected");
        ctx.input(StateInput::TcpConnected { hop: 1 })?;
        return Ok((hop.stream, hop.peer));
    }

    debug!(%session, host = %host.address, port = host.port, "resolving");
    let addrs = lookup(&host.address, host.port).await.map_err(|source| {
        fail(SshError::Resolve {
            host: host.address.clone(),
            source,
        })
    })?;
    ctx.input(StateInput::Resolved { hops })?;

    info!(%session, addresses = addrs.len(), "connecting");
    let (stream, peer) = connect_tcp(&addrs, host.connect_timeout)
        .await
        .map_err(|err| {
            let addr = host.display_addr();
            fail(match err {
                TcpError::TimedOut => SshError::Connect {
                    addr,
                    timed_out: true,
                    causes: Vec::new(),
                },
                TcpError::Failed(failure) => SshError::Connect {
                    addr,
                    timed_out: false,
                    causes: failure.errors,
                },
            })
        })?;
    debug!(%session, %peer, "tcp connected");
    ctx.input(StateInput::TcpConnected { hop: 1 })?;
    Ok((Box::new(stream), peer.to_string()))
}
