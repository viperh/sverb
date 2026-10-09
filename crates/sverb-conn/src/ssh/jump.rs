//! Jump hosts (SPEC §6.1.4, §6.1.1 step 2).
//!
//! `jump_chain = [A, B]` connects to A, opens `direct-tcpip` to B on A's connection,
//! runs SSH over that channel (`Channel::into_stream`), and opens `direct-tcpip` to the
//! target on B's connection.
//!
//! - **Hops are hosts.** Each hop is resolved by the connector's
//!   [`HostResolver`](crate::ssh::HostResolver) as a saved host (`SshSpec::host_id`), so it
//!   brings its own credentials, algorithms, keepalive and its own `jump_chain`, which
//!   is expanded recursively (`sverb_core::resolve::expand_by`: cycle detection, at most
//!   [`MAX_JUMP_HOPS`] hops). A resolver error on a hop fails the connection.
//! - **Host keys** are verified per hop under the hop's **own** `address:port` (as the
//!   previous hop reaches it), like OpenSSH `ProxyJump`; the prompt carries
//!   `hop i/n` from the state.
//! - **Proxy:** only the first hop's TCP connection uses a proxy: the first
//!   hop's own proxy setting. The target's proxy is not used behind a chain.
//! - **State:** `Resolved { hops: n }`, then per hop `TcpConnected { hop: i }`, the
//!   handshake and `AuthSucceeded` (which moves on to `Connecting { i + 1, n }`).
//! - **Errors** name the hop: `hop 2/3 (bastion-eu): Permission denied (…)`. The
//!   target's own failures are labelled `hop n/n (target)` too.
//! - **Lifetime:** the hop connections ([`Chain`]) live as long as the session's
//!   transport. When a hop goes down the target's stream ends; the pump then reports
//!   the hop ([`Chain::hop_failure`]): `Connect`, or `Timeout` after a keepalive
//!   timeout.
//! - Hop connections are shared through the multiplexer (`mux.rs`,
//!   `mux_ssh.rs`): the connect flow goes through `mux_ssh::connect`, which uses
//!   [`resolve_hops`], [`open_direct`] and builds the [`Chain`] from the pooled hops
//!   (with `ssh.multiplex = false` the hops of one chain are a private pool).

use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use russh::{
    ChannelStream,
    client::{Handle, Msg},
};
use sverb_core::{
    error_report::ErrorReport,
    model::ItemId,
    resolve::{HopInfo, MAX_JUMP_HOPS, expand_by},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::{
    SshConnector,
    errors::SshError,
    handler::{ClientHandler, EndCause, Shared},
    resolved::SshTarget,
};
use crate::{
    proxy::BoxedIo,
    session::{DisconnectReason, SshSpec},
    transport::{ConnectError, TransportFailure},
};

/// The most host items fetched while expanding one chain (diamonds and deep recursion
/// stay bounded even before the depth check).
const MAX_FETCHED: usize = 64;

/// How long the pump waits for a hop to report it went down after the target's
/// stream ended without an exit status.
const HOP_SETTLE: Duration = Duration::from_millis(500);
const HOP_POLL: Duration = Duration::from_millis(20);

/// `hop 2/3 (bastion-eu)`.
pub(crate) fn hop_prefix(hop: usize, of: usize, label: &str) -> String {
    format!("hop {hop}/{of} ({label})")
}

/// Prefix `err`'s message with [`hop_prefix`]. A close by the user stays as is.
pub(crate) fn label_error(err: ConnectError, hop: usize, of: usize, label: &str) -> ConnectError {
    if err.reason == DisconnectReason::Closed && err.report.is_none() {
        return err;
    }
    let mut report = err
        .report
        .unwrap_or_else(|| ErrorReport::msg(err.reason.message()));
    report.short = format!("{}: {}", hop_prefix(hop, of, label), report.short);
    ConnectError::with_report(err.reason, report)
}

/// One established hop connection.
struct HopConn {
    index: usize,
    label: String,
    handle: Arc<Handle<ClientHandler>>,
    shared: Arc<Shared>,
}

/// The hop connections under a session (in order; the target is not one of them).
pub(crate) struct Chain {
    hops: Vec<HopConn>,
    /// Number of hops including the target.
    of: usize,
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("hops", &self.hops.len())
            .field("of", &self.of)
            .finish()
    }
}

impl Chain {
    /// The first hop that is down, as the session's failure.
    fn down_now(&self) -> Option<TransportFailure> {
        self.hops.iter().find_map(|hop| {
            let end = hop.shared.end.lock().clone();
            if end.is_none() && !hop.handle.is_closed() {
                return None;
            }
            let (reason, what, detail) = match end {
                Some(EndCause::KeepaliveTimeout) => (
                    DisconnectReason::Timeout,
                    "connection lost (no response)".to_owned(),
                    None,
                ),
                Some(EndCause::Remote(msg)) => (
                    DisconnectReason::Connect,
                    "connection closed by the remote host".to_owned(),
                    Some(msg).filter(|m| !m.is_empty()),
                ),
                Some(EndCause::Error(msg)) => (
                    DisconnectReason::Connect,
                    "connection lost".to_owned(),
                    Some(msg),
                ),
                None => (
                    DisconnectReason::Connect,
                    "connection lost".to_owned(),
                    None,
                ),
            };
            let mut report = ErrorReport::msg(format!(
                "{}: {what}",
                hop_prefix(hop.index, self.of, &hop.label)
            ));
            report.chain.extend(detail);
            Some(TransportFailure::new(reason, report))
        })
    }

    /// After the target's stream ended: the hop that went down, if one did (waits up to
    /// [`HOP_SETTLE`] for the hop's connection to notice).
    pub(crate) async fn hop_failure(&self) -> Option<TransportFailure> {
        let deadline = tokio::time::Instant::now() + HOP_SETTLE;
        loop {
            if let Some(failure) = self.down_now() {
                return Some(failure);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(HOP_POLL).await;
        }
    }
}

/// A `direct-tcpip` channel as the byte stream of the next hop's handshake.
struct HopStream(ChannelStream<Msg>);

impl fmt::Debug for HopStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopStream")
    }
}

impl AsyncRead for HopStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for HopStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn chain_error(msg: String) -> ConnectError {
    ConnectError::with_report(DisconnectReason::Connect, ErrorReport::msg(msg))
}

/// The spec that resolves the saved host `id` as a hop.
fn hop_spec(id: ItemId) -> SshSpec {
    SshSpec {
        host_id: Some(id),
        ..SshSpec::default()
    }
}

/// Resolve the effective hops of `target` (recursive expansion), in order.
async fn resolve_hops(
    conn: &SshConnector,
    spec: &SshSpec,
    target: &SshTarget,
) -> Result<Vec<SshTarget>, ConnectError> {
    let fetch = |id: ItemId| async move {
        conn.resolver.resolve(&hop_spec(id)).await.map_err(|e| {
            let mut report = e.report();
            report.short = format!("Jump host {}: {}", id.short(), report.short);
            ConnectError::with_report(e.reason(), report)
        })
    };
    // Fetch every host reachable through the chains (each once), then expand.
    let mut fetched: HashMap<ItemId, SshTarget> = HashMap::new();
    let mut queue: VecDeque<ItemId> = target.jump_chain.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        if fetched.contains_key(&id) || Some(id) == target.host_id.or(spec.host_id) {
            continue;
        }
        if fetched.len() >= MAX_FETCHED {
            return Err(chain_error(format!(
                "Jump chain too deep (> {MAX_JUMP_HOPS})"
            )));
        }
        let hop = fetch(id).await?;
        queue.extend(hop.jump_chain.iter().copied());
        fetched.insert(id, hop);
    }
    let order = expand_by(
        target.host_id.or(spec.host_id),
        &target.label,
        &target.jump_chain,
        |id| {
            let hop = fetched.get(&id)?;
            Some(HopInfo {
                value: (),
                name: hop.label.clone(),
                chain: hop.jump_chain.clone(),
            })
        },
    )
    .map_err(|e| chain_error(e.to_string()))?;
    let mut hops = Vec::with_capacity(order.len());
    for (id, ()) in order {
        // A hop used twice (two branches share it) is resolved again.
        hops.push(match fetched.remove(&id) {
            Some(hop) => hop,
            None => fetch(id).await?,
        });
    }
    Ok(hops)
}

/// Open `direct-tcpip` to `next` on `prev`, as a stream.
async fn open_direct(
    prev: &Handle<ClientHandler>,
    prev_label: &str,
    next: &SshTarget,
) -> Result<BoxedIo, ConnectError> {
    let open =
        prev.channel_open_direct_tcpip(next.address.clone(), u32::from(next.port), "127.0.0.1", 0);
    match tokio::time::timeout(next.connect_timeout, open).await {
        Ok(Ok(channel)) => Ok(Box::new(HopStream(channel.into_stream()))),
        Ok(Err(err)) => Err(ConnectError::with_report(
            DisconnectReason::Connect,
            ErrorReport::from_messages([
                format!(
                    "Could not connect ({}) through {prev_label}",
                    next.display_addr()
                ),
                err.to_string(),
            ]),
        )),
        Err(_) => Err(SshError::Connect {
            addr: next.display_addr(),
            timed_out: true,
            causes: Vec::new(),
        }
        .into_connect_error()),
    }
}

#[cfg(test)]
#[path = "jump_tests.rs"]
mod tests;

// Connection sharing, next to the jump chain it pools (the hops are pooled
// connections). The merge may move these to `ssh/mod.rs` together with `jump`.
#[path = "mux.rs"]
pub(crate) mod mux;
#[path = "mux_ssh.rs"]
pub(crate) mod mux_ssh;
