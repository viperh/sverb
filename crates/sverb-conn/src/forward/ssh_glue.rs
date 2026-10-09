//! The russh side of forwarding: [`Tunnel`] over a russh client handle, the
//! `forwarded-tcpip` dispatch the handler calls, the per-connection hook the connect
//! flow calls, and the tunnel-only transport for standalone connections.
//!
//! (`ssh/` keeps the connection flow; this file is the forwarding counterpart and the
//! only russh user outside `ssh/`. The two hooks there are a few lines each.)

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use russh::{
    Channel, ChannelOpenFailure, Disconnect,
    client::{ChannelOpenHandle, Handle, Msg},
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{ConnInfo, Incoming, OpenFailure, RemoteListener, RemoteRoutes, Tunnel, TunnelStream};
use crate::{
    session::SshSpec,
    ssh::handler::{ClientHandler, Shared},
    transport::{ConnectCtx, Transport, TransportKind},
};

/// A russh connection as a [`Tunnel`].
pub(crate) struct SshTunnel {
    handle: Arc<Handle<ClientHandler>>,
    routes: Arc<RemoteRoutes>,
}

impl std::fmt::Debug for SshTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTunnel").finish_non_exhaustive()
    }
}

fn open_failure(err: russh::Error) -> OpenFailure {
    match err {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => {
            OpenFailure::Refused("connect failed".to_owned())
        }
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => {
            OpenFailure::Prohibited("administratively prohibited".to_owned())
        }
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::Other { reason, .. })
            if reason.to_ascii_lowercase().contains("unreachable") =>
        {
            OpenFailure::Unreachable(reason)
        }
        russh::Error::RequestDenied => OpenFailure::Prohibited("request denied".to_owned()),
        other => OpenFailure::Other(other.to_string()),
    }
}

#[async_trait]
impl Tunnel for SshTunnel {
    async fn open_direct(
        &self,
        host: &str,
        port: u16,
        originator: SocketAddr,
    ) -> Result<TunnelStream, OpenFailure> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(
                host,
                u32::from(port),
                originator.ip().to_string(),
                u32::from(originator.port()),
            )
            .await
            .map_err(open_failure)?;
        Ok(Box::new(channel.into_stream()))
    }

    async fn listen_remote(&self, addr: &str, port: u16) -> Result<RemoteListener, OpenFailure> {
        let rx = self.routes.add(addr, u32::from(port));
        let got = match self.handle.tcpip_forward(addr, u32::from(port)).await {
            Ok(got) => got,
            Err(err) => {
                self.routes.remove(addr, u32::from(port));
                return Err(match err {
                    russh::Error::RequestDenied => {
                        OpenFailure::Prohibited("the server refused the remote forward".to_owned())
                    }
                    other => open_failure(other),
                });
            }
        };
        let bound = if port == 0 {
            let bound = u16::try_from(got).unwrap_or(0);
            self.routes.rekey(addr, 0, u32::from(bound));
            bound
        } else {
            port
        };
        let (handle, routes, addr) = (
            Arc::clone(&self.handle),
            Arc::clone(&self.routes),
            addr.to_owned(),
        );
        Ok(RemoteListener::new(bound, rx, move || {
            routes.remove(&addr, u32::from(bound));
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    if let Err(err) = handle.cancel_tcpip_forward(addr, u32::from(bound)).await {
                        debug!(%err, "cancel-tcpip-forward failed");
                    }
                });
            }
        }))
    }
}

/// The handler's `server_channel_open_forwarded_tcpip`: hand the channel to the
/// matching rule, or reject it.
pub(crate) async fn on_forwarded(
    routes: &RemoteRoutes,
    channel: Channel<Msg>,
    connected_address: &str,
    connected_port: u32,
    originator: String,
    reply: ChannelOpenHandle,
) {
    match routes.lookup(connected_address, connected_port) {
        Some(tx) if !tx.is_closed() => {
            reply.accept().await;
            let incoming = Incoming {
                stream: Box::new(channel.into_stream()),
                originator,
            };
            if tx.try_send(incoming).is_err() {
                debug!("remote forward queue full; channel closed");
            }
        }
        _ => {
            debug!(
                port = connected_port,
                "forwarded-tcpip channel for no rule; rejected"
            );
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        }
    }
}

fn host_id(spec: &SshSpec) -> Option<sverb_core::model::ItemId> {
    spec.host_id
}

/// The connect flow's hook, after the session channel (or, tunnel-only, after
/// authentication): report the connection to the forward hook. Returns the guard
/// task to own: when the transport drops, the task is aborted and the connection's
/// token is cancelled.
#[allow(dead_code)] // connect.rs calls `attach_under` after the merge.
pub(crate) fn attach(
    ctx: &ConnectCtx<'_>,
    spec: &SshSpec,
    handle: &Arc<Handle<ClientHandler>>,
    routes: &Arc<RemoteRoutes>,
) -> Option<tokio::task::AbortHandle> {
    attach_under(ctx, spec, handle, routes, None)
}

/// [`attach`] on a shared connection: the forwards' token is a child of `parent` (the
/// connection's token), so they also stop when the connection closes.
pub(crate) fn attach_under(
    ctx: &ConnectCtx<'_>,
    spec: &SshSpec,
    handle: &Arc<Handle<ClientHandler>>,
    routes: &Arc<RemoteRoutes>,
    parent: Option<&CancellationToken>,
) -> Option<tokio::task::AbortHandle> {
    let hook = ctx.forwards.clone()?;
    let token = parent.map_or_else(CancellationToken::new, CancellationToken::child_token);
    let guard = token.clone().drop_guard();
    let task = tokio::spawn(async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
    hook.connected(ConnInfo {
        host_id: host_id(spec),
        session: ctx.id(),
        standalone: ctx.tunnel_only,
        tunnel: Arc::new(SshTunnel {
            handle: Arc::clone(handle),
            routes: Arc::clone(routes),
        }),
        token,
    });
    Some(task.abort_handle())
}

/// How often the tunnel-only reader checks whether the connection closed.
const CLOSED_POLL: Duration = Duration::from_millis(250);

/// A standalone connection's [`Transport`]: no shell channel; input is discarded and
/// the reader ends (`Ok(0)`) when the SSH connection closes.
pub(crate) struct TunnelTransport {
    handle: Arc<Handle<ClientHandler>>,
    reader: ClosedReader,
    guard: Option<tokio::task::AbortHandle>,
    closed: bool,
    // The connection is shared; closing the tunnel only releases it.
    shared: bool,
}

impl std::fmt::Debug for TunnelTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelTransport")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl TunnelTransport {
    /// Wrap `handle`; `guard` is the hook's guard task (aborted on drop).
    pub(crate) fn new(
        handle: Arc<Handle<ClientHandler>>,
        guard: Option<tokio::task::AbortHandle>,
    ) -> Self {
        Self {
            reader: ClosedReader {
                handle: Arc::clone(&handle),
                sleep: Box::pin(tokio::time::sleep(CLOSED_POLL)),
                end: None,
            },
            handle,
            guard,
            closed: false,
            shared: false,
        }
    }

    /// The connection is shared with other users (`ssh.multiplex`): `close` releases
    /// it (the guard holds the lease) instead of disconnecting.
    #[must_use]
    pub(crate) fn shared_connection(mut self) -> Self {
        self.shared = true;
        self
    }

    /// When the connection ends, report why (`shared.end`, as a shell channel on the
    /// same connection does), so every user of a shared connection disconnects with
    /// the same reason. Without it the reader just ends.
    #[must_use]
    pub(crate) fn with_end(mut self, shared: Arc<Shared>, keepalive_secs: u32) -> Self {
        self.reader.end = Some((shared, keepalive_secs));
        self
    }
}

impl Drop for TunnelTransport {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.abort();
        }
    }
}

struct ClosedReader {
    handle: Arc<Handle<ClientHandler>>,
    sleep: Pin<Box<tokio::time::Sleep>>,
    // The connection's end cause and keepalive interval.
    end: Option<(Arc<Shared>, u32)>,
}

impl AsyncRead for ClosedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.handle.is_closed() {
                // The same reason as the connection's other users.
                if let Some((shared, keepalive_secs)) = &self.end
                    && let Some(err) = crate::ssh::channel::connection_end(shared, *keepalive_secs)
                {
                    return Poll::Ready(Err(err));
                }
                return Poll::Ready(Ok(()));
            }
            match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    let next = tokio::time::Instant::now() + CLOSED_POLL;
                    self.sleep.as_mut().reset(next);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

use std::future::Future as _;

#[async_trait]
impl Transport for TunnelTransport {
    async fn write(&mut self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn resize(&mut self, _cols: u16, _rows: u16) -> io::Result<()> {
        Ok(())
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut self.reader
    }

    async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // A shared connection stays up for its other users.
        if self.shared {
            if let Some(guard) = self.guard.take() {
                guard.abort();
            }
            return Ok(());
        }
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Ssh
    }
}
