//! Dynamic forwards (`-D`, §9.6): a SOCKS5/SOCKS4a server on the bound listener.
//! Each client runs the handshake in `socks_server` and is spliced to its
//! `direct-tcpip` channel. At [`MAX_CHANNELS`](super::MAX_CHANNELS), new clients get a
//! failure reply (`0x01` / `0x5B`) and are closed.

use std::sync::Arc;

use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{Live, Tunnel, socks_server::handshake, splice};

/// Accept loop of a dynamic rule; ends when `token` is cancelled.
pub(crate) async fn run(
    listener: TcpListener,
    tunnel: Arc<dyn Tunnel>,
    live: Arc<Live>,
    token: CancellationToken,
) {
    let cap = Arc::new(Semaphore::new(super::MAX_CHANNELS));
    loop {
        let accepted = tokio::select! {
            () = token.cancelled() => return,
            a = listener.accept() => a,
        };
        let (mut stream, peer) = match accepted {
            Ok(a) => a,
            Err(err) => {
                debug!(%err, "accept failed");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let (tunnel, live, token) = (Arc::clone(&tunnel), Arc::clone(&live), token.clone());
        let Ok(permit) = Arc::clone(&cap).try_acquire_owned() else {
            live.refuse();
            // Answer with a failure (bounded by the handshake timeout), then close.
            tokio::spawn(async move {
                tokio::select! {
                    () = token.cancelled() => {}
                    _ = handshake(&mut stream, peer, tunnel.as_ref(), true) => {}
                }
            });
            continue;
        };
        let guard = live.opened();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            let res = tokio::select! {
                () = token.cancelled() => return,
                r = handshake(&mut stream, peer, tunnel.as_ref(), false) => r,
            };
            match res {
                Ok((channel, early)) => splice(stream, channel, &early, &live, &token).await,
                Err(err) => debug!(%err, "SOCKS request failed"),
            }
        });
    }
}
