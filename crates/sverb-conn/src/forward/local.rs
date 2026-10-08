//! Local forwards (`-L`, §9.6): accept on the bound listener, open
//! `direct-tcpip(dest_host, dest_port, peer_ip, peer_port)` per connection, splice.
//! At [`MAX_CHANNELS`](super::MAX_CHANNELS) further accepts are closed at once.

use std::sync::Arc;

use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{Live, Tunnel, splice};

/// Accept loop of a local rule; ends when `token` is cancelled.
pub(crate) async fn run(
    listener: TcpListener,
    dest_host: String,
    dest_port: u16,
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
        let (stream, peer) = match accepted {
            Ok(a) => a,
            Err(err) => {
                debug!(%err, "accept failed");
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&cap).try_acquire_owned() else {
            // At the cap: accept and close immediately.
            live.refuse();
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let guard = live.opened();
        let (tunnel, live, token) = (Arc::clone(&tunnel), Arc::clone(&live), token.clone());
        let host = dest_host.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            let channel = tokio::select! {
                () = token.cancelled() => return,
                c = tunnel.open_direct(&host, dest_port, peer) => c,
            };
            match channel {
                Ok(channel) => splice(stream, channel, &[], &live, &token).await,
                Err(err) => debug!(%err, "direct-tcpip refused"),
            }
        });
    }
}
