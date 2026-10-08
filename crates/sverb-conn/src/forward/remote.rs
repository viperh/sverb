//! Remote forwards (`-R`, §9.6).
//!
//! [`RemoteRoutes`] is the per-connection table the russh handler consults for each
//! `forwarded-tcpip` channel: it is matched to a rule by `(connected_address,
//! connected_port)` (falling back to the port alone when exactly one route uses it,
//! since servers normalise the address differently) and handed to that rule's task;
//! unmatched channels are rejected. The rule's task connects to `dest_host:dest_port`
//! locally and splices. Dropping the [`RemoteListener`](super::RemoteListener) sends
//! `cancel-tcpip-forward`.

use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use tokio::{
    net::TcpStream,
    sync::{Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{Incoming, Live, RemoteListener, splice};

/// Channels queued per remote rule before new ones are rejected.
const QUEUE: usize = 32;

/// Routes from `(address, port)` to the rule tasks of one connection.
#[derive(Debug, Default)]
pub struct RemoteRoutes {
    routes: Mutex<HashMap<(String, u32), mpsc::Sender<Incoming>>>,
}

impl RemoteRoutes {
    /// Register a route; returns the receiving end.
    pub(crate) fn add(&self, addr: &str, port: u32) -> mpsc::Receiver<Incoming> {
        let (tx, rx) = mpsc::channel(QUEUE);
        self.routes.lock().insert((addr.to_owned(), port), tx);
        rx
    }

    /// Move a route to another port (a server-allocated one).
    pub(crate) fn rekey(&self, addr: &str, from: u32, to: u32) {
        let mut routes = self.routes.lock();
        if let Some(tx) = routes.remove(&(addr.to_owned(), from)) {
            routes.insert((addr.to_owned(), to), tx);
        }
    }

    /// Remove a route.
    pub(crate) fn remove(&self, addr: &str, port: u32) {
        self.routes.lock().remove(&(addr.to_owned(), port));
    }

    /// The sender for a `forwarded-tcpip` channel, if a rule matches.
    pub(crate) fn lookup(&self, addr: &str, port: u32) -> Option<mpsc::Sender<Incoming>> {
        let routes = self.routes.lock();
        if let Some(tx) = routes.get(&(addr.to_owned(), port)) {
            return Some(tx.clone());
        }
        let mut by_port = routes.iter().filter(|((_, p), _)| *p == port);
        match (by_port.next(), by_port.next()) {
            (Some((_, tx)), None) => Some(tx.clone()),
            _ => None,
        }
    }

    /// Whether a channel for `addr:port` would be accepted.
    pub fn matches(&self, addr: &str, port: u32) -> bool {
        self.lookup(addr, port).is_some_and(|tx| !tx.is_closed())
    }
}

/// The loop of a remote rule: connect each incoming channel to `dest` and splice.
pub(crate) async fn run(
    mut listener: RemoteListener,
    dest_host: String,
    dest_port: u16,
    live: Arc<Live>,
    token: CancellationToken,
) {
    let cap = Arc::new(Semaphore::new(super::MAX_CHANNELS));
    loop {
        let incoming = tokio::select! {
            () = token.cancelled() => break,
            i = listener.incoming.recv() => i,
        };
        let Some(Incoming { stream, originator }) = incoming else {
            break;
        };
        let Ok(permit) = Arc::clone(&cap).try_acquire_owned() else {
            live.refuse();
            drop(stream);
            continue;
        };
        let guard = live.opened();
        let (live, token, host) = (Arc::clone(&live), token.clone(), dest_host.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            debug!(%originator, "forwarded-tcpip channel");
            let tcp = tokio::select! {
                () = token.cancelled() => return,
                t = TcpStream::connect((host.as_str(), dest_port)) => t,
            };
            match tcp {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    splice(tcp, stream, &[], &live, &token).await;
                }
                Err(err) => debug!(%err, "remote forward: local destination refused"),
            }
        });
    }
    drop(listener);
}
