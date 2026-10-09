//! Connection sharing (SPEC §6.1.3, §6.1.4, §15 `ssh.multiplex`).
//!
//! A [`Pool`] keeps the live connections by [`MuxKey`]. Sessions, exec runs,
//! standalone forwards and jump hops ask the pool for a connection and get a [`Lease`]:
//! one user (one channel: a shell, an exec, a tunnel, or the next hop's
//! `direct-tcpip`) of a [`SharedConn`]. This module is transport-agnostic (the
//! connection is any [`MuxConn`]); `mux_ssh.rs` is the russh side.
//!
//! - **Key.** The spec says "same address, port, user and jump chain". The key also
//!   holds the proxy and the authentication identity (and the agent-forwarding and
//!   legacy-algorithm settings), because those change how the connection behaves: two
//!   hosts that differ only in the key used must not share a connection authenticated
//!   with the other key. The jump chain is the previous hop's own key (recursively).
//! - **Map.** `HashMap<MuxKey, Vec<Weak<SharedConn>>>`, newest last. The pool never
//!   keeps a connection alive by itself: leases do, and so does the linger task.
//! - **Concurrency.** [`Pool::claim`] returns [`Slot::Found`] (a live connection) or
//!   [`Slot::Vacant`] holding the key's "connecting" gate (a per-key async mutex): a
//!   second claim of the same key waits for the first to dial (or fail), then finds
//!   its connection. Two sessions opening the same key at once never make two
//!   connections.
//! - **Lifetime.** When the last lease goes, a task keeps the connection [`LINGER`]
//!   longer (closing and reopening a tab is instant), then drops it; dropping the last
//!   reference closes the connection ([`MuxConn::close`]) and cancels its token (the
//!   parent of its forwards).
//! - **Failure.** The first failure seen ([`MuxConn::down`], or `Lease::fail`) is
//!   recorded and returned to every user ([`Lease::failure`]), so all of them
//!   disconnect with the same reason; a failed connection is never handed out again,
//!   and the next claim (a reconnect) dials a new one.
//! - **Server limits.** [`Pool::claim_fresh`] always dials (OpenSSH `MaxSessions`
//!   refused a channel); the new connection is the newest, so later claims prefer it.
//!   A refused connection is marked full ([`Lease::mark_full`]) until one of its users
//!   leaves.
//! - **`ssh.multiplex = false`:** the connector uses a private pool per connect
//!   ([`Pool::private`], no linger), so only the hops of one chain share.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::transport::TransportFailure;

/// How long a connection stays open after its last user left.
pub(crate) const LINGER: Duration = Duration::from_secs(10);

/// What makes two connections interchangeable (see the module docs).
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct MuxKey {
    /// Hostname or address as configured (lowercased).
    pub(crate) address: String,
    /// Port.
    pub(crate) port: u16,
    /// User name.
    pub(crate) username: String,
    /// The previous hop's key (the jump chain); `None`: reached directly.
    pub(crate) via: Option<Arc<MuxKey>>,
    /// The proxy (kind and address, never its password); `None`: direct.
    pub(crate) proxy: Option<String>,
    /// The authentication identity (key item, identity item, a digest of an inline
    /// key; never a secret).
    pub(crate) identity: String,
    /// Other connection-level settings (agent forwarding, legacy algorithms).
    pub(crate) options: String,
}

impl MuxKey {
    /// A key for `username@address:port`, direct, without identity or options.
    pub(crate) fn new(address: &str, port: u16, username: &str) -> Self {
        Self {
            address: address.trim().to_ascii_lowercase(),
            port,
            username: username.to_owned(),
            via: None,
            proxy: None,
            identity: String::new(),
            options: String::new(),
        }
    }

    /// Reached through the hop `prev`.
    #[must_use]
    pub(crate) fn via(mut self, prev: &Self) -> Self {
        self.via = Some(Arc::new(prev.clone()));
        self
    }

    /// Through the proxy `proxy`.
    #[must_use]
    pub(crate) fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Authenticated as `identity`.
    #[must_use]
    pub(crate) fn identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = identity.into();
        self
    }

    /// With the connection-level `options`.
    #[must_use]
    pub(crate) fn options(mut self, options: impl Into<String>) -> Self {
        self.options = options.into();
        self
    }

    /// Number of hops before this one.
    pub(crate) fn depth(&self) -> usize {
        self.via.as_ref().map_or(0, |v| v.depth() + 1)
    }
}

// Hostnames stay out of logs at `info` (SPEC §17): the debug form shows the shape only.
impl fmt::Debug for MuxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxKey")
            .field("port", &self.port)
            .field("depth", &self.depth())
            .field("proxy", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
}

/// A connection the pool can share.
pub(crate) trait MuxConn: Send + Sync + 'static {
    /// Why the connection is down; `None` while it is usable.
    fn down(&self) -> Option<TransportFailure>;

    /// Close the connection (fire and forget). Called once, when the last reference
    /// goes.
    fn close(&self);
}

/// One pooled connection and its users.
pub(crate) struct SharedConn<C: MuxConn> {
    id: u64,
    conn: C,
    users: AtomicUsize,
    linger: Duration,
    failure: Mutex<Option<TransportFailure>>,
    full: AtomicBool,
    cancel: CancellationToken,
}

impl<C: MuxConn> SharedConn<C> {
    fn failure(&self) -> Option<TransportFailure> {
        let mut recorded = self.failure.lock();
        if recorded.is_none() {
            *recorded = self.conn.down();
        }
        recorded.clone()
    }

    fn usable(&self) -> bool {
        !self.full.load(Ordering::SeqCst) && self.failure().is_none()
    }
}

impl<C: MuxConn> Drop for SharedConn<C> {
    fn drop(&mut self) {
        tracing::debug!(conn = self.id, "shared connection closed");
        self.cancel.cancel();
        self.conn.close();
    }
}

/// One user of a shared connection. Dropping it releases the connection (which then
/// lingers if it was the last user).
pub(crate) struct Lease<C: MuxConn> {
    shared: Arc<SharedConn<C>>,
    fresh: bool,
}

impl<C: MuxConn> fmt::Debug for Lease<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("conn", &self.shared.id)
            .field("users", &self.users())
            .field("fresh", &self.fresh)
            .finish()
    }
}

impl<C: MuxConn> Lease<C> {
    fn new(shared: Arc<SharedConn<C>>, fresh: bool) -> Self {
        shared.users.fetch_add(1, Ordering::SeqCst);
        Self { shared, fresh }
    }

    /// The connection.
    pub(crate) fn conn(&self) -> &C {
        &self.shared.conn
    }

    /// The pool's id of the connection (unique per pool).
    #[cfg(test)]
    pub(crate) fn id(&self) -> u64 {
        self.shared.id
    }

    /// This lease dialed the connection (it was not shared when handed out).
    pub(crate) fn fresh(&self) -> bool {
        self.fresh
    }

    /// Current users of the connection (its channels).
    pub(crate) fn users(&self) -> usize {
        self.shared.users.load(Ordering::SeqCst)
    }

    /// Why the connection is down (the same failure for every user); `None` while up.
    pub(crate) fn failure(&self) -> Option<TransportFailure> {
        self.shared.failure()
    }

    /// Record `failure` for every user (the first recorded failure wins). The SSH
    /// side needs no call: its failures come from [`MuxConn::down`].
    #[cfg(test)]
    pub(crate) fn fail(&self, failure: TransportFailure) {
        self.shared.failure.lock().get_or_insert(failure);
    }

    /// The server refused another channel (`MaxSessions`): don't hand this connection
    /// out until one of its users leaves.
    pub(crate) fn mark_full(&self) {
        self.shared.full.store(true, Ordering::SeqCst);
    }

    /// Cancelled when the connection closes: the parent of its forwards' tokens.
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.shared.cancel
    }
}

impl<C: MuxConn> Clone for Lease<C> {
    /// Another user of the same connection.
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.shared), false)
    }
}

impl<C: MuxConn> Drop for Lease<C> {
    fn drop(&mut self) {
        let before = self.shared.users.fetch_sub(1, Ordering::SeqCst);
        // A slot is free again.
        self.shared.full.store(false, Ordering::SeqCst);
        if before != 1 || self.shared.linger.is_zero() || self.shared.failure().is_some() {
            return;
        }
        // The last user left: keep the connection for the linger time.
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let keep = Arc::clone(&self.shared);
        let linger = self.shared.linger;
        tracing::debug!(conn = keep.id, "last user left; lingering");
        rt.spawn(async move {
            tokio::time::sleep(linger).await;
            drop(keep);
        });
    }
}

/// What [`Pool::claim`] found.
pub(crate) enum Slot<C: MuxConn> {
    /// A live connection to share.
    Found(Lease<C>),
    /// Nothing live: dial, then [`DialGuard::register`]. Other claims of the key wait
    /// until the guard is registered or dropped (a failed dial).
    Vacant(DialGuard<C>),
}

impl<C: MuxConn> fmt::Debug for Slot<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found(lease) => f.debug_tuple("Found").field(lease).finish(),
            Self::Vacant(_) => f.write_str("Vacant"),
        }
    }
}

/// The right to dial a key (holds its "connecting" gate).
pub(crate) struct DialGuard<C: MuxConn> {
    pool: Pool<C>,
    key: MuxKey,
    gate: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl<C: MuxConn> fmt::Debug for DialGuard<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialGuard")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<C: MuxConn> DialGuard<C> {
    /// Register the dialed connection (as the key's newest) and take the first lease.
    pub(crate) fn register(self, conn: C) -> Lease<C> {
        let inner = &self.pool.inner;
        let shared = Arc::new(SharedConn {
            id: inner.next_id.fetch_add(1, Ordering::SeqCst),
            conn,
            users: AtomicUsize::new(0),
            linger: inner.linger,
            failure: Mutex::new(None),
            full: AtomicBool::new(false),
            cancel: CancellationToken::new(),
        });
        let lease = Lease::new(Arc::clone(&shared), true);
        let mut state = inner.state.lock();
        let list = state.conns.entry(self.key.clone()).or_default();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(&shared));
        tracing::debug!(conn = shared.id, "shared connection registered");
        lease
    }
}

impl<C: MuxConn> Drop for DialGuard<C> {
    fn drop(&mut self) {
        // Forget the gate once nobody else waits on it (the map's and our reference).
        if self.gate.is_none() {
            return;
        }
        let mut state = self.pool.inner.state.lock();
        if let Some(gate) = state.gates.get(&self.key)
            && Arc::strong_count(gate) <= 2
        {
            state.gates.remove(&self.key);
        }
    }
}

struct PoolState<C: MuxConn> {
    conns: HashMap<MuxKey, Vec<Weak<SharedConn<C>>>>,
    gates: HashMap<MuxKey, Arc<tokio::sync::Mutex<()>>>,
}

struct PoolInner<C: MuxConn> {
    linger: Duration,
    enabled: AtomicBool,
    next_id: AtomicU64,
    state: Mutex<PoolState<C>>,
}

/// The connection pool (cheap to clone; clones share it).
pub(crate) struct Pool<C: MuxConn> {
    inner: Arc<PoolInner<C>>,
}

impl<C: MuxConn> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C: MuxConn> fmt::Debug for Pool<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("enabled", &self.is_enabled())
            .field("linger", &self.inner.linger)
            .finish_non_exhaustive()
    }
}

impl<C: MuxConn> Default for Pool<C> {
    fn default() -> Self {
        Self::new(LINGER)
    }
}

impl<C: MuxConn> Pool<C> {
    /// An enabled pool whose connections linger `linger` after their last user.
    pub(crate) fn new(linger: Duration) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                linger,
                enabled: AtomicBool::new(true),
                next_id: AtomicU64::new(1),
                state: Mutex::new(PoolState {
                    conns: HashMap::new(),
                    gates: HashMap::new(),
                }),
            }),
        }
    }

    /// A pool for one connect (`ssh.multiplex = false`): the hops of one chain share,
    /// nothing lingers, and it reports itself as not sharing between sessions (closing
    /// the session disconnects at once).
    pub(crate) fn private() -> Self {
        let pool = Self::new(Duration::ZERO);
        pool.set_enabled(false);
        pool
    }

    /// Whether connections are shared between sessions (`ssh.multiplex`).
    pub(crate) fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::SeqCst)
    }

    /// Turn sharing on or off for new connects (existing connections stay).
    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::SeqCst);
    }

    /// The newest usable connection for `key`, without waiting.
    pub(crate) fn lookup(&self, key: &MuxKey) -> Option<Lease<C>> {
        let mut state = self.inner.state.lock();
        let list = state.conns.get_mut(key)?;
        list.retain(|w| w.strong_count() > 0);
        let found = list
            .iter()
            .rev()
            .filter_map(Weak::upgrade)
            .find(|c| c.usable());
        if list.is_empty() {
            state.conns.remove(key);
        }
        found.map(|c| Lease::new(c, false))
    }

    /// A live connection for `key`, or the right to dial one. Waits while another
    /// claim of the same key is dialing.
    pub(crate) async fn claim(&self, key: &MuxKey) -> Slot<C> {
        if let Some(lease) = self.lookup(key) {
            return Slot::Found(lease);
        }
        let gate = {
            let mut state = self.inner.state.lock();
            Arc::clone(state.gates.entry(key.clone()).or_default())
        };
        let held = gate.lock_owned().await;
        // Whoever held the gate before us may have connected.
        if let Some(lease) = self.lookup(key) {
            drop(held);
            self.forget_gate(key);
            return Slot::Found(lease);
        }
        Slot::Vacant(DialGuard {
            pool: self.clone(),
            key: key.clone(),
            gate: Some(held),
        })
    }

    /// The right to dial another connection for `key` even though one is live (the
    /// server refused a channel on it).
    pub(crate) fn claim_fresh(&self, key: &MuxKey) -> DialGuard<C> {
        DialGuard {
            pool: self.clone(),
            key: key.clone(),
            gate: None,
        }
    }

    /// Live connections for `key` (usable or not).
    #[cfg(test)]
    pub(crate) fn connections(&self, key: &MuxKey) -> usize {
        let state = self.inner.state.lock();
        state
            .conns
            .get(key)
            .map_or(0, |l| l.iter().filter(|w| w.strong_count() > 0).count())
    }

    fn forget_gate(&self, key: &MuxKey) {
        let mut state = self.inner.state.lock();
        if let Some(gate) = state.gates.get(key)
            && Arc::strong_count(gate) == 1
        {
            state.gates.remove(key);
        }
    }
}

#[cfg(test)]
#[path = "mux_tests.rs"]
mod tests;
