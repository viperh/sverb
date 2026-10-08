//! M3-07 unit tests of the pool (mock connections): T-01 key equality, T-02 concurrent
//! opens dial once, T-03 linger, T-04 failure propagation and reconnect, the
//! `MaxSessions` fallback, and T-09's private pool.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use sverb_core::error_report::ErrorReport;

use super::*;
use crate::session::DisconnectReason;

/// A mock connection: records closes, can be taken down.
#[derive(Debug, Default)]
struct MockState {
    dials: AtomicUsize,
    closes: AtomicUsize,
}

struct MockConn {
    state: Arc<MockState>,
    down: Arc<Mutex<Option<TransportFailure>>>,
    closed: AtomicBool,
}

impl MuxConn for MockConn {
    fn down(&self) -> Option<TransportFailure> {
        self.down.lock().clone()
    }

    fn close(&self) {
        assert!(!self.closed.swap(true, Ordering::SeqCst), "closed twice");
        self.state.closes.fetch_add(1, Ordering::SeqCst);
    }
}

/// The mock connector: claim, dial (after `delay`) if vacant.
async fn open(
    pool: &Pool<MockConn>,
    key: &MuxKey,
    state: &Arc<MockState>,
    delay: Duration,
) -> (Lease<MockConn>, Arc<Mutex<Option<TransportFailure>>>) {
    let down = Arc::new(Mutex::new(None));
    match pool.claim(key).await {
        Slot::Found(lease) => (lease, down),
        Slot::Vacant(guard) => {
            state.dials.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            let lease = guard.register(MockConn {
                state: Arc::clone(state),
                down: Arc::clone(&down),
                closed: AtomicBool::new(false),
            });
            (lease, down)
        }
    }
}

fn key() -> MuxKey {
    MuxKey::new("db.example", 22, "deploy")
}

fn failure(msg: &str) -> TransportFailure {
    TransportFailure::new(DisconnectReason::Connect, ErrorReport::msg(msg))
}

/// Let spawned linger tasks run.
async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// T-01: same host, port and user → equal; another jump chain, key, proxy or port →
/// different.
#[test]
fn t01_mux_key_equality() {
    let bastion = MuxKey::new("bastion", 22, "ops");
    let other_bastion = MuxKey::new("bastion-eu", 22, "ops");
    assert_eq!(key(), key());
    // Case-insensitive host names.
    assert_eq!(MuxKey::new("DB.example", 22, "deploy"), key());
    assert_ne!(MuxKey::new("db.example", 2222, "deploy"), key());
    assert_ne!(MuxKey::new("db.example", 22, "root"), key());
    // Jump chain.
    assert_ne!(key().via(&bastion), key());
    assert_eq!(key().via(&bastion), key().via(&bastion));
    assert_ne!(key().via(&bastion), key().via(&other_bastion));
    assert_ne!(
        key().via(&bastion),
        key().via(&bastion.clone().via(&other_bastion))
    );
    assert_eq!(key().via(&bastion.clone().via(&other_bastion)).depth(), 2);
    // Authentication identity.
    assert_ne!(key().identity("key:aaa"), key().identity("key:bbb"));
    assert_eq!(key().identity("key:aaa"), key().identity("key:aaa"));
    // Proxy and options.
    assert_ne!(key().proxy("socks5 127.0.0.1:1080"), key());
    assert_ne!(key().options("agent=system"), key());
    // The debug form leaks no host or user name (SPEC §17).
    let dbg = format!("{:?}", key().via(&bastion));
    assert!(
        !dbg.contains("db.example") && !dbg.contains("deploy"),
        "{dbg}"
    );
}

/// T-02: 5 concurrent opens of the same key → exactly one connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_concurrent_opens_dial_once() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let tasks: Vec<_> = (0..5)
        .map(|_| {
            let (pool, state) = (pool.clone(), Arc::clone(&state));
            tokio::spawn(async move {
                open(&pool, &key(), &state, Duration::from_millis(50))
                    .await
                    .0
            })
        })
        .collect();
    let mut leases = Vec::new();
    for task in tasks {
        leases.push(task.await.unwrap());
    }
    assert_eq!(state.dials.load(Ordering::SeqCst), 1);
    let id = leases[0].id();
    assert!(leases.iter().all(|l| l.id() == id));
    assert_eq!(leases[0].users(), 5);
    assert_eq!(leases.iter().filter(|l| l.fresh()).count(), 1);
    assert_eq!(pool.connections(&key()), 1);
    // Another key dials its own.
    let other = MuxKey::new("db.example", 22, "root");
    let (lease, _) = open(&pool, &other, &state, Duration::ZERO).await;
    assert_ne!(lease.id(), id);
    assert_eq!(state.dials.load(Ordering::SeqCst), 2);
}

/// A failed dial lets the next waiter dial (no connection was registered).
#[tokio::test]
async fn failed_dial_releases_the_gate() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let Slot::Vacant(guard) = pool.claim(&key()).await else {
        panic!("empty pool");
    };
    let waiter = {
        let (pool, state) = (pool.clone(), Arc::clone(&state));
        tokio::spawn(async move { open(&pool, &key(), &state, Duration::ZERO).await.0 })
    };
    settle().await;
    assert!(
        !waiter.is_finished(),
        "the second claim waits for the first"
    );
    drop(guard); // the dial failed
    let lease = waiter.await.unwrap();
    assert!(lease.fresh());
    assert_eq!(state.dials.load(Ordering::SeqCst), 1);
}

/// T-03: release the last user and reopen within 10 s → no new connect; after 10 s
/// the connection is closed.
#[tokio::test(start_paused = true)]
async fn t03_linger() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let (lease, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    drop(lease);
    settle().await;
    tokio::time::sleep(Duration::from_secs(9)).await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 0);
    let (lease, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert!(!lease.fresh());
    assert_eq!(
        state.dials.load(Ordering::SeqCst),
        1,
        "reused while lingering"
    );
    // The first linger ends while the connection is in use again: it stays.
    tokio::time::sleep(Duration::from_secs(5)).await;
    settle().await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 0);
    assert_eq!(pool.connections(&key()), 1);
    drop(lease);
    settle().await;
    tokio::time::sleep(LINGER - Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_millis(2)).await;
    settle().await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 1, "closed after 10 s");
    assert_eq!(pool.connections(&key()), 0);
    let (lease, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert!(lease.fresh());
    assert_eq!(state.dials.load(Ordering::SeqCst), 2);
}

/// T-04: the shared connection fails → every user sees the same failure; a reconnect
/// dials a new connection and the others reconnect onto it.
#[tokio::test]
async fn t04_failure_reaches_every_user() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let (a, down) = open(&pool, &key(), &state, Duration::ZERO).await;
    let (b, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    let c = b.clone();
    assert_eq!(a.users(), 3);
    assert!(a.failure().is_none());

    *down.lock() = Some(failure("connection lost"));
    let seen: Vec<_> = [&a, &b, &c].iter().map(|l| l.failure()).collect();
    assert!(seen.iter().all(|f| *f == Some(failure("connection lost"))));
    // The first failure sticks even if the connection reports something else later.
    *down.lock() = Some(failure("something else"));
    assert_eq!(c.failure(), Some(failure("connection lost")));

    // A reconnect (of any user) re-establishes the connection…
    let (a2, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert!(a2.fresh());
    assert_eq!(state.dials.load(Ordering::SeqCst), 2);
    drop(a);
    // …and the others reconnect onto it.
    let (b2, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert_eq!(b2.id(), a2.id());
    drop((b, c));
    // A dead connection closes at once (no linger).
    settle().await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 1);
}

/// T-04 (explicit): `fail` records one failure for every user.
#[tokio::test]
async fn fail_is_shared() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let (a, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    let b = a.clone();
    let token = b.token().child_token();
    b.fail(failure("keepalive"));
    assert_eq!(a.failure(), Some(failure("keepalive")));
    assert!(pool.lookup(&key()).is_none());
    drop((a, b));
    settle().await;
    assert!(
        token.is_cancelled(),
        "the connection's forwards are cancelled"
    );
}

/// `MaxSessions`: a refused connection is marked full, the fresh one is preferred.
#[tokio::test]
async fn session_limit_prefers_the_newer_connection() {
    let pool = Pool::<MockConn>::default();
    let state = Arc::new(MockState::default());
    let (a, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    let (b, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    // The third channel is refused on the shared connection.
    b.mark_full();
    let c = pool.claim_fresh(&key()).register(MockConn {
        state: Arc::clone(&state),
        down: Arc::default(),
        closed: AtomicBool::new(false),
    });
    assert_ne!(c.id(), a.id());
    assert_eq!(pool.connections(&key()), 2);
    // Later opens prefer the newer connection.
    let (d, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert_eq!(d.id(), c.id());
    let newer = c.id();
    drop((c, d));
    // Still preferred while it lingers.
    let (e, _) = open(&pool, &key(), &state, Duration::ZERO).await;
    assert_eq!(e.id(), newer);
    drop(e);

    // A full connection is not handed out until one of its users leaves.
    let other = MuxKey::new("db.example", 22, "root");
    let (f, _) = open(&pool, &other, &state, Duration::ZERO).await;
    let g = f.clone();
    f.mark_full();
    assert!(pool.lookup(&other).is_none());
    drop(g);
    assert_eq!(pool.lookup(&other).map(|l| l.id()), Some(f.id()));
    drop((a, b));
}

/// T-09 (pool side): a private pool (`ssh.multiplex = false`) shares nothing between
/// connects and closes as soon as the last user leaves.
#[tokio::test]
async fn t09_private_pools_share_nothing() {
    let state = Arc::new(MockState::default());
    let first = Pool::<MockConn>::private();
    let second = Pool::<MockConn>::private();
    assert!(!first.is_enabled(), "not shared between sessions");
    let (a, _) = open(&first, &key(), &state, Duration::ZERO).await;
    let (b, _) = open(&second, &key(), &state, Duration::ZERO).await;
    assert_eq!(state.dials.load(Ordering::SeqCst), 2);
    // Within one connect (one chain) the hop is shared.
    let (hop_again, _) = open(&first, &key(), &state, Duration::ZERO).await;
    assert_eq!(hop_again.id(), a.id());
    drop((a, b, hop_again));
    settle().await;
    assert_eq!(state.closes.load(Ordering::SeqCst), 2, "no linger");
}

/// The on/off switch.
#[test]
fn enabled_flag() {
    let pool = Pool::<MockConn>::default();
    assert!(pool.is_enabled());
    pool.set_enabled(false);
    assert!(!pool.is_enabled());
    assert!(format!("{pool:?}").contains("enabled: false"));
}
