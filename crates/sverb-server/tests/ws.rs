//! M4-05: `/v1/ws` notifications and multi-replica fan-out.
//!
//! Most scenarios drive `ws::session::run` over in-memory channels, so the
//! 5 s auth window, the 30 s heartbeat and the 15 min token expiry run on
//! paused Tokio time. `e2e_*` tests go through the real axum upgrade with a
//! tokio-tungstenite client on a loopback socket. T-04 runs two replicas on
//! the in-memory backend sharing one `LocalBus`; its PostgreSQL twin (real
//! `LISTEN/NOTIFY`) needs `DATABASE_URL` and otherwise prints
//! "SKIPPED (needs PostgreSQL)".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use chrono::Utc;
use common::{TestDb, config, json, req, send};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sverb_proto::b64;
use sverb_proto::ws::{AccessChange, ClientMsg, ServerMsg, ShareViewer};
use sverb_server::auth::store::mem::{MemDevice, MemMember, MemStore, MemToken, MemUser, MemVault};
use sverb_server::auth::tokens::{ACCESS_TTL, NewToken, TokenKind};
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::{self, RegistrationMode};
use sverb_server::ws::{Bus, Frame, LocalBus, Topic};
use sverb_server::{AppState, app};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

// ------------------------------------------------------------------ harness

fn generous() -> RateLimiters {
    let n = NonZeroU32::new(100_000).unwrap();
    RateLimiters::new(LoginLimits {
        per_email_per_minute: n,
        per_ip_per_minute: n,
    })
}

fn lazy_pool() -> sqlx_postgres::PgPool {
    sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap()
}

/// One replica on the in-memory backend.
struct Replica {
    state: AppState,
    app: Router,
}

/// One "database" (memory model + clock) and its replicas.
struct Env {
    mem: Arc<MemStore>,
    clock: Arc<ManualClock>,
}

impl Env {
    fn new() -> Self {
        Self {
            mem: Arc::new(MemStore::new()),
            clock: Arc::new(ManualClock::new()),
        }
    }

    fn replica(&self, bus: Arc<dyn Bus>) -> Replica {
        let auth = AuthRuntime::new(AuthStore::Memory(self.mem.clone()), self.clock.clone());
        let state = AppState::with_bus(config(&[]), lazy_pool(), generous(), auth, bus);
        Replica {
            app: app::router(state.clone()),
            state,
        }
    }

    /// A user with one device, an access token and a personal vault.
    fn user(&self) -> TUser {
        let user_id = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let now = self.clock_now();
        self.mem.with_data(|d| {
            d.users.insert(
                user_id,
                MemUser {
                    email: format!("{user_id}@example.com"),
                    created_at: now,
                    is_instance_admin: false,
                    opaque_record: vec![0],
                    totp_secret_enc: None,
                    totp_pending_enc: None,
                    totp_last_step: None,
                    disabled: false,
                },
            );
            d.vaults
                .insert(vault, MemVault::personal(user_id, vec![1], 1));
        });
        self.member(vault, user_id);
        let (device_id, token) = self.device(user_id);
        TUser {
            id: user_id,
            device_id,
            vault,
            token,
        }
    }

    fn clock_now(&self) -> chrono::DateTime<Utc> {
        use sverb_server::auth::Clock;
        self.clock.now()
    }

    /// Another device (and access token) of `user_id`.
    fn device(&self, user_id: Uuid) -> (Uuid, String) {
        let device_id = Uuid::now_v7();
        let tok = NewToken::generate();
        let now = self.clock_now();
        self.mem.with_data(|d| {
            d.devices.insert(
                device_id,
                MemDevice {
                    user_id,
                    name: "laptop".into(),
                    platform: "linux".into(),
                    created_at: now,
                    last_seen_at: None,
                    revoked_at: None,
                },
            );
            d.tokens.insert(
                tok.hash,
                MemToken {
                    device_id,
                    kind: TokenKind::Access,
                    expires_at: now + ACCESS_TTL,
                    family: Uuid::now_v7(),
                    used_at: None,
                },
            );
        });
        (device_id, tok.wire.to_string())
    }

    fn member(&self, vault: Uuid, user_id: Uuid) {
        self.mem.with_data(|d| {
            d.vault_members.push(MemMember {
                vault_id: vault,
                user_id,
                permission: "manage".into(),
                key_version: 1,
                wrapped_vault_key: vec![2],
                wrapped_by: user_id,
                signature: vec![3; 64],
            });
        });
    }
}

#[derive(Clone)]
struct TUser {
    id: Uuid,
    device_id: Uuid,
    vault: Uuid,
    token: String,
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<&Value>,
    bearer: &str,
) -> (StatusCode, Value) {
    let b = req(method, path, "198.51.100.7:4000")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let r = match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let (st, _, bytes) = send(app, r).await;
    let v = if bytes.is_empty() {
        Value::Null
    } else {
        json(&bytes)
    };
    (st, v)
}

/// Pushes one new item; returns the new head.
async fn push_one(app: &Router, token: &str, vault: Uuid) -> u64 {
    let body = json!({ "changes": [{
        "id": Uuid::now_v7(),
        "base_revision": 0,
        "key_version": 1,
        "envelope": b64::encode(b"ciphertext"),
        "deleted": false,
    }]});
    let (st, v) = call(
        app,
        "POST",
        &format!("/v1/vaults/{vault}/changes"),
        Some(&body),
        token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    v["results"][0]["revision"].as_u64().unwrap()
}

/// A socket on the in-memory transport.
struct Sock {
    tx: mpsc::UnboundedSender<Frame>,
    rx: mpsc::UnboundedReceiver<Frame>,
    _task: JoinHandle<()>,
}

impl Sock {
    fn open(state: &AppState) -> Self {
        let (tx, srv_in) = mpsc::unbounded();
        let (srv_out, rx) = mpsc::unbounded();
        let task = tokio::spawn(sverb_server::ws::session::run(
            state.clone(),
            srv_in,
            srv_out,
        ));
        Self {
            tx,
            rx,
            _task: task,
        }
    }

    async fn send(&mut self, m: &ClientMsg) {
        // The server may already have closed (e.g. a pong racing expiry).
        let _ = self
            .tx
            .send(Frame::Text(serde_json::to_string(m).unwrap()))
            .await;
    }

    /// Opens and authenticates; returns after the first server ping (sent
    /// once the subscriptions are in place).
    async fn authed(state: &AppState, token: &str) -> Self {
        let mut s = Self::open(state);
        s.send(&ClientMsg::Auth {
            token: token.to_owned(),
        })
        .await;
        assert_eq!(s.next_msg().await, Some(ServerMsg::Ping));
        s.send(&ClientMsg::Pong).await;
        s
    }

    /// The next frame (with a generous timeout).
    async fn frame(&mut self) -> Option<Frame> {
        tokio::time::timeout(Duration::from_secs(3600), self.rx.next())
            .await
            .expect("no frame within an hour")
    }

    /// The next server message; `None` on close.
    async fn next_msg(&mut self) -> Option<ServerMsg> {
        match self.frame().await? {
            Frame::Text(t) => Some(serde_json::from_str(&t).unwrap()),
            other => {
                self.rx.close();
                panic!("expected a message, got {other:?}");
            }
        }
    }

    /// The next non-heartbeat message, answering pings.
    async fn notification(&mut self) -> ServerMsg {
        loop {
            match self.next_msg().await.expect("socket closed") {
                ServerMsg::Ping => self.send(&ClientMsg::Pong).await,
                m => return m,
            }
        }
    }

    /// Asserts nothing but heartbeats arrives within `d` (real or paused
    /// time).
    async fn quiet_for(&mut self, d: Duration) {
        let deadline = Instant::now() + d;
        loop {
            match tokio::time::timeout_at(deadline, self.rx.next()).await {
                Err(_) => return,
                Ok(Some(Frame::Text(t))) => {
                    let m: ServerMsg = serde_json::from_str(&t).unwrap();
                    assert_eq!(m, ServerMsg::Ping, "unexpected notification");
                    self.send(&ClientMsg::Pong).await;
                }
                Ok(other) => panic!("unexpected {other:?}"),
            }
        }
    }

    /// Reads until the close frame (answering pings when `pong`); returns
    /// its code and how many pings came before it.
    async fn close_code(&mut self, pong: bool) -> (u16, u32) {
        let mut pings = 0;
        loop {
            match self
                .frame()
                .await
                .expect("stream ended without a close frame")
            {
                Frame::Close { code, .. } => return (code, pings),
                Frame::Text(t) => {
                    if serde_json::from_str::<ServerMsg>(&t).unwrap() == ServerMsg::Ping {
                        pings += 1;
                        if pong {
                            self.send(&ClientMsg::Pong).await;
                        }
                    }
                }
                Frame::Other => {}
            }
        }
    }
}

// --------------------------------------------------------------------- T-01

/// T-01: no auth message within 5 s → 4401 at exactly 5 s.
#[tokio::test(start_paused = true)]
async fn t01_no_auth_within_5s_closes_4401() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let t0 = Instant::now();
    let mut s = Sock::open(&r.state);
    let (code, _) = s.close_code(false).await;
    assert_eq!(code, 4401);
    assert_eq!(t0.elapsed(), Duration::from_secs(5));

    // Auth arriving just in time is accepted.
    let u = env.user();
    let mut s = Sock::open(&r.state);
    tokio::time::sleep(Duration::from_millis(4900)).await;
    s.send(&ClientMsg::Auth { token: u.token }).await;
    assert_eq!(s.next_msg().await, Some(ServerMsg::Ping));
}

/// T-01b: a first message other than auth → 4401 immediately.
#[tokio::test(start_paused = true)]
async fn t01_first_message_must_be_auth() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let t0 = Instant::now();
    let mut s = Sock::open(&r.state);
    s.send(&ClientMsg::Ping).await;
    assert_eq!(s.close_code(false).await.0, 4401);
    assert!(t0.elapsed() < Duration::from_secs(1));
}

// --------------------------------------------------------------------- T-02

/// T-02: invalid, malformed, expired or revoked tokens → 4401; a valid
/// token → subscribed to the user and their vaults.
#[tokio::test(start_paused = true)]
async fn t02_token_validation() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();

    for bad in [
        "not base64 !!".to_owned(),
        b64::encode(&[7u8; 32]),
        b64::encode(&[7u8; 31]),
        String::new(),
    ] {
        let mut s = Sock::open(&r.state);
        s.send(&ClientMsg::Auth { token: bad }).await;
        assert_eq!(s.close_code(false).await.0, 4401);
    }

    // Valid → subscribed (one socket on the user and personal vault topics).
    let _s = Sock::authed(&r.state, &u.token).await;
    let hub = r.state.ws().hub();
    assert_eq!(hub.subscribers(Topic::User(u.id)), 1);
    assert_eq!(hub.subscribers(Topic::Vault(u.vault)), 1);

    // An expired token → 4401.
    env.clock.advance(ACCESS_TTL);
    let mut s = Sock::open(&r.state);
    s.send(&ClientMsg::Auth { token: u.token }).await;
    assert_eq!(s.close_code(false).await.0, 4401);
}

// --------------------------------------------------------------------- T-03

/// T-03: a push reaches the members' sockets with the new head, and only
/// theirs.
#[tokio::test]
async fn t03_push_notifies_members_only() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let a = env.user();
    let b = env.user();
    // A second device of A, and a vault A and B share.
    let (_, a2_token) = env.device(a.id);
    let shared = Uuid::now_v7();
    env.mem
        .with_data(|d| d.vaults.insert(shared, MemVault::shared(None, vec![1], 1)));
    env.member(shared, a.id);
    env.member(shared, b.id);

    let mut sa = Sock::authed(&r.state, &a.token).await;
    let mut sa2 = Sock::authed(&r.state, &a2_token).await;
    let mut sb = Sock::authed(&r.state, &b.token).await;

    let head = push_one(&r.app, &a.token, a.vault).await;
    let expect = ServerMsg::VaultChanged {
        vault_id: a.vault,
        head_revision: head,
    };
    assert_eq!(sa.notification().await, expect);
    assert_eq!(sa2.notification().await, expect);
    sb.quiet_for(Duration::from_millis(300)).await;

    let head = push_one(&r.app, &b.token, shared).await;
    let expect = ServerMsg::VaultChanged {
        vault_id: shared,
        head_revision: head,
    };
    assert_eq!(sa.notification().await, expect);
    assert_eq!(sb.notification().await, expect);
}

// --------------------------------------------------------------------- T-04

/// T-04: two replicas sharing one database and one bus: a push on A
/// reaches a socket on B.
#[tokio::test]
async fn t04_two_replicas_fan_out_mem() {
    let env = Env::new();
    let bus: Arc<dyn Bus> = Arc::new(LocalBus::new());
    let ra = env.replica(bus.clone());
    let rb = env.replica(bus);
    let u = env.user();

    let mut on_b = Sock::authed(&rb.state, &u.token).await;
    assert_eq!(ra.state.ws().hub().sessions(), 0);
    let head = push_one(&ra.app, &u.token, u.vault).await;
    assert_eq!(
        on_b.notification().await,
        ServerMsg::VaultChanged {
            vault_id: u.vault,
            head_revision: head
        }
    );
}

/// T-04 on PostgreSQL: real `LISTEN/NOTIFY` between two states (each with
/// its own `PgBus` and listener connection).
#[tokio::test]
async fn t04_two_replicas_fan_out_pg() {
    let Some(db) = TestDb::migrated().await else {
        eprintln!("SKIPPED (needs PostgreSQL): set DATABASE_URL to run this database test");
        return;
    };
    registration::set_mode(&db.pool, RegistrationMode::Open)
        .await
        .unwrap();
    let mk = || {
        let auth = AuthRuntime::postgres(db.pool.clone());
        let state = AppState::with_auth(config(&[]), db.pool.clone(), generous(), auth);
        (app::router(state.clone()), state)
    };
    let (app_a, _state_a) = mk();
    let (app_b, state_b) = mk();
    let (token, vault) = register(&app_a, "fanout@example.com").await;

    let mut on_b = Sock::authed(&state_b, &token).await;
    // The listener connects asynchronously; wait until B is ready.
    for _ in 0..100 {
        if state_b.readiness().degraded().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(state_b.readiness().degraded().is_empty());
    let head = push_one(&app_a, &token, vault).await;
    let got = tokio::time::timeout(Duration::from_secs(5), on_b.notification())
        .await
        .expect("no vault_changed via LISTEN/NOTIFY");
    assert_eq!(
        got,
        ServerMsg::VaultChanged {
            vault_id: vault,
            head_revision: head
        }
    );
    drop((app_b, on_b));
    db.cleanup().await;
}

// --------------------------------------------------------------------- T-05

/// T-05: the access token expires → 4401 at expiry, not before (the client
/// answers every ping, so only expiry can close it).
#[tokio::test(start_paused = true)]
async fn t05_token_expiry_closes_4401() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let t0 = Instant::now();
    let mut s = Sock::authed(&r.state, &u.token).await;
    let (code, pings) = s.close_code(true).await;
    assert_eq!(code, 4401);
    let left = ACCESS_TTL.to_std().unwrap();
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= left && elapsed < left + Duration::from_secs(1),
        "{elapsed:?}"
    );
    assert!(pings >= 28, "{pings} pings");
}

// --------------------------------------------------------------------- T-06

/// T-06: pings every 30 s; 2 missed pongs → closed (4408) 60 s after the
/// first unanswered ping. Client pings are answered.
#[tokio::test(start_paused = true)]
async fn t06_missed_pongs_close() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let mut s = Sock::open(&r.state);
    s.send(&ClientMsg::Auth { token: u.token }).await;
    let t0 = Instant::now();
    // The client's own ping is answered.
    s.send(&ClientMsg::Ping).await;
    let (code, pings) = s.close_code(false).await;
    assert_eq!(code, 4408);
    assert_eq!(t0.elapsed(), Duration::from_secs(60));
    assert_eq!(pings, 2);

    // Answering keeps it open well past that.
    let mut s = Sock::authed(&r.state, &env.user().token).await;
    s.quiet_for(Duration::from_secs(300)).await;
    s.send(&ClientMsg::Ping).await;
    assert_eq!(s.notification().await, ServerMsg::Pong);
}

// --------------------------------------------------------------------- T-07

/// T-07: a grant subscribes an open socket; a revocation unsubscribes it
/// and delivers `vault_access revoked`; a rotation reaches all members.
#[tokio::test]
async fn t07_grant_and_revoke_live() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let a = env.user();
    let b = env.user();
    let mut sb = Sock::authed(&r.state, &b.token).await;
    let ws = r.state.ws();

    push_one(&r.app, &a.token, a.vault).await;
    sb.quiet_for(Duration::from_millis(200)).await;

    ws.vault_access(b.id, a.vault, AccessChange::Granted);
    assert_eq!(
        sb.notification().await,
        ServerMsg::VaultAccess {
            vault_id: a.vault,
            change: AccessChange::Granted
        }
    );
    let head = push_one(&r.app, &a.token, a.vault).await;
    assert_eq!(
        sb.notification().await,
        ServerMsg::VaultChanged {
            vault_id: a.vault,
            head_revision: head
        }
    );

    ws.vault_rotated(a.vault);
    assert_eq!(
        sb.notification().await,
        ServerMsg::VaultAccess {
            vault_id: a.vault,
            change: AccessChange::Rotated
        }
    );

    ws.vault_access(b.id, a.vault, AccessChange::Revoked);
    assert_eq!(
        sb.notification().await,
        ServerMsg::VaultAccess {
            vault_id: a.vault,
            change: AccessChange::Revoked
        }
    );
    push_one(&r.app, &a.token, a.vault).await;
    sb.quiet_for(Duration::from_millis(200)).await;
    assert_eq!(ws.hub().subscribers(Topic::Vault(a.vault)), 0);
}

// --------------------------------------------------------------------- T-08

/// T-08: revoking a device closes its sockets with 4401 immediately; the
/// user's other devices stay connected.
#[tokio::test]
async fn t08_device_revoked_closes_4401() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let (_, other_token) = env.device(u.id);
    let mut s = Sock::authed(&r.state, &u.token).await;
    let mut other = Sock::authed(&r.state, &other_token).await;

    let (st, v) = call(
        &r.app,
        "DELETE",
        &format!("/v1/devices/{}", u.device_id),
        None,
        &other_token,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{v}");
    let (code, _) = tokio::time::timeout(Duration::from_secs(2), s.close_code(false))
        .await
        .expect("not closed immediately");
    assert_eq!(code, 4401);
    other.quiet_for(Duration::from_millis(200)).await;
}

/// T-08b: a disabled account → all its sockets close with 4401.
#[tokio::test]
async fn t08_user_disabled_closes_4401() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let mut s = Sock::authed(&r.state, &u.token).await;
    r.state.ws().user_disabled(u.id);
    let (code, _) = tokio::time::timeout(Duration::from_secs(2), s.close_code(false))
        .await
        .unwrap();
    assert_eq!(code, 4401);
}

/// Safety net: tokens deleted behind the bus' back (e.g. a missed event)
/// close the socket at the next heartbeat.
#[tokio::test(start_paused = true)]
async fn revalidation_on_heartbeat_closes_4401() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let mut s = Sock::authed(&r.state, &u.token).await;
    let t0 = Instant::now();
    env.mem.with_data(|d| d.tokens.clear());
    let (code, _) = s.close_code(true).await;
    assert_eq!(code, 4401);
    assert!(t0.elapsed() <= Duration::from_secs(30));
}

// ------------------------------------------------- account / share events

/// `account_changed` reaches the user's other devices, not the origin.
#[tokio::test]
async fn account_changed_skips_the_origin_device() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let (d2, t2) = env.device(u.id);
    let mut s1 = Sock::authed(&r.state, &u.token).await;
    let mut s2 = Sock::authed(&r.state, &t2).await;
    r.state.ws().account_changed(u.id, 2, Some(d2));
    assert_eq!(
        s1.notification().await,
        ServerMsg::AccountChanged { key_version: 2 }
    );
    s2.quiet_for(Duration::from_millis(200)).await;
}

/// The M6-01 hook: `share_join_request` reaches the owner's sockets.
#[tokio::test]
async fn share_join_request_reaches_the_owner() {
    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let owner = env.user();
    let other = env.user();
    let mut so = Sock::authed(&r.state, &owner.token).await;
    let mut sx = Sock::authed(&r.state, &other.token).await;
    let share = Uuid::now_v7();
    let viewer = ShareViewer {
        viewer_id: 3,
        name: Some("bob".into()),
        account: None,
        ip_hint: Some("198.51.100.0/24".into()),
    };
    r.state
        .ws()
        .share_join_request(owner.id, share, viewer.clone());
    assert_eq!(
        so.notification().await,
        ServerMsg::ShareJoinRequest {
            share_id: share,
            viewer
        }
    );
    sx.quiet_for(Duration::from_millis(200)).await;
}

// ------------------------------------------------------------ readiness

/// The PostgreSQL listener marks readiness degraded while it can't connect.
#[tokio::test]
async fn pg_listener_down_degrades_readiness() {
    let pool = lazy_pool();
    let auth = AuthRuntime::postgres(pool.clone());
    let state = AppState::with_auth(config(&[]), pool, generous(), auth);
    assert!(state.readiness().degraded().is_empty());
    state.ws().ensure_started(&state);
    assert_eq!(state.readiness().degraded(), vec!["ws_listener"]);
}

// ------------------------------------------------------- over a real socket

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

/// End to end through axum's upgrade: auth by first message (no token in
/// the URL), a push notification, and 4401 for a bad token.
#[tokio::test]
async fn e2e_upgrade_auth_and_notify() {
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    let env = Env::new();
    let r = env.replica(Arc::new(LocalBus::new()));
    let u = env.user();
    let addr = serve(r.app.clone()).await;
    let url = format!("ws://{addr}/v1/ws");

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::text(
        serde_json::to_string(&ClientMsg::Auth {
            token: u.token.clone(),
        })
        .unwrap(),
    ))
    .await
    .unwrap();
    let first = ws.next().await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<ServerMsg>(first.to_text().unwrap()).unwrap(),
        ServerMsg::Ping
    );
    let head = push_one(&r.app, &u.token, u.vault).await;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<ServerMsg>(msg.to_text().unwrap()).unwrap(),
        ServerMsg::VaultChanged {
            vault_id: u.vault,
            head_revision: head
        }
    );

    let (mut bad, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    bad.send(Message::text(r#"{"type":"auth","token":"nope"}"#))
        .await
        .unwrap();
    match bad.next().await.unwrap().unwrap() {
        Message::Close(Some(f)) => assert_eq!(f.code, CloseCode::from(4401)),
        other => panic!("expected close 4401, got {other:?}"),
    }
}

// ------------------------------------------------- registration (PG twin)

/// Registers an account over HTTP (OPAQUE, cheap test KSF); returns its
/// access token and personal vault.
async fn register(app: &Router, email: &str) -> (String, Uuid) {
    use sverb_crypto::account::{derive_akek, generate_account_keys, seal_private_bundle};
    use sverb_crypto::grant::self_grant;
    use sverb_crypto::opaque::{SverbKsf, client_registration_start};
    use sverb_crypto::random::{os_rng, random_key32};
    use sverb_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};

    let anon = |method: &str, path: &str, body: &Value| {
        req(method, path, "198.51.100.7:4000")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let ksf = SverbKsf::insecure_for_tests();
    let password = b"correct horse battery staple";
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password).unwrap();
    let start = json!({ "email": email, "registration_request": b64::encode(&request) });
    let (st, _, body) = send(app, anon("POST", "/v1/auth/register/start", &start)).await;
    let v = json(&body);
    assert_eq!(st, StatusCode::OK, "{v}");
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state.finish(&mut rng, password, &response, &ksf).unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _words) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let vault = Uuid::now_v7();
    let vk = random_key32(&mut rng);
    let grant = self_grant(&vk, vault.as_bytes(), 1, &uid, &keys, &mut rng).unwrap();
    let pubk = keys.public();
    let finish = json!({
        "email": email,
        "user_id": user_id,
        "registration_upload": b64::encode(&fin.upload),
        "account_keys": {
            "x25519_pub": b64::encode(&pubk.x25519),
            "ed25519_pub": b64::encode(&pubk.ed25519),
            "private_bundle_enc": b64::encode(&private),
            "recovery_bundle_enc": b64::encode(&rbundle),
            "version": 1,
        },
        "personal_vault": {
            "id": vault,
            "name_enc": b64::encode(b"encrypted-name"),
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "laptop", "platform": "linux" },
    });
    let (st, _, body) = send(app, anon("POST", "/v1/auth/register/finish", &finish)).await;
    let v = json(&body);
    assert_eq!(st, StatusCode::OK, "{v}");
    (
        v["tokens"]["access_token"].as_str().unwrap().to_owned(),
        vault,
    )
}
