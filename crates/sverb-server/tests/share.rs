//! M6-01: terminal-share relay (`/v1/shares`).
//!
//! Relay behaviour (routing, stamping, limits, kick, slow viewers, the
//! join notification, the log canary) runs over real TCP WebSockets
//! (tokio-tungstenite against `axum::serve` on loopback). Timing (auth
//! window, expiry, host grace) drives `share::run_host` / `run_viewer` over
//! in-memory channels on paused Tokio time, like the M4-05 tests. The
//! PostgreSQL twin of the share store needs `DATABASE_URL` and otherwise
//! prints "SKIPPED (needs PostgreSQL)".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::io::Write as _;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use chrono::Utc;
use common::{TestDb, config, json, req, send};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sverb_proto::share::{
    CLOSE_AUTH_REQUIRED, CLOSE_FORBIDDEN, CLOSE_KICKED, CLOSE_NOT_FOUND, CLOSE_REPLACED,
    CLOSE_SHARE_ENDED, CLOSE_SHARE_FULL, HostServerMsg, LeaveReason, MAX_RELAY_MESSAGE,
    RelayEnvelope, ShareMode, ShareViewer, ViewerServerMsg,
};
use sverb_proto::ws::{ClientMsg, ServerMsg};
use sverb_server::auth::store::mem::{MemDevice, MemStore, MemToken, MemUser};
use sverb_server::auth::tokens::{ACCESS_TTL, NewToken, TokenKind};
use sverb_server::auth::{AuthRuntime, AuthStore, Clock, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::share::{RelayFrame, ShareRow, ShareStore};
use sverb_server::ws::LocalBus;
use sverb_server::{AppState, app};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
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

struct Env {
    mem: Arc<MemStore>,
    clock: Arc<ManualClock>,
    state: AppState,
    app: Router,
}

#[derive(Clone)]
struct TUser {
    id: Uuid,
    email: String,
    token: String,
}

impl Env {
    fn new() -> Self {
        Self::with_config(&[])
    }

    fn with_config(extra: &[(&str, &str)]) -> Self {
        let mem = Arc::new(MemStore::new());
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let state = AppState::with_bus(
            config(extra),
            lazy_pool(),
            generous(),
            auth,
            Arc::new(LocalBus::new()),
        );
        Self {
            mem,
            clock,
            app: app::router(state.clone()),
            state,
        }
    }

    /// A user with one device and an access token.
    fn user(&self) -> TUser {
        let id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let email = format!("u{}@example.com", id.simple());
        let tok = NewToken::generate();
        let now = self.clock.now();
        self.mem.with_data(|d| {
            d.users.insert(
                id,
                MemUser {
                    email: email.clone(),
                    created_at: now,
                    is_instance_admin: false,
                    opaque_record: vec![0],
                    totp_secret_enc: None,
                    totp_pending_enc: None,
                    totp_last_step: None,
                    disabled: false,
                },
            );
            d.devices.insert(
                device_id,
                MemDevice {
                    user_id: id,
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
        TUser {
            id,
            email,
            token: tok.wire.to_string(),
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut b = req(method, path, "198.51.100.7:4000");
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let r = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let (st, _, bytes) = send(&self.app, r).await;
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            json(&bytes)
        };
        (st, v)
    }

    /// Creates a share; returns its id.
    async fn share(&self, owner: &TUser, body: &Value) -> Uuid {
        let (st, v) = self
            .call("POST", "/v1/shares", Some(body), Some(&owner.token))
            .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        serde_json::from_value(v["share_id"].clone()).unwrap()
    }

    async fn row(&self, id: Uuid) -> ShareRow {
        self.state.shares().store().get(id).await.unwrap().unwrap()
    }
}

fn env_frame(viewer_id: u32, payload: &[u8]) -> Vec<u8> {
    RelayEnvelope {
        viewer_id,
        payload: payload.to_vec(),
    }
    .encode()
}

// ---------------------------------------------- in-memory transport (paused)

/// What a [`MemSock`]'s pump saw.
#[derive(Debug)]
#[allow(dead_code)]
enum Ev {
    Ctl(Value),
    Bin(Vec<u8>),
    Closed(u16),
}

/// A share socket on in-memory channels. A pump task answers pings (unless
/// `silent`), so idle sockets survive paused-time jumps.
struct MemSock {
    tx: mpsc::UnboundedSender<RelayFrame>,
    events: tokio::sync::mpsc::UnboundedReceiver<Ev>,
    _task: JoinHandle<()>,
    _pump: JoinHandle<()>,
}

impl MemSock {
    fn spawn<F, Fut>(run: F, silent: bool) -> Self
    where
        F: FnOnce(mpsc::UnboundedReceiver<RelayFrame>, mpsc::UnboundedSender<RelayFrame>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, srv_in) = mpsc::unbounded();
        let (srv_out, mut rx) = mpsc::unbounded();
        let task = tokio::spawn(run(srv_in, srv_out));
        let (ev_tx, events) = tokio::sync::mpsc::unbounded_channel();
        let mut pong = tx.clone();
        let pump = tokio::spawn(async move {
            while let Some(f) = rx.next().await {
                let ev = match f {
                    RelayFrame::Text(t) => {
                        let v: Value = serde_json::from_str(&t).unwrap();
                        if v["type"] == "ping" {
                            if !silent {
                                let _ = pong
                                    .send(RelayFrame::Text(json!({"type": "pong"}).to_string()))
                                    .await;
                            }
                            continue;
                        }
                        Ev::Ctl(v)
                    }
                    RelayFrame::Binary(b) => Ev::Bin(b),
                    RelayFrame::Close { code, .. } => Ev::Closed(code),
                    RelayFrame::Other => continue,
                };
                let closed = matches!(ev, Ev::Closed(_));
                let _ = ev_tx.send(ev);
                if closed {
                    return;
                }
            }
        });
        Self {
            tx,
            events,
            _task: task,
            _pump: pump,
        }
    }

    fn host(state: &AppState, share: Uuid) -> Self {
        let st = state.clone();
        Self::spawn(
            move |i, o| sverb_server::share::run_host(st, share, i, o),
            false,
        )
    }

    fn viewer_with(state: &AppState, share: Uuid, silent: bool) -> Self {
        let st = state.clone();
        Self::spawn(
            move |i, o| {
                sverb_server::share::run_viewer(
                    st,
                    share,
                    Some("203.0.113.50".parse().unwrap()),
                    i,
                    o,
                )
            },
            silent,
        )
    }

    fn viewer(state: &AppState, share: Uuid) -> Self {
        Self::viewer_with(state, share, false)
    }

    async fn send_json(&mut self, v: &Value) {
        let _ = self.tx.send(RelayFrame::Text(v.to_string())).await;
    }

    async fn ev(&mut self) -> Ev {
        tokio::time::timeout(Duration::from_secs(48 * 3600), self.events.recv())
            .await
            .expect("nothing within two days")
            .expect("ended without a close frame")
    }

    /// The next control message.
    async fn ctl(&mut self) -> Value {
        match self.ev().await {
            Ev::Ctl(v) => v,
            other => panic!("expected a control message, got {other:?}"),
        }
    }

    /// Skips to the close frame; returns its code.
    async fn close_code(&mut self) -> u16 {
        loop {
            if let Ev::Closed(code) = self.ev().await {
                return code;
            }
        }
    }

    async fn authed_host(state: &AppState, share: Uuid, token: &str) -> Self {
        let mut s = Self::host(state, share);
        s.send_json(&json!({"type": "auth", "token": token})).await;
        assert_eq!(s.ctl().await["type"], "ready");
        s
    }

    async fn joined_viewer(state: &AppState, share: Uuid, name: &str) -> (Self, u32) {
        let mut s = Self::viewer(state, share);
        s.send_json(&json!({"type": "join", "name": name})).await;
        let v = s.ctl().await;
        assert_eq!(v["type"], "joined", "{v}");
        let id = u32::try_from(v["viewer_id"].as_u64().unwrap()).unwrap();
        (s, id)
    }
}

// ------------------------------------------------------ TCP transport (real)

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

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

struct Tcp {
    addr: SocketAddr,
}

impl Tcp {
    async fn open(&self, path: &str) -> Ws {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{}{path}", self.addr))
            .await
            .unwrap();
        ws
    }

    async fn host(&self, share: Uuid, token: &str) -> Ws {
        let mut ws = self.open(&format!("/v1/shares/{share}/host")).await;
        send_json(&mut ws, &json!({"type": "auth", "token": token})).await;
        let v = next_ctl(&mut ws).await;
        assert_eq!(v["type"], "ready", "{v}");
        ws
    }

    async fn viewer(&self, share: Uuid, first: &Value) -> Ws {
        let mut ws = self.open(&format!("/v1/shares/{share}/join")).await;
        send_json(&mut ws, first).await;
        ws
    }

    async fn joined(&self, share: Uuid, name: &str) -> (Ws, u32) {
        let mut ws = self
            .viewer(share, &json!({"type": "join", "name": name}))
            .await;
        let v = next_ctl(&mut ws).await;
        assert_eq!(v["type"], "joined", "{v}");
        (ws, u32::try_from(v["viewer_id"].as_u64().unwrap()).unwrap())
    }
}

async fn send_json(ws: &mut Ws, v: &Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

async fn next_msg(ws: &mut Ws) -> Message {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("no message within 10 s")
            .expect("stream ended")
            .expect("socket error");
        match &m {
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Text(t) if serde_json::from_str::<Value>(t).unwrap()["type"] == "ping" => {
                send_json(ws, &json!({"type": "pong"})).await;
            }
            _ => return m,
        }
    }
}

async fn next_ctl(ws: &mut Ws) -> Value {
    match next_msg(ws).await {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected a control message, got {other:?}"),
    }
}

async fn next_bin(ws: &mut Ws) -> Vec<u8> {
    match next_msg(ws).await {
        Message::Binary(b) => b.to_vec(),
        other => panic!("expected binary, got {other:?}"),
    }
}

async fn close_code(ws: &mut Ws) -> u16 {
    match next_msg(ws).await {
        Message::Close(Some(f)) => u16::from(f.code),
        other => panic!("expected close, got {other:?}"),
    }
}

/// Nothing but heartbeats within `d`.
async fn quiet(ws: &mut Ws, d: Duration) {
    if let Ok(m) = tokio::time::timeout(d, next_msg(ws)).await {
        panic!("unexpected {m:?}");
    }
}

// --------------------------------------------------------------------- T-01

/// T-01: create → id and expiry (default 24 h, 10 viewers); over-limit
/// values are clamped, zero is invalid, auth is required.
#[tokio::test]
async fn t01_create_share_defaults_and_limits() {
    let env = Env::new();
    let u = env.user();
    let now = env.clock.now();

    let (st, v) = env
        .call("POST", "/v1/shares", Some(&json!({})), Some(&u.token))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let id: Uuid = serde_json::from_value(v["share_id"].clone()).unwrap();
    let expires: chrono::DateTime<Utc> = serde_json::from_value(v["expires_at"].clone()).unwrap();
    assert_eq!(expires, now + chrono::Duration::hours(24));
    assert_eq!(v["max_viewers"], 10);
    let row = env.row(id).await;
    assert_eq!(row.owner_user_id, u.id);
    assert_eq!(row.mode, ShareMode::View);
    assert_eq!(row.max_viewers, 10);
    assert!(!row.require_account);
    assert_eq!(row.closed_at, None);

    // Over the limits → clamped.
    let (st, v) = env
        .call(
            "POST",
            "/v1/shares",
            Some(&json!({"mode": "control", "expires_in_s": 999_999_999u64,
                         "max_viewers": 50, "require_account": true})),
            Some(&u.token),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let row = env
        .row(serde_json::from_value(v["share_id"].clone()).unwrap())
        .await;
    assert_eq!(row.expires_at, now + chrono::Duration::hours(24));
    assert_eq!(row.max_viewers, 10);
    assert_eq!(row.mode, ShareMode::Control);
    assert!(row.require_account);

    // Within the limits → as asked.
    let (_, v) = env
        .call(
            "POST",
            "/v1/shares",
            Some(&json!({"expires_in_s": 900, "max_viewers": 2})),
            Some(&u.token),
        )
        .await;
    let row = env
        .row(serde_json::from_value(v["share_id"].clone()).unwrap())
        .await;
    assert_eq!(row.expires_at, now + chrono::Duration::seconds(900));
    assert_eq!(row.max_viewers, 2);

    // Zero → 400; no token → 401; a bad mode → 4xx.
    for body in [json!({"expires_in_s": 0}), json!({"max_viewers": 0})] {
        let (st, v) = env
            .call("POST", "/v1/shares", Some(&body), Some(&u.token))
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
        assert_eq!(v["error"]["code"], "invalid");
    }
    let (st, _) = env.call("POST", "/v1/shares", Some(&json!({})), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = env
        .call(
            "POST",
            "/v1/shares",
            Some(&json!({"mode": "root"})),
            Some(&u.token),
        )
        .await;
    assert!(st.is_client_error());
}

/// T-01b: the configured limits apply.
#[tokio::test]
async fn t01_configured_limits() {
    let env = Env::with_config(&[
        ("SVERB_SHARE_MAX_VIEWERS", "3"),
        ("SVERB_SHARE_TTL_HOURS", "1"),
    ]);
    let u = env.user();
    let (_, v) = env
        .call(
            "POST",
            "/v1/shares",
            Some(&json!({"expires_in_s": 7200, "max_viewers": 5})),
            Some(&u.token),
        )
        .await;
    assert_eq!(v["max_viewers"], 3);
    let row = env
        .row(serde_json::from_value(v["share_id"].clone()).unwrap())
        .await;
    assert_eq!(row.expires_at, env.clock.now() + chrono::Duration::hours(1));
}

/// DELETE: owner only (others get 404, like an unknown id); sets
/// `closed_at`; idempotent.
#[tokio::test]
async fn delete_is_owner_only() {
    let env = Env::new();
    let owner = env.user();
    let other = env.user();
    let id = env.share(&owner, &json!({})).await;
    let path = format!("/v1/shares/{id}");
    let (st, _) = env.call("DELETE", &path, None, Some(&other.token)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(env.row(id).await.closed_at, None);
    let (st, _) = env
        .call(
            "DELETE",
            &format!("/v1/shares/{}", Uuid::now_v7()),
            None,
            Some(&owner.token),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = env.call("DELETE", &path, None, Some(&owner.token)).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let closed = env.row(id).await.closed_at.unwrap();
    env.clock.advance(chrono::Duration::seconds(5));
    let (st, _) = env.call("DELETE", &path, None, Some(&owner.token)).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(env.row(id).await.closed_at, Some(closed));
}

// --------------------------------------------------------------------- T-02

/// T-02: the host stream needs the owner's token: silence → 4401 after 5 s,
/// a bad token → 4401, another user → 4403, an unknown share → 4403.
#[tokio::test(start_paused = true)]
async fn t02_host_auth_owner_only() {
    let env = Env::new();
    let owner = env.user();
    let other = env.user();
    let id = env.share(&owner, &json!({})).await;

    let t0 = Instant::now();
    let mut s = MemSock::host(&env.state, id);
    assert_eq!(s.close_code().await, CLOSE_AUTH_REQUIRED);
    assert_eq!(t0.elapsed(), Duration::from_secs(5));

    let mut s = MemSock::host(&env.state, id);
    s.send_json(&json!({"type": "auth", "token": "nope"})).await;
    assert_eq!(s.close_code().await, CLOSE_AUTH_REQUIRED);

    let mut s = MemSock::host(&env.state, id);
    s.send_json(&json!({"type": "join", "name": "x"})).await;
    assert_eq!(s.close_code().await, CLOSE_AUTH_REQUIRED);

    let mut s = MemSock::host(&env.state, id);
    s.send_json(&json!({"type": "auth", "token": other.token}))
        .await;
    assert_eq!(s.close_code().await, CLOSE_FORBIDDEN);

    let mut s = MemSock::host(&env.state, Uuid::now_v7());
    s.send_json(&json!({"type": "auth", "token": owner.token}))
        .await;
    assert_eq!(s.close_code().await, CLOSE_FORBIDDEN);

    let _h = MemSock::authed_host(&env.state, id, &owner.token).await;
    assert!(env.state.shares().relays().get(id).unwrap().has_host());
}

/// T-02 over TCP: another user is rejected with 4403, the owner gets
/// `ready`.
#[tokio::test]
async fn t02_host_auth_over_tcp() {
    let env = Env::new();
    let owner = env.user();
    let other = env.user();
    let id = env.share(&owner, &json!({"mode": "control"})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut ws = tcp.open(&format!("/v1/shares/{id}/host")).await;
    send_json(&mut ws, &json!({"type": "auth", "token": other.token})).await;
    assert_eq!(close_code(&mut ws).await, CLOSE_FORBIDDEN);

    let mut ws = tcp.open(&format!("/v1/shares/{id}/host")).await;
    send_json(&mut ws, &json!({"type": "auth", "token": owner.token})).await;
    let v = next_ctl(&mut ws).await;
    assert_eq!(v["type"], "ready");
    assert_eq!(v["mode"], "control");
    assert_eq!(v["share_id"], json!(id));
}

// --------------------------------------------------------------------- T-03

/// T-03: anonymous viewers join when the share allows it; when it requires
/// an account, `join` → 4401, bad tokens → 4401, a signed-in viewer joins
/// and the host sees its account; unknown shares → 4404.
#[tokio::test]
async fn t03_anonymous_and_account_viewers() {
    let env = Env::new();
    let owner = env.user();
    let viewer_user = env.user();
    let open = env.share(&owner, &json!({})).await;
    let closed = env.share(&owner, &json!({"require_account": true})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };

    // Open share: anonymous.
    let mut host = tcp.host(open, &owner.token).await;
    let (mut v1, id1) = tcp.joined(open, "  bob\u{7} ").await;
    assert_ne!(id1, 0);
    assert_eq!(next_ctl(&mut v1).await["type"], "host_connected");
    let j: HostServerMsg = serde_json::from_value(next_ctl(&mut host).await).unwrap();
    assert_eq!(
        j,
        HostServerMsg::ViewerJoined(ShareViewer {
            viewer_id: id1,
            name: Some("bob".into()),
            account: None,
            ip_hint: Some("127.0.0.0/24".into()),
        })
    );

    // Account required: anonymous → 4401, bad token → 4401.
    let mut ws = tcp
        .viewer(closed, &json!({"type": "join", "name": "eve"}))
        .await;
    assert_eq!(close_code(&mut ws).await, CLOSE_AUTH_REQUIRED);
    let mut ws = tcp
        .viewer(closed, &json!({"type": "auth", "token": "garbage"}))
        .await;
    assert_eq!(close_code(&mut ws).await, CLOSE_AUTH_REQUIRED);

    // Signed in → admitted with the account email.
    let mut host2 = tcp.host(closed, &owner.token).await;
    let mut ws = tcp
        .viewer(
            closed,
            &json!({"type": "auth", "token": viewer_user.token, "name": "Vic"}),
        )
        .await;
    let joined: ViewerServerMsg = serde_json::from_value(next_ctl(&mut ws).await).unwrap();
    assert!(matches!(
        joined,
        ViewerServerMsg::Joined {
            viewer_id: 1,
            mode: ShareMode::View
        }
    ));
    let v = next_ctl(&mut host2).await;
    assert_eq!(v["type"], "viewer_joined");
    assert_eq!(v["account"], json!(viewer_user.email));
    assert_eq!(v["name"], "Vic");

    // Unknown share.
    let mut ws = tcp.viewer(Uuid::now_v7(), &json!({"type": "join"})).await;
    assert_eq!(close_code(&mut ws).await, CLOSE_NOT_FOUND);
}

// --------------------------------------------------------------------- T-04

/// T-04: host → viewer 1 never reaches viewer 2; a viewer's message reaches
/// the host stamped with its real id even when it forged another.
#[tokio::test]
async fn t04_routing_and_stamping() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({"mode": "control"})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut host = tcp.host(id, &owner.token).await;
    let (mut v1, id1) = tcp.joined(id, "one").await;
    let (mut v2, id2) = tcp.joined(id, "two").await;
    assert_ne!(id1, id2);
    for v in [&mut v1, &mut v2] {
        assert_eq!(next_ctl(v).await["type"], "host_connected");
    }
    for want in [id1, id2] {
        let v = next_ctl(&mut host).await;
        assert_eq!(v["type"], "viewer_joined");
        assert_eq!(v["viewer_id"], want);
    }

    // Host → viewer 1 only.
    host.send(Message::binary(env_frame(id1, b"for-one")))
        .await
        .unwrap();
    let got = RelayEnvelope::decode(&next_bin(&mut v1).await).unwrap();
    assert_eq!(got.viewer_id, id1);
    assert_eq!(got.payload, b"for-one");
    // Unknown and control ids are dropped.
    host.send(Message::binary(env_frame(0, b"control")))
        .await
        .unwrap();
    host.send(Message::binary(env_frame(999, b"nobody")))
        .await
        .unwrap();
    host.send(Message::binary(env_frame(id2, b"for-two")))
        .await
        .unwrap();
    let got = RelayEnvelope::decode(&next_bin(&mut v2).await).unwrap();
    assert_eq!(
        (got.viewer_id, got.payload.as_slice()),
        (id2, &b"for-two"[..])
    );
    quiet(&mut v1, Duration::from_millis(300)).await;

    // Viewer 2 forges viewer 1's id → the host sees viewer 2.
    v2.send(Message::binary(env_frame(id1, b"forged")))
        .await
        .unwrap();
    let got = RelayEnvelope::decode(&next_bin(&mut host).await).unwrap();
    assert_eq!(got.viewer_id, id2);
    assert_eq!(got.payload, b"forged");
    v1.send(Message::binary(env_frame(0xFFFF_FFFF, b"hi")))
        .await
        .unwrap();
    let got = RelayEnvelope::decode(&next_bin(&mut host).await).unwrap();
    assert_eq!((got.viewer_id, got.payload.as_slice()), (id1, &b"hi"[..]));
    // Runt messages (shorter than the header) are dropped.
    v1.send(Message::binary(vec![1, 2])).await.unwrap();
    quiet(&mut host, Duration::from_millis(300)).await;

    // A viewer leaving is reported to the host.
    v1.close(None).await.unwrap();
    let v: HostServerMsg = serde_json::from_value(next_ctl(&mut host).await).unwrap();
    assert_eq!(
        v,
        HostServerMsg::ViewerLeft {
            viewer_id: id1,
            reason: LeaveReason::Left
        }
    );
}

/// Messages above 1 MiB close the connection; 1 MiB passes.
#[tokio::test]
async fn message_size_limit() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut host = tcp.host(id, &owner.token).await;
    let (mut v1, id1) = tcp.joined(id, "one").await;
    let _ = next_ctl(&mut host).await;
    let _ = next_ctl(&mut v1).await;
    let max = vec![7u8; MAX_RELAY_MESSAGE - RelayEnvelope::HEADER_LEN];
    host.send(Message::binary(env_frame(id1, &max)))
        .await
        .unwrap();
    assert_eq!(next_bin(&mut v1).await.len(), MAX_RELAY_MESSAGE);
    let too_big = vec![7u8; MAX_RELAY_MESSAGE];
    let _ = v1.send(Message::binary(env_frame(id1, &too_big))).await;
    // The viewer's connection is dropped (1009) and the host is told.
    let v = next_ctl(&mut host).await;
    assert_eq!(v["type"], "viewer_left");
    assert_eq!(v["viewer_id"], id1);
}

// --------------------------------------------------------------------- T-05

/// T-05: with `max_viewers` 10, the 11th viewer is closed with 4429; a
/// freed seat can be taken again.
#[tokio::test]
async fn t05_max_viewers() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut viewers = Vec::new();
    for i in 0..10 {
        viewers.push(tcp.joined(id, &format!("v{i}")).await);
    }
    let ids: std::collections::BTreeSet<u32> = viewers.iter().map(|(_, id)| *id).collect();
    assert_eq!(ids.len(), 10);
    assert!(!ids.contains(&0));
    let mut ws = tcp.viewer(id, &json!({"type": "join"})).await;
    assert_eq!(close_code(&mut ws).await, CLOSE_SHARE_FULL);

    let (mut gone, _) = viewers.pop().unwrap();
    gone.close(None).await.unwrap();
    let relay = env.state.shares().relays().get(id).unwrap();
    for _ in 0..200 {
        if relay.viewer_count() == 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_ws, new_id) = tcp.joined(id, "late").await;
    assert!(!ids.contains(&new_id), "viewer ids are not reused");
}

// --------------------------------------------------------------------- T-06

/// T-06: `kick` closes that viewer (4411) and reports it; others stay.
#[tokio::test]
async fn t06_kick() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut host = tcp.host(id, &owner.token).await;
    let (mut v1, id1) = tcp.joined(id, "one").await;
    let (mut v2, id2) = tcp.joined(id, "two").await;
    for _ in 0..2 {
        let _ = next_ctl(&mut host).await;
    }
    for v in [&mut v1, &mut v2] {
        let _ = next_ctl(v).await;
    }
    send_json(&mut host, &json!({"type": "kick", "viewer_id": id1})).await;
    assert_eq!(close_code(&mut v1).await, CLOSE_KICKED);
    let v: HostServerMsg = serde_json::from_value(next_ctl(&mut host).await).unwrap();
    assert_eq!(
        v,
        HostServerMsg::ViewerLeft {
            viewer_id: id1,
            reason: LeaveReason::Kicked
        }
    );
    // Kicking an unknown id is harmless; viewer 2 still gets frames.
    send_json(&mut host, &json!({"type": "kick", "viewer_id": 4242})).await;
    host.send(Message::binary(env_frame(id2, b"still here")))
        .await
        .unwrap();
    assert_eq!(
        RelayEnvelope::decode(&next_bin(&mut v2).await)
            .unwrap()
            .payload,
        b"still here"
    );
}

// --------------------------------------------------------------------- T-07

/// T-07: at expiry every socket closes with 4410 and `closed_at` is set; a
/// later join is refused with 4410.
#[tokio::test(start_paused = true)]
async fn t07_expiry_closes_everything() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({"expires_in_s": 600})).await;
    let t0 = Instant::now();
    let mut host = MemSock::authed_host(&env.state, id, &owner.token).await;
    let (mut v1, _) = MemSock::joined_viewer(&env.state, id, "one").await;
    let (mut v2, _) = MemSock::joined_viewer(&env.state, id, "two").await;
    assert_eq!(v1.ctl().await["type"], "host_connected");
    assert_eq!(host.ctl().await["type"], "viewer_joined");

    assert_eq!(v1.close_code().await, CLOSE_SHARE_ENDED);
    assert_eq!(t0.elapsed(), Duration::from_secs(600));
    assert_eq!(v2.close_code().await, CLOSE_SHARE_ENDED);
    assert_eq!(host.close_code().await, CLOSE_SHARE_ENDED);
    assert!(env.row(id).await.closed_at.is_some());
    assert!(env.state.shares().relays().get(id).is_none());

    env.clock.advance(chrono::Duration::seconds(600));
    let mut late = MemSock::viewer(&env.state, id);
    assert_eq!(late.close_code().await, CLOSE_SHARE_ENDED);
    let mut late_host = MemSock::host(&env.state, id);
    late_host
        .send_json(&json!({"type": "auth", "token": owner.token}))
        .await;
    assert_eq!(late_host.close_code().await, CLOSE_SHARE_ENDED);
}

/// T-07b: DELETE closes everything with 4410 and sets `closed_at`.
#[tokio::test]
async fn t07_delete_closes_everything() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut host = tcp.host(id, &owner.token).await;
    let (mut v1, _) = tcp.joined(id, "one").await;
    let _ = next_ctl(&mut v1).await;
    let _ = next_ctl(&mut host).await;
    let (st, _) = env
        .call(
            "DELETE",
            &format!("/v1/shares/{id}"),
            None,
            Some(&owner.token),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(close_code(&mut v1).await, CLOSE_SHARE_ENDED);
    assert_eq!(close_code(&mut host).await, CLOSE_SHARE_ENDED);
    assert!(env.row(id).await.closed_at.is_some());
    let mut ws = tcp.viewer(id, &json!({"type": "join"})).await;
    assert_eq!(close_code(&mut ws).await, CLOSE_SHARE_ENDED);
}

/// §14.3 "the session ends": the host gone for more than 60 s ends the
/// share; a reconnect within the grace keeps it (and replaces the old
/// connection, 4409), and the new host learns about waiting viewers.
#[tokio::test(start_paused = true)]
async fn host_grace_and_reconnect() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let mut host = MemSock::authed_host(&env.state, id, &owner.token).await;
    let (mut v1, id1) = MemSock::joined_viewer(&env.state, id, "one").await;
    assert_eq!(v1.ctl().await["type"], "host_connected");
    assert_eq!(host.ctl().await["viewer_id"], id1);

    // A second host connection replaces the first.
    let mut host2 = MemSock::authed_host(&env.state, id, &owner.token).await;
    let v = host2.ctl().await;
    assert_eq!(
        (v["type"].as_str(), v["viewer_id"].as_u64()),
        (Some("viewer_joined"), Some(u64::from(id1)))
    );
    assert_eq!(host.close_code().await, CLOSE_REPLACED);
    assert_eq!(v1.ctl().await["type"], "host_connected");

    // Host drops; back within 50 s → still alive.
    host2.tx.close_channel();
    assert_eq!(v1.ctl().await["type"], "host_disconnected");
    tokio::time::sleep(Duration::from_secs(50)).await;
    let mut host3 = MemSock::authed_host(&env.state, id, &owner.token).await;
    assert_eq!(host3.ctl().await["type"], "viewer_joined");
    assert_eq!(v1.ctl().await["type"], "host_connected");
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(env.row(id).await.closed_at.is_none());

    // Gone for good → ended 60 s later.
    host3.tx.close_channel();
    let t0 = Instant::now();
    assert_eq!(v1.ctl().await["type"], "host_disconnected");
    assert_eq!(v1.close_code().await, CLOSE_SHARE_ENDED);
    assert_eq!(t0.elapsed(), Duration::from_secs(60));
    assert!(env.row(id).await.closed_at.is_some());
}

/// Unanswered pings close a viewer (4408 after 3 intervals) and the host
/// is told.
#[tokio::test(start_paused = true)]
async fn heartbeat_times_out_silent_viewers() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let mut host = MemSock::authed_host(&env.state, id, &owner.token).await;
    let mut v = MemSock::viewer_with(&env.state, id, true);
    v.send_json(&json!({"type": "join"})).await;
    let t0 = Instant::now();
    assert_eq!(v.close_code().await, 4408);
    assert_eq!(t0.elapsed(), Duration::from_secs(90));
    assert_eq!(host.ctl().await["type"], "viewer_joined");
    let left = host.ctl().await;
    assert_eq!(left["type"], "viewer_left");
    assert_eq!(left["reason"], "slow");
    assert!(env.row(id).await.closed_at.is_none());
}

// --------------------------------------------------------------------- T-08

/// T-08: a viewer that never reads is disconnected once its queue is full;
/// the host keeps streaming and the other viewer keeps receiving.
#[tokio::test]
async fn t08_slow_viewer_is_dropped() {
    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let mut host = tcp.host(id, &owner.token).await;
    let (mut fast, fast_id) = tcp.joined(id, "fast").await;
    let (slow, slow_id) = tcp.joined(id, "slow").await;
    let _ = next_ctl(&mut fast).await;
    for _ in 0..2 {
        let _ = next_ctl(&mut host).await;
    }

    // The fast viewer drains in the background and counts.
    let (count_tx, mut count_rx) = tokio::sync::mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        while let Some(Ok(m)) = fast.next().await {
            if let Message::Binary(b) = m {
                let _ = count_tx.send(b.len());
            }
        }
    });

    let chunk = vec![0x5a; 256 * 1024];
    let (mut host_tx, mut host_rx) = host.split();
    let mut sent = 0usize;
    let mut slow_left = false;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !slow_left {
        assert!(Instant::now() < deadline, "slow viewer never dropped");
        host_tx
            .send(Message::binary(env_frame(slow_id, &chunk)))
            .await
            .unwrap();
        sent += 1;
        if sent.is_multiple_of(8) {
            host_tx
                .send(Message::binary(env_frame(fast_id, b"tick")))
                .await
                .unwrap();
        }
        // Poll the host stream without blocking.
        while let Ok(Some(Ok(m))) =
            tokio::time::timeout(Duration::from_millis(1), host_rx.next()).await
        {
            if let Message::Text(t) = m {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "viewer_left" {
                    assert_eq!(v["viewer_id"], slow_id);
                    assert_eq!(v["reason"], "slow");
                    slow_left = true;
                }
            }
        }
    }
    // The queue (256) had to fill on top of the socket buffers.
    assert!(sent > 256, "{sent}");
    assert_eq!(
        env.state.shares().relays().get(id).unwrap().viewer_count(),
        1
    );

    // The host stream is unaffected: the fast viewer still receives.
    host_tx
        .send(Message::binary(env_frame(fast_id, b"after")))
        .await
        .unwrap();
    let mut got_after = false;
    while let Ok(Some(n)) = tokio::time::timeout(Duration::from_secs(5), count_rx.recv()).await {
        if n == RelayEnvelope::HEADER_LEN + b"after".len() {
            got_after = true;
            break;
        }
    }
    assert!(got_after);
    reader.abort();
    // The slow socket was closed by the server: draining it ends.
    let drained = tokio::time::timeout(Duration::from_secs(30), async move {
        let mut slow = slow;
        while let Some(Ok(_)) = slow.next().await {}
    })
    .await;
    assert!(drained.is_ok(), "slow viewer's socket still open");
}

// --------------------------------------------------------------------- T-09

/// T-09: a join is announced on the owner's general WebSocket as
/// `share_join_request` (and only there).
#[tokio::test]
async fn t09_share_join_request_on_general_ws() {
    let env = Env::new();
    let owner = env.user();
    let other = env.user();
    let id = env.share(&owner, &json!({})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let general = |token: String| {
        let tcp = &tcp;
        async move {
            let mut ws = tcp.open("/v1/ws").await;
            send_json(
                &mut ws,
                &serde_json::to_value(ClientMsg::Auth { token }).unwrap(),
            )
            .await;
            // The first server ping means "subscribed".
            let first = ws.next().await.unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<ServerMsg>(first.to_text().unwrap()).unwrap(),
                ServerMsg::Ping
            );
            ws
        }
    };
    let mut gw = general(owner.token.clone()).await;
    let mut gx = general(other.token.clone()).await;

    let (_v, vid) = tcp.joined(id, "carol").await;
    let m: ServerMsg = serde_json::from_value(next_ctl(&mut gw).await).unwrap();
    assert_eq!(
        m,
        ServerMsg::ShareJoinRequest {
            share_id: id,
            viewer: ShareViewer {
                viewer_id: vid,
                name: Some("carol".into()),
                account: None,
                ip_hint: Some("127.0.0.0/24".into()),
            }
        }
    );
    quiet(&mut gx, Duration::from_millis(300)).await;
}

// --------------------------------------------------------------------- T-10

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The process-wide capture (a global subscriber: per-thread defaults race
/// with the callsite interest cache when tests run in parallel). Every test
/// in this binary logs into it, which only widens the canary check.
fn global_logs() -> Captured {
    static LOGS: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("no other global subscriber");
        logs
    })
    .clone()
}

/// T-10: relaying a canary at TRACE level never puts its bytes (raw, hex
/// or as a byte list) or the tokens in the logs.
#[tokio::test]
async fn t10_payloads_never_logged() {
    let logs = global_logs();

    let env = Env::new();
    let owner = env.user();
    let id = env.share(&owner, &json!({"mode": "control"})).await;
    let tcp = Tcp {
        addr: serve(env.app.clone()).await,
    };
    let canary = b"CANARY-share-payload-7f3a91";
    let mut host = tcp.host(id, &owner.token).await;
    let (mut v1, id1) = tcp.joined(id, "one").await;
    let _ = next_ctl(&mut host).await;
    let _ = next_ctl(&mut v1).await;
    host.send(Message::binary(env_frame(id1, canary)))
        .await
        .unwrap();
    assert_eq!(
        RelayEnvelope::decode(&next_bin(&mut v1).await)
            .unwrap()
            .payload,
        canary
    );
    v1.send(Message::binary(env_frame(id1, canary)))
        .await
        .unwrap();
    let _ = next_bin(&mut host).await;
    send_json(&mut host, &json!({"type": "kick", "viewer_id": id1})).await;
    assert_eq!(close_code(&mut v1).await, CLOSE_KICKED);
    assert_eq!(next_ctl(&mut host).await["type"], "viewer_left");
    let (st, _) = env
        .call(
            "DELETE",
            &format!("/v1/shares/{id}"),
            None,
            Some(&owner.token),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let _ = close_code(&mut host).await;
    let _ = std::io::stdout().flush();

    let out = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    assert!(
        out.contains("share created"),
        "logging not captured:\n{out}"
    );
    let hex: String = canary.iter().map(|b| format!("{b:02x}")).collect();
    let list = format!("{:?}", &canary[..8]);
    let list = &list[1..list.len() - 1];
    for needle in ["CANARY", hex.as_str(), list, owner.token.as_str()] {
        assert!(!out.contains(needle), "{needle:?} leaked into logs:\n{out}");
    }
}

// ------------------------------------------------------------ persistence

fn sample_row(owner: Uuid, now: chrono::DateTime<Utc>, secs: i64) -> ShareRow {
    ShareRow {
        id: Uuid::now_v7(),
        owner_user_id: owner,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(secs),
        mode: ShareMode::Control,
        max_viewers: 4,
        require_account: true,
        closed_at: None,
    }
}

async fn store_contract(store: &ShareStore, owner: Uuid) {
    let now = Utc::now();
    let row = sample_row(owner, now, 3600);
    store.create(&row).await.unwrap();
    let got = store.get(row.id).await.unwrap().unwrap();
    assert_eq!(got.mode, row.mode);
    assert_eq!(got.max_viewers, 4);
    assert!(got.require_account);
    assert!(got.is_live(now));
    assert!(store.get(Uuid::now_v7()).await.unwrap().is_none());
    let closed = store.close(row.id, now).await.unwrap().unwrap();
    // Idempotent: the first closed_at stays.
    let again = store
        .close(row.id, now + chrono::Duration::seconds(9))
        .await
        .unwrap();
    assert_eq!(again, Some(closed));
    assert!(!store.get(row.id).await.unwrap().unwrap().is_live(now));
    assert_eq!(store.close(Uuid::now_v7(), now).await.unwrap(), None);
    // GC: closed and expired go, live stays.
    let expired = sample_row(owner, now - chrono::Duration::hours(2), 60);
    let live = sample_row(owner, now, 3600);
    store.create(&expired).await.unwrap();
    store.create(&live).await.unwrap();
    assert_eq!(store.purge_finished(now).await.unwrap(), 2);
    assert!(store.get(live.id).await.unwrap().is_some());
    assert!(store.get(row.id).await.unwrap().is_none());
}

#[tokio::test]
async fn share_store_contract_mem() {
    let env = Env::new();
    let u = env.user();
    store_contract(env.state.shares().store(), u.id).await;
}

/// The PostgreSQL twin (also the `share_started` audit fan-out per org).
#[tokio::test]
async fn share_store_contract_pg() {
    let Some(db) = TestDb::migrated().await else {
        eprintln!("SKIPPED (needs PostgreSQL): set DATABASE_URL to run this database test");
        return;
    };
    let owner = Uuid::now_v7();
    let org = Uuid::now_v7();
    sqlx_core::query::query(
        "INSERT INTO users (id, email, created_at, opaque_record) VALUES ($1, $2, now(), '\\x00')",
    )
    .bind(owner)
    .bind(format!("{owner}@example.com"))
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx_core::query::query("INSERT INTO orgs (id, name, created_at) VALUES ($1, 'o', now())")
        .bind(org)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx_core::query::query(
        "INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'member')",
    )
    .bind(org)
    .bind(owner)
    .execute(&db.pool)
    .await
    .unwrap();
    let store = ShareStore::Postgres(db.pool.clone());
    store_contract(&store, owner).await;
    let (n,): (i64,) = sqlx_core::query_as::query_as(
        "SELECT count(*) FROM audit_events WHERE kind = 'share_started' AND org_id = $1",
    )
    .bind(org)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(n, 3);
    db.cleanup().await;
}
