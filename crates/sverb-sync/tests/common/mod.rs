//! M4-07 test harness: an in-process `sverb-server` on its in-memory backend
//! (no PostgreSQL), served over HTTP on a loopback port, and client devices
//! with their own SQLite store, LMK and vault keys.
//!
//! The server can be stopped and restarted on the same port (all
//! connections are dropped, so clients see it go down). Every request body
//! is recorded for inspection.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use parking_lot::Mutex;
use serde_json::{Value, json};
use sverb_core::model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::account::{AccountKeys, derive_akek, generate_account_keys, seal_private_bundle};
use sverb_crypto::envelope::seal_item;
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::{SverbKsf, client_login_start, client_registration_start};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};
use sverb_crypto::wrap::{WrapPurpose, wrap_key};
use sverb_proto::auth::{SessionResponse, TokenPair};
use sverb_proto::b64;
use sverb_server::auth::store::mem::MemStore;
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::RegistrationMode;
use sverb_server::{AppState, Config, app};
use sverb_store::{Store, SystemClock, VaultKind};
use sverb_sync::{EngineConfig, NoKeySource, SyncEngine, SyncEvent, TokenManager, VaultKeySource};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use uuid::Uuid;

const SECRET: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub body: String,
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub state: AppState,
    pub mem: Arc<MemStore>,
    pub clock: Arc<ManualClock>,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    // M5-03: test hook serving `GET /v1/users/{id}/public-keys` (the real
    // endpoint lands with orgs, M5-01); tests set or swap a user's keys here.
    pub user_keys: Arc<Mutex<HashMap<Uuid, sverb_proto::users::UserPublicKeys>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

async fn record(log: Arc<Mutex<Vec<Recorded>>>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes: Bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    log.lock().push(Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
    });
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

impl TestServer {
    pub async fn start() -> Self {
        let mem = Arc::new(MemStore::new());
        mem.with_data(|d| d.registration_mode = RegistrationMode::Open);
        let pool =
            sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap();
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let env: HashMap<String, String> = HashMap::from([
            ("SVERB_SERVER_SECRET".into(), SECRET.into()),
            (
                "SVERB_PUBLIC_URL".into(),
                "https://sync.example.test".into(),
            ),
        ]);
        let config = Config::from_sources(None, |k| env.get(k).cloned()).unwrap();
        let n = NonZeroU32::new(1_000_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
        let state = AppState::with_auth(config, pool, limits, auth);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let s = Self {
            addr,
            state,
            mem,
            clock,
            requests: Arc::new(Mutex::new(Vec::new())),
            user_keys: Arc::new(Mutex::new(HashMap::new())),
            task: Mutex::new(None),
        };
        s.serve(listener);
        s
    }

    fn serve(&self, listener: TcpListener) {
        let log = self.requests.clone();
        // M5-03: the public-keys hook. M5-01: the server serves the endpoint now, so
        // the hook is a middleware that answers only for users a test overrides.
        let keys = self.user_keys.clone();
        let hook = axum::middleware::from_fn(move |req: Request, next: Next| {
            let keys = keys.clone();
            async move {
                let found = req
                    .uri()
                    .path()
                    .strip_prefix("/v1/users/")
                    .and_then(|rest| rest.strip_suffix("/public-keys"))
                    .and_then(|id| id.parse::<Uuid>().ok())
                    .and_then(|id| keys.lock().get(&id).cloned());
                match found {
                    Some(k) => axum::Json(k).into_response(),
                    None => next.run(req).await,
                }
            }
        });
        let router = app::router(self.state.clone()).layer(hook).layer(axum::middleware::from_fn(
            move |req: Request, next: Next| record(log.clone(), req, next),
        ));
        let task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            loop {
                let Ok((tcp, peer)) = listener.accept().await else {
                    continue;
                };
                let svc = tower::ServiceExt::map_request(
                    router.clone(),
                    move |mut r: Request<hyper::body::Incoming>| {
                        r.extensions_mut().insert(ConnectInfo(peer));
                        r
                    },
                );
                conns.spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), TowerToHyperService::new(svc))
                        .with_upgrades()
                        .await;
                });
                while conns.try_join_next().is_some() {}
            }
        });
        *self.task.lock() = Some(task);
    }

    /// Stops accepting and drops every connection (the JoinSet is dropped
    /// with the task, aborting the connection tasks).
    pub async fn stop(&self) {
        let t = self.task.lock().take();
        if let Some(t) = t {
            t.abort();
            let _ = t.await;
        }
    }

    /// Serves again on the same port.
    pub async fn restart(&self) {
        let mut tries = 0;
        let listener = loop {
            match TcpListener::bind(self.addr).await {
                Ok(l) => break l,
                Err(e) if tries < 50 => {
                    tries += 1;
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("rebind {}: {e}", self.addr),
            }
        };
        self.serve(listener);
    }

    /// The server's (manual) clock.
    pub fn clock_now(&self) -> chrono::DateTime<chrono::Utc> {
        self.state.auth().now()
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn head(&self, vault: VaultId) -> i64 {
        self.mem
            .with_data(|d| d.vaults.get(&vault.uuid()).map_or(-1, |v| v.head_revision))
    }

    /// The server's copy of an item.
    pub fn item(
        &self,
        vault: VaultId,
        id: ItemId,
    ) -> Option<sverb_server::auth::store::mem::MemItem> {
        self.mem
            .with_data(|d| d.items.get(&(vault.uuid(), id.uuid())).cloned())
    }

    /// Number of `POST /v1/vaults/{id}/changes` requests so far.
    pub fn push_requests(&self) -> usize {
        self.requests
            .lock()
            .iter()
            .filter(|r| r.method == "POST" && r.path.ends_with("/changes"))
            .count()
    }

    /// The JSON bodies of every push so far.
    pub fn push_bodies(&self) -> Vec<Value> {
        self.requests
            .lock()
            .iter()
            .filter(|r| r.method == "POST" && r.path.ends_with("/changes"))
            .map(|r| serde_json::from_str(&r.body).unwrap())
            .collect()
    }

    async fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        raw_post(self.addr, path, body).await
    }
}

/// A plain HTTP/1.1 POST over a TCP stream (keeps the harness free of a
/// second HTTP client).
async fn raw_post(addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = body.to_string();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(rest)
    } else {
        rest.to_owned()
    };
    let v = serde_json::from_str(&body).unwrap_or(Value::Null);
    (status, v)
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((len, rest)) = s.split_once("\r\n") {
        let n = usize::from_str_radix(len.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.push_str(&rest[..n]);
        s = &rest[n + 2..];
    }
    out
}

/// An account on the test server.
#[derive(Clone)]
pub struct Account {
    pub email: String,
    pub password: Vec<u8>,
    pub user_id: Uuid,
    pub vault: VaultId,
    pub vk: Key32,
    pub keys: Arc<AccountKeys>,
}

/// One client device.
pub struct Device {
    pub dir: tempfile::TempDir,
    pub store: Store,
    pub lmk: Key32,
    pub vault: VaultId,
    pub vk: Key32,
    pub device: DeviceId,
    pub hlc: Arc<Mutex<HlcClock>>,
}

impl Device {
    /// A device with a local personal vault `vault` keyed by `vk`.
    pub async fn new(vault: VaultId, vk: &Key32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_at(dir.path().join("sverb.db"), Arc::new(SystemClock)).unwrap();
        let lmk = random_key32(&mut os_rng());
        let wrapped = wrap_key(
            &lmk,
            &WrapPurpose::VaultKey(*vault.as_bytes()),
            vk.expose_secret(),
            &mut os_rng(),
        )
        .unwrap();
        store
            .create_vault(vault, VaultKind::Personal, None, 1, wrapped)
            .await
            .unwrap();
        Self {
            dir,
            store,
            lmk,
            vault,
            vk: vk.clone(),
            device: DeviceId::new(),
            hlc: Arc::new(Mutex::new(HlcClock::default())),
        }
    }

    /// The current key version of the local vault.
    pub async fn key_version(&self) -> u32 {
        self.store
            .get_vault(self.vault)
            .await
            .unwrap()
            .unwrap()
            .key_version
    }

    fn open_with(&self, vk: &Key32, id: ItemId, env: &[u8]) -> ItemBody {
        let plain = sverb_crypto::envelope::open_item(
            |_| Some(vk),
            self.vault.as_bytes(),
            id.as_bytes(),
            env,
        )
        .unwrap();
        ItemBody::from_cbor(&plain).unwrap()
    }

    /// The decrypted local body (tombstones included).
    pub async fn body(&self, id: ItemId) -> Option<ItemBody> {
        let row = self.store.get_item(id).await.unwrap()?;
        Some(self.open_with(&self.vk, id, &row.envelope))
    }

    /// Writes `fields` into item `id` (created as `kind` if missing), sealed
    /// under `vk` / `key_version`, as a local (dirty) edit.
    pub async fn edit_kind(&self, id: ItemId, kind: ItemKind, fields: &[(&str, &str)]) {
        let mut body = self
            .body(id)
            .await
            .unwrap_or_else(|| ItemBody::new(kind, 1));
        {
            let mut clock = self.hlc.lock();
            for (k, v) in fields {
                body.set(k, *v, &mut clock, self.device);
            }
        }
        self.write(id, &body).await;
    }

    pub async fn edit(&self, id: ItemId, fields: &[(&str, &str)]) {
        self.edit_kind(id, ItemKind::Host, fields).await;
    }

    pub async fn delete(&self, id: ItemId) {
        let mut body = self.body(id).await.unwrap();
        {
            let mut clock = self.hlc.lock();
            body.delete(&mut clock, self.device);
        }
        self.write(id, &body).await;
    }

    pub async fn write(&self, id: ItemId, body: &ItemBody) {
        let kv = self.key_version().await;
        let env = seal_item(
            &self.vk,
            self.vault.as_bytes(),
            id.as_bytes(),
            kv,
            &body.to_cbor().unwrap(),
            &mut os_rng(),
        )
        .unwrap();
        self.store
            .put_item(self.vault, id, kv, env, body.is_deleted(), true)
            .await
            .unwrap();
    }

    pub async fn dirty_count(&self) -> usize {
        self.store.list_dirty(self.vault).await.unwrap().len()
    }

    pub async fn pending(&self) -> u64 {
        self.store.pending_count().await.unwrap()
    }

    pub async fn cursor(&self) -> i64 {
        self.store
            .get_vault(self.vault)
            .await
            .unwrap()
            .unwrap()
            .sync_cursor
    }

    /// Every live (non-deleted) item, decrypted, by id.
    pub async fn snapshot(&self) -> Vec<(ItemId, ItemBody)> {
        let rows = self.store.list_items(self.vault).await.unwrap();
        rows.into_iter()
            .map(|r| (r.id, self.open_with(&self.vk, r.id, &r.envelope)))
            .collect()
    }

    pub fn config(&self) -> EngineConfig {
        EngineConfig {
            websocket: false,
            push_debounce: Duration::from_millis(2000),
            ..EngineConfig::default()
        }
    }

    pub async fn engine(&self, config: EngineConfig) -> SyncEngine {
        self.engine_with(config, Arc::new(NoKeySource), None).await
    }

    pub async fn engine_with(
        &self,
        config: EngineConfig,
        keys: Arc<dyn VaultKeySource>,
        events: Option<mpsc::UnboundedSender<SyncEvent>>,
    ) -> SyncEngine {
        SyncEngine::new(
            self.store.clone(),
            self.lmk.clone(),
            self.hlc.clone(),
            keys,
            config,
            events,
        )
        .await
        .unwrap()
    }

    pub async fn save_tokens(&self, server: &TestServer, device_id: Uuid, pair: &TokenPair) {
        TokenManager::save_login(
            &self.store,
            &self.lmk,
            &server.url(),
            Some(DeviceId::from_uuid(device_id)),
            pair,
        )
        .await
        .unwrap();
    }
}

fn ksf() -> SverbKsf {
    SverbKsf::insecure_for_tests()
}

/// Registers an account whose personal vault is `dev`'s local vault (what
/// M4-08 does at registration) and stores the tokens on `dev`.
pub async fn register(server: &TestServer, dev: &Device, email: &str) -> Account {
    let password = b"correct horse battery staple".to_vec();
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, &password).unwrap();
    let start = json!({ "email": email, "registration_request": b64::encode(&request) });
    let (st, v) = server.post("/v1/auth/register/start", &start).await;
    assert_eq!(st, 200, "{v}");
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state
        .finish(&mut rng, &password, &response, &ksf())
        .unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _words) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let grant = self_grant(&dev.vk, dev.vault.as_bytes(), 1, &uid, &keys, &mut rng).unwrap();
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
            "id": dev.vault.uuid(),
            "name_enc": b64::encode(b"encrypted-name"),
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "laptop", "platform": "linux" },
    });
    let (st, v) = server.post("/v1/auth/register/finish", &finish).await;
    assert_eq!(st, 200, "{v}");
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    dev.save_tokens(server, session.device_id, &session.tokens)
        .await;
    Account {
        email: email.to_owned(),
        password,
        user_id,
        vault: dev.vault,
        vk: dev.vk.clone(),
        keys: Arc::new(keys),
    }
}

/// Logs `dev` in as a new device of `account` and stores its tokens.
pub async fn login(server: &TestServer, account: &Account, dev: &Device) -> SessionResponse {
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, &account.password).unwrap();
    let (st, v) = server
        .post(
            "/v1/auth/login/start",
            &json!({ "email": account.email, "credential_request": b64::encode(&ke1) }),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let ke2 = b64::decode(v["credential_response"].as_str().unwrap()).unwrap();
    let f = client
        .finish(&mut rng, &account.password, &ke2, &ksf())
        .unwrap();
    let body = json!({
        "login_state_id": v["login_state_id"],
        "credential_finalization": b64::encode(&f.finalization),
        "device": { "name": "phone", "platform": "linux" },
    });
    let (st, v) = server.post("/v1/auth/login/finish", &body).await;
    assert_eq!(st, 200, "{v}");
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    dev.save_tokens(server, session.device_id, &session.tokens)
        .await;
    session
}

/// A registered first device.
pub async fn first_device(server: &TestServer, email: &str) -> (Account, Device) {
    let vault = VaultId::new();
    let vk = random_key32(&mut os_rng());
    let dev = Device::new(vault, &vk).await;
    let acct = register(server, &dev, email).await;
    (acct, dev)
}

/// A second device of `account` (same vault id and key, as M4-08 would set
/// it up after login).
pub async fn second_device(server: &TestServer, account: &Account) -> Device {
    let dev = Device::new(account.vault, &account.vk).await;
    login(server, account, &dev).await;
    dev
}

/// Posts a raw refresh (to simulate a stolen / replayed refresh token).
pub async fn raw_refresh(server: &TestServer, refresh_token: &str) -> (u16, Value) {
    server
        .post(
            "/v1/auth/refresh",
            &json!({ "refresh_token": refresh_token }),
        )
        .await
}

/// The refresh token currently stored on `dev` (unwrapped with its LMK).
pub async fn stored_refresh_token(dev: &Device) -> (Vec<u8>, String) {
    let enc = dev
        .store
        .get_sync_state()
        .await
        .unwrap()
        .unwrap()
        .tokens_enc
        .unwrap();
    let plain = sverb_crypto::wrap::unwrap_key(&dev.lmk, &WrapPurpose::SyncTokens, &enc).unwrap();
    let v: Value = serde_json::from_slice(&plain).unwrap();
    (enc, v["refresh_token"].as_str().unwrap().to_owned())
}

/// Waits until `f` holds (polling every 25 ms) or panics after `timeout`.
pub async fn wait_for<F, Fut>(timeout: Duration, what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if f().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Seals `body` for an item of `vault` under `vk` (test-made remote items).
pub fn seal(vk: &Key32, vault: VaultId, id: ItemId, kv: u32, body: &ItemBody) -> Vec<u8> {
    seal_item(
        vk,
        vault.as_bytes(),
        id.as_bytes(),
        kv,
        &body.to_cbor().unwrap(),
        &mut os_rng(),
    )
    .unwrap()
}
