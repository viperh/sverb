//! M4-02: authentication, tokens, devices, TOTP, password change, recovery
//! and account deletion, end to end over HTTP with the real client-side
//! OPAQUE code (`sverb_crypto::opaque`, with the cheap test KSF).
//!
//! Every scenario runs twice:
//! * `*_mem`: against the in-memory store (always runs);
//! * `*_pg`: against PostgreSQL (needs `DATABASE_URL`, see `common`;
//!   otherwise prints "SKIPPED (needs PostgreSQL)").
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use chrono::TimeDelta;
use common::{TestDb, config, json, req, send};
use serde_json::{Value, json};
use sverb_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, open_private_bundle, seal_private_bundle,
};
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::{SverbKsf, client_login_start, client_registration_start};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::recovery::{
    RecoveryKey, open_recovery_bundle, recovery_key_generate, seal_recovery_bundle,
};
use sverb_proto::auth::{LOGIN_FAILED_MESSAGE, SessionResponse, TOTP_REQUIRED_HINT};
use sverb_proto::b64;
use sverb_server::auth::store::mem::MemStore;
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock, totp};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::{self, RegistrationMode, hash_token};
use sverb_server::{AppState, admin, app, settings};
use uuid::Uuid;

// ------------------------------------------------------------------ harness

enum Backend {
    Mem(Arc<MemStore>),
    Pg(TestDb),
}

struct Harness {
    app: Router,
    clock: Arc<ManualClock>,
    backend: Backend,
    state: AppState,
}

fn generous() -> RateLimiters {
    let n = NonZeroU32::new(100_000).unwrap();
    RateLimiters::new(LoginLimits {
        per_email_per_minute: n,
        per_ip_per_minute: n,
    })
}

impl Harness {
    fn build(
        store: AuthStore,
        pool: sqlx_postgres::PgPool,
        limits: RateLimiters,
        backend: Backend,
    ) -> Self {
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(store, clock.clone());
        let state = AppState::with_auth(config(&[]), pool, limits, auth);
        Self {
            app: app::router(state.clone()),
            clock,
            backend,
            state,
        }
    }

    fn mem_with(limits: RateLimiters) -> Self {
        let mem = Arc::new(MemStore::new());
        let pool =
            sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap();
        Self::build(
            AuthStore::Memory(mem.clone()),
            pool,
            limits,
            Backend::Mem(mem),
        )
    }

    fn mem() -> Self {
        Self::mem_with(generous())
    }

    async fn pg() -> Option<Self> {
        let db = TestDb::migrated().await?;
        let pool = db.pool.clone();
        Some(Self::build(
            AuthStore::Postgres(pool.clone()),
            pool,
            generous(),
            Backend::Pg(db),
        ))
    }

    async fn cleanup(self) {
        if let Backend::Pg(db) = self.backend {
            db.cleanup().await;
        }
    }

    fn mem_store(&self) -> Option<&MemStore> {
        match &self.backend {
            Backend::Mem(m) => Some(m),
            Backend::Pg(_) => None,
        }
    }

    fn pool(&self) -> Option<&sqlx_postgres::PgPool> {
        match &self.backend {
            Backend::Pg(db) => Some(&db.pool),
            Backend::Mem(_) => None,
        }
    }

    async fn set_mode(&self, mode: RegistrationMode) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.registration_mode = mode),
            Backend::Pg(db) => registration::set_mode(&db.pool, mode).await.unwrap(),
        }
    }

    async fn set_setup_token(&self, token: &str) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.set_setup_token(token)),
            Backend::Pg(db) => settings::set(
                &db.pool,
                settings::SETUP_TOKEN_HASH,
                &hex::encode(hash_token(token)),
            )
            .await
            .unwrap(),
        }
    }

    /// An email-bound instance invite; returns the token.
    async fn invite(&self, email: &str) -> String {
        match &self.backend {
            Backend::Mem(m) => {
                let token = registration::generate_token();
                m.with_data(|d| d.add_invite(&token, Some(email)));
                token
            }
            Backend::Pg(db) => {
                admin::invite::create(&db.pool, "https://sync.example.test", email)
                    .await
                    .unwrap()
                    .token
            }
        }
    }

    async fn user_exists(&self, email: &str) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.users.values().any(|u| u.email == email)),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM users WHERE email = $1::citext)",
            )
            .bind(email)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    async fn disable(&self, email: &str) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                for u in d.users.values_mut().filter(|u| u.email == email) {
                    u.disabled = true;
                }
            }),
            Backend::Pg(db) => {
                admin::user::disable(&db.pool, email).await.unwrap();
            }
        }
    }

    async fn recovery_code(&self, email: &str) -> String {
        match &self.backend {
            Backend::Mem(_) => sverb_server::routes::account::issue_recovery_code(
                self.state.auth().store(),
                email,
                self.clock_now(),
            )
            .await
            .unwrap()
            .unwrap(),
            Backend::Pg(db) => admin::user::recovery_code(&db.pool, email)
                .await
                .unwrap()
                .to_string(),
        }
    }

    fn clock_now(&self) -> chrono::DateTime<chrono::Utc> {
        use sverb_server::auth::Clock as _;
        self.clock.now()
    }

    /// Text of everything stored about tokens (a stand-in for a DB dump).
    async fn dump(&self) -> String {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                format!(
                    "{:?}\n{:?}\n{:?}\n{:?}",
                    d.tokens, d.reauth, d.devices, d.login_states
                )
            }),
            Backend::Pg(db) => {
                let mut out = String::new();
                for table in [
                    "auth_tokens",
                    "reauth_tokens",
                    "devices",
                    "login_states",
                    "users",
                    "account_keys",
                    "audit_events",
                ] {
                    let rows: Vec<String> = sqlx_core::query_scalar::query_scalar(&format!(
                        "SELECT row_to_json(t)::text FROM {table} t"
                    ))
                    .fetch_all(&db.pool)
                    .await
                    .unwrap();
                    out.push_str(&rows.join("\n"));
                    out.push('\n');
                }
                out
            }
        }
    }

    async fn token_rows(&self) -> usize {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.tokens.len()),
            Backend::Pg(db) => {
                let n: i64 =
                    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM auth_tokens")
                        .fetch_one(&db.pool)
                        .await
                        .unwrap();
                usize::try_from(n).unwrap()
            }
        }
    }

    async fn audit_kinds(&self) -> Vec<String> {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.audit.iter().map(|a| a.kind.clone()).collect()),
            Backend::Pg(db) => {
                sqlx_core::query_scalar::query_scalar("SELECT kind FROM audit_events ORDER BY id")
                    .fetch_all(&db.pool)
                    .await
                    .unwrap()
            }
        }
    }

    /// A vault id that already exists, so the personal-vault insert of the
    /// next registration that uses it fails (T-03).
    async fn occupy_vault_id(&self, id: Uuid) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.fail_vault_insert = true),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vaults (id, kind, owner_user_id, org_id, name_enc) \
                     VALUES ($1, 'shared', NULL, NULL, '\\x00')",
                )
                .bind(id)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    async fn release_vault_id(&self, id: Uuid) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.fail_vault_insert = false),
            Backend::Pg(db) => {
                sqlx_core::query::query("DELETE FROM vaults WHERE id = $1")
                    .bind(id)
                    .execute(&db.pool)
                    .await
                    .unwrap();
            }
        }
    }

    /// A shared vault with `members` (T-14).
    async fn shared_vault(&self, members: &[Uuid]) -> Uuid {
        let id = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vaults.insert(
                    id,
                    sverb_server::auth::store::mem::MemVault::shared(None, vec![1], 1),
                );
                for u in members {
                    d.vault_members
                        .push(sverb_server::auth::store::mem::MemMember {
                            vault_id: id,
                            user_id: *u,
                            permission: "write".into(),
                            key_version: 1,
                            wrapped_vault_key: vec![2],
                            wrapped_by: members[0],
                            signature: vec![3; 64],
                        });
                }
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vaults (id, kind, owner_user_id, org_id, name_enc) \
                     VALUES ($1, 'shared', NULL, NULL, '\\x01')",
                )
                .bind(id)
                .execute(&db.pool)
                .await
                .unwrap();
                for u in members {
                    sqlx_core::query::query(
                        "INSERT INTO vault_members (vault_id, user_id, permission, key_version, \
                         wrapped_vault_key, wrapped_by, signature) \
                         VALUES ($1, $2, 'write', 1, '\\x02', $3, '\\x03')",
                    )
                    .bind(id)
                    .bind(u)
                    .bind(members[0])
                    .execute(&db.pool)
                    .await
                    .unwrap();
                }
            }
        }
        id
    }

    async fn add_item(&self, vault: Uuid, revision: i64) {
        let item = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.items.insert(
                    (vault, item),
                    sverb_server::auth::store::mem::MemItem {
                        revision,
                        key_version: 1,
                        envelope: vec![9; 8],
                        deleted: false,
                        updated_at: chrono::Utc::now(),
                        updated_by_device: None,
                    },
                );
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO items (vault_id, id, revision, key_version, envelope, updated_at) \
                     VALUES ($1, $2, $3, 1, '\\x09', now())",
                )
                .bind(vault)
                .bind(item)
                .bind(revision)
                .execute(&db.pool)
                .await
                .unwrap();
            }
        }
    }

    async fn count_items(&self, vault: Uuid) -> usize {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.items.keys().filter(|(v, _)| *v == vault).count()),
            Backend::Pg(db) => {
                let n: i64 = sqlx_core::query_scalar::query_scalar(
                    "SELECT count(*) FROM items WHERE vault_id = $1",
                )
                .bind(vault)
                .fetch_one(&db.pool)
                .await
                .unwrap();
                usize::try_from(n).unwrap()
            }
        }
    }

    async fn vault_exists(&self, vault: Uuid) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.vaults.contains_key(&vault)),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM vaults WHERE id = $1)",
            )
            .bind(vault)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    async fn is_member(&self, vault: Uuid, user: Uuid) -> bool {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vault_members
                    .iter()
                    .any(|x| x.vault_id == vault && x.user_id == user)
            }),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM vault_members WHERE vault_id = $1 AND user_id = $2)",
            )
            .bind(vault)
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    // --- HTTP

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
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

    async fn post(&self, path: &str, body: Value, bearer: Option<&str>) -> (StatusCode, Value) {
        self.call("POST", path, Some(body), bearer).await
    }
}

// ------------------------------------------------------------------- client

fn ksf() -> SverbKsf {
    SverbKsf::insecure_for_tests()
}

/// A registered account as the client sees it.
struct Account {
    email: String,
    password: Vec<u8>,
    user_id: Uuid,
    keys: AccountKeys,
    recovery: RecoveryKey,
    vault_id: Uuid,
    session: SessionResponse,
}

impl Account {
    fn access(&self) -> &str {
        &self.session.tokens.access_token
    }
}

/// Registration through both endpoints, building keys, bundles and the
/// self-grant exactly like the client will (M4-08).
async fn try_register(
    h: &Harness,
    email: &str,
    password: &str,
    extra: Value,
    vault_id: Option<Uuid>,
) -> Result<Account, (StatusCode, Value)> {
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password.as_bytes()).unwrap();
    let mut start = json!({ "email": email, "registration_request": b64::encode(&request) });
    merge(&mut start, &extra);
    let (st, v) = h.post("/v1/auth/register/start", start, None).await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state
        .finish(&mut rng, password.as_bytes(), &response, &ksf())
        .unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _words) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let vault_id = vault_id.unwrap_or_else(Uuid::now_v7);
    let vk = random_key32(&mut rng);
    let grant = self_grant(&vk, vault_id.as_bytes(), 1, &uid, &keys, &mut rng).unwrap();
    let pubk = keys.public();
    let mut finish = json!({
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
            "id": vault_id,
            "name_enc": b64::encode(b"encrypted-name"),
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "laptop", "platform": "linux" },
    });
    merge(&mut finish, &extra);
    let (st, v) = h.post("/v1/auth/register/finish", finish, None).await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    let session: SessionResponse = serde_json::from_value(v).unwrap();
    Ok(Account {
        email: email.to_owned(),
        password: password.as_bytes().to_vec(),
        user_id,
        keys,
        recovery,
        vault_id,
        session,
    })
}

fn merge(into: &mut Value, extra: &Value) {
    if let (Some(a), Some(b)) = (into.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}

async fn register(h: &Harness, email: &str, password: &str) -> Account {
    match try_register(h, email, password, json!({}), None).await {
        Ok(a) => a,
        Err((st, v)) => panic!("registration failed: {st} {v}"),
    }
}

/// Opens an "open" instance and registers one account.
async fn open_and_register(h: &Harness, email: &str) -> Account {
    h.set_mode(RegistrationMode::Open).await;
    register(h, email, "correct horse battery staple").await
}

struct Login {
    status: StatusCode,
    body: Value,
    export_key: Option<[u8; 64]>,
}

/// One login attempt; when the client can't open KE2 (wrong password,
/// unknown account) it sends a random KE3 like an attacker would.
async fn login_with(h: &Harness, email: &str, password: &[u8], extra: Value) -> Login {
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, password).unwrap();
    let (st, v) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": email, "credential_request": b64::encode(&ke1) }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "login/start: {v}");
    let ke2 = b64::decode(v["credential_response"].as_str().unwrap()).unwrap();
    let (ke3, export_key) = match client.finish(&mut rng, password, &ke2, &ksf()) {
        Ok(f) => (f.finalization, Some(*f.export_key)),
        Err(_) => (random_key32(&mut rng).expose_secret().repeat(2), None),
    };
    let mut body = json!({
        "login_state_id": v["login_state_id"],
        "credential_finalization": b64::encode(&ke3),
        "device": { "name": "phone", "platform": "android" },
    });
    merge(&mut body, &extra);
    let (status, body) = h.post("/v1/auth/login/finish", body, None).await;
    Login {
        status,
        body,
        export_key,
    }
}

async fn login(h: &Harness, a: &Account) -> SessionResponse {
    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    serde_json::from_value(l.body).unwrap()
}

async fn reauth(h: &Harness, a: &Account, password: &[u8]) -> String {
    let l = login_with(h, &a.email, password, json!({ "purpose": "reauth" })).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    assert!(l.body.get("tokens").is_none());
    l.body["reauth_token"].as_str().unwrap().to_owned()
}

async fn devices_status(h: &Harness, access: &str) -> StatusCode {
    h.call("GET", "/v1/devices", None, Some(access)).await.0
}

fn assert_auth_required(st: StatusCode, v: &Value) {
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"]["code"], "auth_required", "{v}");
}

/// A new OPAQUE registration for `new_password` via `start_path`, returning
/// the upload and the new private bundle (bound to `version`).
async fn new_password_material(
    h: &Harness,
    start: (&str, Value, Option<&str>),
    response_field: &str,
    new_password: &str,
    user_id: Uuid,
    keys: &AccountKeys,
    version: u32,
) -> (Vec<u8>, Vec<u8>, Value) {
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, new_password.as_bytes()).unwrap();
    let mut body = start.1;
    merge(
        &mut body,
        &json!({ "registration_request": b64::encode(&request) }),
    );
    let (st, v) = h.post(start.0, body, start.2).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let response = b64::decode(v[response_field].as_str().unwrap()).unwrap();
    let fin = state
        .finish(&mut rng, new_password.as_bytes(), &response, &ksf())
        .unwrap();
    let akek = derive_akek(&fin.export_key);
    let bundle = seal_private_bundle(&akek, user_id.as_bytes(), version, keys, &mut rng).unwrap();
    (fin.upload, bundle, v)
}

// ---------------------------------------------------------------- scenarios

/// T-01: register → login round-trip; export_key equal across logins;
/// the private bundle opens with the AKEK from login.
async fn t01_roundtrip(h: &Harness) {
    let a = open_and_register(h, "alice@example.com").await;
    assert_eq!(a.session.user_id, a.user_id);
    assert_eq!(a.session.account_keys.version, 1);
    assert_eq!(a.session.tokens.access_token.len(), 43);
    assert_eq!(a.session.tokens.access_expires_in_s, 900);

    let l1 = login_with(h, "Alice@EXAMPLE.com", &a.password, json!({})).await;
    assert_eq!(l1.status, StatusCode::OK, "{}", l1.body);
    let l2 = login_with(h, "alice@example.com", &a.password, json!({})).await;
    assert_eq!(l2.status, StatusCode::OK);
    let (e1, e2) = (l1.export_key.unwrap(), l2.export_key.unwrap());
    assert_eq!(e1, e2, "export_key is stable per password");
    let s: SessionResponse = serde_json::from_value(l1.body).unwrap();
    assert_eq!(s.user_id, a.user_id);
    let keys = open_private_bundle(
        &derive_akek(&e1),
        a.user_id.as_bytes(),
        s.account_keys.version,
        &s.account_keys.private_bundle_enc,
    )
    .unwrap();
    assert_eq!(keys.public(), a.keys.public());
    // The new access token works.
    assert_eq!(
        devices_status(h, &s.tokens.access_token).await,
        StatusCode::OK
    );
}

/// T-02: wrong password and unknown email fail identically.
async fn t02_enumeration(h: &Harness) {
    let a = open_and_register(h, "bob@example.com").await;
    let wrong = login_with(h, &a.email, b"not the password", json!({})).await;
    let unknown = login_with(h, "nobody@example.com", b"whatever", json!({})).await;
    assert_auth_required(wrong.status, &wrong.body);
    assert_eq!(wrong.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    assert_eq!((wrong.status, &wrong.body), (unknown.status, &unknown.body));

    // Informational timing check (median over 50 runs each).
    let mut known_t = Vec::new();
    let mut unknown_t = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        let _ = login_with(h, &a.email, b"nope", json!({})).await;
        known_t.push(t.elapsed());
        let t = Instant::now();
        let _ = login_with(h, "ghost@example.com", b"nope", json!({})).await;
        unknown_t.push(t.elapsed());
    }
    known_t.sort();
    unknown_t.sort();
    let (k, u) = (known_t[25].as_secs_f64(), unknown_t[25].as_secs_f64());
    eprintln!(
        "T-02 timing (informational): median known-wrong {:.2} ms, unknown {:.2} ms, diff {:.1}%",
        k * 1e3,
        u * 1e3,
        (k - u).abs() / k.max(u) * 100.0
    );
}

/// T-03: a failure in the vault insert leaves no user, and the invite is
/// not consumed.
async fn t03_register_atomic(h: &Harness) {
    let token = h.invite("carol@example.com").await;
    let vault = Uuid::now_v7();
    h.occupy_vault_id(vault).await;
    let err = try_register(
        h,
        "carol@example.com",
        "pw-carol",
        json!({ "invite_token": token }),
        Some(vault),
    )
    .await
    .err()
    .expect("registration must fail");
    assert!(!err.0.is_success(), "{err:?}");
    assert!(!h.user_exists("carol@example.com").await);
    assert_eq!(h.token_rows().await, 0);
    h.release_vault_id(vault).await;
    // Rolled back: the same invite still works.
    let a = try_register(
        h,
        "carol@example.com",
        "pw-carol",
        json!({ "invite_token": token }),
        Some(vault),
    )
    .await
    .unwrap();
    assert!(h.user_exists("carol@example.com").await);
    assert!(!a.session.is_instance_admin);
}

/// T-04: registration gating with the real flow.
async fn t04_gating(h: &Harness) {
    let reg = |email: &'static str, extra: Value| async move {
        try_register(h, email, "pw", extra, None)
            .await
            .map(|a| a.session)
    };
    // Default invite-only: nothing presented → forbidden at start.
    let (st, v) = reg("d1@example.com", json!({})).await.unwrap_err();
    assert_eq!(
        (st, v["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    // Setup token → instance admin, once.
    h.set_setup_token("setup-token-123").await;
    let s = reg(
        "admin@example.com",
        json!({ "setup_token": "setup-token-123" }),
    )
    .await
    .unwrap();
    assert!(s.is_instance_admin);
    let (st, _) = reg(
        "d2@example.com",
        json!({ "setup_token": "setup-token-123" }),
    )
    .await
    .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Invite: bound to its email, single use.
    let inv = h.invite("invited@example.com").await;
    let (st, _) = reg("other@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    let s = reg("invited@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap();
    assert!(!s.is_instance_admin);
    let (st, _) = reg("Invited@example.com", json!({ "invite_token": inv }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    // Closed → forbidden even with an invite; open → anyone.
    h.set_mode(RegistrationMode::Closed).await;
    let inv2 = h.invite("late@example.com").await;
    let (st, _) = reg("late@example.com", json!({ "invite_token": inv2 }))
        .await
        .unwrap_err();
    assert_eq!(st, StatusCode::FORBIDDEN);
    h.set_mode(RegistrationMode::Open).await;
    reg("anyone@example.com", json!({})).await.unwrap();
    // Duplicate email → conflict.
    let (st, v) = reg("ANYONE@example.com", json!({})).await.unwrap_err();
    assert_eq!(
        (st, v["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
}

/// T-05: access tokens expire after 15 minutes (time travel).
async fn t05_access_expiry(h: &Harness) {
    let a = open_and_register(h, "erin@example.com").await;
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    h.clock.advance(TimeDelta::minutes(14));
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    h.clock
        .advance(TimeDelta::minutes(1) + TimeDelta::seconds(1));
    let (st, v) = h.call("GET", "/v1/devices", None, Some(a.access())).await;
    assert_auth_required(st, &v);
    // The refresh token still works and yields a working access token.
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": a.session.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        devices_status(h, v["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    // Refresh tokens expire after 30 days.
    h.clock.advance(TimeDelta::days(30) + TimeDelta::seconds(1));
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": v["refresh_token"] }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
    // Garbage tokens.
    let (st, _) = h
        .call("GET", "/v1/devices", None, Some("not-a-token"))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = h.call("GET", "/v1/devices", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// T-06 + T-07: rotation, then reuse detection revokes the family.
async fn t06_t07_rotation_and_reuse(h: &Harness) {
    let a = open_and_register(h, "frank@example.com").await;
    let old_refresh = a.session.tokens.refresh_token.clone();
    let (st, new) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": old_refresh }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{new}");
    let new_access = new["access_token"].as_str().unwrap().to_owned();
    let new_refresh = new["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(new_refresh, old_refresh);
    assert_eq!(devices_status(h, &new_access).await, StatusCode::OK);
    // The old refresh token is marked used, not deleted.
    let used = match &h.backend {
        Backend::Mem(m) => m.with_data(|d| {
            d.tokens
                .get(&sverb_server::auth::tokens::hash_presented(&old_refresh).unwrap())
                .and_then(|t| t.used_at)
                .is_some()
        }),
        Backend::Pg(db) => sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT used_at IS NOT NULL FROM auth_tokens WHERE token_hash = $1",
        )
        .bind(&sverb_server::auth::tokens::hash_presented(&old_refresh).unwrap()[..])
        .fetch_one(&db.pool)
        .await
        .unwrap(),
    };
    assert!(used, "old refresh token has used_at set");

    // T-07: replaying the old refresh token → 401 and the family is gone.
    let (st, v) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": old_refresh }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
    assert!(v["error"]["message"].as_str().unwrap().contains("reuse"));
    assert_eq!(
        devices_status(h, &new_access).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": new_refresh }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(
        h.audit_kinds()
            .await
            .contains(&"refresh_token_reuse".to_owned())
    );
}

/// T-08: logout revokes the current device only.
async fn t08_logout(h: &Harness) {
    let a = open_and_register(h, "grace@example.com").await;
    let b = login(h, &a).await;
    assert_ne!(b.device_id, a.session.device_id);
    let (st, _) = h
        .call("POST", "/v1/auth/logout", None, Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": a.session.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::OK
    );
    let (st, _) = h.call("POST", "/v1/auth/logout", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// T-09 and device listing: revoking a device kills its access token at
/// once; revoked devices are listed with `revoked_at`.
async fn t09_devices(h: &Harness) {
    let a = open_and_register(h, "heidi@example.com").await;
    let b = login(h, &a).await;
    let (st, list) = h.call("GET", "/v1/devices", None, Some(a.access())).await;
    assert_eq!(st, StatusCode::OK);
    let list = list.as_array().unwrap().clone();
    assert_eq!(list.len(), 2);
    let me = list.iter().find(|d| d["current"] == true).unwrap();
    assert_eq!(me["id"], json!(a.session.device_id));
    assert_eq!(me["name"], "laptop");
    assert!(me["last_seen_at"].is_string());

    let path = format!("/v1/devices/{}", b.device_id);
    let (st, _) = h.call("DELETE", &path, None, Some(a.access())).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let (st, _) = h
        .post(
            "/v1/auth/refresh",
            json!({ "refresh_token": b.tokens.refresh_token }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (_, list) = h.call("GET", "/v1/devices", None, Some(a.access())).await;
    let revoked = list
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == json!(b.device_id))
        .unwrap();
    assert!(revoked["revoked_at"].is_string());
    // Another user's or an unknown device → 404.
    let other = register(h, "ivan@example.com", "pw").await;
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/devices/{}", other.session.device_id),
            None,
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(devices_status(h, other.access()).await, StatusCode::OK);
    // A revoked device id cannot be resumed: login creates a new device.
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "device": { "id": b.device_id } }),
    )
    .await;
    assert_eq!(l.status, StatusCode::OK);
    assert_ne!(l.body["device_id"], json!(b.device_id));
    // An existing device id is resumed (its old tokens are replaced).
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "device": { "id": a.session.device_id } }),
    )
    .await;
    assert_eq!(l.body["device_id"], json!(a.session.device_id));
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
}

/// T-10: TOTP enable/confirm, then login needs a valid, fresh code.
async fn t10_totp(h: &Harness) {
    let a = open_and_register(h, "judy@example.com").await;
    let (st, setup) = h
        .post("/v1/account/totp", json!({}), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{setup}");
    assert!(
        setup["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/sverb:judy@example.com?")
    );
    let secret = totp_rs::Secret::Encoded(setup["secret_base32"].as_str().unwrap().to_owned())
        .to_bytes()
        .unwrap();
    let now = || u64::try_from(h.clock_now().timestamp()).unwrap();
    // Wrong confirmation code → 400; right one → enabled.
    let (st, _) = h
        .post(
            "/v1/account/totp",
            json!({ "code": "000000" }),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, v) = h
        .post(
            "/v1/account/totp",
            json!({ "code": totp::code_at(&secret, now()) }),
            Some(a.access()),
        )
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "enabled": true })));

    // Missing code → 401 with the hint.
    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_auth_required(l.status, &l.body);
    assert!(
        l.body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(TOTP_REQUIRED_HINT)
    );
    // Wrong password with TOTP enabled stays the generic failure (no hint).
    let l = login_with(h, &a.email, b"wrong", json!({})).await;
    assert_eq!(l.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    // Wrong code → 401.
    let l = login_with(h, &a.email, &a.password, json!({ "totp": "123456" })).await;
    assert_auth_required(l.status, &l.body);
    // The confirmation step is used up: the same code can't log in.
    let l = login_with(
        h,
        &a.email,
        &a.password,
        json!({ "totp": totp::code_at(&secret, now()) }),
    )
    .await;
    assert_auth_required(l.status, &l.body);
    // Next step → ok; replaying it → 401.
    h.clock.advance(TimeDelta::seconds(30));
    let code = totp::code_at(&secret, now());
    let l = login_with(h, &a.email, &a.password, json!({ "totp": code })).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    let session: SessionResponse = serde_json::from_value(l.body).unwrap();
    let l = login_with(h, &a.email, &a.password, json!({ "totp": code })).await;
    assert_auth_required(l.status, &l.body);

    // Disable needs a fresh code.
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account/totp",
            Some(json!({ "code": code })),
            Some(&session.tokens.access_token),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "replayed code");
    h.clock.advance(TimeDelta::seconds(30));
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account/totp",
            Some(json!({ "code": totp::code_at(&secret, now()) })),
            Some(&session.tokens.access_token),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    login(h, &a).await;
}

/// T-11: password change.
async fn t11_password_change(h: &Harness) {
    let a = open_and_register(h, "mallory@example.com").await;
    let b = login(h, &a).await;
    let token = reauth(h, &a, &a.password).await;
    let (upload, bundle, _) = new_password_material(
        h,
        ("/v1/account/password/start", json!({}), Some(a.access())),
        "registration_response",
        "new password 2",
        a.user_id,
        &a.keys,
        2,
    )
    .await;
    // Wrong version → conflict, and the reauth token survives that.
    let body = |version: u32, token: &str| {
        json!({
            "reauth_token": token,
            "registration_upload": b64::encode(&upload),
            "private_bundle_enc": b64::encode(&bundle),
            "version": version,
        })
    };
    let (st, _) = h
        .post("/v1/account/password", body(3, &token), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    // Without a reauth token → 401.
    let fake = b64::encode(&[7; 32]);
    let (st, _) = h
        .post("/v1/account/password", body(2, &fake), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, v) = h
        .post("/v1/account/password", body(2, &token), Some(a.access()))
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "version": 2 })));
    // The reauth token is single use.
    let (st, _) = h
        .post("/v1/account/password", body(3, &token), Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Other devices are logged out; this one stays.
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(devices_status(h, a.access()).await, StatusCode::OK);
    // Old password fails like any wrong password; the new one works.
    let old = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(old.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    let new = login_with(h, &a.email, b"new password 2", json!({})).await;
    assert_eq!(new.status, StatusCode::OK, "{}", new.body);
    let s: SessionResponse = serde_json::from_value(new.body).unwrap();
    assert_eq!(s.account_keys.version, 2);
    let keys = open_private_bundle(
        &derive_akek(&new.export_key.unwrap()),
        a.user_id.as_bytes(),
        2,
        &s.account_keys.private_bundle_enc,
    )
    .unwrap();
    assert_eq!(keys.public(), a.keys.public());
    assert!(
        h.audit_kinds()
            .await
            .contains(&"password_changed".to_owned())
    );
}

/// T-12: tokens are stored only as hashes.
async fn t12_hashed(h: &Harness) {
    let a = open_and_register(h, "niaj@example.com").await;
    let r = reauth(h, &a, &a.password).await;
    let dump = h.dump().await;
    for t in [
        &a.session.tokens.access_token,
        &a.session.tokens.refresh_token,
        &r,
    ] {
        let raw = b64::decode(t).unwrap();
        assert!(!dump.contains(t.as_str()), "raw base64 token in storage");
        assert!(
            !dump.contains(&hex::encode(&raw)),
            "raw token hex in storage"
        );
        assert!(
            !dump.contains(&format!("{raw:?}")),
            "raw token bytes in storage"
        );
        let hash = sverb_server::auth::tokens::hash_raw(&raw);
        let present = dump.contains(&hex::encode(hash)) || dump.contains(&format!("{hash:?}"));
        assert!(present, "the hash is what is stored");
    }
}

/// T-13: a disabled account fails exactly like a wrong password.
async fn t13_disabled(h: &Harness) {
    let a = open_and_register(h, "olivia@example.com").await;
    let wrong = login_with(h, &a.email, b"wrong", json!({})).await;
    h.disable(&a.email).await;
    let disabled = login_with(h, &a.email, &a.password, json!({})).await;
    assert_auth_required(disabled.status, &disabled.body);
    assert_eq!(
        (wrong.status, &wrong.body),
        (disabled.status, &disabled.body)
    );
    // Existing tokens stop working too.
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
}

/// T-14: deleting the account removes the personal vault and its items;
/// shared vault items stay.
async fn t14_delete(h: &Harness) {
    let a = open_and_register(h, "peggy@example.com").await;
    let other = register(h, "rupert@example.com", "pw").await;
    let shared = h.shared_vault(&[other.user_id, a.user_id]).await;
    h.add_item(a.vault_id, 1).await;
    h.add_item(a.vault_id, 2).await;
    h.add_item(shared, 1).await;
    h.add_item(other.vault_id, 1).await;

    // Requires a reauth token.
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": b64::encode(&[1; 32]) })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let token = reauth(h, &a, &a.password).await;
    // Someone else's reauth token does not work.
    let other_token = reauth(h, &other, &other.password).await;
    let (st, _) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": other_token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, v) = h
        .call(
            "DELETE",
            "/v1/account",
            Some(json!({ "reauth_token": token })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{v}");

    assert!(!h.user_exists(&a.email).await);
    assert!(!h.vault_exists(a.vault_id).await);
    assert_eq!(h.count_items(a.vault_id).await, 0);
    assert_eq!(h.count_items(shared).await, 1);
    assert_eq!(h.count_items(other.vault_id).await, 1);
    assert!(!h.is_member(shared, a.user_id).await);
    assert!(h.is_member(shared, other.user_id).await);
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    let l = login_with(h, &a.email, &a.password, json!({})).await;
    assert_eq!(l.body["error"]["message"], LOGIN_FAILED_MESSAGE);
    assert!(
        h.audit_kinds()
            .await
            .contains(&"account_deleted".to_owned())
    );
    // The email is free again.
    register(h, "peggy@example.com", "again").await;
}

/// Recovery (§10.4 proposal): code + recovery key → new password.
async fn recovery(h: &Harness) {
    let a = open_and_register(h, "trent@example.com").await;
    let b = login(h, &a).await;
    // Without a code → 401; unknown email answers the same.
    let start = |code: &str, email: &str| json!({ "email": email, "code": code, "registration_request": b64::encode(&[0; 32]) });
    let (st, v1) = h
        .post(
            "/v1/account/recovery/start",
            start("AAAA-BBBB", &a.email),
            None,
        )
        .await;
    assert_auth_required(st, &v1);
    let (_, v2) = h
        .post(
            "/v1/account/recovery/start",
            start("AAAA-BBBB", "ghost@example.com"),
            None,
        )
        .await;
    assert_eq!(v1, v2);

    let code = h.recovery_code(&a.email).await;
    let (upload, bundle, v) = new_password_material(
        h,
        (
            "/v1/account/recovery/start",
            json!({ "email": a.email, "code": code.to_lowercase() }),
            None,
        ),
        "registration_response",
        "recovered password",
        a.user_id,
        &a.keys,
        2,
    )
    .await;
    assert_eq!(v["user_id"], json!(a.user_id));
    assert_eq!(v["version"], 1);
    // The bundle opens with the recovery key.
    let rb = b64::decode(v["recovery_bundle_enc"].as_str().unwrap()).unwrap();
    let keys = open_recovery_bundle(&a.recovery, a.user_id.as_bytes(), &rb).unwrap();
    assert_eq!(keys.public(), a.keys.public());

    let proof = |version: u32, keys: &AccountKeys| {
        let msg = sverb_crypto::opaque::recovery_proof_message(
            a.user_id.as_bytes(),
            version,
            &upload,
            &bundle,
        );
        sverb_crypto::sign::sign(keys.ed25519_signing_key(), &msg)
    };
    let finish = |sig: [u8; 64]| {
        json!({
            "email": a.email,
            "code": code,
            "registration_upload": b64::encode(&upload),
            "private_bundle_enc": b64::encode(&bundle),
            "version": 2,
            "signature": b64::encode(&sig),
        })
    };
    // A signature by another key → 403 (the code survives).
    let stranger = generate_account_keys(&mut os_rng());
    let (st, _) = h
        .post("/v1/account/recovery", finish(proof(2, &stranger)), None)
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, v) = h
        .post("/v1/account/recovery", finish(proof(2, &keys)), None)
        .await;
    assert_eq!((st, &v), (StatusCode::OK, &json!({ "version": 2 })));
    // Single use.
    let (st, _) = h
        .post("/v1/account/recovery", finish(proof(2, &keys)), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // Every device is logged out; the new password works.
    assert_eq!(
        devices_status(h, a.access()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        devices_status(h, &b.tokens.access_token).await,
        StatusCode::UNAUTHORIZED
    );
    let l = login_with(h, &a.email, b"recovered password", json!({})).await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.body);
    assert_eq!(l.body["account_keys"]["version"], 2);
    // Five wrong codes discard a code.
    let code2 = h.recovery_code(&a.email).await;
    for _ in 0..5 {
        let (st, _) = h
            .post(
                "/v1/account/recovery/start",
                start("WRONG-CODE", &a.email),
                None,
            )
            .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (st, _) = h
        .post("/v1/account/recovery/start", start(&code2, &a.email), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

/// Registration input validation.
async fn validation(h: &Harness) {
    h.set_mode(RegistrationMode::Open).await;
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, b"pw").unwrap();
    let (st, v) = h
        .post(
            "/v1/auth/register/start",
            json!({ "email": "val@example.com", "registration_request": b64::encode(&request) }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let fin = state.finish(&mut rng, b"pw", &response, &ksf()).unwrap();
    let keys = generate_account_keys(&mut rng);
    let vault = Uuid::now_v7();
    // Signed for another user id → the self-grant does not verify.
    let grant = self_grant(
        &random_key32(&mut rng),
        vault.as_bytes(),
        1,
        Uuid::now_v7().as_bytes(),
        &keys,
        &mut rng,
    )
    .unwrap();
    let akek = derive_akek(&fin.export_key);
    let bundle = seal_private_bundle(&akek, user_id.as_bytes(), 1, &keys, &mut rng).unwrap();
    let body = json!({
        "email": "val@example.com",
        "user_id": user_id,
        "registration_upload": b64::encode(&fin.upload),
        "account_keys": {
            "x25519_pub": b64::encode(&keys.public().x25519),
            "ed25519_pub": b64::encode(&keys.public().ed25519),
            "private_bundle_enc": b64::encode(&bundle),
            "recovery_bundle_enc": b64::encode(&bundle),
            "version": 1,
        },
        "personal_vault": {
            "id": vault,
            "name_enc": "AA",
            "self_grant": {
                "wrapped_vault_key": b64::encode(&grant.wrapped),
                "signature": b64::encode(&grant.signature),
                "key_version": 1,
            },
        },
        "device": { "name": "x", "platform": "linux" },
    });
    let (st, v) = h.post("/v1/auth/register/finish", body.clone(), None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("signature")
    );
    let mut bad = body.clone();
    bad["registration_upload"] = json!("AAAA");
    let (st, _) = h.post("/v1/auth/register/finish", bad, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut bad = body;
    bad["account_keys"]["x25519_pub"] = json!("AAAA");
    let (st, _) = h.post("/v1/auth/register/finish", bad, None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!h.user_exists("val@example.com").await);
    // Garbage OPAQUE messages are 400, not 500.
    let (st, _) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": "val@example.com", "credential_request": "AAAA" }),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // An unknown or expired login state fails generically.
    let (st, v) = h
        .post(
            "/v1/auth/login/finish",
            json!({ "login_state_id": Uuid::now_v7(), "credential_finalization": b64::encode(&[0; 64]) }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
}

/// Login states expire after 60 s.
async fn login_state_ttl(h: &Harness) {
    let a = open_and_register(h, "sybil@example.com").await;
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, &a.password).unwrap();
    let (_, v) = h
        .post(
            "/v1/auth/login/start",
            json!({ "email": a.email, "credential_request": b64::encode(&ke1) }),
            None,
        )
        .await;
    let ke2 = b64::decode(v["credential_response"].as_str().unwrap()).unwrap();
    let fin = client.finish(&mut rng, &a.password, &ke2, &ksf()).unwrap();
    h.clock.advance(TimeDelta::seconds(61));
    let (st, v) = h
        .post(
            "/v1/auth/login/finish",
            json!({ "login_state_id": v["login_state_id"], "credential_finalization": b64::encode(&fin.finalization) }),
            None,
        )
        .await;
    assert_auth_required(st, &v);
}

// ------------------------------------------------------------------- tests

macro_rules! both {
    ($scenario:ident, $mem:ident, $pg:ident) => {
        #[tokio::test]
        async fn $mem() {
            let h = Harness::mem();
            $scenario(&h).await;
        }

        #[tokio::test]
        async fn $pg() {
            let h = $crate::db_or_skip!(Harness::pg());
            $scenario(&h).await;
            h.cleanup().await;
        }
    };
}

both!(
    t01_roundtrip,
    t01_opaque_roundtrip_mem,
    t01_opaque_roundtrip_pg
);
both!(
    t02_enumeration,
    t02_wrong_password_and_unknown_email_identical_mem,
    t02_wrong_password_and_unknown_email_identical_pg
);
both!(
    t03_register_atomic,
    t03_register_is_atomic_mem,
    t03_register_is_atomic_pg
);
both!(
    t04_gating,
    t04_registration_gating_mem,
    t04_registration_gating_pg
);
both!(
    t05_access_expiry,
    t05_access_token_expiry_mem,
    t05_access_token_expiry_pg
);
both!(
    t06_t07_rotation_and_reuse,
    t06_t07_refresh_rotation_and_reuse_mem,
    t06_t07_refresh_rotation_and_reuse_pg
);
both!(
    t08_logout,
    t08_logout_current_device_only_mem,
    t08_logout_current_device_only_pg
);
both!(t09_devices, t09_device_revoke_mem, t09_device_revoke_pg);
both!(t10_totp, t10_totp_mem, t10_totp_pg);
both!(
    t11_password_change,
    t11_password_change_mem,
    t11_password_change_pg
);
both!(
    t12_hashed,
    t12_tokens_stored_hashed_mem,
    t12_tokens_stored_hashed_pg
);
both!(t13_disabled, t13_disabled_user_mem, t13_disabled_user_pg);
both!(t14_delete, t14_account_delete_mem, t14_account_delete_pg);
both!(recovery, recovery_flow_mem, recovery_flow_pg);
both!(
    validation,
    registration_validation_mem,
    registration_validation_pg
);
both!(
    login_state_ttl,
    login_state_expires_mem,
    login_state_expires_pg
);

/// `login/start` calls the M4-01 rate limiter (5 per email per minute).
#[tokio::test]
async fn login_start_is_rate_limited() {
    let h = Harness::mem_with(RateLimiters::default());
    let mut rng = os_rng();
    let (_, ke1) = client_login_start(&mut rng, b"pw").unwrap();
    let body = json!({ "email": "rl@example.com", "credential_request": b64::encode(&ke1) });
    for _ in 0..5 {
        let (st, _) = h.post("/v1/auth/login/start", body.clone(), None).await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, v) = h.post("/v1/auth/login/start", body, None).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{v}");
}

/// The OPAQUE setup is generated once and reused (sealed in server_secrets).
#[tokio::test]
async fn opaque_setup_is_persisted_sealed() {
    let h = Harness::mem();
    let a = h
        .state
        .auth()
        .server_setup(h.state.secrets())
        .await
        .unwrap();
    let b = h
        .state
        .auth()
        .server_setup(h.state.secrets())
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    let mem = h.mem_store().unwrap();
    let sealed = mem
        .with_data(|d| d.secrets.get("opaque_server_setup").cloned())
        .unwrap();
    assert!(
        !sealed
            .windows(32)
            .any(|w| a.to_bytes().windows(32).any(|x| x == w))
    );
    // A second runtime over the same store loads the same setup.
    let auth2 = AuthRuntime::new(
        AuthStore::Memory(Arc::new(MemStore::new())),
        Arc::new(ManualClock::new()),
    );
    mem.with_data(|d| d.secrets.clone())
        .into_iter()
        .for_each(|(k, v)| {
            if let AuthStore::Memory(m2) = auth2.store() {
                m2.with_data(|d| d.secrets.insert(k.clone(), v.clone()));
            }
        });
    let c = auth2.server_setup(h.state.secrets()).await.unwrap();
    assert_eq!(*a.to_bytes(), *c.to_bytes());
    assert!(h.pool().is_none());
}
