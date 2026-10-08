//! M4-04: vault list, pull, push (gap-free revisions, limits, quota),
//! rotation/read-only gating and tombstone GC, end to end over HTTP.
//!
//! Every scenario runs twice:
//! * `*_mem`: against the in-memory model (always runs; it models the vault
//!   row lock, see `sverb_server::sync::mem`);
//! * `*_pg`: against PostgreSQL (needs `DATABASE_URL`, see `common`;
//!   otherwise prints "SKIPPED (needs PostgreSQL)").
//!
//! Tests run on a multi-threaded runtime so the concurrency scenario (T-04)
//! has real parallelism.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use chrono::TimeDelta;
use common::{TestDb, config, json, req, send};
use serde_json::{Value, json};
use sverb_crypto::account::{derive_akek, generate_account_keys, seal_private_bundle};
use sverb_crypto::envelope::seal_item;
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::{SverbKsf, client_registration_start};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};
use sverb_proto::b64;
use sverb_proto::sync::{
    MAX_ENVELOPE_BYTES, PullResponse, PushResponse, PushStatus, QUOTA_EXCEEDED_MESSAGE, VaultView,
};
use sverb_server::auth::store::mem::{MemMember, MemStore, MemVault};
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::{self, RegistrationMode};
use sverb_server::sync::{ChangeNotifier, SyncStore, gc};
use sverb_server::{AppState, app};
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
        backend: Backend,
        cfg: &[(&str, &str)],
    ) -> Self {
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(store, clock.clone());
        let state = AppState::with_auth(config(cfg), pool, generous(), auth);
        Self {
            app: app::router(state.clone()),
            clock,
            backend,
            state,
        }
    }

    fn mem(cfg: &[(&str, &str)]) -> Self {
        let mem = Arc::new(MemStore::new());
        mem.with_data(|d| d.registration_mode = RegistrationMode::Open);
        let pool =
            sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap();
        Self::build(AuthStore::Memory(mem.clone()), pool, Backend::Mem(mem), cfg)
    }

    async fn pg(cfg: &[(&str, &str)]) -> Option<Self> {
        let db = TestDb::migrated().await?;
        registration::set_mode(&db.pool, RegistrationMode::Open)
            .await
            .unwrap();
        let pool = db.pool.clone();
        Some(Self::build(
            AuthStore::Postgres(pool.clone()),
            pool,
            Backend::Pg(db),
            cfg,
        ))
    }

    async fn cleanup(self) {
        if let Backend::Pg(db) = self.backend {
            db.cleanup().await;
        }
    }

    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.state.auth().now()
    }

    /// A shared vault (key version 1) with the given members.
    async fn shared_vault(&self, members: &[(Uuid, &str)]) -> Uuid {
        let id = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vaults.insert(id, MemVault::shared(None, vec![1], 1));
                for (u, perm) in members {
                    d.vault_members.push(MemMember {
                        vault_id: id,
                        user_id: *u,
                        permission: (*perm).into(),
                        key_version: 1,
                        wrapped_vault_key: vec![2],
                        wrapped_by: members[0].0,
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
                for (u, perm) in members {
                    sqlx_core::query::query(
                        "INSERT INTO vault_members (vault_id, user_id, permission, key_version, \
                         wrapped_vault_key, wrapped_by, signature) \
                         VALUES ($1, $2, $3, 1, '\\x02', $4, '\\x03')",
                    )
                    .bind(id)
                    .bind(u)
                    .bind(*perm)
                    .bind(members[0].0)
                    .execute(&db.pool)
                    .await
                    .unwrap();
                }
            }
        }
        id
    }

    /// Starts (`Some(new_key_version)`) or clears a key rotation.
    async fn set_rotation(&self, vault: Uuid, new_key_version: Option<u32>) {
        let rotation =
            new_key_version.map(|v| json!({ "by": Uuid::nil(), "new_key_version": v, "started_at": "2026-10-08T00:00:00Z" }));
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.vaults.get_mut(&vault).unwrap().rotation = rotation),
            Backend::Pg(db) => {
                sqlx_core::query::query("UPDATE vaults SET rotation = $2 WHERE id = $1")
                    .bind(vault)
                    .bind(rotation)
                    .execute(&db.pool)
                    .await
                    .unwrap();
            }
        }
    }

    async fn gc_floor(&self, vault: Uuid) -> i64 {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.vaults[&vault].gc_floor_revision),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar(
                "SELECT gc_floor_revision FROM vaults WHERE id = $1",
            )
            .bind(vault)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// Every stored byte string of the sync tables, plus a text rendering
    /// of the whole database (the stand-in for `pg_dump`).
    async fn dump(&self) -> (Vec<Vec<u8>>, String) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                let mut blobs: Vec<Vec<u8>> =
                    d.items.values().map(|i| i.envelope.clone()).collect();
                blobs.extend(d.vaults.values().map(|v| v.name_enc.clone()));
                blobs.extend(d.vault_members.iter().map(|m| m.wrapped_vault_key.clone()));
                (blobs, format!("{d:?}"))
            }),
            Backend::Pg(db) => {
                let tables: Vec<String> = sqlx_core::query_scalar::query_scalar(
                    "SELECT table_name::text FROM information_schema.tables \
                     WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
                )
                .fetch_all(&db.pool)
                .await
                .unwrap();
                let mut text = String::new();
                for t in tables {
                    let rows: Vec<String> = sqlx_core::query_scalar::query_scalar(&format!(
                        "SELECT row_to_json(t)::text FROM \"{t}\" t"
                    ))
                    .fetch_all(&db.pool)
                    .await
                    .unwrap();
                    text.push_str(&rows.join("\n"));
                    text.push('\n');
                }
                let blobs: Vec<Vec<u8>> =
                    sqlx_core::query_scalar::query_scalar("SELECT envelope FROM items")
                        .fetch_all(&db.pool)
                        .await
                        .unwrap();
                (blobs, text)
            }
        }
    }

    fn mem_sync(&self) -> &sverb_server::sync::MemSync {
        match self.state.sync().store() {
            SyncStore::Memory(m) => m,
            SyncStore::Postgres(_) => panic!("not the in-memory backend"),
        }
    }
}

async fn call(
    app: &Router,
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
    let (st, _, bytes) = send(app, r).await;
    let v = if bytes.is_empty() {
        Value::Null
    } else {
        json(&bytes)
    };
    (st, v)
}

// ------------------------------------------------------------------- client

/// A registered account: its personal vault and an access token.
#[derive(Clone)]
struct User {
    id: Uuid,
    vault: Uuid,
    token: String,
}

async fn register(h: &Harness, email: &str) -> User {
    let ksf = SverbKsf::insecure_for_tests();
    let password = b"correct horse battery staple";
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password).unwrap();
    let start = json!({ "email": email, "registration_request": b64::encode(&request) });
    let (st, v) = call(&h.app, "POST", "/v1/auth/register/start", Some(&start), None).await;
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
    let (st, v) = call(&h.app, "POST", "/v1/auth/register/finish", Some(&finish), None).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    User {
        id: user_id,
        vault,
        token: v["tokens"]["access_token"].as_str().unwrap().to_owned(),
    }
}

fn change(id: Uuid, base: u64, envelope: &[u8], deleted: bool) -> Value {
    json!({
        "id": id,
        "base_revision": base,
        "key_version": 1,
        "envelope": b64::encode(envelope),
        "deleted": deleted,
    })
}

fn new_items(n: usize, len: usize) -> Vec<Value> {
    (0..n)
        .map(|i| change(Uuid::now_v7(), 0, &vec![(i % 251) as u8; len], false))
        .collect()
}

async fn push_raw(app: &Router, token: &str, vault: Uuid, changes: Vec<Value>) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/v1/vaults/{vault}/changes"),
        Some(&json!({ "changes": changes })),
        Some(token),
    )
    .await
}

async fn push(app: &Router, token: &str, vault: Uuid, changes: Vec<Value>) -> PushResponse {
    let (st, v) = push_raw(app, token, vault, changes).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

async fn pull_raw(
    app: &Router,
    token: &str,
    vault: Uuid,
    since: u64,
    limit: Option<u32>,
) -> (StatusCode, Value) {
    let q = limit.map_or(String::new(), |l| format!("&limit={l}"));
    call(
        app,
        "GET",
        &format!("/v1/vaults/{vault}/changes?since={since}{q}"),
        None,
        Some(token),
    )
    .await
}

async fn pull(app: &Router, token: &str, vault: Uuid, since: u64, limit: Option<u32>) -> PullResponse {
    let (st, v) = pull_raw(app, token, vault, since, limit).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

async fn vaults(h: &Harness, token: &str) -> Vec<VaultView> {
    let (st, v) = call(&h.app, "GET", "/v1/vaults", None, Some(token)).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

fn assert_error(st: StatusCode, v: &Value, status: StatusCode, code: &str) {
    assert_eq!(st, status, "{v}");
    assert_eq!(v["error"]["code"], code, "{v}");
}

fn revisions(res: &PushResponse) -> Vec<Option<u64>> {
    res.results.iter().map(|r| r.revision).collect()
}

// ---------------------------------------------------------------- scenarios

/// T-01: new items with base 0 → ok, revisions 1..n, head n; the vault list
/// shows head, permission and the self-grant.
async fn t01_push_new(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let list = vaults(h, &a.token).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, a.vault);
    assert_eq!(list[0].head_revision, 0);

    let res = push(&h.app, &a.token, a.vault, new_items(3, 16)).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    assert_eq!(revisions(&res), vec![Some(1), Some(2), Some(3)]);

    let list = vaults(h, &a.token).await;
    let v = &list[0];
    assert_eq!(v.head_revision, 3);
    assert_eq!(v.kind, sverb_proto::sync::VaultKind::Personal);
    assert_eq!(v.permission, sverb_proto::sync::Permission::Manage);
    assert_eq!(v.key_version, 1);
    assert_eq!(v.grants.len(), 1);
    assert_eq!(v.grants[0].wrapped_by, a.id);
    assert!(v.rotation.is_none());

    let page = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert_eq!(page.head_revision, 3);
    assert_eq!(
        page.items.iter().map(|i| i.revision).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(!page.more);

    // An empty batch is a no-op.
    let res = push(&h.app, &a.token, a.vault, vec![]).await;
    assert!(res.results.is_empty());
    // Duplicate ids in one batch are rejected as a whole.
    let id = Uuid::now_v7();
    let (st, v) = push_raw(
        &h.app,
        &a.token,
        a.vault,
        vec![change(id, 0, b"x", false), change(id, 0, b"y", false)],
    )
    .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert_eq!(pull(&h.app, &a.token, a.vault, 0, None).await.head_revision, 3);
}

/// T-02: stale base → conflict with `current`; in a mixed batch the
/// accepted changes get consecutive revisions and rejected ones consume
/// none.
async fn t02_conflicts(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let x = Uuid::now_v7();
    let res = push(&h.app, &a.token, a.vault, vec![change(x, 0, b"x-v1", false)]).await;
    assert_eq!(res.results[0].revision, Some(1));
    let res = push(&h.app, &a.token, a.vault, vec![change(x, 1, b"x-v2", false)]).await;
    assert_eq!(res.results[0].revision, Some(2));

    let (y, z, ghost) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let res = push(
        &h.app,
        &a.token,
        a.vault,
        vec![
            change(y, 0, b"y", false),
            change(x, 1, b"x-stale", false),
            change(ghost, 9, b"ghost", false),
            change(z, 0, b"z", false),
        ],
    )
    .await;
    let st: Vec<_> = res.results.iter().map(|r| r.status).collect();
    assert_eq!(
        st,
        vec![
            PushStatus::Ok,
            PushStatus::Conflict,
            PushStatus::Conflict,
            PushStatus::Ok
        ]
    );
    assert_eq!(revisions(&res), vec![Some(3), None, None, Some(4)]);
    let cur = res.results[1].current.as_ref().unwrap();
    assert_eq!((cur.id, cur.revision, cur.key_version), (x, 2, 1));
    assert_eq!(cur.envelope, b"x-v2");
    assert!(!cur.deleted);
    // An absent item with a non-zero base: conflict without `current`.
    assert!(res.results[2].current.is_none());

    // All rejected → no revision consumed at all.
    let res = push(&h.app, &a.token, a.vault, vec![change(y, 1, b"y2", false)]).await;
    assert_eq!(res.results[0].status, PushStatus::Conflict);
    assert_eq!(res.results[0].current.as_ref().unwrap().revision, 3);
    let page = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert_eq!(page.head_revision, 4);
    assert_eq!(
        page.items.iter().map(|i| (i.id, i.revision)).collect::<Vec<_>>(),
        vec![(x, 2), (y, 3), (z, 4)]
    );
}

/// T-03: 1,200 items, limit 500 → pages of 500/500/200 with `more`
/// true/true/false, ascending, no duplicates.
async fn t03_pagination(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    for _ in 0..3 {
        push(&h.app, &a.token, a.vault, new_items(400, 8)).await;
    }
    let mut cursor = 0;
    let mut seen = BTreeSet::new();
    let mut shape = Vec::new();
    loop {
        let page = pull(&h.app, &a.token, a.vault, cursor, Some(500)).await;
        assert_eq!(page.head_revision, 1200);
        shape.push((page.items.len(), page.more));
        for i in &page.items {
            assert!(i.revision > cursor, "ascending and after the cursor");
            cursor = i.revision;
            assert!(seen.insert(i.id), "duplicate item");
        }
        if !page.more {
            break;
        }
    }
    assert_eq!(shape, vec![(500, true), (500, true), (200, false)]);
    assert_eq!(seen.len(), 1200);
    assert_eq!(cursor, 1200);
    // Default limit is 500; 0 is invalid; larger is clamped.
    assert_eq!(pull(&h.app, &a.token, a.vault, 0, None).await.items.len(), 500);
    assert_eq!(pull(&h.app, &a.token, a.vault, 0, Some(5000)).await.items.len(), 500);
    let (st, v) = pull_raw(&h.app, &a.token, a.vault, 0, Some(0)).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
}

/// T-04 (§19): 8 parallel pushers (200 single-item pushes each) while a
/// puller follows the cursor. The puller must see every revision 1..=1600
/// exactly once, in order, never skipping. 5 iterations.
async fn t04_concurrency(h: &Harness) {
    const PUSHERS: usize = 8;
    const PUSHES: usize = 200;
    const TOTAL: u64 = (PUSHERS * PUSHES) as u64;
    for iteration in 0..5 {
        let a = register(h, &format!("conc{iteration}@example.com")).await;
        let mut tasks = Vec::new();
        for _ in 0..PUSHERS {
            let (app, token, vault) = (h.app.clone(), a.token.clone(), a.vault);
            tasks.push(tokio::spawn(async move {
                let mut revs = Vec::with_capacity(PUSHES);
                for _ in 0..PUSHES {
                    let res = push(&app, &token, vault, new_items(1, 24)).await;
                    assert_eq!(res.results[0].status, PushStatus::Ok);
                    revs.push(res.results[0].revision.unwrap());
                }
                revs
            }));
        }
        let (app, token, vault) = (h.app.clone(), a.token.clone(), a.vault);
        let puller = tokio::spawn(async move {
            let mut cursor = 0u64;
            let mut seen = Vec::with_capacity(TOTAL as usize);
            let mut pulls = 0u32;
            while cursor < TOTAL {
                let page = pull(&app, &token, vault, cursor, Some(37)).await;
                pulls += 1;
                assert!(page.head_revision >= cursor, "head behind the cursor");
                for i in &page.items {
                    // Items are never overwritten here, so the revisions
                    // present are exactly 1..=head: the next one must be
                    // cursor + 1, or the puller would skip it forever.
                    assert_eq!(i.revision, cursor + 1, "gap: missed revision {}", cursor + 1);
                    cursor = i.revision;
                    seen.push(i.revision);
                }
                if page.items.is_empty() {
                    tokio::task::yield_now().await;
                }
            }
            (seen, pulls)
        });
        let mut pushed = Vec::new();
        for t in tasks {
            pushed.extend(t.await.unwrap());
        }
        let (seen, pulls) = tokio::time::timeout(Duration::from_secs(120), puller)
            .await
            .expect("puller finished")
            .unwrap();
        pushed.sort_unstable();
        let all: Vec<u64> = (1..=TOTAL).collect();
        assert_eq!(pushed, all, "pushers got every revision exactly once");
        assert_eq!(seen, all, "puller saw every revision exactly once, in order");
        assert!(pulls > 1);
        let page = pull(&h.app, &a.token, a.vault, TOTAL, None).await;
        assert!(page.items.is_empty() && page.head_revision == TOTAL);
    }
}

/// T-05: a read-only member's push → 403 forbidden; pull works.
async fn t05_read_only(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let b = register(h, "bob@example.com").await;
    let v = h.shared_vault(&[(a.id, "manage"), (b.id, "read")]).await;
    let res = push(&h.app, &a.token, v, new_items(2, 8)).await;
    assert_eq!(revisions(&res), vec![Some(1), Some(2)]);

    let (st, body) = push_raw(&h.app, &b.token, v, new_items(1, 8)).await;
    assert_error(st, &body, StatusCode::FORBIDDEN, "forbidden");
    let page = pull(&h.app, &b.token, v, 0, None).await;
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.head_revision, 2);

    let list = vaults(h, &b.token).await;
    let shared = list.iter().find(|x| x.id == v).unwrap();
    assert_eq!(shared.permission, sverb_proto::sync::Permission::Read);
    assert_eq!(shared.kind, sverb_proto::sync::VaultKind::Shared);
    assert_eq!(list.len(), 2, "personal + shared");
}

/// T-06: rotation in progress → push 409 rotating, pull works, the vault
/// list shows the rotation.
async fn t06_rotating(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    push(&h.app, &a.token, a.vault, new_items(1, 8)).await;
    h.set_rotation(a.vault, Some(2)).await;
    let (st, v) = push_raw(&h.app, &a.token, a.vault, new_items(1, 8)).await;
    assert_error(st, &v, StatusCode::CONFLICT, "rotating");
    let page = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert_eq!(page.items.len(), 1);
    let rot = vaults(h, &a.token).await[0].rotation.unwrap();
    assert!(rot.in_progress);
    assert_eq!(rot.new_key_version, Some(2));
    h.set_rotation(a.vault, None).await;
    let res = push(&h.app, &a.token, a.vault, new_items(1, 8)).await;
    assert_eq!(res.results[0].revision, Some(2), "nothing consumed by the 409");
}

/// T-07: envelope of 1 MiB + 1 → item `too_large`; 501 changes → 400;
/// 8 MiB + 1 of envelopes → 400; exactly 8 MiB passes.
async fn t07_limits(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let big = Uuid::now_v7();
    let ok = Uuid::now_v7();
    let res = push(
        &h.app,
        &a.token,
        a.vault,
        vec![
            change(big, 0, &vec![1; MAX_ENVELOPE_BYTES + 1], false),
            change(ok, 0, &vec![1; MAX_ENVELOPE_BYTES], false),
        ],
    )
    .await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    assert_eq!(res.results[0].revision, None);
    assert_eq!(res.results[1].status, PushStatus::Ok);
    assert_eq!(res.results[1].revision, Some(1), "the rejected one consumed nothing");

    let (st, v) = push_raw(&h.app, &a.token, a.vault, new_items(501, 1)).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");

    let mut batch = new_items(8, MAX_ENVELOPE_BYTES);
    batch.push(change(Uuid::now_v7(), 0, &[1], false));
    let (st, v) = push_raw(&h.app, &a.token, a.vault, batch).await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");

    // Exactly 8 MiB of envelopes fits the body limit and the batch limit.
    let res = push(&h.app, &a.token, a.vault, new_items(8, MAX_ENVELOPE_BYTES)).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    assert_eq!(pull(&h.app, &a.token, a.vault, 0, Some(1)).await.head_revision, 9);
}

/// T-08 (quota 1 MiB): over quota → `too_large` "quota exceeded", nothing
/// accepted beyond the quota; shrinking is always allowed.
async fn t08_quota(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let batch = new_items(5, 300_000);
    let first = batch[0]["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let res = push(&h.app, &a.token, a.vault, batch).await;
    let st: Vec<_> = res.results.iter().map(|r| r.status).collect();
    assert_eq!(
        st,
        vec![
            PushStatus::Ok,
            PushStatus::Ok,
            PushStatus::Ok,
            PushStatus::TooLarge,
            PushStatus::TooLarge
        ]
    );
    assert_eq!(res.results[3].message.as_deref(), Some(QUOTA_EXCEEDED_MESSAGE));
    assert_eq!(revisions(&res)[..3], [Some(1), Some(2), Some(3)]);
    // 900,000 of 1,048,576 used: 148,576 left.
    let res = push(&h.app, &a.token, a.vault, new_items(1, 148_577)).await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    let res = push(&h.app, &a.token, a.vault, new_items(1, 148_576)).await;
    assert_eq!(res.results[0].revision, Some(4));
    // Full. Replacing an item by a tombstone frees space…
    let res = push(&h.app, &a.token, a.vault, vec![change(first, 1, &[0; 16], true)]).await;
    assert_eq!(res.results[0].revision, Some(5));
    // …which new data may then use.
    let res = push(&h.app, &a.token, a.vault, new_items(1, 299_984)).await;
    assert_eq!(res.results[0].revision, Some(6));
    let res = push(&h.app, &a.token, a.vault, new_items(1, 1)).await;
    assert_eq!(res.results[0].status, PushStatus::TooLarge);
    let total: usize = pull(&h.app, &a.token, a.vault, 0, None)
        .await
        .items
        .iter()
        .map(|i| i.envelope.len())
        .sum();
    assert_eq!(total, 1024 * 1024);
}

/// T-09: GC purges tombstones older than the horizon, raises the floor;
/// `since` below the floor → 410 gone; `since=0` and `since=floor` work.
async fn t09_gc(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let (x, y, z) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    push(
        &h.app,
        &a.token,
        a.vault,
        vec![change(x, 0, b"x", false), change(y, 0, b"y", false)],
    )
    .await;
    let res = push(&h.app, &a.token, a.vault, vec![change(x, 1, b"x-dead", true)]).await;
    assert_eq!(res.results[0].revision, Some(3));
    let t_old = h.now();
    // A newer tombstone, still inside the horizon at GC time.
    h.clock.advance(TimeDelta::minutes(10));
    push(&h.app, &a.token, a.vault, vec![change(z, 0, b"z", false)]).await;
    let res = push(&h.app, &a.token, a.vault, vec![change(z, 4, b"z-dead", true)]).await;
    assert_eq!(res.results[0].revision, Some(5));

    // 90 days after the first tombstone (+5 min) but before the second.
    let horizon = 90;
    let gc_now = t_old + TimeDelta::days(horizon) + TimeDelta::minutes(5);
    let out = h
        .state
        .sync()
        .store()
        .gc_tombstones(gc::cutoff(gc_now, horizon.try_into().unwrap()))
        .await
        .unwrap();
    assert_eq!((out.purged_tombstones, out.vaults), (1, 1));
    assert_eq!(h.gc_floor(a.vault).await, 3);

    let (st, v) = pull_raw(&h.app, &a.token, a.vault, 2, None).await;
    assert_error(st, &v, StatusCode::GONE, "gone");
    let full = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert_eq!(
        full.items.iter().map(|i| (i.id, i.revision, i.deleted)).collect::<Vec<_>>(),
        vec![(y, 2, false), (z, 5, true)],
        "the old tombstone is gone, the recent one stays"
    );
    assert_eq!(full.head_revision, 5);
    let page = pull(&h.app, &a.token, a.vault, 3, None).await;
    assert_eq!(page.items.len(), 1);

    // A second run finds nothing; the floor never goes down.
    let out = h.state.sync().store().gc_tombstones(gc::cutoff(gc_now, 90)).await.unwrap();
    assert_eq!(out.purged_tombstones, 0);
    assert_eq!(h.gc_floor(a.vault).await, 3);

    // The purged item can be pushed again as new (full-resync path).
    let res = push(&h.app, &a.token, a.vault, vec![change(x, 0, b"x-again", false)]).await;
    assert_eq!(res.results[0].revision, Some(6));
}

/// T-10: non-members (and unknown vaults) get 404 for pull and push.
async fn t10_non_member(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let b = register(h, "bob@example.com").await;
    push(&h.app, &a.token, a.vault, new_items(1, 8)).await;
    for vault in [a.vault, Uuid::now_v7()] {
        let (st1, v1) = pull_raw(&h.app, &b.token, vault, 0, None).await;
        assert_error(st1, &v1, StatusCode::NOT_FOUND, "not_found");
        let (st2, v2) = push_raw(&h.app, &b.token, vault, new_items(1, 8)).await;
        assert_error(st2, &v2, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(v1["error"]["message"], v2["error"]["message"]);
    }
    assert!(vaults(h, &b.token).await.iter().all(|v| v.id != a.vault));
    // Unauthenticated.
    let (st, v) = call(&h.app, "GET", "/v1/vaults", None, None).await;
    assert_error(st, &v, StatusCode::UNAUTHORIZED, "auth_required");
}

/// T-11: a key-version mismatch → 400 invalid for the whole batch.
async fn t11_key_version(h: &Harness) {
    let a = register(h, "alice@example.com").await;
    let mut stale = change(Uuid::now_v7(), 0, b"x", false);
    stale["key_version"] = json!(2);
    let (st, v) = push_raw(
        &h.app,
        &a.token,
        a.vault,
        vec![change(Uuid::now_v7(), 0, b"ok", false), stale],
    )
    .await;
    assert_error(st, &v, StatusCode::BAD_REQUEST, "invalid");
    assert_eq!(pull(&h.app, &a.token, a.vault, 0, None).await.head_revision, 0);
}

/// T-12: items sealed client-side with a canary label → nothing in the
/// database contains the canary (text or bytes).
async fn t12_no_plaintext(h: &Harness) {
    const CANARY: &str = "CANARY-prod-db-7731.internal";
    let a = register(h, "alice@example.com").await;
    let mut rng = os_rng();
    let vk = random_key32(&mut rng);
    let mut changes = Vec::new();
    for i in 0..5 {
        let id = Uuid::now_v7();
        let body = format!("{{\"label\":\"{CANARY}-{i}\",\"hostname\":\"{CANARY}\"}}");
        let env = seal_item(&vk, a.vault.as_bytes(), id.as_bytes(), 1, body.as_bytes(), &mut rng)
            .unwrap();
        changes.push(change(id, 0, &env, false));
    }
    let res = push(&h.app, &a.token, a.vault, changes).await;
    assert!(res.results.iter().all(|r| r.status == PushStatus::Ok));
    let (blobs, text) = h.dump().await;
    assert!(!blobs.is_empty());
    let needle = CANARY.as_bytes();
    for b in &blobs {
        assert!(
            !b.windows(needle.len()).any(|w| w == needle),
            "plaintext canary stored"
        );
    }
    assert!(!text.contains(CANARY));
    assert!(!text.contains(&hex::encode(needle)));
}

#[derive(Debug, Default)]
struct Recorder(Mutex<Vec<(Uuid, u64)>>);

impl ChangeNotifier for Recorder {
    fn vault_changed(&self, vault_id: Uuid, head_revision: u64) {
        self.0.lock().unwrap().push((vault_id, head_revision));
    }
}

/// The notify hook (for M4-05) fires after commits that accepted changes.
async fn notify_hook(h: &Harness) {
    let rec = Arc::new(Recorder::default());
    h.state.sync().set_notifier(rec.clone());
    let a = register(h, "alice@example.com").await;
    let x = Uuid::now_v7();
    push(&h.app, &a.token, a.vault, vec![change(x, 0, b"x", false)]).await;
    push(&h.app, &a.token, a.vault, vec![change(x, 0, b"stale", false)]).await;
    push(&h.app, &a.token, a.vault, new_items(2, 4)).await;
    assert_eq!(*rec.0.lock().unwrap(), vec![(a.vault, 1), (a.vault, 3)]);
}

// ------------------------------------------------------------------- tests

macro_rules! both {
    ($scenario:ident, $mem:ident, $pg:ident) => {
        both!($scenario, $mem, $pg, &[]);
    };
    ($scenario:ident, $mem:ident, $pg:ident, $cfg:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        async fn $mem() {
            let h = Harness::mem($cfg);
            $scenario(&h).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        async fn $pg() {
            let h = $crate::db_or_skip!(Harness::pg($cfg));
            $scenario(&h).await;
            h.cleanup().await;
        }
    };
}

both!(t01_push_new, t01_push_new_items_mem, t01_push_new_items_pg);
both!(t02_conflicts, t02_conflicts_consume_no_revisions_mem, t02_conflicts_consume_no_revisions_pg);
both!(t03_pagination, t03_pull_pagination_mem, t03_pull_pagination_pg);
both!(t04_concurrency, t04_parallel_pushers_puller_never_misses_mem, t04_parallel_pushers_puller_never_misses_pg);
both!(t05_read_only, t05_read_member_push_forbidden_mem, t05_read_member_push_forbidden_pg);
both!(t06_rotating, t06_rotation_blocks_push_not_pull_mem, t06_rotation_blocks_push_not_pull_pg);
both!(t07_limits, t07_item_and_batch_limits_mem, t07_item_and_batch_limits_pg);
both!(
    t08_quota,
    t08_quota_exceeded_mem,
    t08_quota_exceeded_pg,
    &[("SVERB_STORAGE_QUOTA_MIB", "1")]
);
both!(t09_gc, t09_tombstone_gc_and_gone_mem, t09_tombstone_gc_and_gone_pg);
both!(t10_non_member, t10_non_member_not_found_mem, t10_non_member_not_found_pg);
both!(t11_key_version, t11_key_version_mismatch_mem, t11_key_version_mismatch_pg);
both!(t12_no_plaintext, t12_no_plaintext_stored_mem, t12_no_plaintext_stored_pg);
both!(notify_hook, notify_after_commit_mem, notify_after_commit_pg);

/// T-04 (model check): while a push holds the vault lock before commit, its
/// changes are invisible, a second push to the same vault waits, and both
/// then land in lock order (in-memory model only; PostgreSQL provides this
/// by `FOR UPDATE`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t04_vault_lock_serializes_and_hides_uncommitted_mem() {
    let h = Harness::mem(&[]);
    let a = register(&h, "alice@example.com").await;
    let paused = h.mem_sync().pause_next_commit();
    let (app, token, vault) = (h.app.clone(), a.token.clone(), a.vault);
    let first = tokio::spawn(async move { push(&app, &token, vault, new_items(2, 8)).await });
    paused.reached.await.unwrap();

    // Uncommitted: invisible to readers, who don't block.
    let page = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert!(page.items.is_empty());
    assert_eq!(page.head_revision, 0);

    let (app, token, vault) = (h.app.clone(), a.token.clone(), a.vault);
    let second = tokio::spawn(async move { push(&app, &token, vault, new_items(1, 8)).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!second.is_finished(), "a second push must wait for the vault lock");

    paused.resume.send(()).unwrap();
    let r1 = first.await.unwrap();
    let r2 = second.await.unwrap();
    assert_eq!(revisions(&r1), vec![Some(1), Some(2)]);
    assert_eq!(revisions(&r2), vec![Some(3)]);
    let page = pull(&h.app, &a.token, a.vault, 0, None).await;
    assert_eq!(
        page.items.iter().map(|i| i.revision).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}
