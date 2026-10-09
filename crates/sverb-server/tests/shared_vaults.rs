//! M5-02: shared vault routes over HTTP: create, grant, revoke, the membership
//! listings, read-only push enforcement (T-04, server half) and the audit rows.
//!
//! The server never sees a vault key, so the grants here carry opaque bytes (the
//! client-side signing and verification are covered in `sverb-sync`'s
//! `tests/shared_vaults.rs`). Every scenario runs on the in-memory store (`*_mem`)
//! and on PostgreSQL (`*_pg`, needs `DATABASE_URL`; otherwise skipped).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use common::{TestDb, config, json, req, send};
use serde_json::{Value, json};
use sverb_crypto::account::{derive_akek, generate_account_keys, seal_private_bundle};
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::{SverbKsf, client_registration_start};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};
use sverb_proto::auth::SessionResponse;
use sverb_proto::b64;
use sverb_server::auth::store::mem::MemStore;
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::{self, RegistrationMode};
use sverb_server::{AppState, app};
use uuid::Uuid;

enum Backend {
    Mem(Arc<MemStore>),
    Pg(TestDb),
}

struct Harness {
    app: Router,
    backend: Backend,
}

impl Harness {
    fn build(store: AuthStore, pool: sqlx_postgres::PgPool, backend: Backend) -> Self {
        let n = NonZeroU32::new(100_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
        let auth = AuthRuntime::new(store, Arc::new(ManualClock::new()));
        let state = AppState::with_auth(config(&[]), pool, limits, auth);
        Self {
            app: app::router(state),
            backend,
        }
    }

    fn mem() -> Self {
        let mem = Arc::new(MemStore::new());
        let pool =
            sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap();
        Self::build(AuthStore::Memory(mem.clone()), pool, Backend::Mem(mem))
    }

    async fn pg() -> Option<Self> {
        let db = TestDb::migrated().await?;
        let pool = db.pool.clone();
        Some(Self::build(
            AuthStore::Postgres(pool.clone()),
            pool,
            Backend::Pg(db),
        ))
    }

    async fn cleanup(self) {
        if let Backend::Pg(db) = self.backend {
            db.cleanup().await;
        }
    }

    async fn open_registration(&self) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.registration_mode = RegistrationMode::Open),
            Backend::Pg(db) => registration::set_mode(&db.pool, RegistrationMode::Open)
                .await
                .unwrap(),
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
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
        let (st, _, bytes) = send(&self.app, r).await;
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            json(&bytes)
        };
        (st, v)
    }

    async fn audit_kinds(&self, org: Uuid) -> Vec<String> {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.audit
                    .iter()
                    .filter(|a| a.org_id == Some(org))
                    .map(|a| a.kind.clone())
                    .collect()
            }),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar(
                "SELECT kind FROM audit_events WHERE org_id = $1 ORDER BY id",
            )
            .bind(org)
            .fetch_all(&db.pool)
            .await
            .unwrap(),
        }
    }
}

struct Account {
    email: String,
    user_id: Uuid,
    session: SessionResponse,
}

impl Account {
    fn t(&self) -> &str {
        &self.session.tokens.access_token
    }
}

async fn register(h: &Harness, email: &str) -> Account {
    h.open_registration().await;
    let password = b"correct horse battery staple";
    let ksf = SverbKsf::insecure_for_tests();
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password).unwrap();
    let r = req("POST", "/v1/auth/register/start", "198.51.100.7:4000")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "email": email, "registration_request": b64::encode(&request) }).to_string(),
        ))
        .unwrap();
    let (st, _, bytes) = send(&h.app, r).await;
    assert_eq!(st, StatusCode::OK);
    let v = json(&bytes);
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state.finish(&mut rng, password, &response, &ksf).unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let vault_id = Uuid::now_v7();
    let vk = random_key32(&mut rng);
    let grant = self_grant(&vk, vault_id.as_bytes(), 1, &uid, &keys, &mut rng).unwrap();
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
    let r = req("POST", "/v1/auth/register/finish", "198.51.100.7:4000")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(finish.to_string()))
        .unwrap();
    let (st, _, bytes) = send(&h.app, r).await;
    assert_eq!(st, StatusCode::OK);
    Account {
        email: email.to_owned(),
        user_id,
        session: serde_json::from_value(json(&bytes)).unwrap(),
    }
}

async fn create_org(h: &Harness, a: &Account) -> Uuid {
    let (st, v) = h
        .call("POST", "/v1/orgs", Some(json!({ "name": "Acme" })), a.t())
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    serde_json::from_value(v["id"].clone()).unwrap()
}

async fn join(h: &Harness, by: &Account, org: Uuid, who: &Account, role: &str) {
    let (st, v) = h
        .call(
            "POST",
            &format!("/v1/orgs/{org}/invites"),
            Some(json!({ "email": who.email, "role": role })),
            by.t(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let token = v["link"].as_str().unwrap().rsplit('/').next().unwrap();
    let (st, v) = h
        .call(
            "POST",
            &format!("/v1/invites/{token}/accept"),
            None,
            who.t(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
}

fn grant_body(permission: &str, kv: u32) -> Value {
    json!({
        "permission": permission,
        "key_version": kv,
        "wrapped_vault_key": b64::encode(&[7u8; 80]),
        "signature": b64::encode(&[9u8; 64]),
    })
}

async fn create_vault(h: &Harness, by: &Account, org: Uuid) -> (StatusCode, Value, Uuid) {
    let id = Uuid::now_v7();
    let body = json!({
        "id": id,
        "org_id": org,
        "name_enc": b64::encode(b"sealed name"),
        "self_grant": {
            "wrapped_vault_key": b64::encode(&[1u8; 80]),
            "signature": b64::encode(&[2u8; 64]),
            "key_version": 1,
        },
    });
    let (st, v) = h.call("POST", "/v1/vaults", Some(body), by.t()).await;
    (st, v, id)
}

async fn grant(h: &Harness, by: &Account, vault: Uuid, to: Uuid, perm: &str) -> StatusCode {
    h.call(
        "PUT",
        &format!("/v1/vaults/{vault}/members/{to}"),
        Some(grant_body(perm, 1)),
        by.t(),
    )
    .await
    .0
}

async fn vault_ids(h: &Harness, who: &Account) -> Vec<Uuid> {
    let (st, v) = h.call("GET", "/v1/vaults", None, who.t()).await;
    assert_eq!(st, StatusCode::OK);
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| serde_json::from_value(x["id"].clone()).unwrap())
        .collect()
}

fn push_body(item: Uuid) -> Value {
    json!({ "changes": [{
        "id": item,
        "base_revision": 0,
        "key_version": 1,
        "envelope": b64::encode(&[1u8; 64]),
        "deleted": false,
    }]})
}

// Create: admins and owners only; ids are unique; members can't see others' vaults.
async fn create_rules(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let admin = register(h, "admin@example.test").await;
    let member = register(h, "member@example.test").await;
    let outsider = register(h, "outsider@example.test").await;
    let org = create_org(h, &owner).await;
    join(h, &owner, org, &admin, "admin").await;
    join(h, &owner, org, &member, "member").await;

    let (st, v, id) = create_vault(h, &admin, org).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["kind"], "shared");
    assert_eq!(v["permission"], "manage");
    assert_eq!(v["grants"][0]["wrapped_by"], json!(admin.user_id));
    assert!(vault_ids(h, &admin).await.contains(&id));
    assert!(!vault_ids(h, &member).await.contains(&id));

    assert_eq!(create_vault(h, &member, org).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        create_vault(h, &outsider, org).await.0,
        StatusCode::NOT_FOUND
    );
    // The same id again: conflict.
    let body = json!({
        "id": id, "org_id": org, "name_enc": b64::encode(b"x"),
        "self_grant": { "wrapped_vault_key": b64::encode(&[1u8; 80]),
                        "signature": b64::encode(&[2u8; 64]), "key_version": 1 },
    });
    assert_eq!(
        h.call("POST", "/v1/vaults", Some(body), owner.t()).await.0,
        StatusCode::CONFLICT
    );

    // Members listing: invisible to a member without a grant, visible to admins.
    let path = format!("/v1/vaults/{id}/members");
    assert_eq!(
        h.call("GET", &path, None, member.t()).await.0,
        StatusCode::NOT_FOUND
    );
    let (st, v) = h.call("GET", &path, None, owner.t()).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["created_by"], json!(admin.user_id));
    assert_eq!(v["members"].as_array().unwrap().len(), 3);

    // T-09 (server half): the owner holds no key yet: "needs key".
    let (st, v) = h
        .call("GET", &format!("/v1/orgs/{org}/vaults"), None, owner.t())
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v[0]["permission"], "manage");
    assert_eq!(v[0]["has_key"], false);
    let (_, v) = h
        .call("GET", &format!("/v1/orgs/{org}/vaults"), None, admin.t())
        .await;
    assert_eq!(v[0]["has_key"], true);
    let (_, v) = h
        .call("GET", &format!("/v1/orgs/{org}/vaults"), None, member.t())
        .await;
    assert_eq!(v, json!([]));
    assert!(h.audit_kinds(org).await.contains(&"vault.created".into()));
}

// Grants: who may grant whom; T-04 (server): a read member's push is 403.
async fn grant_rules(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let bob = register(h, "bob@example.test").await;
    let carol = register(h, "carol@example.test").await;
    let outsider = register(h, "outsider@example.test").await;
    let org = create_org(h, &owner).await;
    join(h, &owner, org, &bob, "member").await;
    join(h, &owner, org, &carol, "member").await;
    let (st, _, vault) = create_vault(h, &owner, org).await;
    assert_eq!(st, StatusCode::OK);

    assert_eq!(
        grant(h, &owner, vault, bob.user_id, "write").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        grant(h, &owner, vault, carol.user_id, "read").await,
        StatusCode::NO_CONTENT
    );
    assert!(vault_ids(h, &bob).await.contains(&vault));
    // A write member can't grant; nobody can grant to a non-member.
    assert_eq!(
        grant(h, &bob, vault, carol.user_id, "manage").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        grant(h, &owner, vault, outsider.user_id, "read").await,
        StatusCode::BAD_REQUEST
    );
    // A stale key version.
    let (st, _) = h
        .call(
            "PUT",
            &format!("/v1/vaults/{vault}/members/{}", carol.user_id),
            Some(grant_body("read", 2)),
            owner.t(),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // A bad signature length.
    let mut body = grant_body("read", 1);
    body["signature"] = json!(b64::encode(&[1u8; 10]));
    let (st, _) = h
        .call(
            "PUT",
            &format!("/v1/vaults/{vault}/members/{}", carol.user_id),
            Some(body),
            owner.t(),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // The listing reflects the grants.
    let (_, v) = h
        .call("GET", &format!("/v1/vaults/{vault}/members"), None, bob.t())
        .await;
    let perm = |u: Uuid| {
        v["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["user_id"] == json!(u))
            .unwrap()["permission"]
            .clone()
    };
    assert_eq!(perm(bob.user_id), "write");
    assert_eq!(perm(carol.user_id), "read");

    // T-04: Bob pushes, Carol (read) is refused.
    let changes = format!("/v1/vaults/{vault}/changes");
    let (st, v) = h
        .call("POST", &changes, Some(push_body(Uuid::now_v7())), bob.t())
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = h
        .call("POST", &changes, Some(push_body(Uuid::now_v7())), carol.t())
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"]["code"], "forbidden");
    let kinds = h.audit_kinds(org).await;
    assert!(kinds.contains(&"vault.member_granted".into()), "{kinds:?}");
    assert!(kinds.contains(&"vault.items_pushed".into()), "{kinds:?}");

    // Upgrading Carol to write lets her push.
    assert_eq!(
        grant(h, &owner, vault, carol.user_id, "write").await,
        StatusCode::NO_CONTENT
    );
    let (st, _) = h
        .call("POST", &changes, Some(push_body(Uuid::now_v7())), carol.t())
        .await;
    assert_eq!(st, StatusCode::OK);

    // Revoke: Bob can't revoke Carol; he can leave; the owner revokes Carol.
    let del = |u: Uuid| format!("/v1/vaults/{vault}/members/{u}");
    assert_eq!(
        h.call("DELETE", &del(carol.user_id), None, bob.t()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.call("DELETE", &del(bob.user_id), None, bob.t()).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(!vault_ids(h, &bob).await.contains(&vault));
    assert_eq!(
        h.call("DELETE", &del(carol.user_id), None, owner.t())
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.call("POST", &changes, Some(push_body(Uuid::now_v7())), carol.t())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(
        h.audit_kinds(org)
            .await
            .contains(&"vault.member_revoked".into())
    );
}

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

both!(create_rules, create_rules_mem, create_rules_pg);
both!(grant_rules, grant_rules_mem, grant_rules_pg);
