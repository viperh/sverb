//! Orgs, roles, invites, public keys and the audit log over HTTP.
//!
//! Every scenario runs on the in-memory store (`*_mem`) and on PostgreSQL
//! (`*_pg`, needs `DATABASE_URL`; otherwise "SKIPPED (needs PostgreSQL)").
//! The role matrix itself is unit-tested in `src/orgs/mod.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use chrono::TimeDelta;
use common::{TestDb, config, json, req, send};
use serde_json::{Value, json};
use sverb_crypto::account::{derive_akek, generate_account_keys, seal_private_bundle};
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::{SverbKsf, client_registration_start};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::recovery::{recovery_key_generate, seal_recovery_bundle};
use sverb_proto::auth::SessionResponse;
use sverb_proto::b64;
use sverb_server::auth::store::mem::{MemMember, MemStore, MemVault};
use sverb_server::auth::{AuthRuntime, AuthStore, ManualClock};
use sverb_server::mail::{Mailer, SentMail};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::registration::{self, RegistrationMode, hash_token};
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

impl Harness {
    fn build(store: AuthStore, pool: sqlx_postgres::PgPool, backend: Backend) -> Self {
        let n = NonZeroU32::new(100_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
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

    async fn set_mode(&self, mode: RegistrationMode) {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| d.registration_mode = mode),
            Backend::Pg(db) => registration::set_mode(&db.pool, mode).await.unwrap(),
        }
    }

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

    /// Every audit row of `org` as (kind, actor, target, meta).
    async fn audit_rows(&self, org: Uuid) -> Vec<(String, Value)> {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.audit
                    .iter()
                    .filter(|a| a.org_id == Some(org))
                    .map(|a| (a.kind.clone(), a.meta.clone()))
                    .collect()
            }),
            Backend::Pg(db) => sqlx_core::query_as::query_as::<_, (String, Value)>(
                "SELECT kind, meta FROM audit_events WHERE org_id = $1 ORDER BY id",
            )
            .bind(org)
            .fetch_all(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// The stored token hashes of `org`'s invites.
    async fn invite_hashes(&self, org: Uuid) -> Vec<Vec<u8>> {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.invites
                    .iter()
                    .filter(|i| i.org_id == Some(org))
                    .map(|i| i.token_hash.to_vec())
                    .collect()
            }),
            Backend::Pg(db) => sqlx_core::query_scalar::query_scalar(
                "SELECT token_hash FROM invites WHERE org_id = $1",
            )
            .bind(org)
            .fetch_all(&db.pool)
            .await
            .unwrap(),
        }
    }

    /// A shared vault of `org` with a grant for each of `members`.
    async fn shared_vault(&self, org: Uuid, members: &[Uuid]) -> Uuid {
        let vault = Uuid::now_v7();
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vaults
                    .insert(vault, MemVault::shared(Some(org), b"name".to_vec(), 1));
                for u in members {
                    d.vault_members.push(MemMember {
                        vault_id: vault,
                        user_id: *u,
                        permission: "write".into(),
                        key_version: 1,
                        wrapped_vault_key: vec![1],
                        wrapped_by: members[0],
                        signature: vec![2],
                    });
                }
            }),
            Backend::Pg(db) => {
                sqlx_core::query::query(
                    "INSERT INTO vaults (id, kind, org_id, name_enc) VALUES ($1, 'shared', $2, $3)",
                )
                .bind(vault)
                .bind(org)
                .bind(b"name".to_vec())
                .execute(&db.pool)
                .await
                .unwrap();
                for u in members {
                    sqlx_core::query::query(
                        "INSERT INTO vault_members (vault_id, user_id, permission, key_version, \
                         wrapped_vault_key, wrapped_by, signature) VALUES ($1, $2, 'write', 1, $3, $4, $5)",
                    )
                    .bind(vault)
                    .bind(u)
                    .bind(vec![1u8])
                    .bind(members[0])
                    .bind(vec![2u8])
                    .execute(&db.pool)
                    .await
                    .unwrap();
                }
            }
        }
        vault
    }

    async fn grants(&self, vault: Uuid) -> usize {
        match &self.backend {
            Backend::Mem(m) => m.with_data(|d| {
                d.vault_members
                    .iter()
                    .filter(|v| v.vault_id == vault)
                    .count()
            }),
            Backend::Pg(db) => {
                let n: i64 = sqlx_core::query_scalar::query_scalar(
                    "SELECT count(*) FROM vault_members WHERE vault_id = $1",
                )
                .bind(vault)
                .fetch_one(&db.pool)
                .await
                .unwrap();
                usize::try_from(n).unwrap()
            }
        }
    }
}

// ------------------------------------------------------------------- client

struct Account {
    email: String,
    user_id: Uuid,
    session: SessionResponse,
}

impl Account {
    fn access(&self) -> &str {
        &self.session.tokens.access_token
    }
}

/// Registration through both endpoints (like the client). `extra` is
/// merged into both requests (an invite token).
async fn try_register(
    h: &Harness,
    email: &str,
    extra: &Value,
) -> Result<Account, (StatusCode, Value)> {
    let password = b"correct horse battery staple";
    let ksf = SverbKsf::insecure_for_tests();
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password).unwrap();
    let mut start = json!({ "email": email, "registration_request": b64::encode(&request) });
    merge(&mut start, extra);
    let (st, v) = h
        .call("POST", "/v1/auth/register/start", Some(start), None)
        .await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    let response = b64::decode(v["registration_response"].as_str().unwrap()).unwrap();
    let user_id: Uuid = serde_json::from_value(v["user_id"].clone()).unwrap();
    let fin = state.finish(&mut rng, password, &response, &ksf).unwrap();
    let akek = derive_akek(&fin.export_key);
    let keys = generate_account_keys(&mut rng);
    let uid = *user_id.as_bytes();
    let private = seal_private_bundle(&akek, &uid, 1, &keys, &mut rng).unwrap();
    let (recovery, _words) = recovery_key_generate(&mut rng);
    let rbundle = seal_recovery_bundle(&recovery, &uid, &keys, &mut rng).unwrap();
    let vault_id = Uuid::now_v7();
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
    merge(&mut finish, extra);
    let (st, v) = h
        .call("POST", "/v1/auth/register/finish", Some(finish), None)
        .await;
    if st != StatusCode::OK {
        return Err((st, v));
    }
    Ok(Account {
        email: email.to_owned(),
        user_id,
        session: serde_json::from_value(v).unwrap(),
    })
}

fn merge(into: &mut Value, extra: &Value) {
    if let (Some(a), Some(b)) = (into.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}

async fn register(h: &Harness, email: &str) -> Account {
    h.set_mode(RegistrationMode::Open).await;
    try_register(h, email, &json!({}))
        .await
        .unwrap_or_else(|(st, v)| panic!("registration failed: {st} {v}"))
}

async fn create_org(h: &Harness, a: &Account, name: &str) -> Uuid {
    let (st, v) = h
        .call(
            "POST",
            "/v1/orgs",
            Some(json!({ "name": name })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["role"], "owner");
    serde_json::from_value(v["id"].clone()).unwrap()
}

/// An invite; returns (status, body).
async fn invite(
    h: &Harness,
    by: &Account,
    org: Uuid,
    email: Option<&str>,
    role: &str,
) -> (StatusCode, Value) {
    let mut body = json!({ "role": role });
    if let Some(e) = email {
        body["email"] = json!(e);
    }
    h.call(
        "POST",
        &format!("/v1/orgs/{org}/invites"),
        Some(body),
        Some(by.access()),
    )
    .await
}

fn token_of(link: &Value) -> String {
    link.as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

async fn accept(h: &Harness, who: &Account, token: &str) -> (StatusCode, Value) {
    h.call(
        "POST",
        &format!("/v1/invites/{token}/accept"),
        None,
        Some(who.access()),
    )
    .await
}

/// Invites `who` as `role` and accepts.
async fn join(h: &Harness, by: &Account, org: Uuid, who: &Account, role: &str) {
    let (st, v) = invite(h, by, org, Some(&who.email), role).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let (st, v) = accept(h, who, &token_of(&v["link"])).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["role"], role);
}

async fn set_role(h: &Harness, by: &Account, org: Uuid, user: Uuid, role: &str) -> StatusCode {
    h.call(
        "PATCH",
        &format!("/v1/orgs/{org}/members/{user}"),
        Some(json!({ "role": role })),
        Some(by.access()),
    )
    .await
    .0
}

async fn remove(h: &Harness, by: &Account, org: Uuid, user: Uuid) -> (StatusCode, Value) {
    h.call(
        "DELETE",
        &format!("/v1/orgs/{org}/members/{user}"),
        None,
        Some(by.access()),
    )
    .await
}

// ---------------------------------------------------------------- scenarios

// Create → owner; list; members.
async fn t01_create_and_list(h: &Harness) {
    let a = register(h, "alice@example.test").await;
    let b = register(h, "bob@example.test").await;
    let org = create_org(h, &a, "  Acme Ops ").await;
    let (st, v) = h.call("GET", "/v1/orgs", None, Some(a.access())).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["name"], "Acme Ops");
    assert_eq!(v[0]["role"], "owner");
    // Not a member: empty list, the org's members are hidden (404).
    let (_, v) = h.call("GET", "/v1/orgs", None, Some(b.access())).await;
    assert_eq!(v, json!([]));
    let (st, _) = h
        .call(
            "GET",
            &format!("/v1/orgs/{org}/members"),
            None,
            Some(b.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, v) = h
        .call(
            "GET",
            &format!("/v1/orgs/{org}/members"),
            None,
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v[0]["email"], "alice@example.test");
    // Bad names.
    let (st, _) = h
        .call(
            "POST",
            "/v1/orgs",
            Some(json!({ "name": " " })),
            Some(a.access()),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

// T-02 (HTTP): the rules hold end to end.
async fn t02_permissions(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let admin = register(h, "admin@example.test").await;
    let member = register(h, "member@example.test").await;
    let other = register(h, "other@example.test").await;
    let org = create_org(h, &owner, "Acme").await;
    join(h, &owner, org, &admin, "admin").await;
    join(h, &owner, org, &member, "member").await;

    // A member can't invite; an admin can, but not owners.
    assert_eq!(
        invite(h, &member, org, None, "member").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        invite(h, &admin, org, None, "member").await.0,
        StatusCode::OK
    );
    assert_eq!(
        invite(h, &admin, org, None, "owner").await.0,
        StatusCode::FORBIDDEN
    );
    // Admin: member ↔ admin, never owners.
    assert_eq!(
        set_role(h, &admin, org, member.user_id, "admin").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        set_role(h, &admin, org, member.user_id, "member").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        set_role(h, &admin, org, member.user_id, "owner").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        set_role(h, &admin, org, owner.user_id, "member").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        set_role(h, &member, org, admin.user_id, "member").await,
        StatusCode::FORBIDDEN
    );
    // The last owner can't be demoted or removed, or leave.
    assert_eq!(
        set_role(h, &owner, org, owner.user_id, "admin").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        remove(h, &owner, org, owner.user_id).await.0,
        StatusCode::BAD_REQUEST
    );
    // A second owner makes it possible.
    assert_eq!(
        set_role(h, &owner, org, admin.user_id, "owner").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        set_role(h, &owner, org, owner.user_id, "admin").await,
        StatusCode::NO_CONTENT
    );
    // Outsiders see nothing.
    assert_eq!(
        set_role(h, &other, org, member.user_id, "admin").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        invite(h, &other, org, None, "member").await.0,
        StatusCode::NOT_FOUND
    );
    // A member leaves; removing revokes their grants on the org's vaults.
    let vault = h.shared_vault(org, &[admin.user_id, member.user_id]).await;
    assert_eq!(h.grants(vault).await, 2);
    let (st, v) = remove(h, &member, org, member.user_id).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(h.grants(vault).await, 1);
    let (_, v) = h
        .call(
            "GET",
            &format!("/v1/orgs/{org}/members"),
            None,
            Some(owner.access()),
        )
        .await;
    assert_eq!(v.as_array().unwrap().len(), 2);
}

// Tokens hashed, expiry, email binding, single-use link invites; and
// registration with an org invite on an invite-only server.
async fn t03_invites(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let bob = register(h, "bob@example.test").await;
    let carol = register(h, "carol@example.test").await;
    let org = create_org(h, &owner, "Acme").await;

    let (st, v) = invite(h, &owner, org, Some("Bob@Example.TEST"), "member").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["emailed"], false);
    assert_eq!(v["email"], "Bob@example.test");
    let token = token_of(&v["link"]);
    assert!(
        v["link"]
            .as_str()
            .unwrap()
            .starts_with("https://sync.example.test/invite/")
    );
    assert_eq!(token.len(), 43, "256-bit token");
    // Only the hash is stored.
    let hashes = h.invite_hashes(org).await;
    assert_eq!(hashes, [hash_token(&token).to_vec()]);
    // Another account can't use an email-bound invite.
    let (st, v) = accept(h, &carol, &token).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
    // Bob can; then it is used up.
    let (st, v) = accept(h, &bob, &token).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(accept(h, &bob, &token).await.0, StatusCode::NOT_FOUND);

    // Link invites: anyone, once.
    let (_, v) = invite(h, &owner, org, None, "admin").await;
    let link = token_of(&v["link"]);
    assert_eq!(accept(h, &carol, &link).await.1["role"], "admin");
    assert_eq!(accept(h, &bob, &link).await.0, StatusCode::NOT_FOUND);

    // Expiry (7 days, time travel): an invite made 8 days ago. (Moving the clock
    // forward instead would expire the access tokens too.)
    h.clock.advance(TimeDelta::days(-8));
    let (_, v) = invite(h, &owner, org, None, "member").await;
    let late = token_of(&v["link"]);
    h.clock.advance(TimeDelta::days(8));
    assert_eq!(accept(h, &bob, &late).await.0, StatusCode::NOT_FOUND);
    assert_eq!(accept(h, &bob, "garbage").await.0, StatusCode::NOT_FOUND);

    // Registration with an org invite on an invite-only server.
    let (_, v) = invite(h, &owner, org, Some("dave@example.test"), "member").await;
    let dave_token = token_of(&v["link"]);
    h.set_mode(RegistrationMode::InviteOnly).await;
    let dave = try_register(
        h,
        "dave@example.test",
        &json!({ "invite_token": dave_token }),
    )
    .await
    .unwrap_or_else(|(st, v)| panic!("{st} {v}"));
    let (_, v) = h.call("GET", "/v1/orgs", None, Some(dave.access())).await;
    assert_eq!(v[0]["id"], json!(org), "{v}");
    assert_eq!(v[0]["role"], "member");
}

// No SMTP → the link; SMTP (fake transport) → a mail with the link.
async fn t04_mail(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let org = create_org(h, &owner, "Acme").await;
    let (_, v) = invite(h, &owner, org, Some("x@example.test"), "member").await;
    assert_eq!(v["emailed"], false);
    assert!(v["link"].is_string());

    let sent: Arc<Mutex<Vec<SentMail>>> = Arc::default();
    h.state.set_mailer(Mailer::Recording(sent.clone()));
    let (st, v) = invite(h, &owner, org, Some("y@example.test"), "member").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["emailed"], true);
    assert!(v.get("link").is_none(), "{v}");
    let mails = sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, "y@example.test");
    assert!(
        mails[0].body.contains("https://sync.example.test/invite/"),
        "{mails:?}"
    );
    assert!(mails[0].body.contains("Acme"));
    // A link invite (no email) is never mailed.
    let (_, v) = invite(h, &owner, org, None, "member").await;
    assert_eq!(v["emailed"], false);
    assert!(v["link"].is_string());
    assert_eq!(sent.lock().unwrap().len(), 1);
}

// Public keys only for users sharing an org.
async fn t05_public_keys(h: &Harness) {
    let a = register(h, "alice@example.test").await;
    let b = register(h, "bob@example.test").await;
    let c = register(h, "carol@example.test").await;
    let path = |u: Uuid| format!("/v1/users/{u}/public-keys");
    assert_eq!(
        h.call("GET", &path(b.user_id), None, Some(a.access()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (st, v) = h
        .call("GET", &path(a.user_id), None, Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "own keys: {v}");
    let org = create_org(h, &a, "Acme").await;
    join(h, &a, org, &b, "member").await;
    let (st, v) = h
        .call("GET", &path(b.user_id), None, Some(a.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["user_id"], json!(b.user_id));
    assert_eq!(v["email"], "bob@example.test");
    assert_eq!(
        b64::decode(v["x25519_pub"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        h.call("GET", &path(a.user_id), None, Some(c.access()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.call("GET", &path(Uuid::now_v7()), None, Some(a.access()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

// An audit event per action; meta never holds names, emails or envelopes.
async fn t06_audit_events(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let bob = register(h, "bob@example.test").await;
    let org = create_org(h, &owner, "Secret Project Name").await;
    join(h, &owner, org, &bob, "member").await;
    assert_eq!(
        set_role(h, &owner, org, bob.user_id, "admin").await,
        StatusCode::NO_CONTENT
    );
    // A new device of a member, then its revocation.
    let (st, v) = h.call("GET", "/v1/devices", None, Some(bob.access())).await;
    assert_eq!(st, StatusCode::OK);
    let bob_device = v[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        remove(h, &owner, org, bob.user_id).await.0,
        StatusCode::NO_CONTENT
    );
    let (st, _) = h
        .call(
            "DELETE",
            &format!("/v1/devices/{bob_device}"),
            None,
            Some(bob.access()),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let rows = h.audit_rows(org).await;
    let kinds: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    for want in [
        "org.created",
        "member.added",
        "invite.sent",
        "invite.accepted",
        "member.role_changed",
        "member.removed",
    ] {
        assert!(kinds.contains(&want), "{want} missing: {kinds:?}");
    }
    assert!(
        !kinds.contains(&"device.revoked"),
        "bob was no longer a member"
    );
    for (kind, meta) in &rows {
        let text = meta.to_string();
        for secret in ["Secret Project", "bob@", "owner@", "example.test"] {
            assert!(!text.contains(secret), "{kind} meta leaks {secret}: {text}");
        }
    }
    let changed = rows
        .iter()
        .find(|(k, _)| k == "member.role_changed")
        .unwrap();
    assert_eq!(changed.1, json!({ "from": "member", "to": "admin" }));
}

// Pagination, admins only.
async fn t07_audit_endpoint(h: &Harness) {
    let owner = register(h, "owner@example.test").await;
    let member = register(h, "member@example.test").await;
    let org = create_org(h, &owner, "Acme").await;
    join(h, &owner, org, &member, "member").await;
    for _ in 0..7 {
        invite(h, &owner, org, None, "member").await;
    }
    let audit = |q: &str| format!("/v1/orgs/{org}/audit{q}");
    assert_eq!(
        h.call("GET", &audit(""), None, Some(member.access()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (st, all) = h
        .call("GET", &audit("?limit=200"), None, Some(owner.access()))
        .await;
    assert_eq!(st, StatusCode::OK, "{all}");
    let total = all["events"].as_array().unwrap().len();
    // org.created, member.added ×2, invite.sent ×8, invite.accepted.
    assert_eq!(total, 12, "{all}");
    assert_eq!(all["next_before"], Value::Null);
    let mut seen = Vec::new();
    let mut before: Option<i64> = None;
    loop {
        let q = before.map_or("?limit=5".to_owned(), |b| format!("?limit=5&before={b}"));
        let (_, page) = h.call("GET", &audit(&q), None, Some(owner.access())).await;
        let events = page["events"].as_array().unwrap();
        assert!(events.len() <= 5);
        seen.extend(events.iter().map(|e| e["id"].as_i64().unwrap()));
        match page["next_before"].as_i64() {
            Some(b) => before = Some(b),
            None => break,
        }
    }
    assert_eq!(seen.len(), total);
    assert!(
        seen.windows(2).all(|w| w[0] > w[1]),
        "newest first: {seen:?}"
    );
    assert_eq!(all["events"][0]["kind"], "invite.sent");
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

both!(
    t01_create_and_list,
    t01_create_and_list_mem,
    t01_create_and_list_pg
);
both!(t02_permissions, t02_permissions_mem, t02_permissions_pg);
both!(t03_invites, t03_invites_mem, t03_invites_pg);
both!(t04_mail, t04_mail_mem, t04_mail_pg);
both!(t05_public_keys, t05_public_keys_mem, t05_public_keys_pg);
both!(t06_audit_events, t06_audit_events_mem, t06_audit_events_pg);
both!(
    t07_audit_endpoint,
    t07_audit_endpoint_mem,
    t07_audit_endpoint_pg
);
