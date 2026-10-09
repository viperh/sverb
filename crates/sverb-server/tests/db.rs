//! Database-backed tests: T-02, T-09, T-10, T-11, T-12.
//!
//! These need PostgreSQL 15+ via `DATABASE_URL` (see `common`); without it
//! each test prints "SKIPPED (needs PostgreSQL)" and returns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;

use axum::body::Body;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{SECRET_A, SECRET_B, TestDb, config, fresh_db, json, req, send};
use serde::Deserialize;
use sverb_server::db::{self, MigrationStatus};
use sverb_server::registration::{self, RegistrationCredential, RegistrationMode};
use sverb_server::serve::{StartupError, prepare_with_pool};
use sverb_server::{ApiError, AppState, admin, app, settings};

#[derive(Deserialize)]
struct Register {
    email: String,
    setup_token: Option<String>,
    invite_token: Option<String>,
}

/// the user in the same transaction.
async fn register(
    State(state): State<AppState>,
    Json(body): Json<Register>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = registration::normalize_email(&body.email)?;
    let cred = match (&body.setup_token, &body.invite_token) {
        (Some(t), _) => RegistrationCredential::SetupToken(t),
        (None, Some(t)) => RegistrationCredential::InviteToken(t),
        (None, None) => RegistrationCredential::None,
    };
    let mut tx = state.db().begin().await?;
    let grant = registration::authorize(&mut tx, &email, cred).await?;
    sqlx_core::query::query(
        "INSERT INTO users (id, email, created_at, is_instance_admin, opaque_record) \
         VALUES ($1, $2, now(), $3, $4)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(&email)
    .bind(grant.is_instance_admin)
    .bind(b"opaque-record-placeholder".to_vec())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({ "is_instance_admin": grant.is_instance_admin }),
    ))
}

fn test_app(state: AppState) -> Router {
    let extra = Router::new()
        .route("/test/register", post(register))
        .route("/test/ping", get(|| async { "pong" }));
    app::with_layers(app::routes(&state).merge(extra), state)
}

async fn post_register(app: &Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let r = req("POST", "/test/register", "198.51.100.1:1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (st, _, b) = send(app, r).await;
    (st, json(&b))
}

/// Log capture. One global JSON subscriber (installed once) writes into a
/// per-thread buffer, so each test (current-thread runtime) reads only its own
/// events. A thread-local default subscriber raced with the other tests, which
/// hit the same callsites without one (tracing caches callsite interest globally).
#[derive(Clone, Copy, Default)]
struct Captured;

thread_local! {
    static CAPTURED: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Captured {
    /// Installs the global subscriber (once) and clears this thread's buffer.
    fn start() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_writer(Captured)
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
        });
        CAPTURED.with(|b| b.borrow_mut().clear());
        Self
    }

    /// This thread's captured output.
    fn text(self) -> String {
        CAPTURED.with(|b| String::from_utf8_lossy(&b.borrow()).into_owned())
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURED.with(|b| b.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

#[tokio::test]
async fn t02_migrations_apply_and_readyz_tracks_them() {
    let db = db_or_skip!(fresh_db());
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::Pending(vec![1, 2, 3, 4])
    );
    // serve refuses to start with pending migrations...
    let err = prepare_with_pool(config(&[]), db.pool.clone(), false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StartupError::PendingMigrations(ref v) if v == &[1, 2, 3, 4]),
        "{err}"
    );
    assert!(err.to_string().contains("sverb-server migrate"));
    // ...and readyz says 503.
    let app = test_app(AppState::new(config(&[]), db.pool.clone()));
    let (st, _, body) = send(
        &app,
        req("GET", "/readyz", "1.2.3.4:1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["migrations"], "pending");

    db::migrate(&db.pool).await.unwrap();
    db::migrate(&db.pool).await.unwrap(); // idempotent
    assert_eq!(
        db::migration_status(&db.pool).await.unwrap(),
        MigrationStatus::Current
    );
    let (st, _, body) = send(
        &app,
        req("GET", "/readyz", "1.2.3.4:1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(json(&body)["status"], "ready");

    let tables: Vec<String> = sqlx_core::query_scalar::query_scalar(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' ORDER BY 1",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "account_keys",
            "audit_events",
            "auth_tokens",
            "devices",
            "invites",
            "items",
            "items_rotation_staging",
            "login_states",
            "org_members",
            "orgs",
            "reauth_tokens",
            "recovery_codes",
            "server_secrets",
            "settings",
            "share_sessions",
            "users",
            "vault_members",
            "vaults",
        ]
    );
    assert_eq!(
        settings::get(&db.pool, settings::REGISTRATION_MODE)
            .await
            .unwrap()
            .as_deref(),
        Some("invite-only")
    );
    // serve --migrate path on a fresh DB.
    let db2 = db_or_skip!(fresh_db());
    prepare_with_pool(config(&[]), db2.pool.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        db::migration_status(&db2.pool).await.unwrap(),
        MigrationStatus::Current
    );
    db2.cleanup().await;
    db.cleanup().await;
}

#[tokio::test]
async fn t09_wrong_server_secret_refuses_to_start() {
    // `opaque_server_setup` now holds the real OPAQUE setup (loaded
    // on start), so this test writes its own row.
    let db = db_or_skip!(TestDb::migrated());
    let state = prepare_with_pool(config(&[]), db.pool.clone(), false)
        .await
        .unwrap();
    state
        .secrets()
        .put(state.db(), "test_secret_row", b"server-setup-bytes")
        .await
        .unwrap();
    assert_eq!(
        state
            .secrets()
            .get(state.db(), "test_secret_row")
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        b"server-setup-bytes"
    );
    // Stored values are not plaintext.
    let raw: Vec<u8> = sqlx_core::query_scalar::query_scalar(
        "SELECT value_enc FROM server_secrets WHERE name = 'test_secret_row'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(!raw.windows(18).any(|w| w == b"server-setup-bytes"));

    // Same secret: restarts fine.
    prepare_with_pool(
        config(&[("SVERB_SERVER_SECRET", SECRET_A)]),
        db.pool.clone(),
        false,
    )
    .await
    .unwrap();
    // Another secret: refuses, with the documented message.
    let err = prepare_with_pool(
        config(&[("SVERB_SERVER_SECRET", SECRET_B)]),
        db.pool.clone(),
        false,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, StartupError::Secrets(_)), "{msg}");
    assert!(msg.contains("SVERB_SERVER_SECRET"), "{msg}");
    assert!(msg.contains("backed up and restored together"), "{msg}");
    db.cleanup().await;
}

#[tokio::test]
async fn t10_bootstrap_setup_token_makes_instance_admin_once() {
    let db = db_or_skip!(TestDb::migrated());
    let logs = Captured::start();
    let state = prepare_with_pool(config(&[]), db.pool.clone(), false)
        .await
        .unwrap();

    let text = logs.text();
    let line = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["fields"]["setup_token"].is_string())
        .unwrap_or_else(|| panic!("no setup token logged: {text}"));
    assert_eq!(line["level"], "WARN");
    let token = line["fields"]["setup_token"].as_str().unwrap().to_owned();

    let app = test_app(state);
    // Without the token, invite-only mode forbids registration.
    let (st, v) = post_register(&app, serde_json::json!({ "email": "x@example.test" })).await;
    assert_eq!(
        (st, v["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );

    let (st, v) = post_register(
        &app,
        serde_json::json!({ "email": "admin@example.test", "setup_token": token }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["is_instance_admin"], true);

    // Single use.
    let (st, v) = post_register(
        &app,
        serde_json::json!({ "email": "second@example.test", "setup_token": token }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "forbidden");
    assert!(
        settings::get(&db.pool, settings::SETUP_TOKEN_HASH)
            .await
            .unwrap()
            .is_none()
    );
    // Users exist now: no new token on restart.
    assert!(registration::bootstrap(&db.pool).await.unwrap().is_none());
    db.cleanup().await;
}

#[tokio::test]
async fn t11_registration_modes() {
    let db = db_or_skip!(TestDb::migrated());
    let cfg = config(&[]);
    let public_url = cfg.public_url.clone();
    let state = prepare_with_pool(cfg, db.pool.clone(), false)
        .await
        .unwrap();
    let app = test_app(state);

    // invite-only without an invite → forbidden; with an admin invite → ok, once.
    let (st, _) = post_register(&app, serde_json::json!({ "email": "a@example.test" })).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let inv = admin::invite::create(&db.pool, &public_url, "a@example.test")
        .await
        .unwrap();
    assert!(inv.link.starts_with("https://sync.example.test/invite/"));
    let (st, _) = post_register(
        &app,
        serde_json::json!({ "email": "b@example.test", "invite_token": inv.token }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "invite is bound to another email"
    );
    let (st, v) = post_register(
        &app,
        serde_json::json!({ "email": "A@Example.Test", "invite_token": inv.token }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["is_instance_admin"], false);
    let (st, _) = post_register(
        &app,
        serde_json::json!({ "email": "a2@example.test", "invite_token": inv.token }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "invite is single-use");

    // closed → forbidden, even with a valid invite.
    let inv = admin::invite::create(&db.pool, &public_url, "c@example.test")
        .await
        .unwrap();
    registration::set_mode(&db.pool, RegistrationMode::Closed)
        .await
        .unwrap();
    let (st, v) = post_register(
        &app,
        serde_json::json!({ "email": "c@example.test", "invite_token": inv.token }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(v["error"]["message"].as_str().unwrap().contains("closed"));

    // open → allowed without anything.
    registration::set_mode(&db.pool, RegistrationMode::Open)
        .await
        .unwrap();
    let (st, _) = post_register(&app, serde_json::json!({ "email": "d@example.test" })).await;
    assert_eq!(st, StatusCode::OK);
    db.cleanup().await;
}

async fn seed_user(db: &TestDb, email: &str, admin: bool, devices: usize) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    sqlx_core::query::query(
        "INSERT INTO users (id, email, created_at, is_instance_admin, opaque_record) \
         VALUES ($1, $2, now(), $3, '\\x00')",
    )
    .bind(id)
    .bind(email)
    .bind(admin)
    .execute(&db.pool)
    .await
    .unwrap();
    for i in 0..devices {
        let dev = uuid::Uuid::now_v7();
        sqlx_core::query::query(
            "INSERT INTO devices (id, user_id, name, platform, created_at) VALUES ($1, $2, $3, 'linux', now())",
        )
        .bind(dev)
        .bind(id)
        .bind(format!("dev{i}"))
        .execute(&db.pool)
        .await
        .unwrap();
        for (kind, expires) in [
            ("access", "now() + interval '15 minutes'"),
            ("refresh", "now() - interval '1 day'"),
        ] {
            sqlx_core::query::query(&format!(
                "INSERT INTO auth_tokens (token_hash, device_id, kind, expires_at, family) \
                 VALUES ($1, $2, $3, {expires}, $4)"
            ))
            .bind(uuid::Uuid::now_v7().as_bytes().to_vec())
            .bind(dev)
            .bind(kind)
            .bind(uuid::Uuid::now_v7())
            .execute(&db.pool)
            .await
            .unwrap();
        }
    }
    id
}

#[tokio::test]
async fn t12_admin_user_list_disable_and_gc() {
    let db = db_or_skip!(TestDb::migrated());
    seed_user(&db, "root@example.test", true, 2).await;
    seed_user(&db, "bob@example.test", false, 1).await;

    let users = admin::user::list(&db.pool).await.unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(
        (
            users[0].email.as_str(),
            users[0].is_instance_admin,
            users[0].devices,
            users[0].disabled
        ),
        ("root@example.test", true, 2, false)
    );
    assert_eq!(
        (users[1].email.as_str(), users[1].devices),
        ("bob@example.test", 1)
    );

    let out = admin::user::disable(&db.pool, "BOB@example.test")
        .await
        .unwrap();
    assert_eq!(out.tokens_revoked, 2);
    let users = admin::user::list(&db.pool).await.unwrap();
    assert!(users[1].disabled);
    assert!(matches!(
        admin::user::disable(&db.pool, "nobody@example.test").await,
        Err(admin::AdminError::NoSuchUser(_))
    ));

    let report = admin::gc::run(&db.pool, &config(&[])).await.unwrap();
    assert_eq!(report.expired_tokens, 2); // root's two expired refresh tokens

    // The real binary against the same database.
    let bin = env!("CARGO_BIN_EXE_sverb-server");
    let run = |args: &[&str]| {
        std::process::Command::new(bin)
            .args(args)
            .env("DATABASE_URL", &db.url)
            .env("SVERB_SERVER_SECRET", SECRET_A)
            .env("SVERB_PUBLIC_URL", "https://sync.example.test")
            .env_remove("SVERB_SERVER_CONFIG")
            .output()
            .unwrap()
    };
    let out = run(&["admin", "user", "list"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("root@example.test") && stdout.contains("bob@example.test"),
        "{stdout}"
    );
    let out = run(&["admin", "user", "disable", "root@example.test"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(admin::user::list(&db.pool).await.unwrap()[0].disabled);
    let out = run(&["admin", "user", "disable", "ghost@example.test"]);
    assert!(!out.status.success());
    let out = run(&["admin", "invite", "new@example.test"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("https://sync.example.test/invite/"));
    let out = run(&["admin", "registration", "closed"]);
    assert!(out.status.success());
    assert_eq!(
        settings::get(&db.pool, settings::REGISTRATION_MODE)
            .await
            .unwrap()
            .as_deref(),
        Some("closed")
    );
    let out = run(&["admin", "gc"]);
    assert!(out.status.success());
    db.cleanup().await;
}

#[test]
fn cli_surface_parses() {
    use clap::Parser;
    use sverb_server::cli::Cli;
    for args in [
        &["sverb-server", "serve"][..],
        &["sverb-server", "serve", "--migrate"],
        &["sverb-server", "migrate"],
        &["sverb-server", "admin", "user", "create", "a@b.c"],
        &["sverb-server", "admin", "user", "disable", "a@b.c"],
        &["sverb-server", "admin", "user", "list"],
        &["sverb-server", "admin", "registration", "open"],
        &["sverb-server", "admin", "registration", "invite-only"],
        &["sverb-server", "admin", "registration", "closed"],
        &["sverb-server", "admin", "gc"],
        &["sverb-server", "admin", "invite", "a@b.c"],
        &["sverb-server", "healthcheck"],
        &[
            "sverb-server",
            "--config",
            "x.toml",
            "healthcheck",
            "--addr",
            "127.0.0.1:8080",
        ],
    ] {
        Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
    }
    assert!(Cli::try_parse_from(["sverb-server", "admin", "registration", "sometimes"]).is_err());
}

#[test]
fn binary_refuses_to_start_without_secret() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sverb-server"))
        .args(["serve"])
        .env_remove("SVERB_SERVER_SECRET")
        .env_remove("SVERB_SERVER_CONFIG")
        .env("SVERB_PUBLIC_URL", "https://sync.example.test")
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("SVERB_SERVER_SECRET is required"));
}
