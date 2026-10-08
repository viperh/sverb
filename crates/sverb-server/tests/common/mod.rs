//! Shared helpers for sverb-server integration tests.
//!
//! Database tests need PostgreSQL 15+: set `DATABASE_URL` to a role that may
//! `CREATE DATABASE` (CI's `server-db` job does). Each test gets its own
//! throw-away database. Without `DATABASE_URL` they print a skip notice and
//! pass.
#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx_core::executor::Executor;
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sverb_server::{AppState, Config};
use tower::ServiceExt;

/// 32 bytes of hex: a valid server secret.
pub const SECRET_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
/// A different valid server secret.
pub const SECRET_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// The metrics token used by tests.
pub const METRICS_TOKEN: &str = "metrics-token-for-tests";

/// A config from the given env pairs on top of a valid baseline.
pub fn config(extra: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        ("SVERB_SERVER_SECRET".into(), SECRET_A.into()),
        (
            "SVERB_PUBLIC_URL".into(),
            "https://sync.example.test".into(),
        ),
    ]);
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    Config::from_sources(None, |k| env.get(k).cloned()).expect("valid test config")
}

/// State on a lazy pool that points nowhere (for tests that never query).
pub fn lazy_state(cfg: Config) -> AppState {
    let pool = sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable")
        .expect("lazy pool");
    AppState::new(cfg, pool)
}

/// A request with a fake TCP peer address.
pub fn req(method: &str, uri: &str, peer: &str) -> axum::http::request::Builder {
    let peer: SocketAddr = peer.parse().unwrap();
    let mut b = Request::builder().method(method).uri(uri);
    b.extensions_mut().unwrap().insert(ConnectInfo(peer));
    b
}

/// Sends one request through the router.
pub async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

/// Parses a JSON body.
pub fn json(body: &Bytes) -> serde_json::Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(body)))
}

/// A throw-away database.
pub struct TestDb {
    pub pool: PgPool,
    pub url: String,
    name: String,
    admin_url: String,
}

/// Creates a fresh, empty (unmigrated) database, or `None` when
/// `DATABASE_URL` is unset.
pub async fn fresh_db() -> Option<TestDb> {
    let admin_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let name = format!("sverb_test_{}", uuid::Uuid::now_v7().simple());
    let admin = PgPool::connect(&admin_url)
        .await
        .expect("DATABASE_URL is set but the database is unreachable");
    admin
        .execute(format!("CREATE DATABASE \"{name}\"").as_str())
        .await
        .expect("CREATE DATABASE (the DATABASE_URL role needs CREATEDB)");
    admin.close().await;
    let opts = PgConnectOptions::from_str(&admin_url)
        .unwrap()
        .database(&name);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .unwrap();
    let url = match admin_url.rsplit_once('/') {
        Some((base, rest)) if !base.ends_with('/') => {
            let query = rest
                .split_once('?')
                .map(|(_, q)| format!("?{q}"))
                .unwrap_or_default();
            format!("{base}/{name}{query}")
        }
        _ => format!("{admin_url}/{name}"),
    };
    Some(TestDb {
        pool,
        url,
        name,
        admin_url,
    })
}

impl TestDb {
    /// A freshly migrated database.
    pub async fn migrated() -> Option<Self> {
        let db = fresh_db().await?;
        sverb_server::db::migrate(&db.pool).await.unwrap();
        Some(db)
    }

    /// Drops the database.
    pub async fn cleanup(self) {
        self.pool.close().await;
        if let Ok(admin) = PgPool::connect(&self.admin_url).await {
            let _ = admin
                .execute(format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.name).as_str())
                .await;
            admin.close().await;
        }
    }
}

/// `let db = db_or_skip!(fresh_db());` returns early with a notice when
/// `DATABASE_URL` is unset.
#[macro_export]
macro_rules! db_or_skip {
    ($e:expr) => {
        match $e.await {
            Some(db) => db,
            None => {
                eprintln!("SKIPPED (needs PostgreSQL): set DATABASE_URL to run this database test");
                return;
            }
        }
    };
}
