//! M7-04 T-06: the sync checks of `sverb doctor` against the in-process
//! `sverb-server` (in-memory backend) on loopback. The exit-code half (✗ → exit 1)
//! is tested in `crates/sverb/src/cli/doctor_tests.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{TestServer, first_device};
use sverb_sync::doctor::{ProbeLevel, ProbeOptions, probe};
use sverb_sync::tokens::peek_access;

fn opts() -> ProbeOptions {
    ProbeOptions {
        timeout: Duration::from_secs(5),
        tls: None,
    }
}

fn levels(checks: &[sverb_sync::doctor::ProbeCheck]) -> Vec<(&'static str, ProbeLevel)> {
    checks.iter().map(|c| (c.id, c.level)).collect()
}

#[tokio::test]
async fn t06_sync_checks_ok_then_server_down() {
    let server = TestServer::start().await;
    let (_account, dev) = first_device(&server, "doctor@example.test").await;
    let (token, expires) = peek_access(&dev.store, &dev.lmk).await.unwrap().unwrap();
    assert!(expires > dev.store.now(), "fresh token");

    let checks = probe(&server.url(), Ok(token.as_str()), &opts()).await;
    // The in-memory test server has no PostgreSQL behind it (its lazy pool points
    // at a closed port), so /readyz is "not ready" or times out: a warning, not a
    // failure.
    assert_eq!(
        levels(&checks),
        vec![
            ("server", ProbeLevel::Ok),
            ("protocol", ProbeLevel::Ok),
            ("readiness", ProbeLevel::Warn),
            ("clock", ProbeLevel::Ok),
            ("token", ProbeLevel::Ok),
            ("websocket", ProbeLevel::Ok),
        ],
        "{checks:#?}"
    );
    assert!(
        checks[2].detail.contains("not ready") || checks[2].detail.contains("/readyz failed"),
        "{checks:#?}"
    );

    // Peeking never refreshed (no rotation), so the same token is still stored.
    let (again, _) = peek_access(&dev.store, &dev.lmk).await.unwrap().unwrap();
    assert_eq!(*again, *token);

    // A rejected token: ✗, and the WebSocket check is skipped.
    let checks = probe(&server.url(), Ok("not-a-token"), &opts()).await;
    let token_check = checks.iter().find(|c| c.id == "token").unwrap();
    assert_eq!(token_check.level, ProbeLevel::Fail, "{checks:#?}");
    assert_eq!(checks.last().unwrap().level, ProbeLevel::Skip);

    // Not signed in: the authenticated checks are skipped with the reason.
    let checks = probe(&server.url(), Err("not signed in".into()), &opts()).await;
    assert_eq!(checks.last().unwrap().detail, "not signed in");

    // Server down: one ✗ line.
    server.stop().await;
    let checks = probe(&server.url(), Ok(token.as_str()), &opts()).await;
    assert_eq!(
        levels(&checks),
        vec![("server", ProbeLevel::Fail)],
        "{checks:#?}"
    );
    assert!(checks[0].detail.contains("unreachable"), "{checks:#?}");
}

#[tokio::test]
async fn non_https_urls_are_refused_without_a_request() {
    let checks = probe("http://sync.example.test", Err("x".into()), &opts()).await;
    assert_eq!(levels(&checks), vec![("server", ProbeLevel::Fail)]);
    assert!(checks[0].detail.contains("https://"), "{checks:#?}");
}
