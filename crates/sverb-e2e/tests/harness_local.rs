//! Docker e2e harness self-tests that need no Docker: `Headless` against the in-process
//! russh server (`sverb_conn::ssh::testing`), `PtyApp` against the local `sverb`
//! binary, `TestHome`, and the failure diagnostics. The Docker variants are in
//! `harness_docker.rs` (`#[ignore]`d).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use sverb_conn::{SessionEvent, SessionState, ssh::testing::start_server};
use sverb_core::model::{Host, ItemKind};
use sverb_e2e::{Headless, Login, PtyApp, PtyOptions, TestHome, diag, keys::FixtureKey, timeout};

fn loopback_login(addr: std::net::SocketAddr) -> Login {
    Login {
        env: vec![("FOO".into(), "bar".into())],
        ..Login::password(addr.ip().to_string(), addr.port(), "sverb", "secret")
    }
}

/// T-02 (loopback): `Headless` connects with password auth and reads the grid; input
/// reaches the server and its answer shows up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_headless_password_loopback() {
    let (addr, seen) = start_server().await;
    let mut session = Headless::connect(loopback_login(addr));
    session.wait_connected().await.unwrap();
    session
        .wait_for_text("TERM=xterm-256color", timeout())
        .await
        .unwrap();
    session.wait_for_text("FOO=bar", timeout()).await.unwrap();
    session.send("hello\r").await;
    let grid = session.wait_for_text("out:hello", timeout()).await.unwrap();
    assert!(grid.contains("TERM=xterm-256color"), "{grid}");
    assert_eq!(seen.lock().users, ["sverb"]);
    // The default verifier recorded the server's host key.
    let keys = session.host_keys();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert_eq!(keys[0].key_type, "ssh-ed25519");
    assert!(keys[0].fingerprint.starts_with("SHA256:"), "{keys:?}");
    assert!(
        session
            .events()
            .iter()
            .any(|e| matches!(e, SessionEvent::SshInfo(_)))
    );
    session.close().await;
}

/// A wrong password ends in `Disconnected`, and `wait_connected` says so instead of
/// waiting for the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_wait_connected_fails_fast() {
    let (addr, _) = start_server().await;
    let login = Login {
        password: Some("wrong".into()),
        ..loopback_login(addr)
    };
    let mut session = Headless::connect(login);
    // The chain asks for a password once the stored one is rejected; cancel it.
    let prompt = session
        .wait_event("a password prompt or a disconnect", |e| {
            matches!(
                e,
                SessionEvent::Prompt(_)
                    | SessionEvent::State(SessionState::Disconnected { .. } | SessionState::Closed)
            )
        })
        .await
        .unwrap();
    if matches!(prompt, SessionEvent::Prompt(_)) {
        session
            .cmd(sverb_conn::SessionCmd::AuthAnswer(
                sverb_conn::AuthAnswer::Cancel,
            ))
            .await;
        let started = std::time::Instant::now();
        let err = session.wait_connected().await.unwrap_err();
        assert!(err.0.contains("expected Connected"), "{err}");
        assert!(err.0.contains("--- events ---"), "{err}");
        assert!(started.elapsed() < timeout(), "it did not fail fast");
    }
    assert!(
        !session
            .events()
            .iter()
            .any(|e| matches!(e, SessionEvent::State(SessionState::Connected { .. }))),
        "{:?}",
        session.events()
    );
    session.close().await;
}

/// `wait_for_text` times out with the screen and the events in the error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headless_wait_error_shows_the_screen() {
    let (addr, _) = start_server().await;
    let mut session = Headless::connect(loopback_login(addr));
    session.wait_for_text("FOO=bar", timeout()).await.unwrap();
    let err = session
        .wait_for_text("never printed", Duration::from_millis(200))
        .await
        .unwrap_err();
    assert!(err.0.contains("\"never printed\" not on screen"), "{err}");
    assert!(err.0.contains("FOO=bar"), "{err}");
    session.close().await;
}

/// T-07 (loopback): a failing test dumps the headless screen and events.
#[test]
#[should_panic(expected = "deliberate failure")]
fn t07_failure_dumps_headless_screen() {
    let (result, dumps) = diag::capture(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (addr, _) = start_server().await;
            let mut session = Headless::connect(loopback_login(addr));
            session.wait_for_text("FOO=bar", timeout()).await.unwrap();
            panic!("deliberate failure");
        });
    });
    let all = dumps.join("\n");
    assert!(all.contains("headless session"), "{all}");
    assert!(all.contains("FOO=bar"), "the screen is in the dump: {all}");
    assert!(
        all.contains("State(Connected"),
        "the events are in the dump: {all}"
    );
    std::panic::resume_unwind(result.unwrap_err());
}

/// `TestHome`: an initialized vault, items written through the item service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_home_writes_items() {
    let home = TestHome::new().await.unwrap();
    assert!(home.paths().db_file().exists());
    let host = home
        .add_host(Host {
            label: "e2e box".into(),
            address: "127.0.0.1".into(),
            port: Some(2222),
            username: Some("test".into()),
            ..Host::default()
        })
        .await
        .unwrap();
    let key = home
        .add_fixture_key(FixtureKey::Ed25519Encrypted)
        .await
        .unwrap();
    let known = home
        .trust_host_key("[127.0.0.1]:2222", FixtureKey::HostCa.public().as_str())
        .await
        .unwrap();
    let items = home.list(&[]).await.unwrap();
    let kinds: Vec<(sverb_core::model::ItemId, ItemKind)> =
        items.iter().map(|(id, b)| (*id, b.kind)).collect();
    assert!(kinds.contains(&(host, ItemKind::Host)), "{kinds:?}");
    assert!(kinds.contains(&(key, ItemKind::Key)), "{kinds:?}");
    assert!(kinds.contains(&(known, ItemKind::KnownHost)), "{kinds:?}");
    let dir = home.path().to_owned();
    drop(home);
    assert!(!dir.exists(), "the home is removed on drop");
}

#[cfg(unix)]
fn launch(home: &TestHome) -> PtyApp {
    PtyApp::launch(home, PtyOptions::default()).unwrap()
}

/// `PtyApp` launches the real binary, unlocks, sees the Hosts view, and
/// `ctrl-\ q` quits with exit code 0.
#[cfg(unix)]
#[test]
fn t06_pty_app_unlock_and_quit() {
    let home = TestHome::new_blocking().unwrap();
    let mut app = launch(&home);
    let screen = app.unlock().unwrap();
    assert!(screen.contains("Hosts"), "{screen}");
    app.send_keys("ctrl-\\ q").unwrap();
    let status = app.wait_exit().unwrap();
    assert_eq!(status.exit_code(), 0, "{status:?}");
    assert!(status.success());
}

/// `PtyApp` sees hosts written into the `TestHome` before the launch.
#[cfg(unix)]
#[test]
fn pty_app_shows_hosts_from_test_home() {
    let home = TestHome::new_blocking().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(home.add_host(Host {
            label: "fixture-bastion".into(),
            address: "192.0.2.10".into(),
            ..Host::default()
        }))
        .unwrap();
    let mut app = launch(&home);
    app.unlock().unwrap();
    app.wait_for_text("fixture-bastion").unwrap();
    app.send_keys("ctrl-\\ q").unwrap();
    assert!(app.wait_exit().unwrap().success());
}

/// T-07 (PTY): a failing test dumps the last screen of the app.
#[cfg(unix)]
#[test]
#[should_panic(expected = "deliberate failure")]
fn t07_failure_dumps_pty_screen() {
    let home = TestHome::new_blocking().unwrap();
    let (result, dumps) = diag::capture(|| {
        let mut app = launch(&home);
        app.unlock().unwrap();
        panic!("deliberate failure");
    });
    let all = dumps.join("\n");
    assert!(all.contains("sverb screen"), "{all}");
    assert!(all.contains("Hosts"), "the screen is in the dump: {all}");
    // Dropped outside the panic, so the home is removed rather than kept for debugging.
    drop(home);
    std::panic::resume_unwind(result.unwrap_err());
}
