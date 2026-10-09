//! versions of the same checks run without Docker in `sverb-conn`'s `ssh::tests`.
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_transport -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use sverb_conn::{DisconnectReason, SessionEvent, SessionState};
use sverb_core::model::AlgoOverrides;
use sverb_e2e::{Headless, Login, Profile, Sshd, require_docker, timeout};

fn env_login(sshd: &Sshd) -> Login {
    Login {
        env: vec![("FOO".into(), "bar".into()), ("BAR".into(), "nope".into())],
        ..Login::sshd_password(sshd)
    }
}

/// T-08 connect + shell, T-09 env (`BAR` rejected without an error), T-10 resize,
/// T-15 stderr, T-11 exit status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t08_to_t11_t15_session() {
    require_docker!();
    let sshd = Sshd::start(Profile::Env).await.unwrap();
    let mut s = Headless::connect(env_login(&sshd));
    s.wait_connected().await.unwrap();
    s.wait_for_text("$", timeout()).await.unwrap();

    // The PTY's TERM.
    s.send("echo T=$TERM\r").await;
    s.wait_for_text("T=xterm-256color", timeout())
        .await
        .unwrap();

    // FOO accepted, BAR rejected, and no error event for it.
    s.send("echo F=$FOO B=${BAR:-unset}\r").await;
    s.wait_for_text("F=bar B=unset", timeout()).await.unwrap();
    assert!(
        !s.events()
            .iter()
            .any(|e| matches!(e, SessionEvent::Error(_))),
        "{:?}",
        s.events()
    );

    // Resize reaches the remote PTY.
    s.send("stty size\r").await;
    s.wait_for_text("24 80", timeout()).await.unwrap();
    s.resize(100, 30).await;
    s.send("stty size\r").await;
    s.wait_for_text("30 100", timeout()).await.unwrap();

    // Stderr reaches the pane.
    s.send("ls /nonexistent\r").await;
    s.wait_for_text("No such file or directory", timeout())
        .await
        .unwrap();

    // `exit 7` → Disconnected { Exited(7) }.
    s.send("exit 7\r").await;
    let state = s
        .wait_state("Disconnected", |st| {
            matches!(st, SessionState::Disconnected { .. })
        })
        .await
        .unwrap();
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Exited(7),
                ..
            }
        ),
        "{state:?}"
    );
    s.close().await;
}

/// T-12 keepalive timeout (`docker pause`) and T-13 latency events.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t12_t13_keepalive() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let mut s = Headless::connect(Login {
        keepalive_secs: Some(1),
        ..Login::sshd_password(&sshd)
    });
    s.wait_connected().await.unwrap();

    // Within 2 × keepalive.
    let t0 = Instant::now();
    s.wait_event("Latency", |e| matches!(e, SessionEvent::Latency(_)))
        .await
        .unwrap();
    assert!(t0.elapsed() <= Duration::from_secs(2), "{:?}", t0.elapsed());

    // T-12.
    sshd.pause().await.unwrap();
    let t0 = Instant::now();
    let state = s
        .wait_state("Disconnected", |st| {
            matches!(st, SessionState::Disconnected { .. })
        })
        .await
        .unwrap();
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Timeout,
                ..
            }
        ),
        "{state:?}"
    );
    assert!(t0.elapsed() < Duration::from_secs(7), "{:?}", t0.elapsed());
    sshd.unpause().await.unwrap();
    s.close().await;
}

/// A legacy-only server → `Negotiation` naming the algorithm; with the host
/// opt-in → connects with the legacy algorithms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t14_legacy_only_server() {
    require_docker!();
    let sshd = Sshd::start(Profile::Legacy).await.unwrap();
    let mut s = Headless::connect(Login::sshd_password(&sshd));
    let state = s
        .wait_state("Disconnected", |st| {
            matches!(
                st,
                SessionState::Disconnected { .. } | SessionState::Connected { .. }
            )
        })
        .await
        .unwrap();
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Negotiation,
                ..
            }
        ),
        "{state:?}"
    );
    let err = s
        .events()
        .iter()
        .find_map(|e| match e {
            SessionEvent::Error(r) => Some(r.short.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert!(err.contains("diffie-hellman-group14-sha1"), "{err}");
    s.close().await;

    let mut s = Headless::connect(Login {
        algorithms: Some(AlgoOverrides {
            kex: Some(vec!["diffie-hellman-group14-sha1".into()]),
            host_key: Some(vec!["ssh-rsa".into()]),
            cipher: Some(vec!["aes128-cbc".into()]),
            mac: Some(vec!["hmac-sha1".into()]),
            ..AlgoOverrides::default()
        }),
        ..Login::sshd_password(&sshd)
    });
    s.wait_connected().await.unwrap();
    let info = s
        .events()
        .iter()
        .find_map(|e| match e {
            SessionEvent::SshInfo(i) => Some(i.clone()),
            _ => None,
        })
        .expect("SshInfo");
    assert_eq!(info.kex, "diffie-hellman-group14-sha1");
    assert_eq!(info.cipher, "aes128-cbc");
    assert!(info.server_version.contains("OpenSSH"), "{info:?}");
    s.wait_for_text("$", timeout()).await.unwrap();
    s.close().await;
}

/// The startup snippet is typed after the first output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t16_startup_input() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let mut s = Headless::connect(Login {
        startup_input: Some("echo started-$((20+3))\r".into()),
        ..Login::sshd_password(&sshd)
    });
    s.wait_for_text("started-23", timeout()).await.unwrap();
    s.close().await;
}
