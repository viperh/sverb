//! M1-18 harness self-tests against OpenSSH in Docker (T-01…T-05, T-07).
//!
//! `#[ignore]`d: run with `SVERB_E2E=1 cargo test -p sverb-e2e -- --ignored`. Without
//! `SVERB_E2E=1` or a Docker daemon they print a skip message and pass (on CI a
//! missing daemon fails). T-06 (`PtyApp`) needs no container: `harness_local.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use sverb_e2e::{
    Headless, JumpNet, Login, Profile, Sshd, diag, require_docker, ssh_key_file_type, timeout,
};

/// T-01: `exec` runs as the user `test`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t01_exec_whoami() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let out = sshd.exec("whoami").await.unwrap();
    assert!(out.success(), "{out:?}");
    assert_eq!(out.stdout.trim(), "test");
    let out = sshd.exec("exit 3").await.unwrap();
    assert_eq!(out.code, 3, "{out:?}");
    let root = sshd.exec_root("id -u").await.unwrap();
    assert_eq!(root.stdout.trim(), "0");
}

/// T-02: `Headless` logs in with a password and sees the shell prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t02_headless_password() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let mut session = Headless::connect(Login::sshd_password(&sshd));
    session.wait_connected().await.unwrap();
    session.wait_for_text("$", timeout()).await.unwrap();
    session.send("echo sverb-$((6*7))\r").await;
    session.wait_for_text("sverb-42", timeout()).await.unwrap();
    session.close().await;
}

/// T-03: `pause` freezes sshd (no banner), `unpause` brings it back, and an open
/// session continues afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t03_pause_unpause() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let mut session = Headless::connect(Login::sshd_password(&sshd));
    session.wait_for_text("$", timeout()).await.unwrap();

    sshd.pause().await.unwrap();
    assert!(!sshd.probe().await, "a paused sshd must not answer");
    session.send("echo after-$((1+1))\r").await;
    let err = session
        .wait_for_text("after-2", Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(err.0.contains("not on screen"), "{err}");

    sshd.unpause().await.unwrap();
    assert!(sshd.probe().await, "sshd answers again");
    session.wait_for_text("after-2", timeout()).await.unwrap();
    session.close().await;
}

/// The fingerprint the client saw, and the server-side fingerprint of the same key.
async fn seen_and_served(sshd: &Sshd) -> (String, String) {
    let mut session = Headless::connect(Login::sshd_password(sshd));
    session.wait_connected().await.unwrap();
    let seen = session.host_keys().pop().expect("a host key was presented");
    session.close().await;
    let file_type = ssh_key_file_type(&seen.key_type).expect("known host key type");
    let served = sshd.host_fingerprint(file_type).await.unwrap();
    (seen.fingerprint, served)
}

/// T-04: `regenerate_host_key` changes the fingerprint the client sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t04_regenerate_host_key() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let (before, served) = seen_and_served(&sshd).await;
    assert_eq!(before, served);
    let keys_before = sshd.host_keys().await.unwrap();

    let keys_after = sshd.regenerate_host_key().await.unwrap();
    assert_ne!(keys_before, keys_after);
    let (after, served) = seen_and_served(&sshd).await;
    assert_eq!(after, served);
    assert_ne!(before, after, "the host fingerprint changed");
}

/// T-05: the inner host of a `JumpNet` is not reachable from the runner, but is
/// from the bastion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t05_jumpnet_inner_only_via_bastion() {
    require_docker!();
    let net = JumpNet::start().await.unwrap();
    let (inner, port) = net.inner_addr_from_bastion();

    // Not published, and its name does not resolve (or connect) from the runner.
    assert!(net.inner.socket_addr().is_none());
    let direct = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect((inner.as_str(), port)),
    )
    .await;
    assert!(
        !matches!(direct, Ok(Ok(_))),
        "{inner}:{port} must not be reachable from the runner"
    );

    let out = net
        .bastion
        .exec(&format!("nc -z -w 3 {inner} {port}"))
        .await
        .unwrap();
    assert!(out.success(), "bastion → inner: {out:?}");
    // The bastion itself is reachable from the runner.
    let mut session = Headless::connect(Login::sshd_password(&net.bastion));
    session.wait_for_text("$", timeout()).await.unwrap();
    session.close().await;
}

/// T-07: a failing test dumps the container logs and the screen.
#[test]
#[ignore = "needs Docker (SVERB_E2E=1)"]
fn t07_failure_dumps_container_logs_and_screen() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    if let Some(reason) = rt.block_on(sverb_e2e::docker_skip_reason()) {
        eprintln!("skipped: {reason}");
        return;
    }
    let (result, dumps) = diag::capture(|| {
        rt.block_on(async {
            let sshd = Sshd::start(Profile::Password).await.unwrap();
            let mut session = Headless::connect(Login::sshd_password(&sshd));
            session.wait_for_text("$", timeout()).await.unwrap();
            session.send("echo marker-$((40+2))\r").await;
            session.wait_for_text("marker-42", timeout()).await.unwrap();
            panic!("deliberate failure");
        });
    });
    let payload = result.unwrap_err();
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .unwrap_or_default();
    assert_eq!(msg, "deliberate failure");
    let all = dumps.join("\n");
    assert!(all.contains("docker logs"), "{all}");
    assert!(
        all.contains("Server listening"),
        "sshd's log is in the dump: {all}"
    );
    assert!(all.contains("headless session"), "{all}");
    assert!(
        all.contains("marker-42"),
        "the screen is in the dump: {all}"
    );
}
