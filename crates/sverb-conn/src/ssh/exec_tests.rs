//! M2-04 loopback tests: exec channels (T-02…T-05), install key (T-06…T-09) and the
//! concurrency cap (T-11) against the in-process exec server
//! ([`exec_testing`](super::exec_testing)). The Docker variants are in
//! `sverb-e2e/tests/openssh_exec.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    os::unix::fs::PermissionsExt as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use super::{
    InsecureAcceptAnyHostKey, SshConnector,
    exec::{
        DEFAULT_CONCURRENCY, ExecOpts, ExecPrompts, OUTPUT_CAP, SshConnection, TIMEOUT_SIGNAL,
        exec, for_each_concurrent,
    },
    exec_testing::{ExecResolver, ExecServerOpts, TempHome, start_exec_server},
    install_key::{InstallOutcome, UNSUPPORTED, install_command, install_on},
    test_keys,
};
use crate::session::{AuthAnswer, PromptKind, SessionCmd, SessionEvent, SessionId, SshSpec};

fn connector(resolver: ExecResolver) -> SshConnector {
    SshConnector::new(Arc::new(resolver))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
}

fn spec() -> SshSpec {
    SshSpec {
        host: "exec".into(),
        label: Some("db-1".into()),
        ..SshSpec::default()
    }
}

async fn server(posix: bool) -> (TempHome, std::net::SocketAddr) {
    let home = TempHome::new();
    let (addr, _) = start_exec_server(ExecServerOpts {
        home: home.0.clone(),
        posix,
    })
    .await;
    (home, addr)
}

async fn open(resolver: ExecResolver) -> SshConnection {
    SshConnection::open(&connector(resolver), &spec(), ExecPrompts::none())
        .await
        .expect("connects")
}

fn secs(n: u64) -> ExecOpts {
    ExecOpts::with_timeout(Duration::from_secs(n))
}

/// T-02: stdout, stderr and the exit status.
#[tokio::test]
async fn t02_exec_basic() {
    let (_home, addr) = server(true).await;
    let conn = open(ExecResolver::password(addr)).await;
    let r = exec(&conn, "echo hi; echo err >&2; exit 3", secs(10))
        .await
        .unwrap();
    assert_eq!(&r.stdout[..], b"hi\n");
    assert_eq!(&r.stderr[..], b"err\n");
    assert_eq!(r.exit, Some(3));
    assert_eq!(r.signal, None);
    assert!(!r.truncated);
    // stdin is passed through, then EOF.
    let r = exec(
        &conn,
        "cat",
        ExecOpts {
            stdin: Some(bytes::Bytes::from_static(b"piped")),
            ..secs(10)
        },
    )
    .await
    .unwrap();
    assert_eq!(&r.stdout[..], b"piped");
    assert_eq!(r.exit, Some(0));
    conn.close().await;
}

/// T-03: 1 MiB kept, `truncated`, and the command still completes.
#[tokio::test]
async fn t03_output_cap() {
    let (_home, addr) = server(true).await;
    let conn = open(ExecResolver::password(addr)).await;
    let r = exec(&conn, "head -c 3000000 /dev/zero", secs(30))
        .await
        .unwrap();
    assert_eq!(r.stdout.len(), OUTPUT_CAP);
    assert!(r.truncated);
    assert_eq!(r.exit, Some(0));
    conn.close().await;
}

/// T-04: the timeout sends TERM; the result says so within about 3 s.
#[tokio::test]
async fn t04_timeout() {
    let (_home, addr) = server(true).await;
    let conn = open(ExecResolver::password(addr)).await;
    let started = Instant::now();
    let r = exec(&conn, "sleep 100", secs(1)).await.unwrap();
    let took = started.elapsed();
    assert_eq!(r.signal.as_deref(), Some(TIMEOUT_SIGNAL));
    assert_eq!(r.exit, None);
    assert!(r.timed_out());
    assert!(took < Duration::from_millis(3500), "{took:?}");
    conn.close().await;
}

/// T-05: with a PTY both streams end up in stdout.
#[tokio::test]
async fn t05_pty_merge() {
    let (_home, addr) = server(true).await;
    let conn = open(ExecResolver::password(addr)).await;
    let r = exec(
        &conn,
        "echo a; echo b >&2",
        ExecOpts {
            request_pty: Some(true),
            ..secs(10)
        },
    )
    .await
    .unwrap();
    let out = String::from_utf8_lossy(&r.stdout);
    assert!(out.contains('a') && out.contains('b'), "{out:?}");
    assert!(r.stderr.is_empty());
    // The host's `request_pty_for_exec` applies when the run doesn't say.
    let conn2 = open(ExecResolver {
        request_pty_for_exec: true,
        ..ExecResolver::password(addr)
    })
    .await;
    let r = exec(&conn2, "echo c >&2", secs(10)).await.unwrap();
    assert!(r.stderr.is_empty());
    assert!(String::from_utf8_lossy(&r.stdout).contains('c'));
    conn.close().await;
    conn2.close().await;
}

async fn install(addr: std::net::SocketAddr, public: &str) -> InstallOutcome {
    let conn = open(ExecResolver::password(addr)).await;
    let out = install_on(
        &conn,
        &install_command(public).unwrap(),
        Duration::from_secs(10),
    )
    .await;
    conn.close().await;
    out
}

/// T-06: installed, then already present, then key auth works.
#[tokio::test]
async fn t06_install_key() {
    let (home, addr) = server(true).await;
    assert_eq!(
        install(addr, test_keys::ED25519_PUB).await,
        InstallOutcome::Installed
    );
    assert_eq!(
        install(addr, test_keys::ED25519_PUB).await,
        InstallOutcome::AlreadyPresent
    );
    let text = std::fs::read_to_string(home.0.join(".ssh/authorized_keys")).unwrap();
    assert_eq!(text, format!("{}\n", test_keys::ED25519_PUB));
    // Key-only login (no password stored) now works.
    let conn = open(ExecResolver {
        password: None,
        key: Some(test_keys::ED25519.to_owned()),
        ..ExecResolver::password(addr)
    })
    .await;
    let r = exec(&conn, "echo ok", secs(10)).await.unwrap();
    assert_eq!(&r.stdout[..], b"ok\n");
    conn.close().await;
}

/// T-07: a comment with a quote (`bob's key`) installs exactly.
#[tokio::test]
async fn t07_quote_in_comment() {
    let (home, addr) = server(true).await;
    let line = test_keys::ED25519_PUB.replace("plain@test", "bob's key");
    assert_eq!(install(addr, &line).await, InstallOutcome::Installed);
    assert_eq!(install(addr, &line).await, InstallOutcome::AlreadyPresent);
    let text = std::fs::read_to_string(home.0.join(".ssh/authorized_keys")).unwrap();
    assert_eq!(text, format!("{line}\n"));
}

/// T-08: a Windows-like server is reported as unsupported.
#[tokio::test]
async fn t08_windows_like() {
    let (home, addr) = server(false).await;
    let out = install(addr, test_keys::ED25519_PUB).await;
    assert_eq!(out, InstallOutcome::Unsupported);
    assert_eq!(out.text(), UNSUPPORTED);
    assert!(!home.0.join(".ssh").exists());
}

/// T-09: `~/.ssh` is 700 and `authorized_keys` 600 (umask 077).
#[tokio::test]
async fn t09_permissions() {
    let (home, addr) = server(true).await;
    assert_eq!(
        install(addr, test_keys::ED25519_PUB).await,
        InstallOutcome::Installed
    );
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&home.0.join(".ssh")), 0o700);
    assert_eq!(mode(&home.0.join(".ssh/authorized_keys")), 0o600);
}

/// Prompts surface as session events under the run's id; answers come back as
/// commands.
#[tokio::test]
async fn password_prompt_goes_through_exec_prompts() {
    let (_home, addr) = server(true).await;
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<(SessionId, SessionEvent)>();
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let prompts = ExecPrompts {
        id: SessionId(77),
        events: Arc::new(ev_tx),
        answers: cmd_rx,
    };
    let conn = connector(ExecResolver {
        password: None,
        ..ExecResolver::password(addr)
    });
    let task = tokio::spawn(async move { SshConnection::open(&conn, &spec(), prompts).await });
    loop {
        let (id, ev) = ev_rx.recv().await.expect("a prompt");
        assert_eq!(id, SessionId(77));
        if let SessionEvent::Prompt(p) = ev {
            assert!(matches!(p.kind, PromptKind::Password { .. }), "{p:?}");
            cmd_tx
                .send(SessionCmd::AuthAnswer(AuthAnswer::Responses(vec![
                    "secret".into(),
                ])))
                .await
                .unwrap();
            break;
        }
    }
    let conn = task.await.unwrap().expect("authenticated");
    assert_eq!(
        &exec(&conn, "echo yes", secs(10)).await.unwrap().stdout[..],
        b"yes\n"
    );
    conn.close().await;
}

/// Without a way to answer, a prompt fails the connection (non-interactive use).
#[tokio::test]
async fn no_prompts_fails_cleanly() {
    let (_home, addr) = server(true).await;
    let res = SshConnection::open(
        &connector(ExecResolver {
            password: None,
            ..ExecResolver::password(addr)
        }),
        &spec(),
        ExecPrompts::none(),
    )
    .await;
    assert!(res.is_err());
}

/// T-11: 25 targets, never more than 10 in flight.
#[tokio::test]
async fn t11_concurrency_cap() {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    for_each_concurrent((0..25).collect::<Vec<u32>>(), DEFAULT_CONCURRENCY, |i| {
        let (in_flight, max, done) = (Arc::clone(&in_flight), Arc::clone(&max), Arc::clone(&done));
        async move {
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5 + u64::from(i % 3) * 5)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            done.fetch_add(1, Ordering::SeqCst);
        }
    })
    .await;
    assert_eq!(done.load(Ordering::SeqCst), 25);
    assert_eq!(max.load(Ordering::SeqCst), DEFAULT_CONCURRENCY);
}
