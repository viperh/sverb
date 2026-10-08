//! M2-08 T-19: `sverb forward <rule>` on a PTY prints the listening line, the forward
//! works until SIGINT (Ctrl-C), and `--detach` returns with a pid file while the
//! background process keeps forwarding.
//!
//! The SSH server is the in-process russh test server (`sverb_conn::ssh::testing`,
//! loopback only); the vault is seeded directly (host + rule). The OS keyring is
//! disabled (`SVERB_KEYRING=off`) and the vault is unlocked on the PTY; host keys are
//! accepted with the development switch `SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1`.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener as StdListener, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault, unique_home};
use portable_pty::CommandBuilder;
use sverb_core::{
    model::{ForwardKind, Host, ItemKind, PortForward},
    paths::{MapEnv, Paths},
    secret::SecretString,
};
use sverb_tui::services::vault::{VaultEngine, items::ItemOps};

fn paths(home: &Path) -> Paths {
    Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A loopback service answering `hello:<request>` after the request's EOF.
async fn service() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut req = Vec::new();
                let _ = s.read_to_end(&mut req).await;
                let mut resp = b"hello:".to_vec();
                resp.extend_from_slice(&req);
                let _ = s.write_all(&resp).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Seed a host (the test server, password auth) and a Local rule `db` to `svc`.
async fn seed(home: &Path, server: SocketAddr, bind_port: u16, svc: SocketAddr) {
    let store = sverb_store::Store::open(&paths(home)).unwrap();
    let engine = VaultEngine::new(
        store,
        Arc::new(sverb_core::vault::NoKeyring),
        sverb_core::vault::Argon2Cost::TEST,
    );
    let vault = engine.unlock_with_password(TEST_PASSWORD).await.unwrap();
    let ops = ItemOps::new(engine, Arc::new(vault));
    let host = Host {
        label: "test-server".into(),
        address: server.ip().to_string(),
        port: Some(server.port()),
        username: Some("sverb".into()),
        password: Some(SecretString::from("secret")),
        ..Host::default()
    };
    let written = ops
        .save(ItemKind::Host, None, None, move |body, clock, device| {
            host.apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();
    let rule = PortForward {
        label: "db".into(),
        kind: ForwardKind::Local,
        host_id: written.id,
        bind_addr: "127.0.0.1".into(),
        bind_port,
        dest_host: Some("127.0.0.1".into()),
        dest_port: Some(svc.port()),
        auto_start: false,
        read_only: false,
    };
    ops.save(
        ItemKind::PortForward,
        None,
        None,
        move |body, clock, device| {
            rule.apply_to(body, clock, device);
            Ok(())
        },
    )
    .await
    .unwrap();
}

fn command(home: &Path, args: &[&str]) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.args(args);
    cmd.env("SVERB_HOME", home);
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("SVERB_INSECURE_ACCEPT_ANY_HOST_KEY", "1");
    cmd.env("TERM", "xterm-256color");
    cmd
}

fn roundtrip(port: u16, req: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(req).unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).unwrap();
    out
}

struct Setup {
    _rt: tokio::runtime::Runtime,
    home: std::path::PathBuf,
    bind_port: u16,
    svc: SocketAddr,
}

fn setup(tag: &str) -> Setup {
    let home = unique_home(tag);
    init_vault(&home);
    let rt = runtime();
    let (server, _seen) = rt.block_on(sverb_conn::ssh::testing::start_server());
    let svc = rt.block_on(service());
    let bind_port = free_port();
    rt.block_on(seed(&home, server, bind_port, svc));
    Setup {
        _rt: rt,
        home,
        bind_port,
        svc,
    }
}

/// T-19: the listening line, a working forward, and Ctrl-C stops it (exit 0).
#[test]
fn t19_forward_until_sigint() -> TestResult {
    let s = setup("forward");
    let mut run = PtyRun::spawn(command(&s.home, &["forward", "db"]))?;
    let at = run.wait_for("Master password:", 0)?;
    // The prompt is printed just before raw mode is enabled: let it switch first, or
    // the typed password lands in cooked mode.
    run.poll(Duration::from_millis(500));
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    let line = format!(
        "listening on 127.0.0.1:{} → 127.0.0.1:{}",
        s.bind_port,
        s.svc.port()
    );
    run.wait_for(&line, at)?;
    assert_eq!(roundtrip(s.bind_port, b"ping"), b"hello:ping");
    assert_eq!(roundtrip(s.bind_port, b"again"), b"hello:again");
    run.send(b"\x03")?; // SIGINT
    let status = run.wait_exit()?;
    assert!(status.success(), "{status:?}: {}", run.output());
    // Stopped: nothing listens any more.
    assert!(TcpStream::connect(("127.0.0.1", s.bind_port)).is_err());
    let _ = std::fs::remove_dir_all(&s.home);
    Ok(())
}

/// T-19: `--detach` returns, the pid file exists, and the forward keeps working.
#[test]
fn t19_forward_detach_writes_a_pid_file() -> TestResult {
    let s = setup("forward-detach");
    let mut run = PtyRun::spawn(command(&s.home, &["forward", "db", "--detach"]))?;
    let at = run.wait_for("Master password:", 0)?;
    // The prompt is printed just before raw mode is enabled: let it switch first, or
    // the typed password lands in cooked mode.
    run.poll(Duration::from_millis(500));
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for("listening on 127.0.0.1:", at)?;
    let status = run.wait_exit()?;
    assert!(status.success(), "{status:?}: {}", run.output());

    let p = paths(&s.home);
    let dir = p.runtime_dir().unwrap_or_else(|| p.state_dir());
    let pid_path = dir.join("forward-db.pid");
    let pid = std::fs::read_to_string(&pid_path)?.trim().to_owned();
    assert!(pid.parse::<u32>().is_ok(), "{pid:?}");
    let works = roundtrip(s.bind_port, b"detached");
    let _ = std::process::Command::new("kill").arg(&pid).status();
    assert_eq!(works, b"hello:detached");
    let _ = std::fs::remove_dir_all(&s.home);
    Ok(())
}

/// Without a terminal and with the keyring off, the vault cannot be unlocked: exit 3.
#[test]
fn forward_without_tty_is_locked() {
    let s = setup("forward-notty");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sverb"))
        .args(["forward", "db"])
        .env("SVERB_HOME", &s.home)
        .env("SVERB_KEYRING", "off")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let _ = std::fs::remove_dir_all(&s.home);
}
