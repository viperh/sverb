//! M3-07 T-05…T-08 against OpenSSH in Docker: connection sharing seen from the server.
//! The server's TCP connections are counted inside the container (established sockets
//! on port 22 in `/proc/net/tcp`; the image has no `ss`), its shells as the `test`
//! user's `bash` processes. The loopback versions (and T-02, T-04, T-09) run without
//! Docker in `sverb-conn` (`ssh::mux_loopback`, `ssh::connect::jump::mux::tests`).
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_mux -- --ignored`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use sverb_conn::{
    OpenOptions, SessionEvent, SessionHandle, SessionId, SessionManager, SessionSpec, SessionState,
    SshSpec, TransportKind,
    ssh::{
        HostResolver, InsecureAcceptAnyHostKey, SshConnector, SshError, SshTarget,
        exec::{ExecOpts, ExecPrompts, SshConnection, exec},
        resolve,
    },
};
use sverb_core::{
    config::Config,
    model::{Host, ItemId},
    secret::SecretString,
};
use sverb_e2e::{JumpNet, Profile, Sshd, keys, require_docker, timeout};
use tokio::sync::mpsc;

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

/// Saved hosts by id (password auth with the fixture password).
#[derive(Debug, Default)]
struct Hosts(HashMap<ItemId, Host>);

impl Hosts {
    fn add(mut self, b: u8, address: String, port: u16, user: &str, chain: &[u8]) -> Self {
        self.0.insert(
            id(b),
            Host {
                label: format!("host{b}"),
                address,
                port: Some(port),
                username: Some(user.into()),
                password: Some(SecretString::from(keys::PASSWORD)),
                jump_chain: chain.iter().map(|b| id(*b)).collect(),
                ..Host::default()
            },
        );
        self
    }
}

#[async_trait]
impl HostResolver for Hosts {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host_id = spec.host_id.expect("saved hosts only");
        let host = self
            .0
            .get(&host_id)
            .ok_or_else(|| SshError::Settings("the host no longer exists".into()))?;
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 10;
        Ok(resolve(host, Some(host_id), None, &config, || None))
    }
}

fn connector(hosts: Hosts) -> SshConnector {
    SshConnector::new(Arc::new(hosts))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
        .with_multiplex(true)
}

fn manager(conn: &SshConnector) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(conn.clone()));
    (mgr, rx)
}

fn spec(b: u8) -> SshSpec {
    SshSpec {
        host_id: Some(id(b)),
        ..SshSpec::default()
    }
}

/// Open a tab (or a standalone tunnel) and wait until it is connected.
async fn open(mgr: &SessionManager, rx: &mut Events, b: u8, tunnel_only: bool) -> SessionHandle {
    let handle = mgr
        .open_with(
            SessionSpec::Ssh(spec(b)),
            OpenOptions {
                cols: 80,
                rows: 24,
                tunnel_only,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    let res = tokio::time::timeout(timeout() * 2, async {
        while let Some((sid, ev)) = rx.recv().await {
            if sid != handle.id {
                continue;
            }
            match ev {
                SessionEvent::State(SessionState::Connected { .. }) => return,
                SessionEvent::State(SessionState::Disconnected { reason, .. }) => {
                    panic!("disconnected: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(res.is_ok(), "not connected in time");
    handle
}

/// Established TCP connections to the container's sshd (port 22).
async fn tcp_conns(sshd: &Sshd) -> usize {
    let out = sshd
        .exec_root(
            "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
             | awk '$2 ~ /:0016$/ && $4 == \"01\"' | wc -l",
        )
        .await
        .unwrap();
    out.stdout.trim().parse().unwrap()
}

/// Login shells of `user` in the container.
async fn shells(sshd: &Sshd, user: &str) -> usize {
    let out = sshd
        .exec_root(&format!("pgrep -c -x -u {user} bash || true"))
        .await
        .unwrap();
    out.stdout.trim().parse().unwrap_or(0)
}

/// Poll `f` until it returns `want` (the server needs a moment to start shells).
async fn until(what: &str, want: usize, f: impl AsyncFn() -> usize) {
    let deadline = tokio::time::Instant::now() + timeout();
    loop {
        let got = f().await;
        if got == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: {got}, expected {want}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Make `sshd` enforce `MaxSessions n` (appended to the active profile, then `SIGHUP`
/// re-executes sshd; existing connections are not affected).
async fn max_sessions(sshd: &Sshd, n: usize) {
    let out = sshd
        .exec_root(&format!(
            "echo 'MaxSessions {n}' >> /etc/ssh/sverb-profile.conf && kill -HUP 1"
        ))
        .await
        .unwrap();
    assert!(out.success(), "{out:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    sshd.wait_ready().await.unwrap();
}

const HOST: u8 = 1;

/// T-05: two tabs to the same host → one TCP connection, two shell channels.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t05_two_tabs_one_tcp_connection() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    let conn = connector(Hosts::default().add(HOST, sshd.host(), sshd.port(), keys::USER, &[]));
    let (mgr, mut rx) = manager(&conn);
    let _a = open(&mgr, &mut rx, HOST, false).await;
    let _b = open(&mgr, &mut rx, HOST, false).await;
    until("shells", 2, async || shells(&sshd, keys::USER).await).await;
    assert_eq!(tcp_conns(&sshd).await, 1);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-06: `MaxSessions 2`, three tabs → the third uses a new connection; all three work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t06_max_sessions_fallback() {
    require_docker!();
    let sshd = Sshd::start(Profile::Password).await.unwrap();
    max_sessions(&sshd, 2).await;
    let conn = connector(Hosts::default().add(HOST, sshd.host(), sshd.port(), keys::USER, &[]));
    let (mgr, mut rx) = manager(&conn);
    let mut tabs = Vec::new();
    for _ in 0..3 {
        tabs.push(open(&mgr, &mut rx, HOST, false).await);
    }
    until("shells", 3, async || shells(&sshd, keys::USER).await).await;
    assert_eq!(tcp_conns(&sshd).await, 2);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-07: a standalone forward (tunnel-only session) and an exec run reuse the tab's
/// connection. The exec half needs the M3-07 `exec.rs` (merged from
/// `.merge/agent-M3-07`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t07_forward_and_exec_reuse_the_tab() {
    require_docker!();
    let sshd = Sshd::start(Profile::Forward).await.unwrap();
    let conn = connector(Hosts::default().add(HOST, sshd.host(), sshd.port(), keys::USER, &[]));
    let (mgr, mut rx) = manager(&conn);
    let _tab = open(&mgr, &mut rx, HOST, false).await;
    let _tunnel = open(&mgr, &mut rx, HOST, true).await;
    let run = SshConnection::open(&conn, &spec(HOST), ExecPrompts::none())
        .await
        .unwrap();
    let out = exec(&run, "echo shared", ExecOpts::default())
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "shared");
    assert_eq!(tcp_conns(&sshd).await, 1);
    run.close().await;
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-08: two targets (two users on the inner host) behind the same bastion share the
/// bastion connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t08_targets_share_the_bastion() {
    require_docker!();
    const BASTION: u8 = 2;
    const T1: u8 = 3;
    const T2: u8 = 4;
    let net = JumpNet::start().await.unwrap();
    let (inner, inner_port) = net.inner_addr_from_bastion();
    let hosts = Hosts::default()
        .add(
            BASTION,
            net.bastion.host(),
            net.bastion.port(),
            keys::USER,
            &[],
        )
        .add(T1, inner.clone(), inner_port, keys::USER, &[BASTION])
        .add(T2, inner, inner_port, "testzsh", &[BASTION]);
    let conn = connector(hosts);
    let (mgr, mut rx) = manager(&conn);
    let _a = open(&mgr, &mut rx, T1, false).await;
    let _b = open(&mgr, &mut rx, T2, false).await;
    assert_eq!(tcp_conns(&net.bastion).await, 1, "one bastion connection");
    assert_eq!(
        tcp_conns(&net.inner).await,
        2,
        "one connection per target user"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}
