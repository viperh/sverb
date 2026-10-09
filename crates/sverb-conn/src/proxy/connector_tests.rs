//! The SSH connector through proxies, end to end over loopback (session
//! manager → `SshConnector` → `first_hop::open` → proxy → in-process russh server).
//! Needs the `connect.rs` hook (`first_hop::open`), so this module is declared only
//! once that hook is merged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use sverb_core::{
    config::Config,
    model::{DeviceId, Host, ItemId},
    secret::SecretString,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

use super::{ProxyConfig, ValueOrigin};
use crate::{
    DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionState, SshSpec, TransportKind,
    ssh::{
        HostResolver, InsecureAcceptAnyHostKey, SshConnector, SshError, SshTarget, resolve,
        testing::start_server,
    },
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const WAIT: Duration = Duration::from_secs(10);

/// A target name only the proxy "resolves" (it doesn't exist in DNS).
const TARGET_NAME: &str = "ssh.only-the-proxy-knows.invalid";

/// Resolves to the test server with a proxy made by `proxy`.
struct ProxyResolver {
    addr: SocketAddr,
    /// The target's address as configured (`None`: the server's IP).
    name: Option<&'static str>,
    proxy: Box<dyn Fn() -> ProxyConfig + Send + Sync>,
}

impl fmt::Debug for ProxyResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyResolver").finish_non_exhaustive()
    }
}

#[async_trait]
impl HostResolver for ProxyResolver {
    async fn resolve(&self, _spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host = Host {
            label: "db".into(),
            address: self
                .name
                .map_or_else(|| self.addr.ip().to_string(), str::to_owned),
            port: Some(self.addr.port()),
            username: Some("sverb".into()),
            password: Some(SecretString::from("secret")),
            ..Host::default()
        };
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        let mut target = resolve(&host, None, None, &config, || None);
        target.proxy = Some((self.proxy)());
        target.proxy_configured = true;
        Ok(target)
    }
}

fn manager(
    addr: SocketAddr,
    name: Option<&'static str>,
    proxy: impl Fn() -> ProxyConfig + Send + Sync + 'static,
) -> (SessionManager, Events) {
    let connector = SshConnector::new(Arc::new(ProxyResolver {
        addr,
        name,
        proxy: Box::new(proxy),
    }))
    .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    (mgr, rx)
}

fn open(mgr: &SessionManager) -> SessionHandle {
    mgr.open_with(
        crate::SessionSpec::Ssh(SshSpec {
            host: "ignored".into(),
            port: 22,
            ..SshSpec::default()
        }),
        OpenOptions {
            cols: 80,
            rows: 24,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

async fn wait_event(
    rx: &mut Events,
    pred: impl Fn(&SessionEvent) -> bool,
) -> (SessionEvent, Vec<SessionEvent>) {
    let mut seen = Vec::new();
    let res = tokio::time::timeout(WAIT, async {
        loop {
            let (_, ev) = rx.recv().await.unwrap();
            if pred(&ev) {
                return ev;
            }
            seen.push(ev);
        }
    })
    .await;
    match res {
        Ok(ev) => (ev, seen),
        Err(_) => panic!("event not received; saw {seen:#?}"),
    }
}

fn connected(e: &SessionEvent) -> bool {
    matches!(e, SessionEvent::State(SessionState::Connected { .. }))
}

fn disconnected(e: &SessionEvent) -> bool {
    matches!(e, SessionEvent::State(SessionState::Disconnected { .. }))
}

fn error_of(events: &[SessionEvent]) -> sverb_core::error_report::ErrorReport {
    events
        .iter()
        .find_map(|e| match e {
            SessionEvent::Error(r) => Some(r.clone()),
            _ => None,
        })
        .expect("an error event")
}

/// A SOCKS5 proxy without auth forwarding every CONNECT to `upstream`.
async fn socks_forwarder(upstream: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 2];
                s.read_exact(&mut b).await.unwrap();
                let mut m = vec![0u8; usize::from(b[1])];
                s.read_exact(&mut m).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.unwrap();
                assert_eq!(req[3], 3, "the target must be sent by name");
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await.unwrap();
                let mut rest = vec![0u8; usize::from(len[0]) + 2];
                s.read_exact(&mut rest).await.unwrap();
                assert_eq!(&rest[..rest.len() - 2], TARGET_NAME.as_bytes());
                s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22])
                    .await
                    .unwrap();
                let mut up = TcpStream::connect(upstream).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    addr
}

/// SOCKS5 through the connector: the session connects; the peer names the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_through_socks5() {
    let (server, _) = start_server().await;
    let proxy = socks_forwarder(server).await;
    // A name only the proxy can resolve: no local DNS of the target.
    let (mgr, mut rx) = manager(server, Some(TARGET_NAME), move || ProxyConfig::Socks5 {
        addr: proxy.to_string(),
        auth: None,
    });
    let _handle = open(&mgr);
    let (_, before) = wait_event(&mut rx, connected).await;
    let info = before
        .iter()
        .find_map(|e| match e {
            SessionEvent::SshInfo(i) => Some(i.clone()),
            _ => None,
        })
        .expect("SshInfo");
    assert_eq!(info.peer, format!("socks5 {proxy}"));
    mgr.shutdown(Duration::from_secs(2)).await;
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// T-06/T-07 through the connector: a ProxyCommand (`socat`) connects; closing the
/// session kills (and reaps) it within 2 s.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_proxy_command_and_kill_on_close() {
    if std::process::Command::new("socat")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("socat not installed; skipping");
        return;
    }
    let (server, _) = start_server().await;
    let dir = std::env::temp_dir().join(format!("sverb-m2-06-c-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("pid");
    let command = format!(
        "sh -c 'echo $$ > {}; exec socat - TCP:%h:%p'",
        pidfile.display()
    );
    let (mgr, mut rx) = manager(server, None, move || ProxyConfig::Command {
        command: command.clone(),
        origin: ValueOrigin::default(),
    });
    let handle = open(&mgr);
    wait_event(&mut rx, connected).await;
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(alive(pid));
    handle.cmd_tx.send(SessionCmd::Close).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "ProxyCommand {pid} still alive after close"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = std::fs::remove_dir_all(&dir);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-08 through the connector: a failing ProxyCommand's stderr is in the error
/// report (the ConnLog detail).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_reports_proxy_command_stderr() {
    let (server, _) = start_server().await;
    let (mgr, mut rx) = manager(server, None, || ProxyConfig::Command {
        command: "sh -c 'echo \"bastion: no route to %h\" >&2; exit 1'".into(),
        origin: ValueOrigin::default(),
    });
    let _handle = open(&mgr);
    let (ev, before) = wait_event(&mut rx, disconnected).await;
    assert!(matches!(
        ev,
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::Connect,
            ..
        })
    ));
    let report = error_of(&before);
    let all = format!("{} {}", report.short, report.chain.join(" "));
    assert!(all.contains("bastion: no route to 127.0.0.1"), "{report:?}");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-12 through the connector: a synced ProxyCommand fails with the approval message
/// and never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_blocks_unapproved_proxy_command() {
    let (server, _) = start_server().await;
    let (mgr, mut rx) = manager(server, None, || ProxyConfig::Command {
        command: "socat - TCP:%h:%p".into(),
        origin: ValueOrigin {
            item_id: Some(ItemId::from_bytes([3; 16])),
            written_by: Some(DeviceId::from_bytes([9; 16])),
            this_device: Some(DeviceId::from_bytes([1; 16])),
        },
    });
    let _handle = open(&mgr);
    let (_, before) = wait_event(&mut rx, disconnected).await;
    let report = error_of(&before);
    assert_eq!(
        report.short,
        "host \"db\" uses a local command that has not been approved on this device. Run: sverb approve db"
    );
    assert_eq!(report.chain, ["ProxyCommand: socat - TCP:%h:%p"]);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// A wrong SOCKS5 proxy address fails readably (no direct fallback).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_proxy_failure_never_falls_back_to_direct() {
    let (server, _) = start_server().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);
    let (mgr, mut rx) = manager(server, None, move || ProxyConfig::Http {
        addr: dead.clone(),
        auth: None,
    });
    let _handle = open(&mgr);
    let (_, before) = wait_event(&mut rx, disconnected).await;
    let report = error_of(&before);
    assert!(
        report
            .short
            .starts_with("proxy: could not connect to 127.0.0.1:"),
        "{report:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}
