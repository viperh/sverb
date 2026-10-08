//! M2-08 tests.
//!
//! - T-01…T-09: SOCKS conformance over an in-memory stream with a mock opener.
//! - T-10…T-12: local forwards through the manager over a mock tunnel.
//! - Loopback (no Docker) equivalents of T-13…T-17 against the in-process russh
//!   server (`ssh::testing`): -L, -R with a server-allocated port, -D with remote DNS,
//!   connection drop and reconnect, standalone tunnels. The Docker e2e variants are at
//!   the end, `#[ignore]`d for the M1-18 harness.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use sverb_core::model::{ForwardKind, ItemId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::SessionId;

const WAIT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- mock tunnel

/// Records `open_direct` calls; answers with `fail` or with a duplex whose other end
/// goes to `peers`.
#[derive(Debug)]
struct MockTunnel {
    calls: Mutex<Vec<(String, u16)>>,
    fail: Option<OpenFailure>,
    peers: mpsc::UnboundedSender<DuplexStream>,
}

impl MockTunnel {
    fn new(fail: Option<OpenFailure>) -> (Arc<Self>, mpsc::UnboundedReceiver<DuplexStream>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                fail,
                peers: tx,
            }),
            rx,
        )
    }

    fn calls(&self) -> Vec<(String, u16)> {
        self.calls.lock().clone()
    }
}

#[async_trait]
impl Tunnel for MockTunnel {
    async fn open_direct(
        &self,
        host: &str,
        port: u16,
        _originator: SocketAddr,
    ) -> Result<TunnelStream, OpenFailure> {
        self.calls.lock().push((host.to_owned(), port));
        if let Some(fail) = &self.fail {
            return Err(fail.clone());
        }
        let (ours, theirs) = duplex(64 * 1024);
        let _ = self.peers.send(theirs);
        Ok(Box::new(ours))
    }

    async fn listen_remote(&self, _addr: &str, _port: u16) -> Result<RemoteListener, OpenFailure> {
        Err(OpenFailure::Other("not in this mock".into()))
    }
}

fn peer() -> SocketAddr {
    "127.0.0.1:40000".parse().unwrap()
}

/// Run the SOCKS handshake with `request` as the client's bytes; returns what the
/// server replied and whether a tunnel was opened.
async fn socks(tunnel: &MockTunnel, request: &[u8]) -> (Vec<u8>, bool) {
    let (mut client, mut server) = duplex(4096);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    let ok = handshake_on(&mut server, tunnel).await;
    drop(server);
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    (reply, ok)
}

async fn handshake_on(server: &mut DuplexStream, tunnel: &MockTunnel) -> bool {
    socks_handshake(server, peer(), tunnel, false).await.is_ok()
}

const OK5: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

fn v5(cmd: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut v = vec![5, 1, 0, 5, cmd, 0, atyp];
    v.extend_from_slice(addr);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

// ---------------------------------------------------------------- T-01 … T-09

/// T-01: CONNECT IPv4 → opener gets `"1.2.3.4", 80`; reply `05 00 00 01 0…0`.
#[tokio::test]
async fn t01_connect_ipv4() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let (reply, ok) = socks(&tunnel, &v5(1, 1, &[1, 2, 3, 4], 80)).await;
    assert!(ok);
    assert_eq!(tunnel.calls(), [("1.2.3.4".to_owned(), 80)]);
    assert_eq!(reply, [&[5_u8, 0][..], &OK5[..]].concat());
}

/// T-02: CONNECT domain → the opener gets the domain string, unresolved.
#[tokio::test]
async fn t02_connect_domain_is_not_resolved() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let mut addr = vec![11];
    addr.extend_from_slice(b"example.com");
    let (reply, ok) = socks(&tunnel, &v5(1, 3, &addr, 443)).await;
    assert!(ok);
    assert_eq!(tunnel.calls(), [("example.com".to_owned(), 443)]);
    assert_eq!(&reply[2..], OK5);
}

/// T-03: CONNECT IPv6.
#[tokio::test]
async fn t03_connect_ipv6() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let ip: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
    let (reply, ok) = socks(&tunnel, &v5(1, 4, &ip.octets(), 22)).await;
    assert!(ok);
    assert_eq!(tunnel.calls(), [("2001:db8::7".to_owned(), 22)]);
    assert_eq!(&reply[2..], OK5);
}

/// T-04: BIND and UDP ASSOCIATE → `0x07`, no channel.
#[tokio::test]
async fn t04_bind_and_udp_not_supported() {
    for cmd in [2, 3] {
        let (tunnel, _peers) = MockTunnel::new(None);
        let (reply, ok) = socks(&tunnel, &v5(cmd, 1, &[1, 2, 3, 4], 80)).await;
        assert!(!ok);
        assert_eq!(reply[..2], [5, 0]);
        assert_eq!(reply[3], 0x07, "cmd {cmd}");
        assert!(tunnel.calls().is_empty());
    }
}

/// T-05: only `0x02` (user/password) offered → `05 FF` and close.
#[tokio::test]
async fn t05_no_acceptable_method() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let (reply, ok) = socks(&tunnel, &[5, 1, 2]).await;
    assert!(!ok);
    assert_eq!(reply, [5, 0xFF]);
}

/// T-06: unknown ATYP → `0x08`.
#[tokio::test]
async fn t06_unknown_atyp() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let (reply, ok) = socks(&tunnel, &v5(1, 9, &[0, 0], 80)).await;
    assert!(!ok);
    assert_eq!(reply[2..], [5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]);
}

/// T-07: SOCKS4 CONNECT IPv4 → `0x5A`; SOCKS4a domain → the opener gets the domain.
#[tokio::test]
async fn t07_socks4_and_4a() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let mut req = vec![4, 1, 0, 80, 10, 1, 2, 3];
    req.extend_from_slice(b"user\0");
    let (reply, ok) = socks(&tunnel, &req).await;
    assert!(ok);
    assert_eq!(reply, [0, 0x5A, 0, 0, 0, 0, 0, 0]);
    assert_eq!(tunnel.calls(), [("10.1.2.3".to_owned(), 80)]);

    let (tunnel, _peers) = MockTunnel::new(None);
    let mut req = vec![4, 1, 0x1F, 0x90, 0, 0, 0, 1, 0];
    req.extend_from_slice(b"inner-service\0");
    let (reply, ok) = socks(&tunnel, &req).await;
    assert!(ok);
    assert_eq!(reply[1], 0x5A);
    assert_eq!(tunnel.calls(), [("inner-service".to_owned(), 8080)]);

    // A failure is 0x5B.
    let (tunnel, _peers) = MockTunnel::new(Some(OpenFailure::Refused("x".into())));
    let mut req = vec![4, 1, 0, 80, 10, 1, 2, 3];
    req.extend_from_slice(b"\0");
    let (reply, ok) = socks(&tunnel, &req).await;
    assert!(!ok);
    assert_eq!(reply[1], 0x5B);
}

/// T-08: truncated and garbage requests close without panicking; a silent client
/// times out after 10 s (virtual time).
#[tokio::test(start_paused = true)]
async fn t08_truncated_garbage_and_timeout() {
    let (tunnel, _peers) = MockTunnel::new(None);
    for bad in [
        &b""[..],
        &[5][..],
        &[5, 1, 0, 5, 1, 0, 3, 200, b'a'][..],
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        &[4, 1, 0][..],
        &[5, 0][..],
        &[5, 1, 0, 5, 1, 7, 1, 1, 2, 3, 4, 0, 80][..],
    ] {
        let (_, ok) = socks(&tunnel, bad).await;
        assert!(!ok, "{bad:?}");
    }
    assert!(tunnel.calls().is_empty());

    // Nothing more after the greeting: the handshake times out at 10 s.
    let (mut client, mut server) = duplex(4096);
    client.write_all(&[5, 1, 0]).await.unwrap();
    let started = tokio::time::Instant::now();
    let res = socks_handshake(&mut server, peer(), tunnel.as_ref(), false).await;
    assert!(matches!(res, Err(SocksError::Timeout)), "{:?}", res.err());
    assert_eq!(started.elapsed(), SOCKS_TIMEOUT);
    drop(client);
}

/// T-09: opener failures map to SOCKS replies (`connect failed` → `0x05`, …).
#[tokio::test]
async fn t09_open_failure_replies() {
    for (fail, code) in [
        (OpenFailure::Refused("connect failed".into()), 0x05),
        (OpenFailure::Prohibited("no".into()), 0x02),
        (OpenFailure::Unreachable("no route".into()), 0x04),
        (OpenFailure::Other("gone".into()), 0x01),
    ] {
        let (tunnel, _peers) = MockTunnel::new(Some(fail));
        let (reply, ok) = socks(&tunnel, &v5(1, 1, &[1, 2, 3, 4], 80)).await;
        assert!(!ok);
        assert_eq!(reply[3], code);
    }
}

/// Bytes sent right after the request are forwarded once the channel is open.
#[tokio::test]
async fn socks_early_data_is_kept() {
    let (tunnel, _peers) = MockTunnel::new(None);
    let mut req = v5(1, 1, &[1, 2, 3, 4], 80);
    req.extend_from_slice(b"GET /");
    let (mut client, mut server) = duplex(4096);
    client.write_all(&req).await.unwrap();
    let (_, early) = socks_handshake(&mut server, peer(), tunnel.as_ref(), false)
        .await
        .unwrap();
    assert_eq!(early, b"GET /");
}

// ---------------------------------------------------------------- manager helpers

fn rule(kind: ForwardKind, host: ItemId, bind_port: u16, dest: Option<(&str, u16)>) -> ForwardRule {
    ForwardRule {
        id: ItemId::new(),
        label: "test".into(),
        kind,
        host_id: host,
        bind_addr: "127.0.0.1".into(),
        bind_port,
        dest_host: dest.map(|d| d.0.to_owned()),
        dest_port: dest.map(|d| d.1),
        auto_start: false,
        typed_here: true,
    }
}

fn mock_conn(fm: &ForwardManager, host: ItemId, tunnel: Arc<dyn Tunnel>) -> CancellationToken {
    let token = CancellationToken::new();
    fm.connected(ConnInfo {
        host_id: Some(host),
        session: SessionId(1),
        standalone: false,
        tunnel,
        token: token.clone(),
    });
    token
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn listening(fm: &ForwardManager, id: ItemId) -> u16 {
    let state = fm.wait_started(id, WAIT).await.unwrap();
    assert_eq!(state, ForwardState::Listening, "{state}");
    fm.status(id).unwrap().port.unwrap()
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------- T-10 … T-12

/// T-10: half-close both ways (like `nc -N`): the client sends data then FIN; the
/// channel sees the data then eof; the server answers after eof and the client reads
/// the answer, then eof.
#[tokio::test]
async fn t10_half_close() {
    let host = ItemId::new();
    let (tunnel, mut peers) = MockTunnel::new(None);
    let fm = ForwardManager::new();
    let r = rule(
        ForwardKind::Local,
        host,
        free_port().await,
        Some(("db", 5432)),
    );
    let id = r.id;
    fm.set_rules([r]);
    let _conn = mock_conn(&fm, host, tunnel.clone());
    fm.start(id).unwrap();
    let port = listening(&fm, id).await;

    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap(); // FIN

    let mut channel = tokio::time::timeout(WAIT, peers.recv())
        .await
        .unwrap()
        .unwrap();
    let mut got = Vec::new();
    // read_to_end returns only at eof: the FIN became the channel's eof.
    tokio::time::timeout(WAIT, channel.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"request");
    assert_eq!(tunnel.calls(), [("db".to_owned(), 5432)]);

    // The server replies after eof, then sends its own eof.
    channel.write_all(b"response").await.unwrap();
    channel.shutdown().await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, b"response");

    wait_for("counters", || {
        let s = fm.status(id).unwrap();
        s.bytes_out == 7 && s.bytes_in == 8 && s.active == 0
    })
    .await;
}

/// T-11: 300 concurrent connections → 256 carried, 44 closed at once; after some
/// close, new ones succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t11_channel_cap() {
    let host = ItemId::new();
    let (tunnel, mut peers) = MockTunnel::new(None);
    let fm = ForwardManager::new();
    let r = rule(
        ForwardKind::Local,
        host,
        free_port().await,
        Some(("db", 5432)),
    );
    let id = r.id;
    fm.set_rules([r]);
    let _conn = mock_conn(&fm, host, tunnel);
    fm.start(id).unwrap();
    let port = listening(&fm, id).await;

    let mut clients = Vec::new();
    for _ in 0..300 {
        clients.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    wait_for("256 active and 44 refused", || {
        let s = fm.status(id).unwrap();
        s.active == 256 && s.refused == 44
    })
    .await;
    assert!(fm.status(id).unwrap().saturated());
    // Keep the channel ends alive.
    let mut channels = Vec::new();
    while channels.len() < 256 {
        channels.push(
            tokio::time::timeout(WAIT, peers.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }

    // Exactly 44 clients see an immediate close; the others stay open.
    let probes = clients.into_iter().map(|mut c| async move {
        let mut b = [0_u8; 1];
        match tokio::time::timeout(Duration::from_millis(300), c.read(&mut b)).await {
            Ok(Ok(0) | Err(_)) => None,
            Ok(Ok(_)) => panic!("unexpected data"),
            Err(_) => Some(c),
        }
    });
    let results = futures::future::join_all(probes).await;
    let closed = results.iter().filter(|r| r.is_none()).count();
    let mut open: Vec<TcpStream> = results.into_iter().flatten().collect();
    assert_eq!(closed, 44);
    assert_eq!(open.len(), 256);

    // The remote side closes each channel once it sees eof (like a server whose
    // client went away); the others stay open.
    for mut ch in channels {
        tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = ch.read_to_end(&mut sink).await;
        });
    }
    // Close ten: ten new connections are carried.
    open.truncate(246);
    wait_for("246 active", || fm.status(id).unwrap().active == 246).await;
    let mut more = Vec::new();
    for _ in 0..10 {
        more.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    wait_for("256 active again", || fm.status(id).unwrap().active == 256).await;
    assert_eq!(fm.status(id).unwrap().refused, 44);
}

/// T-12: the bind port is taken → `error: address in use`.
#[tokio::test]
async fn t12_bind_in_use() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port();
    let host = ItemId::new();
    let (tunnel, _peers) = MockTunnel::new(None);
    let fm = ForwardManager::new();
    let r = rule(ForwardKind::Local, host, port, Some(("db", 5432)));
    let id = r.id;
    fm.set_rules([r]);
    let _conn = mock_conn(&fm, host, tunnel);
    fm.start(id).unwrap();
    let state = fm.wait_started(id, WAIT).await.unwrap();
    assert_eq!(state, ForwardState::Error("address in use".into()));
    assert_eq!(state.to_string(), "error: address in use");
}

/// Lifecycle with a mock connection: not connected → error; a dropped connection
/// stops the rule (`stopped (connection lost)`); a new connection restarts only the
/// auto-start rules; approvals gate non-loopback binds.
#[tokio::test]
async fn lifecycle_and_approval() {
    let host = ItemId::new();
    let (tunnel, _peers) = MockTunnel::new(None);
    let fm = ForwardManager::new();
    let mut auto = rule(ForwardKind::Dynamic, host, free_port().await, None);
    auto.auto_start = true;
    let manual = rule(ForwardKind::Local, host, free_port().await, Some(("db", 1)));
    let mut wide = rule(ForwardKind::Local, host, free_port().await, Some(("db", 1)));
    wide.bind_addr = "0.0.0.0".into();
    let (a, m, w) = (auto.id, manual.id, wide.id);
    fm.set_rules([auto, manual, wide]);
    assert_eq!(fm.start(m), Err(StartError::NotConnected));

    let conn = mock_conn(&fm, host, tunnel.clone());
    listening(&fm, a).await; // auto-start
    fm.start(m).unwrap();
    listening(&fm, m).await;
    // Non-loopback bind: confirmation first (never actually bound in this test).
    let Err(StartError::NeedsApproval(values)) = fm.start(w) else {
        panic!()
    };
    assert_eq!(
        values[0].value,
        format!("0.0.0.0:{}", fm.rule(w).unwrap().bind_port)
    );
    fm.approve(&values);
    assert!(fm.pending_approval(w).is_empty());

    conn.cancel();
    wait_for("connection lost", || {
        fm.status(a).unwrap().state == ForwardState::ConnectionLost
            && fm.status(m).unwrap().state == ForwardState::ConnectionLost
    })
    .await;
    assert_eq!(
        fm.status(a).unwrap().state.to_string(),
        "stopped (connection lost)"
    );

    let _conn2 = mock_conn(&fm, host, tunnel);
    listening(&fm, a).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fm.status(m).unwrap().state, ForwardState::ConnectionLost);
    assert_eq!(fm.stop(a), None);
    assert_eq!(fm.status(a).unwrap().state, ForwardState::Stopped);
}

#[test]
fn rule_validation_and_display() {
    let host = ItemId::new();
    let mut r = rule(ForwardKind::Local, host, 5432, Some(("db", 5432)));
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.summary(), "L:5432→db:5432");
    r.bind_port = 0;
    assert!(r.validate().is_err());
    r.kind = ForwardKind::Remote;
    assert_eq!(r.validate(), Ok(()), "remote may ask for port 0");
    r.dest_host = None;
    assert_eq!(r.validate(), Err(RuleError::MissingDest));
    let mut d = rule(ForwardKind::Dynamic, host, 1080, None);
    assert_eq!(d.summary(), "D:1080");
    for ok in ["*", "0.0.0.0", "::", "localhost", "::1", "10.0.0.1"] {
        d.bind_addr = ok.into();
        assert_eq!(d.validate(), Ok(()), "{ok}");
    }
    d.bind_addr = "my host".into();
    assert_eq!(d.validate(), Err(RuleError::BindAddr));
    assert!(is_loopback("127.4.5.6") && is_loopback("::1") && is_loopback("localhost"));
    assert!(!is_loopback("0.0.0.0") && !is_loopback("*"));
}

// ---------------------------------------------------------------- loopback SSH

mod loopback {
    use sverb_core::model::Host;

    use super::*;
    use crate::{
        OpenOptions, SessionCmd, SessionEvent, SessionManager, SessionSpec, SessionState, SshSpec,
        TransportKind,
        ssh::{
            InsecureAcceptAnyHostKey, SshConnector,
            testing::{TestResolver, start_server},
        },
    };

    type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

    fn no_edit(_: &mut Host) {}

    fn sessions(addr: SocketAddr, fm: &ForwardManager) -> (SessionManager, Events) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mgr = SessionManager::new(tx);
        let connector = SshConnector::new(Arc::new(TestResolver {
            addr,
            password: "secret",
            edit: no_edit,
        }))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
        mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
        mgr.set_forward_hook(Arc::new(fm.clone()));
        (mgr, rx)
    }

    fn spec(host: ItemId) -> SshSpec {
        SshSpec {
            host: "ignored".into(),
            port: 22,
            host_id: Some(host),
            ..SshSpec::default()
        }
    }

    /// A loopback service that answers each connection with `hello:<request>` after
    /// reading to eof.
    async fn service() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

    async fn roundtrip(port: u16, req: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(req).await.unwrap();
        c.shutdown().await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(WAIT, c.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        out
    }

    async fn wait_state(rx: &mut Events, f: impl Fn(&SessionState) -> bool) {
        tokio::time::timeout(WAIT, async {
            loop {
                if let (_, SessionEvent::State(s)) = rx.recv().await.unwrap()
                    && f(&s)
                {
                    return;
                }
            }
        })
        .await
        .expect("state not reached");
    }

    /// T-13 (loopback): -L through `direct-tcpip`; the byte counters increase.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t13_local_forward_loopback() {
        let (addr, seen) = start_server().await;
        let svc = service().await;
        let host = ItemId::new();
        let fm = ForwardManager::new();
        let mut r = rule(
            ForwardKind::Local,
            host,
            free_port().await,
            Some(("127.0.0.1", svc.port())),
        );
        r.auto_start = true;
        let id = r.id;
        fm.set_rules([r]);
        let (mgr, mut rx) = sessions(addr, &fm);
        let _h = mgr
            .open_with(SessionSpec::Ssh(spec(host)), OpenOptions::default())
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        let port = listening(&fm, id).await;
        assert_eq!(roundtrip(port, b"GET /").await, b"hello:GET /");
        let s = fm.status(id).unwrap();
        assert_eq!((s.bytes_out, s.bytes_in), (5, 11));
        assert_eq!(s.total, 1);
        assert!(
            seen.lock()
                .direct
                .contains(&("127.0.0.1".to_owned(), u32::from(svc.port())))
        );
        mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// T-14 (loopback): -R with `bind_port = 0` → the allocated port is reported, and
    /// connecting to it on the server side reaches the local service; stopping sends
    /// `cancel-tcpip-forward`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t14_remote_forward_allocated_port() {
        let (addr, seen) = start_server().await;
        let svc = service().await;
        let host = ItemId::new();
        let fm = ForwardManager::new();
        let r = rule(
            ForwardKind::Remote,
            host,
            0,
            Some(("127.0.0.1", svc.port())),
        );
        let id = r.id;
        fm.set_rules([r]);
        let (mgr, mut rx) = sessions(addr, &fm);
        let _h = mgr
            .open_with(SessionSpec::Ssh(spec(host)), OpenOptions::default())
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        fm.start(id).unwrap();
        let port = listening(&fm, id).await;
        assert_ne!(port, 0);
        assert!(
            fm.status(id)
                .unwrap()
                .route()
                .contains(&format!(":{port} → "))
        );
        // "From inside the container": the server's listener is on 127.0.0.1:<port>.
        assert_eq!(roundtrip(port, b"ping").await, b"hello:ping");
        fm.stop(id);
        wait_for("cancel-tcpip-forward", || {
            seen.lock()
                .cancelled
                .contains(&("127.0.0.1".to_owned(), u32::from(port)))
        })
        .await;
        mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// T-15 (loopback): -D with a domain the **server** resolves (`*.sverb-test`):
    /// the name reaches `direct-tcpip` unresolved (remote DNS).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t15_dynamic_remote_dns() {
        let (addr, seen) = start_server().await;
        let svc = service().await;
        let host = ItemId::new();
        let fm = ForwardManager::new();
        let mut r = rule(ForwardKind::Dynamic, host, free_port().await, None);
        r.auto_start = true;
        let id = r.id;
        fm.set_rules([r]);
        let (mgr, mut rx) = sessions(addr, &fm);
        let _h = mgr
            .open_with(SessionSpec::Ssh(spec(host)), OpenOptions::default())
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        let port = listening(&fm, id).await;

        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let name = b"inner.sverb-test";
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
        req.extend_from_slice(name);
        req.extend_from_slice(&svc.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut head = [0_u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        c.write_all(b"via socks").await.unwrap();
        c.shutdown().await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(WAIT, c.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out, b"hello:via socks");
        assert!(
            seen.lock()
                .direct
                .contains(&("inner.sverb-test".to_owned(), u32::from(svc.port())))
        );

        // A destination the server can't reach → 0x05 (connect failed).
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(&[5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80])
            .await
            .unwrap();
        let mut head = [0_u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert_eq!(head[3], 0x05);
        mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// A TCP proxy whose connections can all be cut (a dropped network).
    async fn cuttable_proxy(target: SocketAddr) -> (SocketAddr, CancellationToken) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let cut = Arc::new(Mutex::new(CancellationToken::new()));
        let current = CancellationToken::new();
        let outer = current.clone();
        *cut.lock() = current;
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                // After a cut, new connections use a fresh token.
                let token = {
                    let mut current = cut.lock();
                    if current.is_cancelled() {
                        *current = CancellationToken::new();
                    }
                    current.clone()
                };
                tokio::spawn(async move {
                    let Ok(mut s) = TcpStream::connect(target).await else {
                        return;
                    };
                    tokio::select! {
                        () = token.cancelled() => {}
                        _ = tokio::io::copy_bidirectional(&mut c, &mut s) => {}
                    }
                });
            }
        });
        (addr, outer)
    }

    /// T-16 (loopback): a connection drop stops the rules; reconnecting restarts the
    /// auto-start ones only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t16_drop_and_reconnect() {
        let (server, _seen) = start_server().await;
        let (addr, cut) = cuttable_proxy(server).await;
        let svc = service().await;
        let host = ItemId::new();
        let fm = ForwardManager::new();
        let mut auto = rule(
            ForwardKind::Local,
            host,
            free_port().await,
            Some(("127.0.0.1", svc.port())),
        );
        auto.auto_start = true;
        let manual = rule(ForwardKind::Dynamic, host, free_port().await, None);
        let (a, m) = (auto.id, manual.id);
        fm.set_rules([auto, manual]);
        let (mgr, mut rx) = sessions(addr, &fm);
        let h = mgr
            .open_with(SessionSpec::Ssh(spec(host)), OpenOptions::default())
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        listening(&fm, a).await;
        fm.start(m).unwrap();
        listening(&fm, m).await;

        cut.cancel();
        wait_state(&mut rx, |s| matches!(s, SessionState::Disconnected { .. })).await;
        wait_for("rules stopped", || {
            fm.status(a).unwrap().state == ForwardState::ConnectionLost
                && fm.status(m).unwrap().state == ForwardState::ConnectionLost
        })
        .await;

        h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        let port = listening(&fm, a).await;
        assert_eq!(roundtrip(port, b"again").await, b"hello:again");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fm.status(m).unwrap().state, ForwardState::ConnectionLost);
        mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// T-17 (loopback): a standalone tunnel opens no shell channel, and the forward
    /// works; stopping the last rule hands back the session to close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t17_standalone_tunnel() {
        let (addr, seen) = start_server().await;
        let svc = service().await;
        let host = ItemId::new();
        let fm = ForwardManager::new();
        let r = rule(
            ForwardKind::Local,
            host,
            free_port().await,
            Some(("localhost", svc.port())),
        );
        let id = r.id;
        fm.set_rules([r]);
        let (mgr, mut rx) = sessions(addr, &fm);
        let h = open_standalone(&mgr, &fm, id, spec(host), None)
            .unwrap()
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        let port = listening(&fm, id).await;
        assert!(fm.status(id).unwrap().standalone);
        assert_eq!(roundtrip(port, b"x").await, b"hello:x");
        {
            let seen = seen.lock();
            assert!(seen.term.is_none(), "no pty request");
            assert!(seen.input.is_empty());
        }
        // A second "start without terminal" reuses the connection.
        assert!(
            open_standalone(&mgr, &fm, id, spec(host), None)
                .unwrap()
                .is_none()
        );
        assert_eq!(fm.stop(id), Some(h.id));
        mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// An unmatched `forwarded-tcpip` channel is rejected (no route).
    #[test]
    fn unmatched_routes() {
        let routes = RemoteRoutes::default();
        let _rx = routes.add("127.0.0.1", 8080);
        assert!(routes.matches("127.0.0.1", 8080));
        assert!(routes.matches("localhost", 8080), "port-only fallback");
        assert!(!routes.matches("127.0.0.1", 8081));
        let _rx2 = routes.add("::1", 8080);
        assert!(!routes.matches("localhost", 8080), "ambiguous port");
    }
}

// ---------------------------------------------------------------- Docker e2e (M1-18)

/// T-13 (e2e): -L to the container's `python3 -m http.server`. Needs the M1-18
/// harness; the loopback variant is `loopback::t13_local_forward_loopback`.
#[test]
#[ignore = "needs the M1-18 Docker harness"]
fn t13_e2e_local_http() {}

/// T-14 (e2e): -R with `bind_port = 0`; `curl localhost:<port>` from the container.
#[test]
#[ignore = "needs the M1-18 Docker harness"]
fn t14_e2e_remote_allocated() {}

/// T-15 (e2e): `curl --socks5-hostname 127.0.0.1:<p> http://inner-service/`.
#[test]
#[ignore = "needs the M1-18 Docker harness"]
fn t15_e2e_socks_remote_dns() {}

/// T-16 (e2e): `docker pause`/restart drops the connection; auto-start rules return.
#[test]
#[ignore = "needs the M1-18 Docker harness"]
fn t16_e2e_drop_reconnect() {}

/// T-17 (e2e): standalone tunnel against OpenSSH.
#[test]
#[ignore = "needs the M1-18 Docker harness"]
fn t17_e2e_standalone() {}
