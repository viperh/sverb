//! M3-07 loopback tests of shared connections against an in-process russh server that
//! counts TCP connections, authentications and session channels, and can enforce a
//! `MaxSessions`-like limit (no Docker). The OpenSSH variants (T-05…T-08 with `ss -tn`
//! in the container) are in `crates/sverb-e2e/tests/openssh_mux.rs` (`#[ignore]`d).
//!
//! Declared from `ssh/mod.rs` (`#[cfg(test)] mod mux_loopback;`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use russh::{
    Channel, ChannelId,
    keys::{PrivateKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use sverb_core::{
    config::Config,
    model::{Host, ItemId},
    secret::SecretString,
};
use sverb_term::GridPoint;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::AbortHandle,
};

use super::{
    ExecOpts, ExecPrompts, HostResolver, InsecureAcceptAnyHostKey, SshConnection, SshConnector,
    SshError, SshTarget, exec, resolve,
};
use crate::{
    Bytes, DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionSpec, SessionState, SshSpec, TransportKind,
};

const WAIT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------- the counting server

/// What the server saw (all connections).
#[derive(Debug, Default)]
struct Counts {
    /// TCP connections accepted.
    tcp: usize,
    /// Successful password authentications.
    auths: usize,
    /// Session channels opened (shells and execs).
    sessions: usize,
    /// Session channels refused by the limit.
    refused: usize,
    /// Session channels open now.
    open: usize,
    /// The per-connection session limit (`MaxSessions`).
    max_sessions: Option<usize>,
    /// The connections' tasks (finished once a connection ended).
    conns: Vec<AbortHandle>,
    /// A clone of each accepted socket (to drop the connections: `run_stream` runs the
    /// session in its own task, so aborting ours would not end it).
    sockets: Vec<std::net::TcpStream>,
}

/// Drop every connection the server holds (TCP shutdown, as a network failure).
fn drop_all(counts: &Shared) {
    for socket in &counts.lock().sockets {
        let _ = socket.shutdown(std::net::Shutdown::Both);
    }
}

type Shared = Arc<Mutex<Counts>>;

#[derive(Clone)]
struct Server {
    counts: Shared,
    /// This connection's open session channels.
    sessions: Arc<Mutex<HashSet<ChannelId>>>,
    /// Input per channel.
    input: Arc<Mutex<HashMap<ChannelId, Vec<u8>>>>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == "secret" {
            self.counts.lock().auths += 1;
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let limit = self.counts.lock().max_sessions;
        if limit.is_some_and(|max| self.sessions.lock().len() >= max) {
            self.counts.lock().refused += 1;
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.sessions.lock().insert(channel.id());
        {
            let mut counts = self.counts.lock();
            counts.sessions += 1;
            counts.open += 1;
        }
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Loopback only.
        let tcp = match (host, u16::try_from(port)) {
            ("127.0.0.1", Ok(port)) => TcpStream::connect(("127.0.0.1", port)).await.ok(),
            _ => None,
        };
        let Some(mut tcp) = tcp else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.sessions.lock().remove(&channel) {
            self.counts.lock().open -= 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_w: u32,
        _px_h: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ready\r\n".to_vec())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let mut out = b"exec:".to_vec();
        out.extend_from_slice(data);
        session.data(channel, out)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let line = {
            let mut input = self.input.lock();
            let buf = input.entry(channel).or_default();
            buf.extend_from_slice(data);
            if !buf.ends_with(b"\r") {
                return Ok(());
            }
            let line = String::from_utf8_lossy(buf).trim().to_owned();
            buf.clear();
            line
        };
        session.data(channel, format!("\r\nout:{line}\r\n").into_bytes())?;
        Ok(())
    }
}

/// A counting server on 127.0.0.1 (any user, password `secret`).
async fn start(max_sessions: Option<usize>) -> (SocketAddr, Shared) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counts: Shared = Arc::new(Mutex::new(Counts {
        max_sessions,
        ..Counts::default()
    }));
    let shared = Arc::clone(&counts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let std_stream = stream.into_std().unwrap();
            let socket = std_stream.try_clone().unwrap();
            let stream = TcpStream::from_std(std_stream).unwrap();
            let handler = Server {
                counts: Arc::clone(&shared),
                sessions: Arc::default(),
                input: Arc::default(),
            };
            let config = Arc::clone(&config);
            let task = tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
            let mut counts = shared.lock();
            counts.tcp += 1;
            counts.conns.push(task.abort_handle());
            counts.sockets.push(socket);
        }
    });
    (addr, counts)
}

// ---------------------------------------------------------------- the client side

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

/// Saved hosts by id.
#[derive(Debug, Default)]
struct Hosts(HashMap<ItemId, Host>);

impl Hosts {
    fn add(&mut self, b: u8, addr: SocketAddr, user: &str, chain: &[u8]) -> &mut Self {
        self.0.insert(
            id(b),
            Host {
                label: format!("host{b}"),
                address: addr.ip().to_string(),
                port: Some(addr.port()),
                username: Some(user.into()),
                password: Some(SecretString::from("secret")),
                jump_chain: chain.iter().map(|b| id(*b)).collect(),
                ..Host::default()
            },
        );
        self
    }
}

#[async_trait::async_trait]
impl HostResolver for Hosts {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host_id = spec.host_id.expect("saved hosts only");
        let host = self.0.get(&host_id).expect("known host");
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        config.ssh.keepalive_secs = 0;
        Ok(resolve(host, Some(host_id), None, &config, || None))
    }
}

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

fn connector(hosts: Hosts, multiplex: bool) -> SshConnector {
    SshConnector::new(Arc::new(hosts))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
        .with_multiplex(multiplex)
}

fn manager(connector: &SshConnector) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector.clone()));
    (mgr, rx)
}

fn spec(host: u8) -> SshSpec {
    SshSpec {
        host_id: Some(id(host)),
        ..SshSpec::default()
    }
}

fn open(mgr: &SessionManager, host: u8, tunnel_only: bool) -> SessionHandle {
    mgr.open_with(
        SessionSpec::Ssh(spec(host)),
        OpenOptions {
            cols: 80,
            rows: 24,
            tunnel_only,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

/// Events seen so far, by session.
#[derive(Default)]
struct Log(Vec<(SessionId, SessionEvent)>);

impl Log {
    /// Read events until `pred` matches one of `id`'s.
    async fn until(
        &mut self,
        rx: &mut Events,
        id: SessionId,
        pred: impl Fn(&SessionEvent) -> bool,
    ) -> SessionEvent {
        if let Some((_, ev)) = self.0.iter().find(|(i, e)| *i == id && pred(e)) {
            return ev.clone();
        }
        let res = tokio::time::timeout(WAIT, async {
            loop {
                let (i, ev) = rx.recv().await.unwrap();
                self.0.push((i, ev.clone()));
                if i == id && pred(&ev) {
                    return ev;
                }
            }
        })
        .await;
        match res {
            Ok(ev) => ev,
            Err(_) => panic!("event not received for {id:?}; saw {:#?}", self.0),
        }
    }

    async fn connected(&mut self, rx: &mut Events, id: SessionId) {
        self.until(rx, id, |e| {
            matches!(e, SessionEvent::State(SessionState::Connected { .. }))
        })
        .await;
    }

    async fn disconnected(&mut self, rx: &mut Events, id: SessionId) -> DisconnectReason {
        let ev = self
            .until(rx, id, |e| {
                matches!(e, SessionEvent::State(SessionState::Disconnected { .. }))
            })
            .await;
        match ev {
            SessionEvent::State(SessionState::Disconnected { reason, .. }) => reason,
            _ => unreachable!(),
        }
    }

    fn states(&self, id: SessionId) -> Vec<SessionState> {
        self.0
            .iter()
            .filter(|(i, _)| *i == id)
            .filter_map(|(_, e)| match e {
                SessionEvent::State(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    fn info(&self, id: SessionId) -> Option<crate::SshSessionInfo> {
        self.0.iter().rev().find_map(|(i, e)| match e {
            SessionEvent::SshInfo(info) if *i == id => Some(info.clone()),
            _ => None,
        })
    }

    fn errors(&self, id: SessionId) -> Vec<String> {
        self.0
            .iter()
            .filter(|(i, _)| *i == id)
            .filter_map(|(_, e)| match e {
                SessionEvent::Error(r) => Some(r.short.clone()),
                _ => None,
            })
            .collect()
    }
}

fn screen(handle: &SessionHandle) -> String {
    let term = handle.term.lock();
    let (cols, rows) = term.size();
    let top = -i32::try_from(term.scrollback_len()).unwrap();
    term.grid_text(
        GridPoint::new(top, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

/// Type `word` and wait for the echo.
async fn echo(handle: &SessionHandle, word: &str) {
    handle
        .cmd_tx
        .send(SessionCmd::Input(Bytes::from(format!("{word}\r"))))
        .await
        .unwrap();
    let needle = format!("out:{word}");
    let deadline = Instant::now() + WAIT;
    loop {
        let text = screen(handle);
        if text.contains(&needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{needle:?} not on screen:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const HOST: u8 = 1;

// ---------------------------------------------------------------- tests

/// T-05 (loopback): two tabs to the same host → one TCP connection, one
/// authentication, two shell channels; the second goes from `Resolving` straight to
/// `Connected`, and the info panel shows the shared connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_two_tabs_share_one_connection() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();

    let a = open(&mgr, HOST, false);
    log.connected(&mut rx, a.id).await;
    let b = open(&mgr, HOST, false);
    log.connected(&mut rx, b.id).await;
    echo(&a, "alpha").await;
    echo(&b, "bravo").await;
    {
        let c = counts.lock();
        assert_eq!((c.tcp, c.auths, c.sessions, c.open), (1, 1, 2, 2));
    }
    // The shared session skipped the connecting states.
    let states = log.states(b.id);
    assert!(
        !states
            .iter()
            .any(|s| matches!(s, SessionState::Connecting { .. })),
        "{states:?}"
    );
    assert_eq!(log.info(a.id).unwrap().shared_channels, Some(1));
    assert_eq!(log.info(b.id).unwrap().shared_channels, Some(2));
    assert_eq!(
        log.info(a.id).unwrap().cipher,
        log.info(b.id).unwrap().cipher
    );

    // Closing one tab closes its channel only.
    a.cmd_tx.send(SessionCmd::Close).await.unwrap();
    eventually("the first channel closed", || counts.lock().open == 1).await;
    echo(&b, "still").await;
    assert_eq!(counts.lock().tcp, 1);
    // Reopening within the linger time reuses the connection.
    b.cmd_tx.send(SessionCmd::Close).await.unwrap();
    eventually("no channel open", || counts.lock().open == 0).await;
    let c = open(&mgr, HOST, false);
    log.connected(&mut rx, c.id).await;
    echo(&c, "again").await;
    assert_eq!(counts.lock().tcp, 1, "reused while lingering");
}

/// T-02 (loopback): tabs opened at the same moment make one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_concurrent_tabs_dial_once() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let tabs: Vec<_> = (0..5).map(|_| open(&mgr, HOST, false)).collect();
    for tab in &tabs {
        log.connected(&mut rx, tab.id).await;
    }
    for (i, tab) in tabs.iter().enumerate() {
        echo(tab, &format!("tab{i}")).await;
    }
    let c = counts.lock();
    assert_eq!((c.tcp, c.auths, c.sessions), (1, 1, 5));
}

/// T-06 (loopback): a `MaxSessions 2` server, 3 tabs → the third gets a new
/// connection and all 3 work; a fourth prefers the newer connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_session_limit_opens_another_connection() {
    let (addr, counts) = start(Some(2)).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let mut tabs = Vec::new();
    for _ in 0..3 {
        let tab = open(&mgr, HOST, false);
        log.connected(&mut rx, tab.id).await;
        tabs.push(tab);
    }
    for (i, tab) in tabs.iter().enumerate() {
        echo(tab, &format!("tab{i}")).await;
    }
    {
        let c = counts.lock();
        assert_eq!((c.tcp, c.sessions, c.refused), (2, 3, 1));
    }
    let fourth = open(&mgr, HOST, false);
    log.connected(&mut rx, fourth.id).await;
    echo(&fourth, "four").await;
    let c = counts.lock();
    assert_eq!((c.tcp, c.sessions, c.refused), (2, 4, 1), "{c:?}");
}

/// T-07 (loopback): a standalone forward (tunnel-only session) reuses the tab's
/// connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_forward_reuses_the_tab() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let tab = open(&mgr, HOST, false);
    log.connected(&mut rx, tab.id).await;
    let tunnel = open(&mgr, HOST, true);
    log.connected(&mut rx, tunnel.id).await;
    // Closing the tunnel keeps the tab's connection.
    tunnel.cmd_tx.send(SessionCmd::Close).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    echo(&tab, "tab").await;
    let c = counts.lock();
    assert_eq!((c.tcp, c.auths), (1, 1), "{c:?}");
}

/// T-07 (loopback): an exec run reuses the tab's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_exec_reuses_the_tab() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let tab = open(&mgr, HOST, false);
    log.connected(&mut rx, tab.id).await;
    let run = SshConnection::open(&conn, &spec(HOST), ExecPrompts::none())
        .await
        .unwrap();
    let result = exec(&run, "uptime", ExecOpts::default()).await.unwrap();
    assert_eq!(&result.stdout[..], b"exec:uptime");
    assert!(result.success());
    run.close().await;
    echo(&tab, "tab").await;
    let c = counts.lock();
    assert_eq!((c.tcp, c.auths), (1, 1), "{c:?}");
}

/// T-08 (loopback): two targets behind the same bastion share the bastion connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_targets_share_the_bastion() {
    const BASTION: u8 = 2;
    const T1: u8 = 3;
    const T2: u8 = 4;
    let (bastion_addr, bastion) = start(None).await;
    let (inner_addr, inner) = start(None).await;
    let mut hosts = Hosts::default();
    hosts
        .add(BASTION, bastion_addr, "ops", &[])
        .add(T1, inner_addr, "alice", &[BASTION])
        .add(T2, inner_addr, "bob", &[BASTION]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let a = open(&mgr, T1, false);
    log.connected(&mut rx, a.id).await;
    let b = open(&mgr, T2, false);
    log.connected(&mut rx, b.id).await;
    echo(&a, "alice").await;
    echo(&b, "bob").await;
    assert_eq!(bastion.lock().tcp, 1, "one bastion connection");
    assert_eq!(
        bastion.lock().sessions,
        0,
        "only direct-tcpip on the bastion"
    );
    assert_eq!(inner.lock().tcp, 2, "one connection per target user");
    assert!(log.info(b.id).unwrap().peer.contains(" via "));
    // The second target dialed only itself (one hop left: `Connecting { 1, 1 }`).
    let states = log.states(b.id);
    assert!(
        states
            .iter()
            .any(|s| matches!(s, SessionState::Connecting { hop: 1, of: 1 })),
        "{states:?}"
    );
    // A third tab to the first target shares everything.
    let c = open(&mgr, T1, false);
    log.connected(&mut rx, c.id).await;
    echo(&c, "again").await;
    assert_eq!((bastion.lock().tcp, inner.lock().tcp), (1, 2));
}

/// T-09 (loopback): `multiplex = false` → separate connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_multiplex_off_separate_connections() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, false);
    assert!(!conn.multiplex());
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let a = open(&mgr, HOST, false);
    log.connected(&mut rx, a.id).await;
    let b = open(&mgr, HOST, false);
    log.connected(&mut rx, b.id).await;
    echo(&a, "a").await;
    echo(&b, "b").await;
    assert_eq!(counts.lock().tcp, 2);
    assert_eq!(log.info(b.id).unwrap().shared_channels, None);
    // Closing disconnects at once (nothing lingers).
    a.cmd_tx.send(SessionCmd::Close).await.unwrap();
    eventually("the first connection closed", || {
        counts
            .lock()
            .conns
            .iter()
            .filter(|t| t.is_finished())
            .count()
            == 1
    })
    .await;
    // The setting applies to new connects.
    conn.set_multiplex(true);
    let c = open(&mgr, HOST, false);
    log.connected(&mut rx, c.id).await;
    let d = open(&mgr, HOST, false);
    log.connected(&mut rx, d.id).await;
    assert_eq!(counts.lock().tcp, 3);
}

/// T-04 (loopback): the shared connection drops → both tabs and a standalone tunnel on
/// it disconnect with the same reason; reconnecting one tab re-establishes the
/// connection, the other reconnects onto it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_drop_disconnects_every_tab_and_reconnect_shares_again() {
    let (addr, counts) = start(None).await;
    let mut hosts = Hosts::default();
    hosts.add(HOST, addr, "sverb", &[]);
    let conn = connector(hosts, true);
    let (mgr, mut rx) = manager(&conn);
    let mut log = Log::default();
    let a = open(&mgr, HOST, false);
    log.connected(&mut rx, a.id).await;
    let b = open(&mgr, HOST, false);
    log.connected(&mut rx, b.id).await;
    let tunnel = open(&mgr, HOST, true);
    log.connected(&mut rx, tunnel.id).await;
    assert_eq!(counts.lock().tcp, 1);

    // The server drops the connection.
    drop_all(&counts);
    let ra = log.disconnected(&mut rx, a.id).await;
    let rb = log.disconnected(&mut rx, b.id).await;
    let rt = log.disconnected(&mut rx, tunnel.id).await;
    assert_eq!(ra, rb);
    assert_eq!(ra, rt, "the tunnel sees the same reason");
    assert_ne!(ra, DisconnectReason::Closed);
    assert_eq!(log.errors(a.id), log.errors(b.id));
    assert_eq!(log.errors(a.id), log.errors(tunnel.id));

    a.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    log.0.retain(|(i, _)| *i != a.id && *i != b.id);
    log.connected(&mut rx, a.id).await;
    b.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    log.connected(&mut rx, b.id).await;
    echo(&a, "back").await;
    echo(&b, "both").await;
    assert_eq!(counts.lock().tcp, 2, "one new connection for both");
}
