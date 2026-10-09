//! (no Docker). T-05…T-08 of the task run here; the Docker `JumpNet` variants are in
//! `crates/sverb-e2e` (`#[ignore]`d).
//!
//! The test server connects `direct-tcpip` to loopback addresses and to names ending
//! in `.sverb-test` (→ 127.0.0.1), so hops are named `inner.sverb-test` and so on:
//! known-hosts entries then show which name each hop was recorded under.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use parking_lot::Mutex;
use sverb_core::{
    config::{Config, HostKeyPolicy},
    known_hosts::lookup::lookup_key,
    model::{Host, ItemId},
    secret::SecretString,
};
use sverb_term::GridPoint;
use tokio::{net::TcpListener, sync::mpsc, task::AbortHandle};

use super::super::super::{
    HostKeyTarget, HostKeyVerdict, HostKeyVerifier, HostResolver, KnownHostsStore,
    KnownHostsVerifier, MemoryKnownHosts, ServerKey, SshConnector, SshError, SshTarget,
    VerifyOptions, resolve,
    testing::{Seen, start_server},
};
use crate::{
    Bytes, DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionSpec, SessionState, SshSpec, TransportKind, Verification,
    session::Decision,
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const WAIT: Duration = Duration::from_secs(15);

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

const TARGET: u8 = 1;
const BASTION: u8 = 2;
const INNER: u8 = 3;

/// Saved hosts by id; the session's spec names the target.
#[derive(Debug, Default)]
struct Hosts(HashMap<ItemId, Host>);

impl Hosts {
    fn add(&mut self, b: u8, label: &str, address: &str, port: u16, chain: &[u8]) -> &mut Host {
        self.0.insert(
            id(b),
            Host {
                label: label.into(),
                address: address.into(),
                port: Some(port),
                username: Some("sverb".into()),
                password: Some(SecretString::from("secret")),
                jump_chain: chain.iter().map(|b| id(*b)).collect(),
                ..Host::default()
            },
        );
        self.0.get_mut(&id(b)).unwrap()
    }
}

#[async_trait::async_trait]
impl HostResolver for Hosts {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host_id = spec.host_id.expect("saved hosts only");
        let host = self
            .0
            .get(&host_id)
            .ok_or_else(|| SshError::Settings("the host no longer exists".into()))?;
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        config.ssh.keepalive_secs = 0;
        Ok(resolve(host, Some(host_id), None, &config, || None))
    }
}

/// Accepts every key and records which hop asked under which name.
#[derive(Debug, Default)]
struct Recording(Mutex<Vec<HostKeyTarget>>);

impl HostKeyVerifier for Recording {
    fn verify(&self, target: &HostKeyTarget, _key: &ServerKey) -> HostKeyVerdict {
        self.0.lock().push(target.clone());
        HostKeyVerdict::Accept
    }
}

fn manager(hosts: Hosts, verifier: Arc<dyn HostKeyVerifier>) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    let connector = SshConnector::new(Arc::new(hosts)).with_verifier(verifier);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    (mgr, rx)
}

fn open(mgr: &SessionManager) -> SessionHandle {
    mgr.open_with(
        SessionSpec::Ssh(SshSpec {
            host: "target".into(),
            port: 22,
            host_id: Some(id(TARGET)),
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

fn known_hosts(policy: HostKeyPolicy) -> (Arc<MemoryKnownHosts>, Arc<KnownHostsVerifier>) {
    let store = Arc::new(MemoryKnownHosts::new(Vec::new()));
    let v = KnownHostsVerifier::new(
        Arc::clone(&store) as Arc<dyn KnownHostsStore>,
        VerifyOptions {
            policy,
            hash_known_hosts: false,
        },
    );
    (store, Arc::new(v))
}

/// What happened up to the first `Connected`/`Disconnected`.
#[derive(Debug, Default)]
struct Outcome {
    states: Vec<SessionState>,
    prompts: Vec<Verification>,
    errors: Vec<String>,
    peer: Option<String>,
    connected: bool,
    reason: Option<DisconnectReason>,
}

async fn run(handle: &SessionHandle, rx: &mut Events, answer: Option<Decision>) -> Outcome {
    let mut out = Outcome::default();
    let done = tokio::time::timeout(WAIT, async {
        loop {
            let (_, ev) = rx.recv().await.unwrap();
            match ev {
                SessionEvent::HostKey(v) => {
                    out.prompts.push(v);
                    if let Some(decision) = answer {
                        handle
                            .cmd_tx
                            .send(SessionCmd::HostKeyDecision(decision))
                            .await
                            .unwrap();
                    }
                }
                SessionEvent::SshInfo(info) => out.peer = Some(info.peer),
                SessionEvent::Error(r) => out.errors.push(r.short),
                SessionEvent::State(s) => {
                    out.states.push(s.clone());
                    match s {
                        SessionState::Connected { .. } => {
                            out.connected = true;
                            return;
                        }
                        SessionState::Disconnected { reason, .. } => {
                            out.reason = Some(reason);
                            return;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(done.is_ok(), "no outcome: {out:?}");
    out
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

async fn wait_screen(handle: &SessionHandle, needle: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let text = screen(handle);
        if text.contains(needle) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{needle:?} not on screen:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A TCP relay to `target` whose connections can all be cut (a host going down).
async fn relay(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<AbortHandle>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
    let list = Arc::clone(&conns);
    let accept = tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let mut server = tokio::net::TcpStream::connect(target).await.unwrap();
            let task = tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
            list.lock().push(task.abort_handle());
        }
    });
    conns.lock().push(accept.abort_handle());
    (addr, conns)
}

/// Bastion at 127.0.0.1 (`bastion_addr`), the target `inner.sverb-test` behind it.
fn two_hops(bastion_addr: SocketAddr, inner: SocketAddr) -> Hosts {
    let mut hosts = Hosts::default();
    hosts.add(BASTION, "bastion", "127.0.0.1", bastion_addr.port(), &[]);
    hosts.add(
        TARGET,
        "inner",
        "inner.sverb-test",
        inner.port(),
        &[BASTION],
    );
    hosts
}

fn assert_progress(states: &[SessionState], of: usize) {
    for hop in 1..=of {
        assert!(
            states.contains(&SessionState::Connecting { hop, of }),
            "no Connecting {{ {hop}, {of} }} in {states:?}"
        );
    }
}

/// Each hop's host key is checked under its own address:port (as the previous
/// hop reaches it); non-22 ports give `[addr]:port` lookup keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_host_key_lookup_per_hop() {
    let (bastion, _) = start_server().await;
    let (inner, _) = start_server().await;
    let recording = Arc::new(Recording::default());
    let (mgr, mut rx) = manager(two_hops(bastion, inner), recording.clone());
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    let seen: Vec<String> = recording
        .0
        .lock()
        .iter()
        .map(|t| lookup_key(&t.host, t.port))
        .collect();
    assert_eq!(
        seen,
        [
            format!("[127.0.0.1]:{}", bastion.port()),
            format!("[inner.sverb-test]:{}", inner.port()),
        ]
    );
    assert_eq!(lookup_key("bastion", 22), "bastion");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-05 (loopback): a shell on `inner` through `bastion`; per-hop progress; both host
/// keys saved under their own names; each hop authenticated with its own credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_single_hop_shell() {
    let (bastion, bastion_seen) = start_server().await;
    let (inner, inner_seen) = start_server().await;
    let (store, verifier) = known_hosts(HostKeyPolicy::AcceptNew);
    let (mgr, mut rx) = manager(two_hops(bastion, inner), verifier);
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    assert!(out.errors.is_empty(), "{out:?}");
    assert_eq!(out.states[1], SessionState::Connecting { hop: 1, of: 2 });
    assert_progress(&out.states, 2);
    assert_eq!(
        out.peer.as_deref(),
        Some(format!("inner.sverb-test:{} via {bastion}", inner.port()).as_str())
    );

    wait_screen(&handle, "TERM=xterm-256color").await;
    handle
        .cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"hello\r")))
        .await
        .unwrap();
    wait_screen(&handle, "out:hello").await;

    let patterns: Vec<String> = store
        .saves()
        .into_iter()
        .map(|(k, _)| k.host_pattern)
        .collect();
    assert_eq!(
        patterns,
        [
            format!("[127.0.0.1]:{}", bastion.port()),
            format!("[inner.sverb-test]:{}", inner.port()),
        ]
    );
    let seen = |s: &Arc<Mutex<Seen>>| {
        let s = s.lock();
        (s.users.clone(), s.direct.clone())
    };
    let (users, direct) = seen(&bastion_seen);
    assert_eq!(users, ["sverb"]);
    assert_eq!(
        direct,
        [("inner.sverb-test".to_owned(), u32::from(inner.port()))]
    );
    let (users, direct) = seen(&inner_seen);
    assert_eq!(users, ["sverb"]);
    assert!(direct.is_empty());
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// Recursion end to end: the target jumps through `inner-bastion`, which itself jumps
/// through `bastion` (three servers, `Connecting { 1..=3, 3 }`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursive_chain_connects_through_every_hop() {
    let (bastion, _) = start_server().await;
    let (middle, middle_seen) = start_server().await;
    let (target, _) = start_server().await;
    let mut hosts = Hosts::default();
    hosts.add(BASTION, "bastion", "127.0.0.1", bastion.port(), &[]);
    hosts.add(
        INNER,
        "inner-bastion",
        "middle.sverb-test",
        middle.port(),
        &[BASTION],
    );
    hosts.add(
        TARGET,
        "target",
        "target.sverb-test",
        target.port(),
        &[INNER],
    );
    let (mgr, mut rx) = manager(
        hosts,
        Arc::new(super::super::super::InsecureAcceptAnyHostKey::insecure_for_testing()),
    );
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    assert_progress(&out.states, 3);
    assert_eq!(
        middle_seen.lock().direct,
        [("target.sverb-test".to_owned(), u32::from(target.port()))]
    );
    wait_screen(&handle, "TERM=xterm-256color").await;
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-06 (loopback): a wrong password on the bastion fails as "hop 1/2 (bastion): …",
/// on the target as "hop 2/2 (inner): …"; both `Auth`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_hop_labelled_errors() {
    let (bastion, _) = start_server().await;
    let (inner, _) = start_server().await;
    for (wrong, prefix) in [
        (BASTION, "hop 1/2 (bastion): "),
        (TARGET, "hop 2/2 (inner): "),
    ] {
        let mut hosts = two_hops(bastion, inner);
        hosts.0.get_mut(&id(wrong)).unwrap().password = Some(SecretString::from("wrong"));
        let (mgr, mut rx) = manager(
            hosts,
            Arc::new(super::super::super::InsecureAcceptAnyHostKey::insecure_for_testing()),
        );
        let handle = open(&mgr);
        let out = run(&handle, &mut rx, None).await;
        assert_eq!(out.reason, Some(DisconnectReason::Auth), "{out:?}");
        assert!(
            out.errors
                .iter()
                .any(|e| e.starts_with(prefix) && e.contains("Permission denied")),
            "{prefix}: {out:?}"
        );
        mgr.shutdown(Duration::from_secs(2)).await;
    }
}

/// Cycles and unreachable hops fail before or while connecting, with clear messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cycles_and_unreachable_hops_fail_clearly() {
    let (bastion, _) = start_server().await;
    // T → B → T.
    let mut hosts = Hosts::default();
    hosts.add(BASTION, "bastion", "127.0.0.1", bastion.port(), &[TARGET]);
    hosts.add(TARGET, "inner", "inner.sverb-test", 22, &[BASTION]);
    let (mgr, mut rx) = manager(hosts, Arc::new(Recording::default()));
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert_eq!(out.reason, Some(DisconnectReason::Connect));
    assert_eq!(out.errors, ["Jump chain cycle: inner → bastion → inner"]);
    mgr.shutdown(Duration::from_secs(2)).await;

    // The bastion can't reach the target (not a test destination).
    let mut hosts = Hosts::default();
    hosts.add(BASTION, "bastion", "127.0.0.1", bastion.port(), &[]);
    hosts.add(TARGET, "inner", "inner.example.org", 22, &[BASTION]);
    let (mgr, mut rx) = manager(hosts, Arc::new(Recording::default()));
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert_eq!(out.reason, Some(DisconnectReason::Connect));
    assert!(
        out.errors.iter().any(|e| e.starts_with(
            "hop 2/2 (inner): Could not connect (inner.example.org:22) through bastion"
        )),
        "{out:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-07 (loopback): the host-key prompts carry the hop (`hop 2/2`) and the hop's own
/// host name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_host_key_prompt_shows_the_hop() {
    let (bastion, _) = start_server().await;
    let (inner, _) = start_server().await;
    let (_store, verifier) = known_hosts(HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(two_hops(bastion, inner), verifier);
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, Some(Decision::AcceptOnce)).await;
    assert!(out.connected, "{out:?}");
    let hops: Vec<(usize, usize, &str, u16)> = out
        .prompts
        .iter()
        .map(|p| (p.hop, p.of, p.details.hostname.as_str(), p.details.port))
        .collect();
    assert_eq!(
        hops,
        [
            (1, 2, "127.0.0.1", bastion.port()),
            (2, 2, "inner.sverb-test", inner.port()),
        ]
    );
    assert!(
        out.states
            .iter()
            .any(|s| matches!(s, SessionState::AwaitingHostKey(v) if v.hop == 2 && v.of == 2)),
        "{out:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-08 (loopback): the bastion goes down → the target session disconnects with the
/// hop named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_bastion_dies() {
    let (bastion, _) = start_server().await;
    let (inner, _) = start_server().await;
    let (via, conns) = relay(bastion).await;
    let (mgr, mut rx) = manager(
        two_hops(via, inner),
        Arc::new(super::super::super::InsecureAcceptAnyHostKey::insecure_for_testing()),
    );
    let handle = open(&mgr);
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    wait_screen(&handle, "TERM=xterm-256color").await;

    for task in conns.lock().drain(..) {
        task.abort();
    }
    let out = run(&handle, &mut rx, None).await;
    assert_eq!(out.reason, Some(DisconnectReason::Connect), "{out:?}");
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("hop 1/2 (bastion): connection")),
        "{out:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}
