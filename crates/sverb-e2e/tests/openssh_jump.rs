//! host reachable only from the bastion). The loopback versions run without Docker in
//! `sverb-conn` (`ssh::connect::jump::tests`).
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_jump -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use sverb_conn::{
    DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionSpec, SessionState, SshSpec, TransportKind, Verification,
    session::Decision,
    ssh::{
        HostKeyVerifier, HostResolver, KnownHostsStore, KnownHostsVerifier, MemoryKnownHosts,
        SshConnector, SshError, SshTarget, VerifyOptions, resolve,
    },
};
use sverb_core::{
    config::{Config, HostKeyPolicy},
    known_hosts::lookup::lookup_key,
    model::{Host, ItemId},
    secret::SecretString,
};
use sverb_e2e::{JumpNet, RecordingVerifier, keys, require_docker, timeout};
use tokio::sync::mpsc;

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const BASTION: u8 = 1;
const INNER: u8 = 2;

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

/// The bastion (as the runner reaches it) and the inner host (as the bastion reaches
/// it), with the fixture password; `wrong` gets a wrong one.
#[derive(Debug)]
struct Hosts(HashMap<ItemId, Host>);

impl Hosts {
    fn new(net: &JumpNet, wrong: Option<u8>) -> Self {
        let (inner, inner_port) = net.inner_addr_from_bastion();
        let host = |label: &str, address: String, port: u16, chain: Vec<ItemId>, b: u8| Host {
            label: label.into(),
            address,
            port: Some(port),
            username: Some(keys::USER.into()),
            password: Some(SecretString::from(if wrong == Some(b) {
                "wrong"
            } else {
                keys::PASSWORD
            })),
            jump_chain: chain,
            ..Host::default()
        };
        Self(HashMap::from([
            (
                id(BASTION),
                host(
                    "bastion",
                    net.bastion.host(),
                    net.bastion.port(),
                    Vec::new(),
                    BASTION,
                ),
            ),
            (
                id(INNER),
                host("inner", inner, inner_port, vec![id(BASTION)], INNER),
            ),
        ]))
    }
}

#[async_trait]
impl HostResolver for Hosts {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let host_id = spec.host_id.unwrap_or(id(INNER));
        let host = self
            .0
            .get(&host_id)
            .ok_or_else(|| SshError::Settings("the host no longer exists".into()))?;
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 10;
        Ok(resolve(host, Some(host_id), None, &config, || None))
    }
}

fn open(
    hosts: Hosts,
    verifier: Arc<dyn HostKeyVerifier>,
) -> (SessionManager, SessionHandle, Events) {
    let connector = SshConnector::new(Arc::new(hosts)).with_verifier(verifier);
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    let handle = mgr
        .open_with(
            SessionSpec::Ssh(SshSpec {
                host: "inner".into(),
                host_id: Some(id(INNER)),
                ..SshSpec::default()
            }),
            OpenOptions {
                cols: 80,
                rows: 24,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    (mgr, handle, rx)
}

#[derive(Debug, Default)]
struct Outcome {
    prompts: Vec<Verification>,
    errors: Vec<String>,
    connected: bool,
    reason: Option<DisconnectReason>,
}

async fn run(handle: &SessionHandle, rx: &mut Events, answer: Option<Decision>) -> Outcome {
    let mut out = Outcome::default();
    let done = tokio::time::timeout(timeout() * 2, async {
        while let Some((_, ev)) = rx.recv().await {
            match ev {
                SessionEvent::HostKey(v) => {
                    out.prompts.push(v);
                    if let Some(d) = answer {
                        handle
                            .cmd_tx
                            .send(SessionCmd::HostKeyDecision(d))
                            .await
                            .unwrap();
                    }
                }
                SessionEvent::Error(r) => out.errors.push(r.short),
                SessionEvent::State(SessionState::Connected { .. }) => {
                    out.connected = true;
                    return;
                }
                SessionEvent::State(SessionState::Disconnected { reason, .. }) => {
                    out.reason = Some(reason);
                    return;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(done.is_ok(), "no outcome: {out:?}");
    out
}

/// A shell on `inner` through `bastion`; the known hosts get both entries under
/// their own names (the inner one as the bastion reaches it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t05_single_hop() {
    require_docker!();
    let net = JumpNet::start().await.unwrap();
    let store = Arc::new(MemoryKnownHosts::new(Vec::new()));
    let verifier = KnownHostsVerifier::new(
        Arc::clone(&store) as Arc<dyn KnownHostsStore>,
        VerifyOptions {
            policy: HostKeyPolicy::AcceptNew,
            hash_known_hosts: false,
        },
    );
    let (mgr, handle, mut rx) = open(Hosts::new(&net, None), Arc::new(verifier));
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    handle
        .cmd_tx
        .send(SessionCmd::Input(sverb_conn::Bytes::from_static(
            b"hostname\r",
        )))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let patterns: Vec<String> = store
        .saves()
        .into_iter()
        .map(|(k, _)| k.host_pattern)
        .collect();
    let (inner, port) = net.inner_addr_from_bastion();
    assert_eq!(
        patterns,
        [
            lookup_key(&net.bastion.host(), net.bastion.port()),
            lookup_key(&inner, port),
        ]
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// A wrong password on the bastion → "hop 1/2 (bastion): …"; on the inner host
/// → "hop 2/2 (inner): …".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t06_hop_labelled_errors() {
    require_docker!();
    let net = JumpNet::start().await.unwrap();
    for (wrong, prefix) in [
        (BASTION, "hop 1/2 (bastion): "),
        (INNER, "hop 2/2 (inner): "),
    ] {
        let (mgr, handle, mut rx) = open(
            Hosts::new(&net, Some(wrong)),
            Arc::new(RecordingVerifier::default()),
        );
        let out = run(&handle, &mut rx, None).await;
        assert_eq!(out.reason, Some(DisconnectReason::Auth), "{out:?}");
        assert!(out.errors.iter().any(|e| e.starts_with(prefix)), "{out:?}");
        mgr.shutdown(Duration::from_secs(2)).await;
    }
}

/// The inner host's first connection asks with the hop (`hop 2/2`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t07_host_key_prompt_shows_the_hop() {
    require_docker!();
    let net = JumpNet::start().await.unwrap();
    let verifier = KnownHostsVerifier::new(
        Arc::new(MemoryKnownHosts::new(Vec::new())) as Arc<dyn KnownHostsStore>,
        VerifyOptions {
            policy: HostKeyPolicy::Ask,
            hash_known_hosts: false,
        },
    );
    let (mgr, handle, mut rx) = open(Hosts::new(&net, None), Arc::new(verifier));
    let out = run(&handle, &mut rx, Some(Decision::AcceptOnce)).await;
    assert!(out.connected, "{out:?}");
    let (inner, _) = net.inner_addr_from_bastion();
    let hops: Vec<(usize, usize, String)> = out
        .prompts
        .iter()
        .map(|p| (p.hop, p.of, p.details.hostname.clone()))
        .collect();
    assert_eq!(hops[1], (2, 2, inner), "{hops:?}");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// `docker stop bastion` → the target session disconnects naming the hop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t08_bastion_dies() {
    require_docker!();
    let net = JumpNet::start().await.unwrap();
    let (mgr, handle, mut rx) = open(
        Hosts::new(&net, None),
        Arc::new(RecordingVerifier::default()),
    );
    let out = run(&handle, &mut rx, None).await;
    assert!(out.connected, "{out:?}");
    net.bastion.stop().await.unwrap();
    let out = run(&handle, &mut rx, None).await;
    assert!(
        matches!(
            out.reason,
            Some(DisconnectReason::Connect | DisconnectReason::Timeout)
        ),
        "{out:?}"
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.starts_with("hop 1/2 (bastion)")),
        "{out:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}
