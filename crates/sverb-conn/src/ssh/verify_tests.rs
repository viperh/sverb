//! M1-15 loopback tests: the known-hosts verifier against the in-process russh server
//! (no Docker). Unknown → accept & save → no prompt next time (T-14), changed key →
//! red warning → reject (T-15), several key types with one known (T-16), a host
//! certificate from a trusted CA (T-17), `accept-new`, `strict`, `@revoked`, and the
//! 120 s prompt timeout in virtual time (T-12). The Docker variants are at the end,
//! `#[ignore]`d for the M1-18 harness.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use parking_lot::Mutex;
use russh::{
    keys::{
        Certificate, PrivateKey,
        ssh_key::{
            certificate::{Builder, CertType},
            private::Ed25519Keypair,
        },
    },
    server,
};
use sverb_core::{
    config::HostKeyPolicy,
    known_hosts::{KeyInfo, lookup_key},
    model::{KnownHost, KnownHostMarker},
};
use tokio::{net::TcpListener, sync::mpsc};

use super::testing::{Seen, TestResolver, TestServer};
use super::*;
use crate::{
    DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionState, TransportKind, session::Decision,
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const WAIT: Duration = Duration::from_secs(10);

/// An unencrypted ECDSA P-256 test key (generated with `ssh-keygen -t ecdsa -b 256`).
const ECDSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS0AboLihakmpKQ14Zr9Jijz62moxcD
fkyfcecNnu8XVpL2NW8+z7LeULfM8qedOyfij+uGJAxY5VDqO9iJ73YwAAAAmHEXD8xxFw
/MAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLQBuguKFqSakpDX
hmv0mKPPraajFwN+TJ9x5w2e7xdWkvY1bz7Pst5Qt8zyp507J+KP64YkDFjlUOo72Invdj
AAAAAgewa9AfaFVl2MA7oKW2D/245HJ/9v3Gx5ku+Q4Ln8CRgAAAAA
-----END OPENSSH PRIVATE KEY-----
";

fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn ecdsa() -> PrivateKey {
    PrivateKey::from_openssh(ECDSA_KEY).unwrap()
}

/// A `known_hosts` entry for `key` under `pattern`.
fn entry(pattern: &str, key: &PrivateKey, marker: KnownHostMarker) -> KnownHost {
    let info = KeyInfo::of(key.public_key().key_data());
    KnownHost {
        host_pattern: pattern.to_owned(),
        key_type: info.key_type,
        public_key: info.base64,
        marker,
        ..KnownHost::default()
    }
}

fn fingerprint(key: &PrivateKey) -> String {
    KeyInfo::of(key.public_key().key_data()).fingerprint
}

/// A host certificate for `key` signed by `ca`, valid for `principal` now.
fn host_cert(key: &PrivateKey, ca: &PrivateKey, principal: &str) -> Certificate {
    let now = u64::try_from(sverb_core::model::UnixMillis::now().0 / 1000).unwrap();
    let mut b = Builder::new(
        [9_u8; 32].to_vec(),
        key.public_key().key_data().clone(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    b.cert_type(CertType::Host).unwrap();
    b.key_id("sverb-test-host").unwrap();
    b.valid_principal(principal).unwrap();
    b.sign(ca).unwrap()
}

/// The test server (password `secret`) with these host keys and certificates.
async fn server(keys: Vec<PrivateKey>, certificates: Vec<Certificate>) -> SocketAddr {
    let config = Arc::new(server::Config {
        keys,
        certificates,
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = TestServer {
        seen: Arc::new(Mutex::new(Seen::default())),
    };
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = Arc::clone(&config);
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    addr
}

fn verifier(
    entries: Vec<KnownHost>,
    policy: HostKeyPolicy,
) -> (Arc<MemoryKnownHosts>, Arc<KnownHostsVerifier>) {
    let store = Arc::new(MemoryKnownHosts::new(entries));
    let v = KnownHostsVerifier::new(
        Arc::clone(&store) as Arc<dyn KnownHostsStore>,
        VerifyOptions {
            policy,
            hash_known_hosts: false,
        },
    );
    (store, Arc::new(v))
}

fn manager(addr: SocketAddr, verifier: Arc<KnownHostsVerifier>) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    let connector = SshConnector::new(Arc::new(TestResolver {
        addr,
        password: "secret",
        edit: |_| {},
    }))
    .with_verifier(verifier);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    (mgr, rx)
}

fn open(mgr: &SessionManager) -> SessionHandle {
    mgr.open_with(
        crate::SessionSpec::Ssh(crate::SshSpec {
            host: "ignored".into(),
            port: 22,
            ..crate::SshSpec::default()
        }),
        OpenOptions {
            cols: 80,
            rows: 24,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

/// What happened up to the first `Connected`/`Disconnected`.
#[derive(Debug, Default)]
struct Outcome {
    prompts: Vec<crate::Verification>,
    connected: bool,
    reason: Option<DisconnectReason>,
    host_key_algo: Option<String>,
    errors: Vec<String>,
}

/// Run a session, answering host-key prompts with `answer` (`None`: never answer).
async fn run(
    mgr: &SessionManager,
    rx: &mut Events,
    answer: Option<Decision>,
) -> (SessionHandle, Outcome) {
    let handle = open(mgr);
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
                SessionEvent::SshInfo(info) => out.host_key_algo = Some(info.host_key),
                SessionEvent::Error(r) => {
                    out.errors
                        .push(format!("{} {}", r.short, r.chain.join(" / ")));
                }
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
    (handle, out)
}

/// T-14 (loopback): unknown key → modal → accept & save → the next connection does not
/// ask. The prompt shows the fingerprint, key type and randomart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t14_unknown_accept_save_then_no_prompt() {
    let key = ed25519(42);
    let addr = server(vec![key.clone()], vec![]).await;
    let (store, v) = verifier(vec![], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);

    let (_h, out) = run(&mgr, &mut rx, Some(Decision::AcceptAndSave)).await;
    assert!(out.connected, "{out:?}");
    let [prompt] = out.prompts.as_slice() else {
        panic!("{out:?}")
    };
    assert!(!prompt.changed);
    assert_eq!(prompt.fingerprint, fingerprint(&key));
    assert_eq!(prompt.details.key_type, "ssh-ed25519");
    assert_eq!(prompt.details.hostname, "127.0.0.1");
    assert!(prompt.details.randomart.starts_with("+--[ED25519 256]--+"));
    let saves = store.saves();
    assert_eq!(saves.len(), 1);
    assert_eq!(
        saves[0].0.host_pattern,
        lookup_key("127.0.0.1", addr.port())
    );
    assert!(!saves[0].1, "saved by the user, not accept-new");

    let (_h, out) = run(&mgr, &mut rx, None).await;
    assert!(out.connected && out.prompts.is_empty(), "{out:?}");

    // "Once" does not save.
    let (store, v) = verifier(vec![], HostKeyPolicy::Ask);
    let (mgr2, mut rx2) = manager(addr, v);
    let (_h, out) = run(&mgr2, &mut rx2, Some(Decision::AcceptOnce)).await;
    assert!(out.connected && out.prompts.len() == 1);
    assert!(store.saves().is_empty());
    mgr.shutdown(Duration::from_secs(2)).await;
    mgr2.shutdown(Duration::from_secs(2)).await;
}

/// T-15 (loopback): a changed key → the changed-key prompt with old and new
/// fingerprints → reject → `Disconnected { HostKey }`; "replace" (accept & save after
/// the typed host name) swaps the entry. `strict` and `accept-new` reject without asking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t15_changed_key() {
    let (old, new) = (ed25519(41), ed25519(42));
    let addr = server(vec![new.clone()], vec![]).await;
    let pattern = lookup_key("127.0.0.1", addr.port());
    let known = vec![entry(&pattern, &old, KnownHostMarker::None)];

    let (store, v) = verifier(known.clone(), HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, Some(Decision::Reject)).await;
    assert_eq!(out.reason, Some(DisconnectReason::HostKey), "{out:?}");
    let [prompt] = out.prompts.as_slice() else {
        panic!("{out:?}")
    };
    assert!(prompt.changed);
    assert_eq!(prompt.details.old_fingerprints, [fingerprint(&old)]);
    assert_eq!(prompt.fingerprint, fingerprint(&new));
    assert!(store.saves().is_empty());

    // Replace.
    let (_h, out) = run(&mgr, &mut rx, Some(Decision::AcceptAndSave)).await;
    assert!(out.connected, "{out:?}");
    let entries = store.entries();
    assert_eq!(
        entries.len(),
        1,
        "the old key of that type is gone: {entries:?}"
    );
    assert_eq!(
        entries[0].public_key,
        KeyInfo::of(new.public_key().key_data()).base64
    );
    mgr.shutdown(Duration::from_secs(2)).await;

    for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
        let (store, v) = verifier(known.clone(), policy);
        let (mgr, mut rx) = manager(addr, v);
        let (_h, out) = run(&mgr, &mut rx, Some(Decision::AcceptAndSave)).await;
        assert_eq!(
            out.reason,
            Some(DisconnectReason::HostKey),
            "{policy:?}: {out:?}"
        );
        assert!(out.prompts.is_empty());
        assert!(
            out.errors
                .iter()
                .any(|e| e.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")),
            "{out:?}"
        );
        assert!(store.saves().is_empty());
        mgr.shutdown(Duration::from_secs(2)).await;
    }
}

/// T-16 (loopback): the server offers ed25519 and ecdsa, only the ecdsa key is known →
/// no prompt, ecdsa negotiated (known types are preferred).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t16_multiple_key_types() {
    let addr = server(vec![ed25519(42), ecdsa()], vec![]).await;
    let pattern = lookup_key("127.0.0.1", addr.port());
    let (_, v) = verifier(
        vec![entry(&pattern, &ecdsa(), KnownHostMarker::None)],
        HostKeyPolicy::Ask,
    );
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, None).await;
    assert!(out.connected && out.prompts.is_empty(), "{out:?}");
    assert_eq!(out.host_key_algo.as_deref(), Some("ecdsa-sha2-nistp256"));
    mgr.shutdown(Duration::from_secs(2)).await;

    // Without the reordering the server's first type (ed25519) would be unknown.
    let (_, v) = verifier(vec![], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, Some(Decision::Reject)).await;
    assert_eq!(out.prompts[0].details.key_type, "ssh-ed25519");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-17 (loopback): a host certificate signed by a CA trusted with `@cert-authority`
/// → no prompt. A revoked CA, or a certificate for another principal, is not accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_cert_authority() {
    let (key, ca) = (ed25519(42), ed25519(7));
    let ca_entry = entry("[127.0.0.1]:*", &ca, KnownHostMarker::CertAuthority);

    let addr = server(vec![key.clone()], vec![host_cert(&key, &ca, "127.0.0.1")]).await;
    let (store, v) = verifier(vec![ca_entry.clone()], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, None).await;
    // No plain entry exists, so connecting without a prompt means the certificate was
    // presented and accepted (russh reports the certified key's algorithm).
    assert!(out.connected && out.prompts.is_empty(), "{out:?}");
    assert!(store.saves().is_empty());
    mgr.shutdown(Duration::from_secs(2)).await;

    // @revoked beats the CA: rejected without a prompt.
    let revoked = entry("*", &ca, KnownHostMarker::Revoked);
    let (_, v) = verifier(vec![ca_entry.clone(), revoked], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, Some(Decision::AcceptOnce)).await;
    assert_eq!(out.reason, Some(DisconnectReason::HostKey), "{out:?}");
    assert!(out.prompts.is_empty());
    assert!(out.errors.iter().any(|e| e.contains("@revoked")), "{out:?}");
    mgr.shutdown(Duration::from_secs(2)).await;

    // A certificate for another host: treated as an unknown plain key (asked).
    let other = server(vec![key.clone()], vec![host_cert(&key, &ca, "db.test")]).await;
    let (_, v) = verifier(vec![ca_entry], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(other, v);
    let (_h, out) = run(&mgr, &mut rx, Some(Decision::Reject)).await;
    let [prompt] = out.prompts.as_slice() else {
        panic!("{out:?}")
    };
    assert!(
        prompt
            .details
            .note
            .as_deref()
            .is_some_and(|n| n.contains("not valid for 127.0.0.1")),
        "{prompt:?}"
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// `accept-new` saves an unknown key without asking; `strict` rejects it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_new_and_strict_with_unknown_keys() {
    let addr = server(vec![ed25519(42)], vec![]).await;
    let (store, v) = verifier(vec![], HostKeyPolicy::AcceptNew);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, None).await;
    assert!(out.connected && out.prompts.is_empty(), "{out:?}");
    let saves = store.saves();
    assert_eq!(saves.len(), 1);
    assert!(saves[0].1, "auto-saved");
    mgr.shutdown(Duration::from_secs(2)).await;

    let (store, v) = verifier(vec![], HostKeyPolicy::Strict);
    let (mgr, mut rx) = manager(addr, v);
    let (_h, out) = run(&mgr, &mut rx, None).await;
    assert_eq!(out.reason, Some(DisconnectReason::HostKey), "{out:?}");
    assert!(out.prompts.is_empty() && store.saves().is_empty());
    assert!(out.errors.iter().any(|e| e.contains("strict")), "{out:?}");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-12: no decision within 120 s (virtual time) → reject → `Disconnected { HostKey }`.
#[tokio::test]
async fn t12_prompt_timeout_rejects() {
    let addr = server(vec![ed25519(42)], vec![]).await;
    let (store, v) = verifier(vec![], HostKeyPolicy::Ask);
    let (mgr, mut rx) = manager(addr, v);
    let _handle = open(&mgr);
    // Wait (in real time) until the handshake is suspended on the prompt.
    loop {
        let (_, ev) = tokio::time::timeout(WAIT, rx.recv())
            .await
            .unwrap()
            .unwrap();
        if matches!(ev, SessionEvent::HostKey(_)) {
            break;
        }
    }
    // Then let virtual time run: the 120 s prompt timeout fires at once.
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let mut errors = Vec::new();
    let reason = loop {
        let (_, ev) = rx.recv().await.unwrap();
        match ev {
            SessionEvent::Error(r) => errors.push(r.chain.join(" / ")),
            SessionEvent::State(SessionState::Disconnected { reason, .. }) => break reason,
            SessionEvent::State(SessionState::Connected { .. }) => panic!("connected"),
            _ => {}
        }
    };
    assert_eq!(reason, DisconnectReason::HostKey);
    assert!(started.elapsed() >= HOST_KEY_PROMPT_TIMEOUT);
    assert!(errors.iter().any(|e| e.contains("120 s")), "{errors:?}");
    assert!(store.saves().is_empty());
    tokio::time::resume();
    mgr.shutdown(Duration::from_secs(2)).await;
}

// ------------------------------------------------------------- Docker (M1-18)

/// T-14…T-17 against OpenSSH in Docker (M1-18 harness): unknown → accept → reconnect
/// without a prompt; regenerate the container host key → red warning, reject →
/// `HostKey`; ecdsa known and ed25519 + ecdsa offered → no prompt; a host certificate
/// signed by the test CA with `@cert-authority *.test` → no prompt. Covered on loopback
/// above until the harness lands.
#[tokio::test]
#[ignore = "needs Docker (M1-18 e2e harness)"]
async fn e2e_openssh_t14_to_t17() {
    unimplemented!("M1-18: run the loopback scenarios against the OpenSSH container")
}
