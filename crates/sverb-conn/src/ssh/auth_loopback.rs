//! machine, prompts and answers over the command channel) against the in-process russh
//! server ([`auth_testing`](super::auth_testing)) and an in-process agent. These cover
//! the behaviour of the Docker e2e tests T-11…T-17, which are at the end, `#[ignore]`d
//! for the Docker e2e harness.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::{
    MethodKind, MethodSet,
    keys::{Algorithm, HashAlg, PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair},
};
use sverb_core::{
    config::Config,
    model::{Host, ItemId},
    secret::SecretString,
};
use tokio::sync::mpsc;

use super::{
    HostResolver, InsecureAcceptAnyHostKey, KeyMaterial, SshConnector, SshError, SshTarget,
    auth::ChainAuthenticator,
    auth_testing::{AuthPolicy, AuthSeen, KbdRound, start_auth_server},
    resolve, test_keys,
};
use crate::{
    AuthAnswer, DisconnectReason, OpenOptions, PromptKind, SessionCmd, SessionEvent, SessionHandle,
    SessionId, SessionManager, SessionState, TransportKind,
    agent_client::{AgentConnector, InProcessAgent},
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const WAIT: Duration = Duration::from_secs(10);
const HOST_ID: ItemId = ItemId::from_bytes([5; 16]);
const KEY_ID: ItemId = ItemId::from_bytes([6; 16]);

/// What the resolver puts into the target.
#[derive(Debug, Default, Clone)]
struct Creds {
    password: Option<&'static str>,
    key: Option<&'static str>,
    passphrase: Option<&'static str>,
    certs: Vec<&'static str>,
    max_attempts: Option<u32>,
    legacy_rsa: bool,
}

#[derive(Debug)]
struct Resolver {
    addr: SocketAddr,
    creds: Creds,
}

#[async_trait]
impl HostResolver for Resolver {
    async fn resolve(&self, _spec: &crate::SshSpec) -> Result<SshTarget, SshError> {
        let host = Host {
            label: "authbox".into(),
            address: self.addr.ip().to_string(),
            port: Some(self.addr.port()),
            username: Some("sverb".into()),
            password: self.creds.password.map(SecretString::from),
            ..Host::default()
        };
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 5;
        let mut t = resolve(&host, Some(HOST_ID), None, &config, || None);
        if let Some(key) = self.creds.key {
            t.auth.key_id = Some(KEY_ID);
            t.auth.key = Some(KeyMaterial {
                key_id: Some(KEY_ID),
                label: "test key".into(),
                private_key: SecretString::from(key),
                passphrase: self.creds.passphrase.map(SecretString::from),
                certificates: self.creds.certs.iter().map(|c| (*c).to_owned()).collect(),
            });
        }
        if let Some(n) = self.creds.max_attempts {
            t.auth.max_attempts = n;
        }
        t.auth.allow_ssh_rsa = self.creds.legacy_rsa;
        Ok(t)
    }
}

fn session(
    addr: SocketAddr,
    creds: Creds,
    agent: Option<Arc<dyn AgentConnector>>,
) -> (SessionManager, Events, SessionHandle) {
    let mut auth = ChainAuthenticator::new();
    if let Some(agent) = agent {
        auth = auth.with_agent(agent);
    }
    let connector = SshConnector::new(Arc::new(Resolver { addr, creds }))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
        .with_authenticator(Arc::new(auth));
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    let handle = mgr
        .open_with(
            crate::SessionSpec::Ssh(crate::SshSpec {
                host: "ignored".into(),
                port: 22,
                host_id: Some(HOST_ID),
                ..crate::SshSpec::default()
            }),
            OpenOptions {
                cols: 80,
                rows: 24,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    (mgr, rx, handle)
}

/// Events until one matches `pred` (returned with the ones before it).
async fn until(
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

fn connected(ev: &SessionEvent) -> bool {
    matches!(ev, SessionEvent::State(SessionState::Connected { .. }))
}

fn disconnected(ev: &SessionEvent) -> bool {
    matches!(ev, SessionEvent::State(SessionState::Disconnected { .. }))
}

fn prompt(ev: &SessionEvent) -> bool {
    matches!(ev, SessionEvent::Prompt(_))
}

/// Connected or disconnected (the end of authentication).
async fn outcome(rx: &mut Events) -> (SessionEvent, Vec<SessionEvent>) {
    until(rx, |e| connected(e) || disconnected(e)).await
}

fn error_text(events: &[SessionEvent]) -> Option<String> {
    events.iter().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.short.clone()),
        _ => None,
    })
}

async fn answer(handle: &SessionHandle, answers: &[&str]) {
    handle
        .cmd_tx
        .send(SessionCmd::AuthAnswer(AuthAnswer::Responses(
            answers.iter().map(|a| SecretString::from(*a)).collect(),
        )))
        .await
        .unwrap();
}

fn public(text: &str) -> PublicKey {
    PublicKey::from_openssh(text).unwrap()
}

fn methods(m: &[MethodKind]) -> MethodSet {
    MethodSet::from(m)
}

fn requests(seen: &Arc<Mutex<AuthSeen>>) -> Vec<String> {
    seen.lock().requests.clone()
}

// ---------------------------------------------------------------- tests

/// T-11 (loopback): password prompt → wrong → re-prompt → right: connects, and the
/// typed password is reported as accepted (the UI saves it only now).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_password_prompt() {
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        password: Some("secret"),
        methods: methods(&[MethodKind::Password]),
        ..AuthPolicy::default()
    })
    .await;
    let (mgr, mut rx, handle) = session(addr, Creds::default(), None);

    let (ev, before) = until(&mut rx, prompt).await;
    let SessionEvent::Prompt(p) = ev else {
        unreachable!()
    };
    assert_eq!(
        p.kind,
        PromptKind::Password {
            host: Some(HOST_ID)
        }
    );
    assert_eq!(p.title, "Authenticate to authbox");
    assert!(p.instruction.starts_with("Password for sverb@127.0.0.1"));
    assert!(p.prompts.len() == 1 && !p.prompts[0].echo);
    assert!(
        before
            .iter()
            .any(|e| matches!(e, SessionEvent::State(SessionState::AwaitingUser(_))))
    );
    answer(&handle, &["wrong"]).await;

    let (ev, before) = until(&mut rx, prompt).await;
    let SessionEvent::Prompt(p) = ev else {
        unreachable!()
    };
    assert!(p.instruction.contains("please try again"));
    assert!(
        !before
            .iter()
            .any(|e| matches!(e, SessionEvent::PromptAccepted(_))),
        "a wrong password is never reported as accepted"
    );
    answer(&handle, &["secret"]).await;

    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert!(
        before.contains(&SessionEvent::PromptAccepted(PromptKind::Password {
            host: Some(HOST_ID)
        }))
    );
    assert_eq!(requests(&seen), ["none", "password", "password"]);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-12 (loopback): ed25519 key; RSA with `server-sig-algs` offering only
/// `rsa-sha2-256` → accepted (russh verifies the signature with the algorithm it
/// advertised); an RSA key against a server offering no `rsa-sha2-*` → skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_key_auth() {
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        authorized: vec![public(test_keys::ED25519_PUB)],
        ..AuthPolicy::default()
    })
    .await;
    let creds = Creds {
        key: Some(test_keys::ED25519),
        ..Creds::default()
    };
    let (mgr, mut rx, _h) = session(addr, creds, None);
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert!(requests(&seen).contains(&"publickey:ssh-ed25519".to_owned()));
    mgr.shutdown(Duration::from_secs(2)).await;

    let rsa_server = |algs: Vec<Algorithm>| {
        start_auth_server(AuthPolicy {
            authorized: vec![public(test_keys::RSA_2048_PUB)],
            methods: methods(&[MethodKind::PublicKey]),
            sig_algs: Some(algs),
            ..AuthPolicy::default()
        })
    };
    let rsa = Creds {
        key: Some(test_keys::RSA_2048),
        ..Creds::default()
    };
    let (addr, _, seen) = rsa_server(vec![
        Algorithm::Ed25519,
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    ])
    .await;
    let (mgr, mut rx, _h) = session(addr, rsa.clone(), None);
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert!(requests(&seen).contains(&"publickey:ssh-rsa".to_owned()));
    mgr.shutdown(Duration::from_secs(2)).await;

    // No rsa-sha2-* advertised and no legacy opt-in: the key isn't even offered.
    let (addr, _, seen) = rsa_server(vec![Algorithm::Ed25519]).await;
    let (mgr, mut rx, _h) = session(addr, rsa, None);
    let (ev, before) = outcome(&mut rx).await;
    assert!(disconnected(&ev));
    assert_eq!(error_text(&before).as_deref(), Some("Permission denied"));
    assert_eq!(requests(&seen), ["none"]);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-13 (loopback): an encrypted key without a stored passphrase → passphrase prompt;
/// a wrong one is asked again; the right one connects and is reported for saving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_passphrase_prompt() {
    let (addr, _, _) = start_auth_server(AuthPolicy {
        authorized: vec![public(test_keys::ED25519_ENCRYPTED_PUB)],
        ..AuthPolicy::default()
    })
    .await;
    let creds = Creds {
        key: Some(test_keys::ED25519_ENCRYPTED),
        ..Creds::default()
    };
    let (mgr, mut rx, handle) = session(addr, creds.clone(), None);
    let kind = PromptKind::Passphrase {
        key: Some(KEY_ID),
        label: "test key".into(),
    };
    let (SessionEvent::Prompt(p), _) = until(&mut rx, prompt).await else {
        unreachable!()
    };
    assert_eq!(p.kind, kind);
    assert_eq!(p.method, crate::AuthMethod::PublicKey);
    answer(&handle, &["nope"]).await;
    let (SessionEvent::Prompt(p), _) = until(&mut rx, prompt).await else {
        unreachable!()
    };
    assert!(p.instruction.contains("Wrong passphrase"));
    answer(&handle, &[test_keys::PASSPHRASE]).await;
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert!(before.contains(&SessionEvent::PromptAccepted(kind)));
    mgr.shutdown(Duration::from_secs(2)).await;

    // Saved: the next connect needs no prompt.
    let saved = Creds {
        passphrase: Some(test_keys::PASSPHRASE),
        ..creds
    };
    let (mgr, mut rx, _h) = session(addr, saved, None);
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev));
    assert!(!before.iter().any(prompt));
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-14 (loopback): the key isn't authorized, but its certificate is signed by the
/// server's trusted CA → connects via the certificate (expired ones are skipped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_certificate_auth() {
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        trusted_ca: Some(public(test_keys::CA_PUB)),
        methods: methods(&[MethodKind::PublicKey]),
        ..AuthPolicy::default()
    })
    .await;
    let creds = Creds {
        key: Some(test_keys::ED25519),
        certs: vec![test_keys::ED25519_CERT_EXPIRED, test_keys::ED25519_CERT],
        ..Creds::default()
    };
    let (mgr, mut rx, _h) = session(addr, creds, None);
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    let reqs = requests(&seen);
    assert!(reqs.contains(&"cert:testcert".to_owned()), "{reqs:?}");
    assert!(!reqs.contains(&"cert:expired".to_owned()));
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-15 (loopback): keyboard-interactive, two rounds: the password round is answered
/// with the stored password (no dialog), the OTP round is a dialog with the server's
/// (sanitized) name and instruction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_keyboard_interactive() {
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        methods: methods(&[MethodKind::KeyboardInteractive]),
        kbd: vec![
            KbdRound {
                name: "",
                instructions: String::new(),
                prompts: vec![("Password: ", false)],
                expect: vec!["pw"],
            },
            KbdRound {
                name: "Duo",
                instructions: format!("\x1b[2JEnter the code{}", "!".repeat(1000)),
                prompts: vec![("Verification code: ", true)],
                expect: vec!["123456"],
            },
        ],
        ..AuthPolicy::default()
    })
    .await;
    let creds = Creds {
        password: Some("pw"),
        ..Creds::default()
    };
    let (mgr, mut rx, handle) = session(addr, creds, None);
    let (SessionEvent::Prompt(p), _) = until(&mut rx, prompt).await else {
        unreachable!()
    };
    assert_eq!(p.kind, PromptKind::KeyboardInteractive);
    assert_eq!(p.name, "Duo");
    assert!(p.instruction.starts_with("Enter the code!"));
    assert_eq!(p.instruction.chars().count(), 513);
    assert_eq!(p.prompts[0].text, "Verification code:");
    assert!(p.prompts[0].echo);
    answer(&handle, &["123456"]).await;
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert_eq!(requests(&seen), ["none", "kbd", "kbd-answer", "kbd-answer"]);
    mgr.shutdown(Duration::from_secs(2)).await;
}

fn agent_keys(n: u8) -> Vec<PrivateKey> {
    (1..=n)
        .map(|i| PrivateKey::from(Ed25519Keypair::from_seed(&[i; 32])))
        .collect()
}

/// T-16 (loopback, `MaxAuthTries 2`): five agent identities and no configured key →
/// fails gracefully when the server gives up, naming the methods tried; with a
/// configured key the agent is never asked and the login succeeds (IdentitiesOnly).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_max_auth_tries() {
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        authorized: vec![public(test_keys::ED25519_PUB)],
        methods: methods(&[MethodKind::PublicKey]),
        max_auth_attempts: 2,
        ..AuthPolicy::default()
    })
    .await;
    let agent = InProcessAgent::start(&agent_keys(5)).await.unwrap();
    let (mgr, mut rx, _h) = session(addr, Creds::default(), Some(Arc::new(agent.clone())));
    let (ev, before) = outcome(&mut rx).await;
    assert!(
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Auth,
                ..
            })
        ),
        "{ev:?} {before:#?}"
    );
    assert_eq!(
        error_text(&before).as_deref(),
        Some("Permission denied (methods tried: publickey)")
    );
    assert!(requests(&seen).len() <= 3, "{:?}", requests(&seen));
    mgr.shutdown(Duration::from_secs(2)).await;

    let creds = Creds {
        key: Some(test_keys::ED25519),
        ..Creds::default()
    };
    let connects = agent.connects();
    let (mgr, mut rx, _h) = session(addr, creds, Some(Arc::new(agent.clone())));
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert_eq!(agent.connects(), connects, "the agent is not asked");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-17 (loopback): an agent holding the authorized key and no configured key →
/// connects through the agent (the agent signs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_agent_auth() {
    let keys = agent_keys(3);
    let (addr, _, seen) = start_auth_server(AuthPolicy {
        authorized: vec![keys[2].public_key().clone()],
        methods: methods(&[MethodKind::PublicKey, MethodKind::Password]),
        ..AuthPolicy::default()
    })
    .await;
    let agent = InProcessAgent::start(&keys).await.unwrap();
    let (mgr, mut rx, _h) = session(addr, Creds::default(), Some(Arc::new(agent.clone())));
    let (ev, before) = outcome(&mut rx).await;
    assert!(connected(&ev), "{before:#?}");
    assert!(before.iter().any(|e| matches!(
        e,
        SessionEvent::State(SessionState::Authenticating {
            method: crate::AuthMethod::Agent,
            ..
        })
    )));
    assert_eq!(agent.connects(), 1);
    assert!(!requests(&seen).contains(&"password".to_owned()));
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// Closing the session while a prompt is open ends in `Closed`, not an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_close_while_prompting() {
    let (addr, _, _) = start_auth_server(AuthPolicy {
        password: Some("secret"),
        ..AuthPolicy::default()
    })
    .await;
    let (mgr, mut rx, handle) = session(addr, Creds::default(), None);
    let _ = until(&mut rx, prompt).await;
    handle.cmd_tx.send(SessionCmd::Close).await.unwrap();
    let (_, before) = until(&mut rx, |e| {
        matches!(e, SessionEvent::State(SessionState::Closed))
    })
    .await;
    assert!(error_text(&before).is_none(), "{before:#?}");
    mgr.shutdown(Duration::from_secs(2)).await;
}

// ---------------------------------------------------------------- e2e

/// T-11…T-17 against OpenSSH containers live in the Docker e2e harness crate
/// (`crates/sverb-e2e/tests/openssh_auth.rs`): password, ed25519/ecdsa/RSA 4096 keys
/// (`rsa-sha2-512` in the sshd log), an encrypted key with and without a stored
/// passphrase, a user certificate (`TrustedUserCAKeys`), keyboard-interactive through
/// PAM with a test OTP module, `MaxAuthTries 2` with five agent identities, and a real
/// `ssh-agent` (its own socket, never the user's) through
/// [`SocketAgent`](crate::agent_client::SocketAgent). A unit test of this crate cannot
/// use `sverb-e2e`, which depends on `sverb-conn`.
#[tokio::test]
#[ignore = "moved to crates/sverb-e2e/tests/openssh_auth.rs (M1-18 harness)"]
async fn e2e_openssh_t11_to_t17() {
    // See crates/sverb-e2e/tests/openssh_auth.rs.
    eprintln!("moved: SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_auth -- --ignored");
}
