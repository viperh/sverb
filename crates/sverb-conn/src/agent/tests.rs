//! (queue side), the local socket, `ssh-add -l` against it
//! (first half), and the control socket. Never touches the user's agent: the
//! "system agent" is an in-process russh agent server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{io, sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::keys::{
    PrivateKey, PublicKey,
    agent::client::AgentClient,
    signature::Verifier,
    ssh_key::{Algorithm, Certificate, HashAlg, Signature, private::Ed25519Keypair},
};
use sverb_core::model::{AgentSource, Certificate as CertItem, ItemId, Key, KeyAlgorithm};
use sverb_core::secret::SecretString;

use super::{
    builtin::{
        AgentKey, BuiltinAgent, ConfirmRequest, Confirmer, DenyConfirm, Requester, SignOutcome,
        StaticKeys, agent_keys, sign_with,
    },
    confirm::ConfirmQueue,
    forward::{AgentServer, RawAgent},
    proto,
};
use crate::{agent_client::AgentStreamBox, ssh::test_keys};

// ------------------------------------------------------------------ helpers

fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn rsa() -> PrivateKey {
    PrivateKey::from_openssh(test_keys::RSA_2048).unwrap()
}

fn requester() -> Requester {
    Requester::Session {
        host: "db".into(),
        session: "s1".into(),
    }
}

fn agent(keys: Vec<AgentKey>) -> BuiltinAgent {
    BuiltinAgent::new(Arc::new(StaticKeys::new(keys)), Arc::new(DenyConfirm))
}

fn blob(key: &PrivateKey) -> Vec<u8> {
    russh::keys::ssh_encoding::Encode::encode_vec(key.public_key().key_data()).unwrap()
}

/// A mock system agent: russh's agent server over in-memory pipes, holding `keys`.
#[derive(Debug, Clone)]
struct MockSystem {
    tx: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
}

impl MockSystem {
    async fn start(keys: &[PrivateKey]) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let mock = Self { tx };
        let mut client = AgentClient::connect(mock.open().await.unwrap());
        for key in keys {
            client.add_identity(key, &[]).await.unwrap();
        }
        mock
    }
}

#[async_trait]
impl RawAgent for MockSystem {
    async fn open(&self) -> io::Result<AgentStreamBox> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.tx
            .send(server)
            .map_err(|_| io::Error::other("mock agent stopped"))?;
        Ok(Box::new(client))
    }
}

#[derive(Debug)]
struct NoSystem;

#[async_trait]
impl RawAgent for NoSystem {
    async fn open(&self) -> io::Result<AgentStreamBox> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no agent"))
    }
}

fn server(builtin: BuiltinAgent, system: Arc<dyn RawAgent>, source: AgentSource) -> AgentServer {
    AgentServer::new(Arc::new(builtin), system, source, requester())
}

/// Serve `server` over an in-memory stream and talk to it with russh's client.
fn client(server: AgentServer) -> AgentClient<AgentStreamBox> {
    let (a, b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move { server.serve(b).await });
    AgentClient::connect(Box::new(a) as AgentStreamBox)
}

async fn ask(server: &AgentServer, frame: &[u8]) -> Vec<u8> {
    server.answer(frame, &mut None).await
}

fn verify(public: &PublicKey, data: &[u8], sig: &[u8]) -> Signature {
    let sig = Signature::try_from(sig).unwrap();
    Verifier::verify(public, data, &sig).unwrap();
    sig
}

// ------------------------------------------------------------------ T-01

fn key_item(label: &str, private: &PrivateKey, forwardable: bool) -> Key {
    Key {
        label: label.into(),
        algorithm: KeyAlgorithm::Ed25519,
        private_key: SecretString::from(
            private
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_str(),
        ),
        public_key: private.public_key().to_openssh().unwrap(),
        passphrase: None,
        certificate_ids: Vec::new(),
        agent_forwardable: forwardable,
        confirm_on_use: false,
        read_only: false,
    }
}

#[tokio::test]
async fn t01_identities_are_forwardable_keys_plus_certs() {
    let plain = PrivateKey::from_openssh(test_keys::ED25519).unwrap();
    let other = ed25519(9);
    let hidden = ed25519(10);
    let (k1, k2, k3, c1) = (
        ItemId::from_bytes([1; 16]),
        ItemId::from_bytes([2; 16]),
        ItemId::from_bytes([3; 16]),
        ItemId::from_bytes([4; 16]),
    );
    let mut with_cert = key_item("plain", &plain, true);
    with_cert.certificate_ids = vec![c1];
    let keys = vec![
        (k1, with_cert),
        (k2, key_item("other", &other, true)),
        (k3, key_item("hidden", &hidden, false)),
    ];
    let certs = vec![(
        c1,
        CertItem {
            label: "cert".into(),
            cert: test_keys::ED25519_CERT.into(),
            key_id: None,
            read_only: false,
        },
    )];
    let served = agent_keys(&keys, &certs);
    assert_eq!(served.len(), 2);
    let agent = agent(served);
    let ids = agent.identities().await;
    let cert = Certificate::from_openssh(test_keys::ED25519_CERT).unwrap();
    let blobs: Vec<_> = ids.iter().map(|(b, _)| b.clone()).collect();
    assert_eq!(
        blobs,
        vec![blob(&plain), cert.to_bytes().unwrap(), blob(&other)]
    );
    assert!(!blobs.contains(&blob(&hidden)));
    assert_eq!(ids[0].1, "plain");

    // Over the wire, russh's client sees the key, the certificate and the other key.
    let s = server(agent, Arc::new(NoSystem), AgentSource::Builtin);
    let listed = client(s).request_identities().await.unwrap();
    assert_eq!(listed.len(), 3);
}

// ------------------------------------------------------------------ T-02

#[tokio::test]
async fn t02_sign_ed25519_verifies() {
    let key = ed25519(1);
    let agent = agent(vec![AgentKey::new("k", key.clone())]);
    let SignOutcome::Signed(sig) = agent.sign(&blob(&key), b"hello", 0, &requester()).await else {
        panic!("not signed");
    };
    let sig = verify(key.public_key(), b"hello", &sig);
    assert_eq!(sig.algorithm(), Algorithm::Ed25519);
}

#[tokio::test]
async fn t02_sign_via_certificate_blob() {
    let key = PrivateKey::from_openssh(test_keys::ED25519).unwrap();
    let cert = Certificate::from_openssh(test_keys::ED25519_CERT).unwrap();
    let mut k = AgentKey::new("k", key.clone());
    k.certificates.push(cert.clone());
    let agent = agent(vec![k]);
    let SignOutcome::Signed(sig) = agent
        .sign(&cert.to_bytes().unwrap(), b"x", 0, &requester())
        .await
    else {
        panic!("not signed");
    };
    verify(key.public_key(), b"x", &sig);
}

#[test]
fn t02_rsa_flags_choose_the_algorithm() {
    let key = rsa();
    for (flags, hash) in [
        (proto::RSA_SHA2_256, Some(HashAlg::Sha256)),
        (proto::RSA_SHA2_512, Some(HashAlg::Sha512)),
        (0, None),
    ] {
        let sig = sign_with(&key, b"data", flags).unwrap();
        let sig = verify(key.public_key(), b"data", &sig);
        assert_eq!(sig.algorithm(), Algorithm::Rsa { hash }, "flags {flags}");
    }
}

#[tokio::test]
async fn t02_rsa_over_the_wire() {
    let key = rsa();
    let s = server(
        agent(vec![AgentKey::new("rsa", key.clone())]),
        Arc::new(NoSystem),
        AgentSource::Builtin,
    );
    let reply = ask(
        &s,
        &proto::sign_request(&blob(&key), b"d", proto::RSA_SHA2_256),
    )
    .await;
    let sig = proto::parse_sign_response(&reply).unwrap();
    let sig = verify(key.public_key(), b"d", &sig);
    assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
}

// ------------------------------------------------------------------ T-03

#[tokio::test]
async fn t03_locked_refuses_and_lists_nothing() {
    let key = ed25519(1);
    let keys = Arc::new(StaticKeys::new(vec![AgentKey::new("k", key.clone())]));
    let builtin = BuiltinAgent::new(keys.clone(), Arc::new(DenyConfirm));
    let s = server(builtin, Arc::new(NoSystem), AgentSource::Builtin);
    // Unlocked first: it signs.
    let reply = ask(&s, &proto::sign_request(&blob(&key), b"d", 0)).await;
    assert_eq!(reply[0], proto::SIGN_RESPONSE);
    keys.lock();
    assert!(keys.is_locked());
    let reply = ask(&s, &[proto::REQUEST_IDENTITIES]).await;
    assert_eq!(proto::parse_identities(&reply).unwrap(), Vec::new());
    let reply = ask(&s, &proto::sign_request(&blob(&key), b"d", 0)).await;
    assert_eq!(reply, vec![proto::FAILURE]);
}

// ------------------------------------------------------------------ T-04

#[tokio::test]
async fn t04_unsupported_requests_fail() {
    let key = ed25519(1);
    let s = server(
        agent(vec![AgentKey::new("k", key.clone())]),
        Arc::new(NoSystem),
        AgentSource::Builtin,
    );
    let mut c = client(s.clone());
    assert!(c.add_identity(&ed25519(2), &[]).await.is_err());
    // (russh's client frames REMOVE_ALL / LOCK oddly; those are sent raw below.)
    for kind in [
        proto::ADD_IDENTITY,
        proto::REMOVE_IDENTITY,
        proto::REMOVE_ALL_IDENTITIES,
        proto::LOCK,
        proto::UNLOCK,
        proto::EXTENSION,
        200,
    ] {
        assert_eq!(ask(&s, &[kind]).await, vec![proto::FAILURE], "type {kind}");
    }
    // The key is still there.
    assert_eq!(c.request_identities().await.unwrap().len(), 1);
    // Garbage gets FAILURE too.
    assert_eq!(ask(&s, &[]).await, vec![proto::FAILURE]);
    assert_eq!(
        ask(&s, &[proto::SIGN_REQUEST, 0, 0]).await,
        vec![proto::FAILURE]
    );
}

// ------------------------------------------------------------------ T-05

#[tokio::test]
async fn t05_both_merges_and_falls_back() {
    let shared = ed25519(1);
    let mine = ed25519(2);
    let theirs = ed25519(3);
    let system = MockSystem::start(&[theirs.clone(), shared.clone()]).await;
    let s = server(
        agent(vec![
            AgentKey::new("shared", shared.clone()),
            AgentKey::new("mine", mine.clone()),
        ]),
        Arc::new(system.clone()),
        AgentSource::Both,
    );
    let ids = proto::parse_identities(&ask(&s, &[proto::REQUEST_IDENTITIES]).await).unwrap();
    let blobs: Vec<_> = ids.into_iter().map(|(b, _)| b).collect();
    assert_eq!(blobs, vec![blob(&shared), blob(&mine), blob(&theirs)]);

    // A key only the system agent holds: proxied.
    let mut conn = None;
    let reply = s
        .answer(&proto::sign_request(&blob(&theirs), b"z", 0), &mut conn)
        .await;
    verify(
        theirs.public_key(),
        b"z",
        &proto::parse_sign_response(&reply).unwrap(),
    );
    // Unknown everywhere: FAILURE.
    let reply = s
        .answer(&proto::sign_request(&blob(&ed25519(4)), b"z", 0), &mut conn)
        .await;
    assert_eq!(reply, vec![proto::FAILURE]);

    // `builtin` never asks the system agent.
    let b = server(
        agent(vec![AgentKey::new("mine", mine)]),
        Arc::new(system),
        AgentSource::Builtin,
    );
    let ids = proto::parse_identities(&ask(&b, &[proto::REQUEST_IDENTITIES]).await).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ask(&b, &proto::sign_request(&blob(&theirs), b"z", 0)).await,
        vec![proto::FAILURE]
    );
}

#[tokio::test]
async fn both_without_system_agent_is_builtin() {
    let mine = ed25519(2);
    let s = server(
        agent(vec![AgentKey::new("mine", mine.clone())]),
        Arc::new(NoSystem),
        AgentSource::Both,
    );
    let mut c = client(s);
    assert_eq!(c.request_identities().await.unwrap().len(), 1);
}

#[tokio::test]
async fn system_source_splices_to_the_system_agent() {
    let theirs = ed25519(3);
    let system = MockSystem::start(std::slice::from_ref(&theirs)).await;
    let s = server(
        agent(vec![AgentKey::new("mine", ed25519(2))]),
        Arc::new(system),
        AgentSource::System,
    );
    let mut c = client(s);
    let ids = c.request_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ids[0].public_key().key_data(),
        theirs.public_key().key_data()
    );

    // No system agent: the connection just closes.
    let s = server(agent(Vec::new()), Arc::new(NoSystem), AgentSource::System);
    assert!(client(s).request_identities().await.is_err());
}

// ------------------------------------------------------------------ T-06 (queue side)

fn confirm_key(key: &PrivateKey) -> AgentKey {
    let mut k = AgentKey::new("deploy", key.clone());
    k.confirm_on_use = true;
    k
}

#[tokio::test]
async fn t06_confirm_allow_deny_timeout() {
    let key = ed25519(5);
    let (queue, mut prompts) = ConfirmQueue::new();
    let agent = Arc::new(BuiltinAgent::new(
        Arc::new(StaticKeys::new(vec![confirm_key(&key)])),
        queue.clone(),
    ));

    // Allow → signature.
    let a = Arc::clone(&agent);
    let b = blob(&key);
    let task = tokio::spawn(async move { a.sign(&b, b"m", 0, &requester()).await });
    let prompt = prompts.recv().await.unwrap();
    assert_eq!(prompt.request.key_label, "deploy");
    assert_eq!(prompt.request.requester.to_string(), "db");
    assert_eq!(prompt.timeout, Duration::from_secs(60));
    queue.answer(prompt.id, true);
    assert!(matches!(task.await.unwrap(), SignOutcome::Signed(_)));

    // Deny → FAILURE (Refused).
    let a = Arc::clone(&agent);
    let b = blob(&key);
    let task = tokio::spawn(async move { a.sign(&b, b"m", 0, &requester()).await });
    let prompt = prompts.recv().await.unwrap();
    queue.answer(prompt.id, false);
    assert_eq!(task.await.unwrap(), SignOutcome::Refused);
}

#[tokio::test(start_paused = true)]
async fn t06_confirm_times_out_after_60s() {
    let key = ed25519(5);
    let (queue, mut prompts) = ConfirmQueue::new();
    let agent = Arc::new(BuiltinAgent::new(
        Arc::new(StaticKeys::new(vec![confirm_key(&key)])),
        queue.clone(),
    ));
    let a = Arc::clone(&agent);
    let b = blob(&key);
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move { a.sign(&b, b"m", 0, &requester()).await });
    let prompt = prompts.recv().await.unwrap();
    assert_eq!(task.await.unwrap(), SignOutcome::Refused);
    assert!(started.elapsed() >= Duration::from_secs(60));
    // A late answer is ignored.
    queue.answer(prompt.id, true);
    assert_eq!(queue.waiting(), 0);
}

#[tokio::test]
async fn t06_concurrent_prompts_queue() {
    let key = ed25519(5);
    let (queue, mut prompts) = ConfirmQueue::new();
    let agent = Arc::new(BuiltinAgent::new(
        Arc::new(StaticKeys::new(vec![confirm_key(&key)])),
        queue.clone(),
    ));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let a = Arc::clone(&agent);
        let b = blob(&key);
        tasks.push(tokio::spawn(async move {
            a.sign(&b, b"m", 0, &requester()).await
        }));
    }
    let first = prompts.recv().await.unwrap();
    // The second waits for the first to be answered.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(prompts.try_recv().is_err());
    queue.answer(first.id, false);
    let second = prompts.recv().await.unwrap();
    queue.answer(second.id, true);
    let mut outcomes = Vec::new();
    for t in tasks {
        outcomes.push(t.await.unwrap());
    }
    assert!(outcomes.contains(&SignOutcome::Refused));
    assert!(outcomes.iter().any(|o| matches!(o, SignOutcome::Signed(_))));
}

#[tokio::test]
async fn confirm_without_ui_denies() {
    #[derive(Debug)]
    struct Never;
    #[async_trait]
    impl Confirmer for Never {
        async fn confirm(&self, _: ConfirmRequest) -> bool {
            false
        }
    }
    let key = ed25519(5);
    let agent = BuiltinAgent::new(
        Arc::new(StaticKeys::new(vec![confirm_key(&key)])),
        Arc::new(Never),
    );
    assert_eq!(
        agent.sign(&blob(&key), b"m", 0, &requester()).await,
        SignOutcome::Refused
    );
    let (queue, prompts) = ConfirmQueue::new();
    drop(prompts);
    let agent = BuiltinAgent::new(Arc::new(StaticKeys::new(vec![confirm_key(&key)])), queue);
    assert_eq!(
        agent.sign(&blob(&key), b"m", 0, &requester()).await,
        SignOutcome::Refused
    );
}

#[test]
fn requester_display() {
    let local = |pid, exe: Option<&str>| Requester::Local {
        pid,
        exe: exe.map(str::to_owned),
    };
    assert_eq!(local(Some(42), Some("git")).to_string(), "git (pid 42)");
    assert_eq!(local(Some(42), None).to_string(), "pid 42");
    assert_eq!(local(None, None).to_string(), "a local process");
    assert_eq!(local(Some(42), None).log_id(), "pid:42");
    assert_eq!(requester().log_id(), "s1");
}

// ------------------------------------------------------------------ local socket (Unix)

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::agent::{
        control::{self, ControlCommand, ControlError},
        peercred::{PeerCred, PeerCredProvider},
        serve_local,
        socket::{DirPolicy, PrivateSocket, SocketError},
    };

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    async fn local_agent(
        path: &std::path::Path,
        keys: Vec<AgentKey>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = PrivateSocket::bind(path, DirPolicy::Private, "agent")
            .await
            .unwrap();
        let s = server(agent(keys), Arc::new(NoSystem), AgentSource::Builtin);
        tokio::spawn(async move {
            let _ = serve_local(&socket, s).await;
        })
    }

    #[tokio::test]
    async fn t07_socket_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/sverb/agent.sock");
        let socket = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap();
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        drop(socket);
        assert!(!path.exists(), "removed on drop");
    }

    #[tokio::test]
    async fn t07_open_dir_is_refused_for_the_default_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("open");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("agent.sock");
        let err = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap_err();
        assert!(matches!(err, SocketError::InsecureDir(_)), "{err}");
        // A user-chosen path is only warned about.
        let socket = PrivateSocket::bind(&path, DirPolicy::Lenient, "agent")
            .await
            .unwrap();
        assert_eq!(mode(&path), 0o600);
        drop(socket);
    }

    #[derive(Debug)]
    struct OtherUser;

    impl PeerCredProvider for OtherUser {
        fn peer(&self, stream: &tokio::net::UnixStream) -> io::Result<PeerCred> {
            let real = stream.peer_cred()?;
            Ok(PeerCred {
                uid: real.uid().wrapping_add(1),
                pid: real.pid(),
            })
        }
    }

    #[tokio::test]
    async fn t08_other_uid_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/agent.sock");
        let socket = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap()
            .with_peer_creds(Arc::new(OtherUser));
        let s = server(
            agent(vec![AgentKey::new("k", ed25519(1))]),
            Arc::new(NoSystem),
            AgentSource::Builtin,
        );
        tokio::spawn(async move {
            let _ = serve_local(&socket, s).await;
        });
        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut c = AgentClient::connect(Box::new(stream) as AgentStreamBox);
        assert!(
            c.request_identities().await.is_err(),
            "closed without an answer"
        );
    }

    #[tokio::test]
    async fn t08_same_uid_is_served() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/agent.sock");
        let _task = local_agent(&path, vec![AgentKey::new("k", ed25519(1))]).await;
        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut c = AgentClient::connect(Box::new(stream) as AgentStreamBox);
        assert_eq!(c.request_identities().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn t09_ssh_add_lists_the_keys() {
        if std::process::Command::new("ssh-add")
            .arg("-h")
            .output()
            .is_err()
        {
            eprintln!("ssh-add not installed; skipped");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/agent.sock");
        let key = PrivateKey::from_openssh(test_keys::ED25519).unwrap();
        let mut k = AgentKey::new("vault-key", key.clone());
        k.certificates
            .push(Certificate::from_openssh(test_keys::ED25519_CERT).unwrap());
        let _task = local_agent(&path, vec![k]).await;
        let p = path.clone();
        let out = tokio::task::spawn_blocking(move || {
            std::process::Command::new("ssh-add")
                .arg("-L")
                .env("SSH_AUTH_SOCK", &p)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let key_b64 = key.public_key().to_openssh().unwrap();
        let key_b64 = key_b64.split_whitespace().nth(1).unwrap();
        assert!(lines[0].contains(key_b64));
        assert!(lines[0].ends_with("vault-key"));
        assert!(lines[1].starts_with("ssh-ed25519-cert-v01@openssh.com"));
    }

    #[tokio::test]
    async fn t10_stale_socket_is_replaced_live_one_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run/agent.sock");
        let dir = path.parent().unwrap();
        std::fs::create_dir(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A crashed run: the file stays, nobody listens.
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists());
        let socket = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap();
        // Accept in the background so the probe connects.
        let live = tokio::spawn(async move {
            let _ = socket.accept().await;
            socket
        });
        let err = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap_err();
        match &err {
            SocketError::AlreadyRunning { pid, .. } => {
                assert_eq!(*pid, Some(i32::try_from(std::process::id()).unwrap()));
            }
            other => panic!("{other}"),
        }
        assert!(
            err.to_string().starts_with("agent already running (pid "),
            "{err}"
        );
        let socket = live.await.unwrap();
        assert!(path.exists(), "the live socket was left alone");
        drop(socket);

        // Not a socket: never deleted.
        std::fs::write(&path, b"x").unwrap();
        let err = PrivateSocket::bind(&path, DirPolicy::Private, "agent")
            .await
            .unwrap_err();
        assert!(matches!(err, SocketError::NotASocket(_)));
        assert!(path.exists());
    }

    #[tokio::test]
    async fn control_lock_reaches_the_handler() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("run").join(control::CONTROL_SOCKET);
        assert!(matches!(
            control::send(&path, ControlCommand::Lock).await,
            Err(ControlError::NotRunning)
        ));
        let socket = PrivateSocket::bind(&path, DirPolicy::Private, "sverb")
            .await
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(control::serve(
            socket,
            Arc::new(move |cmd| tx.send(cmd).is_ok()),
        ));
        let pid = control::send(&path, ControlCommand::Lock).await.unwrap();
        assert_eq!(pid, Some(i32::try_from(std::process::id()).unwrap()));
        assert_eq!(rx.recv().await, Some(ControlCommand::Lock));
        control::send(&path, ControlCommand::Ping).await.unwrap();
        assert_eq!(rx.recv().await, Some(ControlCommand::Ping));
    }

    #[tokio::test]
    async fn headless_lock_refuses_after_auto_lock() {
        let key = ed25519(1);
        let keys = Arc::new(StaticKeys::new(vec![AgentKey::new("k", key.clone())]));
        let builtin = BuiltinAgent::new(keys.clone(), Arc::new(DenyConfirm));
        assert!(keys.idle() < Duration::from_secs(5));
        keys.lock();
        assert_eq!(
            builtin.sign(&blob(&key), b"d", 0, &requester()).await,
            SignOutcome::Locked
        );
        keys.unlock(vec![AgentKey::new("k", key.clone())]);
        assert!(matches!(
            builtin.sign(&blob(&key), b"d", 0, &requester()).await,
            SignOutcome::Signed(_)
        ));
    }
}
