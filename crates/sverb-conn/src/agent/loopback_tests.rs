//! russh server that opens `auth-agent@openssh.com` channels back to the client and
//! lists the identities there (the stand-in for `ssh-add -l` on the remote; the Docker
//! variants are `crates/sverb-e2e/tests/agent.rs`). The system agent is an in-process
//! russh agent, never the user's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::{
    Channel, ChannelId, Pty,
    keys::{
        PrivateKey,
        agent::client::AgentClient,
        ssh_key::{PublicKey, private::Ed25519Keypair},
    },
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use sverb_core::model::{AgentSource, DeviceId, Host, ItemId};
use tokio::{net::TcpListener, sync::mpsc};

use super::{AgentForwarding, AgentKey, BuiltinAgent, DenyConfirm, RawAgent, StaticKeys};
use crate::{
    OpenOptions, SessionEvent, SessionId, SessionManager, SessionState, TransportKind,
    agent_client::AgentStreamBox,
    proxy::ValueOrigin,
    ssh::{HostResolver, InsecureAcceptAnyHostKey, SshConnector, SshError, SshTarget, resolve},
};

const WAIT: Duration = Duration::from_secs(10);

/// What the remote saw: whether forwarding was requested, and the forwarded
/// identities (`None`: the agent channel could not be opened).
#[derive(Debug, Default)]
struct Remote {
    requested: bool,
    listed: Option<Result<Vec<PublicKey>, String>>,
}

#[derive(Clone)]
struct AgentTestServer {
    remote: Arc<Mutex<Remote>>,
}

impl server::Handler for AgentTestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == "secret" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.remote.lock().requested = true;
        session.channel_success(channel)?;
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_w: u32,
        _px_h: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    // Like `ssh-add -l` on the remote: once the shell starts, open an agent channel
    // back to the client (only when forwarding was requested) and list identities.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let handle = session.handle();
        let remote = Arc::clone(&self.remote);
        let requested = remote.lock().requested;
        tokio::spawn(async move {
            let listed = if requested {
                match handle.channel_open_agent().await {
                    Ok(ch) => {
                        let stream: AgentStreamBox = Box::new(ch.into_stream());
                        let mut client = AgentClient::connect(stream);
                        client
                            .request_identities()
                            .await
                            .map(|ids| ids.iter().map(|i| i.public_key().into_owned()).collect())
                            .map_err(|e| e.to_string())
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Err("Could not open a connection to your authentication agent.".to_owned())
            };
            remote.lock().listed = Some(listed);
        });
        Ok(())
    }
}

async fn start() -> (SocketAddr, Arc<Mutex<Remote>>) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let remote = Arc::new(Mutex::new(Remote::default()));
    let handler = AgentTestServer {
        remote: Arc::clone(&remote),
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
    (addr, remote)
}

#[derive(Debug)]
struct Resolver {
    addr: SocketAddr,
    forwarding: Option<bool>,
    source: AgentSource,
    origin: ValueOrigin,
}

#[async_trait]
impl HostResolver for Resolver {
    async fn resolve(&self, _spec: &crate::SshSpec) -> Result<SshTarget, SshError> {
        let host = Host {
            label: "agent-test".into(),
            address: self.addr.ip().to_string(),
            port: Some(self.addr.port()),
            username: Some("sverb".into()),
            password: Some(sverb_core::secret::SecretString::from("secret")),
            agent_forwarding: self.forwarding,
            agent_source: Some(self.source),
            ..Host::default()
        };
        let mut config = sverb_core::config::Config::default();
        config.ssh.connect_timeout_secs = 5;
        let mut target = resolve(&host, None, None, &config, || None);
        target.agent_origin = self.origin;
        Ok(target)
    }
}

/// A system agent holding `keys` (russh's agent server over in-memory pipes).
#[derive(Debug, Clone)]
struct MockSystem(mpsc::UnboundedSender<tokio::io::DuplexStream>);

impl MockSystem {
    async fn start(keys: &[PrivateKey]) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, std::io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let mock = Self(tx);
        let mut client = AgentClient::connect(mock.open().await.unwrap());
        for key in keys {
            client.add_identity(key, &[]).await.unwrap();
        }
        mock
    }
}

#[async_trait]
impl RawAgent for MockSystem {
    async fn open(&self) -> std::io::Result<AgentStreamBox> {
        let (a, b) = tokio::io::duplex(64 * 1024);
        self.0
            .send(b)
            .map_err(|_| std::io::Error::other("stopped"))?;
        Ok(Box::new(a))
    }
}

fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

async fn connect(
    resolver: Resolver,
    vault: Vec<AgentKey>,
    system: MockSystem,
) -> (SessionState, Vec<SessionEvent>, SessionManager) {
    let forwarding = AgentForwarding::new(Arc::new(BuiltinAgent::new(
        Arc::new(StaticKeys::new(vault)),
        Arc::new(DenyConfirm),
    )))
    .with_system(Arc::new(system));
    let connector = SshConnector::new(Arc::new(resolver))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
        .with_agent_forwarding(forwarding);
    let (tx, mut rx) = mpsc::unbounded_channel::<(SessionId, SessionEvent)>();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    let _handle = mgr
        .open_with(
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
        .unwrap();
    let mut seen = Vec::new();
    let state = tokio::time::timeout(WAIT, async {
        loop {
            let (_, ev) = rx.recv().await.unwrap();
            if let SessionEvent::State(
                s @ (SessionState::Connected { .. } | SessionState::Disconnected { .. }),
            ) = &ev
            {
                return s.clone();
            }
            seen.push(ev);
        }
    })
    .await
    .expect("no final state");
    (state, seen, mgr)
}

async fn listed(remote: &Arc<Mutex<Remote>>) -> Result<Vec<PublicKey>, String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(l) = remote.lock().listed.clone() {
            return l;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the remote never listed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn resolver(addr: SocketAddr, forwarding: Option<bool>, source: AgentSource) -> Resolver {
    Resolver {
        addr,
        forwarding,
        source,
        origin: ValueOrigin::default(),
    }
}

/// T-11 (loopback): `builtin` → the remote lists exactly the forwardable keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t11_builtin_forwarding_lists_vault_keys() {
    let (addr, remote) = start().await;
    let vault = ed25519(1);
    let system = MockSystem::start(&[ed25519(2)]).await;
    let (state, _, mgr) = connect(
        resolver(addr, Some(true), AgentSource::Builtin),
        vec![AgentKey::new("vault", vault.clone())],
        system,
    )
    .await;
    assert!(matches!(state, SessionState::Connected { .. }), "{state:?}");
    let keys = listed(&remote).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_data(), vault.public_key().key_data());
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-12 (loopback): `system` → the remote sees the system agent's key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_system_forwarding_lists_system_keys() {
    let (addr, remote) = start().await;
    let theirs = ed25519(2);
    let system = MockSystem::start(std::slice::from_ref(&theirs)).await;
    let (state, _, mgr) = connect(
        resolver(addr, Some(true), AgentSource::System),
        vec![AgentKey::new("vault", ed25519(1))],
        system,
    )
    .await;
    assert!(matches!(state, SessionState::Connected { .. }), "{state:?}");
    let keys = listed(&remote).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_data(), theirs.public_key().key_data());
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-13 (loopback): forwarding off → never requested; the remote has no agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t13_forwarding_off() {
    let (addr, remote) = start().await;
    let system = MockSystem::start(&[]).await;
    let (state, _, mgr) = connect(
        resolver(addr, None, AgentSource::Builtin),
        vec![AgentKey::new("vault", ed25519(1))],
        system,
    )
    .await;
    assert!(matches!(state, SessionState::Connected { .. }), "{state:?}");
    let err = listed(&remote).await.unwrap_err();
    assert!(err.contains("Could not open a connection"), "{err}");
    assert!(!remote.lock().requested);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// §17.1: forwarding the system agent for a host configured on another device fails
/// (until approved); the built-in agent needs no approval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synced_system_forwarding_needs_approval() {
    let (addr, remote) = start().await;
    let other = ValueOrigin {
        item_id: Some(ItemId::from_bytes([1; 16])),
        written_by: Some(DeviceId::from_bytes([2; 16])),
        this_device: Some(DeviceId::from_bytes([3; 16])),
    };
    let mut r = resolver(addr, Some(true), AgentSource::Both);
    r.origin = other;
    let (state, seen, mgr) = connect(r, Vec::new(), MockSystem::start(&[]).await).await;
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: crate::DisconnectReason::Connect,
                ..
            }
        ),
        "{state:?}"
    );
    let msg = seen.iter().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.short.clone()),
        _ => None,
    });
    assert!(msg.unwrap().contains("sverb approve agent-test"));
    assert!(!remote.lock().requested);
    mgr.shutdown(Duration::from_secs(2)).await;

    let mut r = resolver(addr, Some(true), AgentSource::Builtin);
    r.origin = other;
    let (state, _, mgr) = connect(r, Vec::new(), MockSystem::start(&[]).await).await;
    assert!(matches!(state, SessionState::Connected { .. }), "{state:?}");
    mgr.shutdown(Duration::from_secs(2)).await;
}
