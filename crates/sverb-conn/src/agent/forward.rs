//! Serving an agent connection by `agent_source` (SPEC §6.1.6), for forwarded
//! `auth-agent@openssh.com` channels and the local socket.
//!
//! - `system`: the stream is spliced byte-for-byte to the system agent
//!   (`SSH_AUTH_SOCK`; Windows: the OpenSSH pipe, then Pageant). No system agent →
//!   the connection is closed (logged at `debug`).
//! - `builtin`: [`BuiltinAgent`] answers; every other request gets `FAILURE`.
//! - `both`: built-in first. `REQUEST_IDENTITIES` returns the union (built-in first,
//!   deduplicated by key blob); a `SIGN_REQUEST` for a key the built-in agent doesn't
//!   hold (or while the vault is locked, which only hides the vault's keys) goes to the
//!   system agent. Other requests get `FAILURE`.
//!
//! [`AgentForwarding`] is the connector-wide part (keys, confirmer, system agent);
//! [`AgentForwarding::for_session`] binds it to one session's source and requester.
//! The SSH handler calls [`on_channel`] for each forwarded channel.

use std::{fmt, io, sync::Arc};

use async_trait::async_trait;
use sverb_core::model::AgentSource;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use super::{
    builtin::{BuiltinAgent, Requester, SignOutcome},
    proto::{self, Request},
};
use crate::agent_client::AgentStreamBox;

/// Opens raw byte streams to an agent (the system agent; tests inject their own).
#[async_trait]
pub trait RawAgent: Send + Sync + fmt::Debug {
    /// A new connection.
    ///
    /// # Errors
    /// No agent, or it can't be reached.
    async fn open(&self) -> io::Result<AgentStreamBox>;
}

/// The user's system agent (`SSH_AUTH_SOCK`; Windows: `SSH_AUTH_SOCK` naming a pipe,
/// the OpenSSH pipe, then Pageant).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRawAgent;

#[async_trait]
impl RawAgent for SystemRawAgent {
    #[cfg(unix)]
    async fn open(&self) -> io::Result<AgentStreamBox> {
        let Some(path) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "SSH_AUTH_SOCK is not set",
            ));
        };
        Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
    }

    #[cfg(windows)]
    async fn open(&self) -> io::Result<AgentStreamBox> {
        let pipe = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|p| p.starts_with(r"\\.\pipe\"))
            .unwrap_or_else(|| crate::agent_client::OPENSSH_PIPE.to_owned());
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe) {
            Ok(stream) => return Ok(Box::new(stream)),
            Err(err) => debug!(%err, "no OpenSSH agent pipe; trying Pageant"),
        }
        let client = russh::keys::agent::client::AgentClient::connect_pageant()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(client.into_inner())
    }

    #[cfg(not(any(unix, windows)))]
    async fn open(&self) -> io::Result<AgentStreamBox> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no system agent on this platform",
        ))
    }
}

/// Serves agent connections for one source and requester.
#[derive(Debug, Clone)]
pub struct AgentServer {
    builtin: Arc<BuiltinAgent>,
    system: Arc<dyn RawAgent>,
    source: AgentSource,
    requester: Requester,
}

impl AgentServer {
    /// A server answering per `source` on behalf of `requester`.
    pub fn new(
        builtin: Arc<BuiltinAgent>,
        system: Arc<dyn RawAgent>,
        source: AgentSource,
        requester: Requester,
    ) -> Self {
        Self {
            builtin,
            system,
            source,
            requester,
        }
    }

    /// The source.
    pub fn source(&self) -> AgentSource {
        self.source
    }

    /// The same server for another requester (the local socket's peers).
    #[must_use]
    pub fn with_requester(&self, requester: Requester) -> Self {
        Self {
            requester,
            ..self.clone()
        }
    }

    /// Serve `stream` until it closes.
    pub async fn serve<S>(&self, mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.source == AgentSource::System {
            match self.system.open().await {
                Ok(mut agent) => {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut agent).await;
                }
                Err(err) => debug!(%err, "no system agent; closing the agent connection"),
            }
            return;
        }
        let mut system: Option<AgentStreamBox> = None;
        loop {
            let frame = match proto::read_frame(&mut stream).await {
                Ok(Some(frame)) => frame,
                Ok(None) => return,
                Err(err) => {
                    debug!(%err, "agent connection closed");
                    return;
                }
            };
            let reply = self.answer(&frame, &mut system).await;
            if let Err(err) = proto::write_frame(&mut stream, &reply).await {
                debug!(%err, "agent connection closed");
                return;
            }
        }
    }

    /// The reply to one request frame.
    pub async fn answer(&self, frame: &[u8], system: &mut Option<AgentStreamBox>) -> Vec<u8> {
        let both = self.source == AgentSource::Both;
        match proto::parse(frame) {
            Ok(Request::Identities) => {
                let mut ids = self.builtin.identities().await;
                if both {
                    let extra = self
                        .ask_system(system, &[proto::REQUEST_IDENTITIES])
                        .await
                        .and_then(|reply| proto::parse_identities(&reply).ok())
                        .unwrap_or_default();
                    for (blob, comment) in extra {
                        if !ids.iter().any(|(b, _)| *b == blob) {
                            ids.push((blob, comment));
                        }
                    }
                }
                proto::identities_answer(&ids)
            }
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            }) => {
                match self
                    .builtin
                    .sign(&key_blob, &data, flags, &self.requester)
                    .await
                {
                    SignOutcome::Signed(sig) => proto::sign_response(&sig),
                    SignOutcome::NotHeld | SignOutcome::Locked if both => {
                        debug!(requester = %self.requester.log_id(), "agent: sign request passed to the system agent");
                        self.ask_system(system, frame)
                            .await
                            .unwrap_or_else(proto::failure)
                    }
                    SignOutcome::NotHeld | SignOutcome::Locked | SignOutcome::Refused => {
                        proto::failure()
                    }
                }
            }
            Ok(Request::Unsupported(kind)) => {
                debug!(kind, "agent: unsupported request refused");
                proto::failure()
            }
            Err(_) => proto::failure(),
        }
    }

    /// One request/response with the system agent (connection opened on first use).
    async fn ask_system(
        &self,
        system: &mut Option<AgentStreamBox>,
        frame: &[u8],
    ) -> Option<Vec<u8>> {
        if system.is_none() {
            match self.system.open().await {
                Ok(stream) => *system = Some(stream),
                Err(err) => {
                    debug!(%err, "no system agent");
                    return None;
                }
            }
        }
        let stream = system.as_mut()?;
        let result = async {
            proto::write_frame(stream, frame).await?;
            proto::read_frame(stream).await
        }
        .await;
        match result {
            Ok(Some(reply)) => Some(reply),
            Ok(None) | Err(_) => {
                *system = None;
                None
            }
        }
    }
}

/// The connector-wide forwarding setup: the built-in agent and the system agent.
#[derive(Debug, Clone)]
pub struct AgentForwarding {
    builtin: Arc<BuiltinAgent>,
    system: Arc<dyn RawAgent>,
}

impl AgentForwarding {
    /// Forwarding answered by `builtin` and, per source, the user's system agent.
    pub fn new(builtin: Arc<BuiltinAgent>) -> Self {
        Self {
            builtin,
            system: Arc::new(SystemRawAgent),
        }
    }

    /// Use `system` instead of the user's system agent (tests).
    #[must_use]
    pub fn with_system(mut self, system: Arc<dyn RawAgent>) -> Self {
        self.system = system;
        self
    }

    /// The built-in agent.
    pub fn builtin(&self) -> &Arc<BuiltinAgent> {
        &self.builtin
    }

    /// The server for one session's forwarded channels.
    pub fn for_session(&self, source: AgentSource, host: &str, session: &str) -> AgentServer {
        AgentServer::new(
            Arc::clone(&self.builtin),
            Arc::clone(&self.system),
            source,
            Requester::Session {
                host: host.to_owned(),
                session: session.to_owned(),
            },
        )
    }
}

/// A forwarded `auth-agent@openssh.com` channel arrived: serve it, or reject it when
/// this connection didn't ask for forwarding.
pub async fn on_channel(
    server: Option<AgentServer>,
    channel: russh::Channel<russh::client::Msg>,
    reply: russh::client::ChannelOpenHandle,
) {
    let Some(server) = server else {
        debug!("agent channel without forwarding; rejected");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        return;
    };
    reply.accept().await;
    debug!(source = ?server.source(), "agent channel opened");
    tokio::spawn(async move {
        server.serve(channel.into_stream()).await;
    });
}

/// **Tests only** (`test-util`): an in-memory agent (russh's agent server) holding
/// the given keys, standing in for the system agent. Never touches `SSH_AUTH_SOCK`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone)]
pub struct MemoryAgent {
    tx: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryAgent {
    /// Start one holding `keys` (inside a tokio runtime).
    ///
    /// # Errors
    /// Adding a key failed.
    pub async fn start(keys: &[russh::keys::PrivateKey]) -> io::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let agent = Self { tx };
        let mut client = russh::keys::agent::client::AgentClient::connect(agent.open().await?);
        for key in keys {
            client
                .add_identity(key, &[])
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(agent)
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl RawAgent for MemoryAgent {
    async fn open(&self) -> io::Result<AgentStreamBox> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.tx
            .send(server)
            .map_err(|_| io::Error::other("the memory agent stopped"))?;
        Ok(Box::new(client))
    }
}
