//! The system SSH agent client (SPEC §6.1.1 step 4.3, §9.4).
//!
//! Lists identities and signs through an agent reached over a Unix socket
//! (`SSH_AUTH_SOCK`) or, on Windows, the OpenSSH named pipe
//! (`\\.\pipe\openssh-ssh-agent`, or `SSH_AUTH_SOCK` when it names a pipe) and Pageant.
//! FIDO (`sk-*`) and hardware keys work through it: the agent does the signing.
//!
//! [`AgentConnector`] opens a connection ([`Agent`]); the auth chain asks for a fresh one
//! per authentication. Failing to reach the agent is not an error for the user: the
//! passthrough).
//!
//! This module is the one russh user outside `ssh/` (the task places the agent client
//! here); it only touches russh's agent client types.

use std::fmt;

use async_trait::async_trait;
use russh::keys::{
    HashAlg,
    agent::{AgentIdentity, client::AgentClient},
};
use tracing::debug;

/// A connection to an agent.
pub type AgentStreamBox = Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>;

/// Why the agent could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ssh agent: {0}")]
pub struct AgentError(pub String);

impl From<russh::keys::Error> for AgentError {
    fn from(err: russh::keys::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<std::io::Error> for AgentError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

/// An open agent connection.
#[async_trait]
pub trait Agent: Send {
    /// The agent's identities (keys and certificates), in the agent's order.
    ///
    /// # Errors
    /// The agent failed or closed the connection.
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError>;

    /// Sign `data` with `identity` (RSA: with `hash`, `None` meaning SHA-1).
    ///
    /// # Errors
    /// The agent refused or failed.
    async fn sign(
        &mut self,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError>;
}

/// Opens agent connections.
#[async_trait]
pub trait AgentConnector: Send + Sync + fmt::Debug {
    /// A new connection.
    ///
    /// # Errors
    /// No agent is configured or it can't be reached.
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError>;
}

/// An agent over any byte stream (russh's client).
pub struct StreamAgent {
    client: AgentClient<AgentStreamBox>,
}

impl fmt::Debug for StreamAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamAgent").finish_non_exhaustive()
    }
}

impl StreamAgent {
    /// An agent speaking over `stream`.
    pub fn new(stream: AgentStreamBox) -> Self {
        Self {
            client: AgentClient::connect(stream),
        }
    }

    /// Add `key` to the agent (tests).
    ///
    /// # Errors
    /// The agent refused.
    pub async fn add(&mut self, key: &russh::keys::PrivateKey) -> Result<(), AgentError> {
        self.client.add_identity(key, &[]).await.map_err(Into::into)
    }
}

#[async_trait]
impl Agent for StreamAgent {
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        self.client.request_identities().await.map_err(Into::into)
    }

    async fn sign(
        &mut self,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        self.client
            .sign_request(identity, hash, data)
            .await
            .map_err(Into::into)
    }
}

/// The user's agent: `SSH_AUTH_SOCK` (Unix socket); on Windows `SSH_AUTH_SOCK` when it
/// names a pipe, then the OpenSSH pipe, then Pageant.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemAgent;

/// The OpenSSH for Windows agent pipe.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

#[async_trait]
impl AgentConnector for SystemAgent {
    #[cfg(unix)]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let Some(path) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) else {
            return Err(AgentError("SSH_AUTH_SOCK is not set".to_owned()));
        };
        let stream = tokio::net::UnixStream::connect(&path).await?;
        debug!("connected to the system agent");
        Ok(Box::new(StreamAgent::new(Box::new(stream))))
    }

    #[cfg(windows)]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let pipe = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|p| p.starts_with(r"\\.\pipe\"))
            .unwrap_or_else(|| OPENSSH_PIPE.to_owned());
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe) {
            Ok(stream) => {
                debug!("connected to the OpenSSH agent pipe");
                return Ok(Box::new(StreamAgent::new(Box::new(stream))));
            }
            Err(err) => debug!(%err, "no OpenSSH agent pipe; trying Pageant"),
        }
        let client = AgentClient::connect_pageant().await?;
        debug!("connected to Pageant");
        Ok(Box::new(StreamAgent::new(client.into_inner())))
    }

    #[cfg(not(any(unix, windows)))]
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Err(AgentError("no system agent on this platform".to_owned()))
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct SocketAgent {
    /// The socket.
    pub path: std::path::PathBuf,
}

#[cfg(unix)]
#[async_trait]
impl AgentConnector for SocketAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        let stream = tokio::net::UnixStream::connect(&self.path).await?;
        Ok(Box::new(StreamAgent::new(Box::new(stream))))
    }
}

// ---------------------------------------------------------------- test support

/// **Tests only** (`test-util`): an in-process agent (russh's agent server over
/// in-memory pipes) holding the keys it was given. Never touches `SSH_AUTH_SOCK`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone)]
pub struct InProcessAgent {
    tx: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
    connects: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(any(test, feature = "test-util"))]
impl fmt::Debug for InProcessAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessAgent").finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl InProcessAgent {
    /// Start an agent holding `keys` (must run inside a tokio runtime).
    ///
    /// # Errors
    /// Adding a key failed.
    pub async fn start(keys: &[russh::keys::PrivateKey]) -> Result<Self, AgentError> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let listener = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|s| (Ok::<_, std::io::Error>(s), rx))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(listener), ()));
        let agent = Self {
            tx,
            connects: std::sync::Arc::default(),
        };
        let mut conn = agent.open()?;
        for key in keys {
            conn.add(key).await?;
        }
        agent.connects.store(0, std::sync::atomic::Ordering::SeqCst);
        Ok(agent)
    }

    fn open(&self) -> Result<StreamAgent, AgentError> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.tx
            .send(server)
            .map_err(|_| AgentError("the test agent stopped".to_owned()))?;
        self.connects
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(StreamAgent::new(Box::new(client)))
    }

    /// How many connections were opened since [`InProcessAgent::start`].
    pub fn connects(&self) -> usize {
        self.connects.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl AgentConnector for InProcessAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Ok(Box::new(self.open()?))
    }
}

/// **Tests only**: an agent that can't be reached.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreachableAgent;

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl AgentConnector for UnreachableAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Err(AgentError("connection refused".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};

    use super::*;

    #[tokio::test]
    async fn in_process_agent_lists_and_signs() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let agent = InProcessAgent::start(std::slice::from_ref(&key))
            .await
            .unwrap();
        let mut conn = agent.connect().await.unwrap();
        let ids = conn.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key().key_data(), key.public_key().key_data());
        let sig = conn.sign(&ids[0], None, b"hello".to_vec()).await.unwrap();
        assert!(!sig.is_empty());
        assert_eq!(agent.connects(), 1);
    }

    #[tokio::test]
    async fn unreachable_agents_are_errors_not_panics() {
        assert!(UnreachableAgent.connect().await.is_err());
        #[cfg(unix)]
        {
            let missing = SocketAgent {
                path: std::path::PathBuf::from("/nonexistent/sverb-agent.sock"),
            };
            assert!(missing.connect().await.is_err());
        }
    }
}
