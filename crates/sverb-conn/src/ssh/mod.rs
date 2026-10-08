//! SSH sessions over russh (SPEC §6.1). **All russh API usage stays in this module**, so
//! an upstream rename touches only these files.
//!
//! - [`SshConnector`]: the [`Connector`] for [`TransportKind::Ssh`](crate::TransportKind::Ssh); runs the flow in
//!   `connect.rs` and returns an [`SshTransport`].
//! - Seams for later tasks: [`HostResolver`] (settings and secrets; the UI resolves
//!   groups through `sverb_core::resolve`),
//!   [`HostKeyVerifier`] (known hosts, M1-15: [`KnownHostsVerifier`]), [`Authenticator`] (the auth chain,
//!   M1-14).
//! - [`algorithms`]: preferences and the per-host legacy opt-in (§6.1.8);
//!   [`errors`]: the §6.1.9 mapping; [`tcp`]: DNS and Happy Eyeballs.
//! - M3-07: connection sharing (§6.1.3). The connector owns a pool of connections
//!   (`mux.rs`, `mux_ssh.rs`); sessions, exec runs, standalone tunnels and jump hops
//!   to the same key share one connection with a channel each.
//!   [`SshConnector::with_multiplex`] turns it on (`ssh.multiplex`; the TUI's connector
//!   follows the config, whose default is on); off, every connect has connections of
//!   its own.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use sverb_core::config::Config;

use crate::{
    session::{DisconnectReason, SessionSpec, SshSpec},
    transport::{ConnectCtx, ConnectError, Connector, Transport},
};

pub mod algorithms;
pub mod auth_stub;
pub mod channel;
mod connect;
pub mod errors;
// M2-06: the first hop's stream (direct TCP or a proxy).
pub mod first_hop;
pub mod handler;
pub mod keepalive;
pub mod resolved;
pub mod tcp;

#[cfg(any(test, feature = "test-util"))]
pub mod testing;
#[cfg(test)]
mod tests;
// M3-07: loopback tests of shared connections (a counting russh server).
#[cfg(test)]
mod mux_loopback;
// M1-14: the authentication chain, the M1 key-file import, test key fixtures.
pub mod auth;
#[cfg(test)]
mod auth_loopback;
#[cfg(any(test, feature = "test-util"))]
pub mod auth_testing;
#[cfg(test)]
mod auth_tests;
pub mod keyfile;
#[cfg(any(test, feature = "test-util"))]
pub mod test_keys;

pub use auth_stub::{AuthOutcome, AuthSession, Authenticator, StubAuthenticator};
pub use channel::{SshTransport, pty_modes};
pub use connect::HOST_KEY_PROMPT_TIMEOUT;
pub use errors::SshError;
pub use handler::{
    AskEveryTime, HostKeyTarget, HostKeyVerdict, HostKeyVerifier, InsecureAcceptAnyHostKey,
    ServerKey, UnverifiedHostKeys,
};
pub use resolved::{AuthMaterial, SshTarget, local_user, resolve, resolve_spec};
// M1-14
pub use auth::{ChainAuthenticator, sanitize_server_text};
pub use resolved::{KeyMaterial, allows_ssh_rsa};
// M1-15: host-key verification over known hosts.
pub mod verify;
#[cfg(test)]
mod verify_tests;
// M2-04: non-interactive exec channels and install-key on host (§6.1.7, §9.4).
pub mod exec;
#[cfg(all(unix, any(test, feature = "test-util")))]
pub mod exec_testing;
#[cfg(all(unix, test))]
mod exec_tests;
pub mod install_key;
pub use exec::{ExecOpts, ExecPrompts, ExecResult, SshConnection, exec};
pub use verify::{KnownHostsStore, KnownHostsVerifier, MemoryKnownHosts, VerifyOptions};

/// Turns an [`SshSpec`] into an [`SshTarget`], fresh on every connect and reconnect.
#[async_trait]
pub trait HostResolver: Send + Sync + fmt::Debug {
    /// Resolve `spec`.
    ///
    /// # Errors
    /// The host's settings could not be loaded ([`SshError::Settings`]).
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError>;
}

/// Resolves from the spec and the global config only (unsaved targets, tests).
#[derive(Debug, Clone, Default)]
pub struct ConfigResolver {
    config: Arc<Config>,
}

impl ConfigResolver {
    /// A resolver over `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl HostResolver for ConfigResolver {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        Ok(resolve_spec(spec, &self.config, local_user))
    }
}

/// The [`Connector`] for SSH sessions.
#[derive(Debug, Clone)]
pub struct SshConnector {
    resolver: Arc<dyn HostResolver>,
    verifier: Arc<dyn HostKeyVerifier>,
    auth: Arc<dyn Authenticator>,
    // M2-06
    approvals: Arc<dyn crate::proxy::LocalApprovals>,
    // M2-07: serves forwarded agent channels; `None`: forwarding is never requested.
    agent: Option<crate::agent::AgentForwarding>,
    // M3-07: shared connections (clones of the connector share the pool).
    pool: connect::jump::mux_ssh::SshPool,
}

impl SshConnector {
    /// A connector resolving hosts with `resolver`. Host keys are rejected
    /// ([`UnverifiedHostKeys`]) until a verifier is set. M1-14: authentication is the
    /// full chain without the system agent ([`ChainAuthenticator::with_agent`] adds it).
    pub fn new(resolver: Arc<dyn HostResolver>) -> Self {
        Self {
            resolver,
            verifier: Arc::new(UnverifiedHostKeys),
            auth: Arc::new(ChainAuthenticator::new()),
            // M2-06: the stub until M2-10's store.
            approvals: Arc::new(crate::proxy::StampApprovals),
            // M2-07
            agent: None,
            // M3-07: off until `with_multiplex(true)` (the TUI applies `ssh.multiplex`).
            pool: {
                let pool = connect::jump::mux_ssh::SshPool::default();
                pool.set_enabled(false);
                pool
            },
        }
    }

    // M3-07
    /// Share connections between sessions, exec runs and tunnels (`ssh.multiplex`).
    #[must_use]
    pub fn with_multiplex(self, enabled: bool) -> Self {
        self.set_multiplex(enabled);
        self
    }

    // M3-07
    /// Change `ssh.multiplex` for new connects (a config reload); connections already
    /// open stay as they are. Clones of this connector share the setting.
    pub fn set_multiplex(&self, enabled: bool) {
        self.pool.set_enabled(enabled);
    }

    // M3-07
    /// Whether connections are shared.
    pub fn multiplex(&self) -> bool {
        self.pool.is_enabled()
    }

    // M3-07
    /// The connection pool.
    pub(crate) fn pool(&self) -> &connect::jump::mux_ssh::SshPool {
        &self.pool
    }

    // M2-07
    /// Serve forwarded agent channels (hosts with `agent_forwarding`) with `agent`.
    /// Without it, forwarding is never requested.
    #[must_use]
    pub fn with_agent_forwarding(mut self, agent: crate::agent::AgentForwarding) -> Self {
        self.agent = Some(agent);
        self
    }

    // M2-07
    /// The agent-forwarding setup, if any.
    pub fn agent_forwarding(&self) -> Option<&crate::agent::AgentForwarding> {
        self.agent.as_ref()
    }

    // M2-06
    /// Check locally-acting values (a ProxyCommand) with `approvals` (§17.1).
    #[must_use]
    pub fn with_local_approvals(
        mut self,
        approvals: Arc<dyn crate::proxy::LocalApprovals>,
    ) -> Self {
        self.approvals = approvals;
        self
    }

    // M2-06
    /// The local-action approval check.
    pub fn local_approvals(&self) -> &dyn crate::proxy::LocalApprovals {
        self.approvals.as_ref()
    }

    /// Verify host keys with `verifier`.
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn HostKeyVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Authenticate with `auth`.
    #[must_use]
    pub fn with_authenticator(mut self, auth: Arc<dyn Authenticator>) -> Self {
        self.auth = auth;
        self
    }
}

#[async_trait]
impl Connector for SshConnector {
    async fn connect(
        &self,
        spec: &SessionSpec,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError> {
        let SessionSpec::Ssh(ssh) = spec else {
            return Err(ConnectError::new(DisconnectReason::Connect));
        };
        connect::connect(self, ssh, ctx).await
    }
}
