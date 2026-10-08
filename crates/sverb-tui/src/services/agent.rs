//! M2-07: the TUI side of the agent (SPEC §6.1.6).
//!
//! - [`VaultAgentKeys`]: the built-in agent's keys, read from the vault on each
//!   request: Key items with `agent_forwardable = true` (decrypted with their stored
//!   passphrase) and their certificates. Locked vault → no keys (signing refused).
//! - [`AgentService`]: the `confirm_on_use` queue (prompts arrive as
//!   `UiEvent::AgentConfirm`, answers go back through `Effect::AgentConfirm`), the
//!   [`AgentForwarding`] for the SSH connector, and the control socket
//!   (`control.sock` in the runtime dir) that turns `sverb lock` into
//!   `VaultEvent::LockRequested`.
//!
//! The TUI does not expose `agent.sock` itself (the task's proposed opt-in
//! `agent.socket_in_tui` is not implemented); use `sverb agent` for that.

use std::sync::Arc;

use async_trait::async_trait;
use sverb_conn::agent::{
    AgentForwarding, BuiltinAgent, ConfirmQueue, KeySet, KeySource,
    builtin::agent_keys,
    control::{self, ControlCommand},
};
use tracing::{debug, warn};

use super::{EventSender, vault::VaultService};
use crate::app::{UiEvent, VaultEvent};

/// The vault's forwardable keys (see the module docs).
#[derive(Debug, Clone)]
pub struct VaultAgentKeys {
    vault: Option<VaultService>,
}

impl VaultAgentKeys {
    /// Keys from `vault` (`None`: always locked).
    pub fn new(vault: Option<VaultService>) -> Self {
        Self { vault }
    }
}

#[async_trait]
impl KeySource for VaultAgentKeys {
    async fn keys(&self) -> Option<KeySet> {
        let ops = self.vault.as_ref()?.item_ops()?;
        let keys = match ops.keys().await {
            Ok(keys) => keys,
            Err(err) => {
                debug!(%err, "agent: keys unreadable");
                return Some(Arc::default());
            }
        };
        let certs = ops.certificates().await.unwrap_or_default();
        let keys: Vec<_> = keys.into_iter().map(|(l, k)| (l.id, k)).collect();
        let certs: Vec<_> = certs.into_iter().map(|(l, c)| (l.id, c)).collect();
        Some(Arc::new(agent_keys(&keys, &certs)))
    }
}

/// The TUI's agent pieces (see the module docs). Dropping it stops its tasks and
/// removes the control socket.
#[derive(Debug)]
pub struct AgentService {
    queue: Arc<ConfirmQueue>,
    forwarding: AgentForwarding,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Drop for AgentService {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl AgentService {
    /// Start: prompts are sent on `tx` as `UiEvent::AgentConfirm`. Must run inside a
    /// tokio runtime.
    pub fn start(vault: Option<VaultService>, tx: EventSender) -> Self {
        let (queue, mut prompts) = ConfirmQueue::new();
        let builtin = BuiltinAgent::new(
            Arc::new(VaultAgentKeys::new(vault)),
            Arc::clone(&queue) as Arc<dyn sverb_conn::agent::Confirmer>,
        );
        let forwarding = AgentForwarding::new(Arc::new(builtin));
        let prompt_tx = tx;
        let relay = tokio::spawn(async move {
            while let Some(prompt) = prompts.recv().await {
                if prompt_tx.send(UiEvent::AgentConfirm(prompt)).await.is_err() {
                    return;
                }
            }
        });
        Self {
            queue,
            forwarding,
            tasks: vec![relay.abort_handle()],
        }
    }

    /// Also listen on the control socket at `path` (`sverb lock`). Another running
    /// TUI owning it is not an error: this one runs without it.
    #[cfg(unix)]
    pub async fn listen_control(&mut self, path: &std::path::Path, tx: EventSender) {
        use sverb_conn::agent::socket::{DirPolicy, PrivateSocket};
        let socket = match PrivateSocket::bind(path, DirPolicy::Private, "sverb").await {
            Ok(socket) => socket,
            Err(err) => {
                warn!(%err, "control socket unavailable; `sverb lock` cannot reach this TUI");
                return;
            }
        };
        let handler = Arc::new(move |cmd: ControlCommand| match cmd {
            ControlCommand::Lock => tx
                .try_send(UiEvent::Vault(VaultEvent::LockRequested))
                .is_ok(),
            ControlCommand::Ping => true,
        });
        let task = tokio::spawn(control::serve(socket, handler));
        self.tasks.push(task.abort_handle());
    }

    /// Windows: no control pipe yet.
    #[cfg(not(unix))]
    pub async fn listen_control(&mut self, _path: &std::path::Path, _tx: EventSender) {}

    /// The forwarding setup for the SSH connector.
    pub fn forwarding(&self) -> AgentForwarding {
        self.forwarding.clone()
    }

    /// The user answered prompt `id`.
    pub fn answer(&self, id: u64, allow: bool) {
        self.queue.answer(id, allow);
    }
}
