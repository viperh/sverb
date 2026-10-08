//! M2-07: agent forwarding, the built-in agent and the local agent socket (SPEC §6.1.6).
//!
//! - [`proto`]: the agent wire protocol subset.
//! - [`builtin`]: the built-in agent over vault keys with `agent_forwardable = true`
//!   (plus their certificates); refuses while the vault is locked; `confirm_on_use`.
//! - [`confirm`]: the queue of `confirm_on_use` prompts for a UI (60 s, then deny).
//! - [`forward`]: serving a connection per `agent_source` (builtin / system / both),
//!   the hook for forwarded `auth-agent@openssh.com` channels.
//! - [`socket`], [`peercred`]: the private local socket (`0700` dir, `0600` socket,
//!   peer uid check, stale-socket handling); [`serve_local`] runs the agent on it.
//! - [`control`]: the TUI's control socket (`sverb lock`).
//! - `pipe_windows`: the Windows named-pipe skeleton (no DACL yet; M7-05).

pub mod builtin;
pub mod confirm;
pub mod control;
pub mod forward;
pub mod peercred;
#[cfg(windows)]
pub mod pipe_windows;
pub mod proto;
#[cfg(unix)]
pub mod socket;

#[cfg(test)]
mod tests;
// M2-07: needs the ssh/{mod,connect,channel}.rs copies.
#[cfg(test)]
mod loopback_tests;

pub use builtin::{
    AgentKey, BuiltinAgent, ConfirmRequest, Confirmer, DenyConfirm, KeySet, KeySource, Requester,
    SignOutcome, StaticKeys,
};
pub use confirm::{AgentConfirmRequest, CONFIRM_TIMEOUT, ConfirmQueue};
pub use control::{CONTROL_SOCKET, ControlCommand, ControlError};
pub use forward::{AgentForwarding, AgentServer, RawAgent, SystemRawAgent};

/// The §17.1 approval field for agent forwarding (value: the source, `system`/`both`).
pub const APPROVAL_FIELD: &str = sverb_core::resolve::approval::AGENT_FIELD;

/// Does forwarding with `source` act locally (§17.1: exposes the system agent)?
/// M2-10: the classification lives in `sverb_core::resolve::approval`.
pub fn needs_approval(forwarding: bool, source: sverb_core::model::AgentSource) -> bool {
    sverb_core::resolve::approval::agent_acts_locally(forwarding, source)
}

/// Serve `server` on the local `socket` until accepting fails. Each peer (same uid,
/// checked by the socket) becomes the [`Requester::Local`] shown in confirm prompts.
#[cfg(unix)]
pub async fn serve_local(
    socket: &socket::PrivateSocket,
    server: AgentServer,
) -> std::io::Result<()> {
    loop {
        let (stream, cred) = socket.accept().await?;
        let requester = Requester::Local {
            pid: cred.pid,
            exe: cred.pid.and_then(peercred::process_name),
        };
        tracing::debug!(pid = ?cred.pid, "local agent connection");
        let server = server.with_requester(requester);
        tokio::spawn(async move { server.serve(stream).await });
    }
}
