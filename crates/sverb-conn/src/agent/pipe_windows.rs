//! The local agent on Windows: a named pipe (`\\.\pipe\sverb-agent…`).
//!
//! The pipe is created as the first instance (so a second agent fails instead of
//! sharing the name) and rejects remote clients. Every instance carries an
//! owner-only, protected DACL (only the current user's SID), and each client's token
//! user must equal ours or the connection is dropped (`dacl_windows`, SPEC §6.1.6).

use std::io;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use super::builtin::Requester;
use super::dacl_windows::{OwnerOnly, client_pid_if_same_user};
use super::forward::AgentServer;

fn create(security: &mut OwnerOnly, name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    security.create(&options, name)
}

/// Serve `server` on the pipe `name` until an error.
///
/// # Errors
/// The pipe can't be created (e.g. another agent owns it: `PermissionDenied`), or the
/// owner-only DACL can't be built.
pub async fn serve(name: &str, server: AgentServer) -> io::Result<()> {
    let mut security = OwnerOnly::current_user()?;
    tracing::debug!(sddl = security.sddl(), "agent pipe DACL");
    let mut pipe = create(&mut security, name, true)?;
    loop {
        pipe.connect().await?;
        let client = pipe;
        pipe = create(&mut security, name, false)?;
        let pid = match client_pid_if_same_user(&client) {
            Ok(pid) => pid,
            Err(err) => {
                tracing::warn!(error = %err, "agent pipe: client rejected");
                continue;
            }
        };
        let server = server.with_requester(Requester::Local {
            pid: i32::try_from(pid).ok(),
            exe: None,
        });
        tokio::spawn(async move { server.serve(client).await });
    }
}
