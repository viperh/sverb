//! M2-07: the local agent on Windows: a named pipe (`\\.\pipe\sverb-agent…`).
//!
//! **Skeleton.** The pipe is created as the first instance (so a second agent fails
//! instead of sharing the name) and rejects remote clients. The owner-only DACL and
//! the client-token SID comparison (SPEC §6.1.6, T-14) need Win32 calls that require
//! `unsafe`; they belong in the documented `unsafe` exception module (M7-05) and are
//! not implemented yet. Until then the pipe has the default DACL (the creator, SYSTEM
//! and administrators get full access; Everyone gets read).

use std::io;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use super::builtin::Requester;
use super::forward::AgentServer;

fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    ServerOptions::new()
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .create(name)
}

/// Serve `server` on the pipe `name` until an error.
///
/// # Errors
/// The pipe can't be created (e.g. another agent owns it: `PermissionDenied`).
pub async fn serve(name: &str, server: AgentServer) -> io::Result<()> {
    let mut pipe = create(name, true)?;
    loop {
        pipe.connect().await?;
        let client = pipe;
        pipe = create(name, false)?;
        let server = server.with_requester(Requester::Local {
            pid: None,
            exe: None,
        });
        tokio::spawn(async move { server.serve(client).await });
    }
}
