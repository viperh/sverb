//! The TUI's control socket (`control.sock`, next to `agent.sock` in the runtime
//! directory, same permission rules). `sverb lock` uses it to lock a running TUI
//!
//! Protocol: the client sends one command line (`lock` or `ping`), the server answers
//! one line (`ok <pid>` or `err <message>`) and closes. Only one TUI owns the socket;
//! a second one runs without it. Windows (named pipe with an owner-only DACL) is not
//! implemented yet: the client reports that no TUI is reachable.

use std::{io, path::Path, sync::Arc, time::Duration};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

/// The control socket's file name.
pub const CONTROL_SOCKET: &str = "control.sock";

/// A request to the running TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCommand {
    /// Lock the vault now.
    Lock,
    /// Is anyone there?
    Ping,
}

impl ControlCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Ping => "ping",
        }
    }

    fn parse(line: &str) -> Option<Self> {
        match line.trim() {
            "lock" => Some(Self::Lock),
            "ping" => Some(Self::Ping),
            _ => None,
        }
    }
}

/// Why a control request failed.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// No TUI listens.
    #[error("no running sverb TUI")]
    NotRunning,
    /// The TUI answered with an error.
    #[error("the running sverb refused: {0}")]
    Refused(String),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// How long a client waits for the answer.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Send `command` to the TUI listening on `path`; its pid on success.
///
/// # Errors
/// [`ControlError::NotRunning`] when nothing listens (or a stale file), else the
/// refusal or I/O error.
#[cfg(unix)]
pub async fn send(path: &Path, command: ControlCommand) -> Result<Option<i32>, ControlError> {
    let Ok(stream) = tokio::net::UnixStream::connect(path).await else {
        return Err(ControlError::NotRunning);
    };
    let exchange = async {
        let mut stream = BufReader::new(stream);
        stream
            .get_mut()
            .write_all(format!("{}\n", command.as_str()).as_bytes())
            .await?;
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        Ok::<_, io::Error>(line)
    };
    let line = tokio::time::timeout(CLIENT_TIMEOUT, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("ok") {
        return Ok(rest.trim().parse().ok());
    }
    Err(ControlError::Refused(
        line.strip_prefix("err").unwrap_or(line).trim().to_owned(),
    ))
}

/// Windows: not implemented (see the module docs).
#[cfg(not(unix))]
pub async fn send(_path: &Path, _command: ControlCommand) -> Result<Option<i32>, ControlError> {
    Err(ControlError::NotRunning)
}

/// Serve `socket` until it fails: each command goes to `handler` (which returns
/// whether it was accepted).
#[cfg(unix)]
pub async fn serve(
    socket: super::socket::PrivateSocket,
    handler: Arc<dyn Fn(ControlCommand) -> bool + Send + Sync>,
) {
    loop {
        let (stream, _) = match socket.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                debug!(%err, "control socket closed");
                return;
            }
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            let read = tokio::time::timeout(CLIENT_TIMEOUT, stream.read_line(&mut line)).await;
            if !matches!(read, Ok(Ok(_))) {
                return;
            }
            let reply = match ControlCommand::parse(&line) {
                Some(cmd) if handler(cmd) => format!("ok {}\n", std::process::id()),
                Some(_) => "err not accepted\n".to_owned(),
                None => "err unknown command\n".to_owned(),
            };
            let _ = stream.get_mut().write_all(reply.as_bytes()).await;
        });
    }
}

/// Where the control socket lives: next to the agent socket in the runtime directory
/// (`None` on Windows, where the agent endpoint is a named pipe).
pub fn control_path(paths: &sverb_core::paths::Paths) -> Option<std::path::PathBuf> {
    match paths.agent_endpoint() {
        sverb_core::paths::AgentEndpoint::UnixSocket(p) => Some(p.with_file_name(CONTROL_SOCKET)),
        sverb_core::paths::AgentEndpoint::NamedPipe(_) => None,
    }
}
