//! Private Unix sockets for the local agent (`agent.sock`) and the TUI's control
//! channel (`control.sock`) (SPEC §6.1.6).
//!
//! - The directory is created `0700` when missing. An existing directory that other
//!   users can write to is refused for the default endpoint (the runtime dir, checked
//!   by `Paths::ensure(DirKind::Run)`); for a user-chosen `--socket` it is only
//!   warned about, since the socket itself is private and peers are checked.
//! - The socket is `0600`.
//! - A socket file left by a crashed run (nothing accepts on it) is removed and
//!   recreated; a live one is [`SocketError::AlreadyRunning`] with the owner's pid (from
//!   its peer credentials). Anything that is not a socket is never deleted.
//! - Every accepted connection's peer uid must equal the socket owner's uid (the uid
//!   this process created it with); others are closed at once.
//! - Dropping the [`PrivateSocket`] removes the file (if it is still ours).

use std::{
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, warn};

use super::peercred::{OsPeerCred, PeerCred, PeerCredProvider};

/// Why the socket couldn't be set up.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    /// Another process serves this socket.
    #[error("{what} already running{}", pid.map(|p| format!(" (pid {p})")).unwrap_or_default())]
    AlreadyRunning {
        /// "agent" or "sverb".
        what: &'static str,
        /// Its pid, when known.
        pid: Option<i32>,
    },
    /// The path exists and isn't a socket (never deleted).
    #[error("{0} exists and is not a socket")]
    NotASocket(PathBuf),
    /// The directory is unsafe.
    #[error("refusing to use {0}")]
    InsecureDir(String),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// How strictly to treat the socket's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirPolicy {
    /// Must be a real directory owned by us and not accessible to others (0700).
    Private,
    /// A user-chosen location: created 0700 when missing; an open existing directory is
    /// only warned about.
    Lenient,
}

/// A listening private socket.
#[derive(Debug)]
pub struct PrivateSocket {
    path: PathBuf,
    listener: UnixListener,
    owner: u32,
    ino: u64,
    peers: Arc<dyn PeerCredProvider>,
}

fn check_dir(dir: &Path, policy: DirPolicy) -> Result<(), SocketError> {
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    let mode = meta.mode() & 0o777;
    let problem = if !meta.file_type().is_dir() {
        Some(format!("{}: not a directory", dir.display()))
    } else if mode & 0o077 != 0 {
        Some(format!("{}: mode {mode:04o}, expected 0700", dir.display()))
    } else {
        None
    };
    match (problem, policy) {
        (None, _) => Ok(()),
        (Some(p), DirPolicy::Private) => Err(SocketError::InsecureDir(p)),
        (Some(p), DirPolicy::Lenient) => {
            warn!("agent socket directory {p}; the socket itself is private (0600)");
            Ok(())
        }
    }
}

/// The pid of whoever serves `path`, `None` when nothing does (stale).
async fn live_owner(path: &Path) -> Option<Option<i32>> {
    match UnixStream::connect(path).await {
        Ok(stream) => Some(stream.peer_cred().ok().and_then(|c| c.pid())),
        Err(_) => None,
    }
}

impl PrivateSocket {
    /// Bind `path` (see the module docs). `what` names the owner in errors.
    ///
    /// # Errors
    /// [`SocketError`].
    pub async fn bind(
        path: &Path,
        policy: DirPolicy,
        what: &'static str,
    ) -> Result<Self, SocketError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            check_dir(dir, policy)?;
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                if let Some(pid) = live_owner(path).await {
                    return Err(SocketError::AlreadyRunning { what, pid });
                }
                debug!(path = %path.display(), "removing a stale socket");
                std::fs::remove_file(path)?;
            }
            Ok(_) => return Err(SocketError::NotASocket(path.to_owned())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            listener,
            owner: meta.uid(),
            ino: meta.ino(),
            peers: Arc::new(OsPeerCred),
        })
    }

    /// Check peers with `peers` instead of the OS (tests).
    #[must_use]
    pub fn with_peer_creds(mut self, peers: Arc<dyn PeerCredProvider>) -> Self {
        self.peers = peers;
        self
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The uid allowed to connect (the owner).
    pub fn owner_uid(&self) -> u32 {
        self.owner
    }

    /// The next connection from the owner's uid. Others are closed and skipped.
    ///
    /// # Errors
    /// `accept` failed.
    pub async fn accept(&self) -> io::Result<(UnixStream, PeerCred)> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            match self.peers.peer(&stream) {
                Ok(cred) if cred.uid == self.owner => return Ok((stream, cred)),
                Ok(cred) => {
                    warn!(uid = cred.uid, pid = ?cred.pid, "refused a connection from another user");
                }
                Err(err) => warn!(%err, "refused a connection: no peer credentials"),
            }
            drop(stream);
        }
    }
}

impl Drop for PrivateSocket {
    fn drop(&mut self) {
        let ours = std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino);
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
