//! M2-07: peer credentials of local-socket clients (SPEC §6.1.6): connections from
//! another uid are refused.
//!
//! [`OsPeerCred`] uses tokio's `UnixStream::peer_cred` (`SO_PEERCRED` on Linux,
//! `getpeereid` + `LOCAL_PEERPID` on macOS/BSD), so no `unsafe` code is needed here.
//! [`PeerCredProvider`] is injectable so tests can simulate another uid (T-08).

use std::{fmt, io};

/// Who is on the other end of a local socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer's effective uid.
    pub uid: u32,
    /// The peer's pid, when the platform reports one.
    pub pid: Option<i32>,
}

/// Reads a connection's peer credentials.
#[cfg(unix)]
pub trait PeerCredProvider: Send + Sync + fmt::Debug {
    /// The credentials of `stream`'s peer.
    ///
    /// # Errors
    /// The platform can't tell (the connection is then refused).
    fn peer(&self, stream: &tokio::net::UnixStream) -> io::Result<PeerCred>;
}

/// The operating system's answer.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsPeerCred;

#[cfg(unix)]
impl PeerCredProvider for OsPeerCred {
    fn peer(&self, stream: &tokio::net::UnixStream) -> io::Result<PeerCred> {
        let cred = stream.peer_cred()?;
        Ok(PeerCred {
            uid: cred.uid(),
            pid: cred.pid(),
        })
    }
}

/// The executable name of `pid` (Linux: `/proc/<pid>/comm`; elsewhere `None`).
pub fn process_name(pid: i32) -> Option<String> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    } else {
        None
    }
}
