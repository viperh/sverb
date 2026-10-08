//! Error mapping (SPEC §6.1.9): every way an SSH connection fails becomes a
//! [`DisconnectReason`] and a user-facing message, with the raw error chain kept for
//! the detail view ([`ErrorReport::chain`]).
//!
//! Messages name the host or address (they are shown in the UI); logs at `info` and
//! above never do (§17): log the `SessionId` instead.

use std::{fmt, io, net::SocketAddr};

use sverb_core::error_report::ErrorReport;

use super::algorithms::{AlgoKind, is_kex_extension};
use crate::{session::DisconnectReason, transport::ConnectError};

/// Where to enable a legacy algorithm (§6.1.8).
pub const LEGACY_HINT: &str = "Enable it for this host in Host → Connection → Algorithms (legacy).";

/// Why an SSH connection failed or ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum SshError {
    /// The host's settings could not be loaded (vault locked, host deleted).
    Settings(String),
    /// DNS failed.
    Resolve {
        /// The name looked up.
        host: String,
        /// The resolver's error.
        source: io::Error,
    },
    /// TCP failed (refused, unreachable) or timed out.
    Connect {
        /// The address shown (`host:port`, or the first address tried).
        addr: String,
        /// Nothing answered within the connect timeout.
        timed_out: bool,
        /// The underlying errors (one per address tried).
        causes: Vec<(SocketAddr, io::Error)>,
    },
    /// The handshake didn't finish within the connect timeout.
    HandshakeTimeout {
        /// The address.
        addr: String,
    },
    /// No algorithm in common with the server.
    Negotiation {
        /// The category.
        kind: AlgoKind,
        /// What the server offered.
        theirs: Vec<String>,
        /// What sverb offered.
        ours: Vec<String>,
    },
    /// The host key was rejected (by the user, the policy, or a changed key).
    HostKey {
        /// Why, for the detail view.
        detail: String,
    },
    /// Every authentication method failed.
    Auth {
        /// Methods tried, in order (`none`, `password`, …).
        tried: Vec<&'static str>,
    },
    /// No keepalive reply for `interval × 3` seconds.
    KeepaliveTimeout {
        /// The keepalive interval in seconds.
        interval_secs: u32,
    },
    /// Something this build can't do yet (proxies, jump hosts).
    Unsupported(String),
    /// The session channel could not be opened or set up.
    Channel(String),
    /// The server disconnected.
    RemoteDisconnect {
        /// The server's message.
        message: String,
    },
    /// Any other protocol or I/O failure.
    Protocol(String),
    // M2-06: proxies (§6.1.5) and the §17.1 approval gate.
    /// The proxy failed (SOCKS5, HTTP CONNECT, ProxyCommand).
    Proxy {
        /// The readable message (`proxy: authentication failed`).
        message: String,
        /// Detail lines (raw causes, ProxyCommand stderr).
        detail: Vec<String>,
    },
    /// A ProxyCommand that did not originate on this device and is not approved.
    NeedsApproval {
        /// The host's label.
        host: String,
        /// The exact command.
        command: String,
    },
    // M2-07
    /// Forwarding the system agent (`agent_source = system | both`) for a host whose
    /// agent settings did not originate on this device, and are not approved (§17.1).
    AgentNeedsApproval {
        /// The host's label.
        host: String,
        /// The source (`system` / `both`).
        source: String,
    },
}

impl SshError {
    /// The reason the session shows (§6.1.9).
    pub fn reason(&self) -> DisconnectReason {
        match self {
            Self::Resolve { .. } => DisconnectReason::Resolve,
            Self::Settings(_)
            | Self::Connect { .. }
            | Self::HandshakeTimeout { .. }
            | Self::Unsupported(_)
            | Self::Channel(_)
            | Self::RemoteDisconnect { .. }
            | Self::Protocol(_) => DisconnectReason::Connect,
            // M2-06
            Self::Proxy { .. } | Self::NeedsApproval { .. } => DisconnectReason::Connect,
            // M2-07
            Self::AgentNeedsApproval { .. } => DisconnectReason::Connect,
            Self::Negotiation { .. } => DisconnectReason::Negotiation,
            Self::HostKey { .. } => DisconnectReason::HostKey,
            Self::Auth { .. } => DisconnectReason::Auth,
            Self::KeepaliveTimeout { .. } => DisconnectReason::Timeout,
        }
    }

    /// The user-facing message (§6.1.9).
    pub fn message(&self) -> String {
        match self {
            Self::Settings(msg) => format!("Could not load the host settings: {msg}"),
            Self::Resolve { host, .. } => format!("Could not resolve {host}"),
            Self::Connect {
                addr,
                timed_out: true,
                ..
            }
            | Self::HandshakeTimeout { addr } => {
                format!("Connection timed out ({addr})")
            }
            Self::Connect { addr, causes, .. } => {
                let refused = causes
                    .iter()
                    .any(|(_, e)| e.kind() == io::ErrorKind::ConnectionRefused);
                if refused || causes.is_empty() {
                    format!("Connection refused ({addr})")
                } else {
                    format!("Could not connect ({addr})")
                }
            }
            Self::Negotiation { kind, theirs, .. } => negotiation_message(*kind, theirs),
            Self::HostKey { .. } => "Host key verification failed".to_owned(),
            Self::Auth { tried } => {
                if tried.is_empty() {
                    "Permission denied".to_owned()
                } else {
                    format!("Permission denied (methods tried: {})", tried.join(", "))
                }
            }
            Self::KeepaliveTimeout { interval_secs } => format!(
                "Connection lost (no response for {} s)",
                interval_secs.saturating_mul(3)
            ),
            Self::Unsupported(what) => what.clone(),
            Self::Channel(msg) => format!("Could not open the session channel: {msg}"),
            Self::RemoteDisconnect { message } if message.is_empty() => {
                "Connection closed by the remote host".to_owned()
            }
            Self::RemoteDisconnect { message } => {
                format!("Connection closed by the remote host: {message}")
            }
            Self::Protocol(msg) => format!("SSH connection failed: {msg}"),
            // M2-06
            Self::Proxy { message, .. } => message.clone(),
            Self::NeedsApproval { host, .. } => format!(
                "host \"{host}\" uses a local command that has not been approved on this \
                 device. Run: sverb approve {host}"
            ),
            // M2-07
            Self::AgentNeedsApproval { host, .. } => format!(
                "host \"{host}\" forwards your system SSH agent, which has not been approved on \
                 this device. Run: sverb approve {host}"
            ),
        }
    }

    /// The detail lines (outermost first) below [`SshError::message`].
    pub fn detail(&self) -> Vec<String> {
        match self {
            Self::Resolve { source, .. } => vec![source.to_string()],
            Self::Connect { causes, .. } => causes
                .iter()
                .map(|(addr, err)| format!("{addr}: {err}"))
                .collect(),
            Self::Negotiation { kind, theirs, ours } => vec![
                format!("server {}s: {}", kind.noun(), theirs.join(", ")),
                format!("sverb {}s: {}", kind.noun(), ours.join(", ")),
            ],
            Self::HostKey { detail } => vec![detail.clone()],
            // M2-06
            Self::Proxy { detail, .. } => detail.clone(),
            Self::NeedsApproval { command, .. } => vec![format!("ProxyCommand: {command}")],
            // M2-07
            Self::AgentNeedsApproval { source, .. } => {
                vec![format!("agent_forwarding = true, agent_source = {source}")]
            }
            _ => Vec::new(),
        }
    }

    // M2-06
    /// A proxy failure.
    pub fn proxy(message: String, detail: Vec<String>) -> Self {
        Self::Proxy { message, detail }
    }

    /// The report for the toast and the detail view.
    pub fn report(&self) -> ErrorReport {
        let mut report = ErrorReport::msg(self.message());
        report.chain = self.detail();
        report
    }

    /// As the connector's error.
    pub fn into_connect_error(self) -> ConnectError {
        ConnectError::with_report(self.reason(), self.report())
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SshError {}

/// "No common key exchange: server offers diffie-hellman-group14-sha1. Enable it for
/// this host in Host → Connection → Algorithms (legacy)." The hint is added only when
/// the server offers something the host could opt into.
pub fn negotiation_message(kind: AlgoKind, theirs: &[String]) -> String {
    let offered: Vec<&str> = theirs
        .iter()
        .map(String::as_str)
        .filter(|n| !(kind == AlgoKind::Kex && is_kex_extension(n)))
        .collect();
    let mut msg = format!(
        "No common {}: server offers {}.",
        kind.noun(),
        offered.join(", ")
    );
    let enable: Vec<&str> = offered
        .iter()
        .copied()
        .filter(|n| kind.legacy().contains(n) && kind.is_supported(n))
        .collect();
    if !enable.is_empty() {
        msg.push(' ');
        msg.push_str(LEGACY_HINT);
    }
    msg
}

/// Map a russh error. `addr` is the target as shown in messages.
pub(crate) fn from_russh(err: &russh::Error, keepalive_secs: u32, addr: &str) -> SshError {
    use russh::Error as E;
    match err {
        E::NoCommonAlgo { kind, ours, theirs } => SshError::Negotiation {
            kind: match kind {
                russh::AlgorithmKind::Kex => AlgoKind::Kex,
                russh::AlgorithmKind::Key => AlgoKind::HostKey,
                russh::AlgorithmKind::Cipher => AlgoKind::Cipher,
                russh::AlgorithmKind::Compression => AlgoKind::Compression,
                russh::AlgorithmKind::Mac => AlgoKind::Mac,
            },
            ours: ours.clone(),
            theirs: theirs.clone(),
        },
        E::UnknownKey | E::KeyChanged { .. } | E::WrongServerSig => SshError::HostKey {
            detail: err.to_string(),
        },
        E::KeepaliveTimeout => SshError::KeepaliveTimeout {
            interval_secs: keepalive_secs,
        },
        E::ConnectionTimeout | E::InactivityTimeout | E::Elapsed(_) => SshError::HandshakeTimeout {
            addr: addr.to_owned(),
        },
        E::NoAuthMethod | E::NotAuthenticated => SshError::Auth { tried: Vec::new() },
        E::ChannelOpenFailure(reason) => SshError::Channel(format!("{reason:?}")),
        E::HUP | E::Disconnect => SshError::RemoteDisconnect {
            message: String::new(),
        },
        E::IO(io) => SshError::Protocol(io.to_string()),
        other => SshError::Protocol(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn refused() -> io::Error {
        io::Error::from(io::ErrorKind::ConnectionRefused)
    }

    /// T-07: each error class → reason and message.
    #[test]
    fn t07_error_mapping_table() {
        let addr: SocketAddr = "192.0.2.7:22".parse().unwrap();
        let rows: Vec<(SshError, DisconnectReason, &str)> = vec![
            (
                SshError::Resolve {
                    host: "nope.example".into(),
                    source: io::Error::other("no such host"),
                },
                DisconnectReason::Resolve,
                "Could not resolve nope.example",
            ),
            (
                SshError::Connect {
                    addr: "db:22".into(),
                    timed_out: false,
                    causes: vec![(addr, refused())],
                },
                DisconnectReason::Connect,
                "Connection refused (db:22)",
            ),
            (
                SshError::Connect {
                    addr: "db:22".into(),
                    timed_out: true,
                    causes: vec![],
                },
                DisconnectReason::Connect,
                "Connection timed out (db:22)",
            ),
            (
                from_russh(
                    &russh::Error::NoCommonAlgo {
                        kind: russh::AlgorithmKind::Kex,
                        ours: vec!["curve25519-sha256".into()],
                        theirs: vec!["diffie-hellman-group14-sha1".into(), "ext-info-s".into()],
                    },
                    30,
                    "db:22",
                ),
                DisconnectReason::Negotiation,
                "No common key exchange: server offers diffie-hellman-group14-sha1. Enable it for this host in Host → Connection → Algorithms (legacy).",
            ),
            (
                from_russh(
                    &russh::Error::NoCommonAlgo {
                        kind: russh::AlgorithmKind::Cipher,
                        ours: vec!["aes256-ctr".into()],
                        theirs: vec!["arcfour".into()],
                    },
                    30,
                    "db:22",
                ),
                DisconnectReason::Negotiation,
                "No common cipher: server offers arcfour.",
            ),
            (
                from_russh(&russh::Error::UnknownKey, 30, "db:22"),
                DisconnectReason::HostKey,
                "Host key verification failed",
            ),
            (
                SshError::Auth {
                    tried: vec!["none", "password"],
                },
                DisconnectReason::Auth,
                "Permission denied (methods tried: none, password)",
            ),
            (
                from_russh(&russh::Error::KeepaliveTimeout, 1, "db:22"),
                DisconnectReason::Timeout,
                "Connection lost (no response for 3 s)",
            ),
            (
                from_russh(&russh::Error::ConnectionTimeout, 30, "db:22"),
                DisconnectReason::Connect,
                "Connection timed out (db:22)",
            ),
            (
                from_russh(&russh::Error::HUP, 30, "db:22"),
                DisconnectReason::Connect,
                "Connection closed by the remote host",
            ),
        ];
        for (err, reason, msg) in rows {
            assert_eq!(err.reason(), reason, "{err:?}");
            assert_eq!(err.message(), msg);
            let ce = err.into_connect_error();
            assert_eq!(ce.reason, reason);
            assert_eq!(ce.report.unwrap().short, msg);
        }
        // Remote exit: the reason's own message, no reconnect banner.
        assert_eq!(
            DisconnectReason::Exited(7).message(),
            "Session ended (exit 7)"
        );
        assert!(!DisconnectReason::Exited(7).offers_reconnect());
    }

    #[test]
    fn details_keep_the_raw_chain() {
        let addr: SocketAddr = "[2001:db8::1]:22".parse().unwrap();
        let err = SshError::Connect {
            addr: "db:22".into(),
            timed_out: false,
            causes: vec![(addr, refused())],
        };
        let report = err.report();
        assert_eq!(report.chain.len(), 1);
        assert!(report.chain[0].starts_with("[2001:db8::1]:22: "));
        let neg = SshError::Negotiation {
            kind: AlgoKind::Mac,
            theirs: vec!["hmac-sha1".into()],
            ours: vec!["hmac-sha2-256-etm@openssh.com".into()],
        };
        assert!(neg.message().ends_with(LEGACY_HINT));
        assert_eq!(neg.report().chain.len(), 2);
    }
}
