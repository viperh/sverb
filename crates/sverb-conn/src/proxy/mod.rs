//! M2-06: proxies for the first hop (SPEC §6.1.5).
//!
//! A configured [`ProxyConfig`] replaces the direct TCP step of the SSH flow: the
//! connector asks [`open_first_hop`] (the stream factory) for the first hop's byte
//! stream, and runs the SSH handshake over it. Jump chains (M2-05) apply the proxy
//! to the first hop only.
//!
//! - [`socks5`]: SOCKS5 via `tokio-socks`, CONNECT **by domain name** (the proxy
//!   resolves the target; no local DNS), optional RFC 1929 user/password.
//! - [`http_connect`]: HTTP CONNECT (in-house), optional basic auth; bytes received
//!   after the response headers are replayed as the start of the SSH stream
//!   ([`PrefixedStream`]).
//! - [`command`]: ProxyCommand via `sh -c` / `cmd /C` with `%h %p %r %%`, the child's
//!   stdin/stdout as the stream, stderr to the debug log and the connection's error
//!   detail, killed when the stream is dropped (session close or connect failure).
//!
//! **§17.1:** a ProxyCommand runs a local process, so before it is spawned the
//! [`LocalApprovals`] check must pass. M2-10: sverb checks against the device's
//! explicit `local_approvals` rows
//! ([`DeviceApprovals`](sverb_core::resolve::approval::DeviceApprovals)); a value
//! denied in this session fails with "blocked by approval policy" without asking.

pub mod command;
pub mod http_connect;
pub mod socks5;

#[cfg(test)]
mod tests;

use std::{fmt, time::Duration};

use sverb_core::{
    model::{DeviceId, ItemId},
    secret::SecretString,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ssh::{
    SshError,
    tcp::{TcpError, connect_tcp, lookup},
};

pub use command::{CommandError, ProxyCommandStream, expand_command, validate_command};
pub use http_connect::{HttpConnectError, PrefixedStream, connect_request};

/// The §17.1 field name of a ProxyCommand.
pub const COMMAND_FIELD: &str = sverb_core::resolve::approval::PROXY_COMMAND_FIELD;

/// A byte stream the SSH handshake can run over.
pub trait ProxyIo: AsyncRead + AsyncWrite + Send + Unpin + fmt::Debug {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + fmt::Debug> ProxyIo for T {}

/// A boxed [`ProxyIo`].
pub type BoxedIo = Box<dyn ProxyIo>;

/// User and password for a SOCKS5 or HTTP proxy.
pub struct ProxyCredentials {
    /// The proxy user.
    pub user: String,
    /// The proxy password (empty when none is stored).
    pub password: Option<SecretString>,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl ProxyCredentials {
    /// The password text (`""` when none is stored).
    pub fn password_text(&self) -> &str {
        self.password.as_ref().map_or("", SecretString::expose)
    }
}

/// Where a locally-acting value came from (§17.1): the item that defines it and the
/// device that last wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValueOrigin {
    /// The item defining the value (host, group or vault defaults; `None`: an unsaved
    /// target).
    pub item_id: Option<ItemId>,
    /// The device of the value's stamp.
    pub written_by: Option<DeviceId>,
    /// This device.
    pub this_device: Option<DeviceId>,
}

impl ValueOrigin {
    /// The value was typed on this device: its stamp names this device, or it was never
    /// stored (an unsaved target typed into this process).
    pub fn typed_here(&self) -> bool {
        match (self.written_by, self.this_device) {
            (Some(by), Some(here)) => by == here,
            (None, _) => self.item_id.is_none(),
            (Some(_), None) => false,
        }
    }
}

/// How the first hop reaches the target (§6.1.5), with its secrets.
#[derive(Debug)]
pub enum ProxyConfig {
    /// SOCKS5 via `addr` (`host:port`).
    Socks5 {
        /// The proxy's `host:port`.
        addr: String,
        /// RFC 1929 user/password.
        auth: Option<ProxyCredentials>,
    },
    /// HTTP CONNECT via `addr` (`host:port`).
    Http {
        /// The proxy's `host:port`.
        addr: String,
        /// Basic auth.
        auth: Option<ProxyCredentials>,
    },
    /// A ProxyCommand (`%h %p %r %%`).
    Command {
        /// The command as configured (before substitution).
        command: String,
        /// Where it came from (§17.1 approval).
        origin: ValueOrigin,
    },
}

impl ProxyConfig {
    /// The secret-free model value as the connector's config (`origin` applies to a
    /// ProxyCommand).
    pub fn from_model(proxy: &sverb_core::model::Proxy, origin: ValueOrigin) -> Self {
        use sverb_core::model::{Proxy, ProxyAuth};
        let creds = |a: &Option<ProxyAuth>| {
            a.as_ref().map(|a| ProxyCredentials {
                user: a.user.clone(),
                password: a.password.as_ref().map(|p| SecretString::from(p.expose())),
            })
        };
        match proxy {
            Proxy::Socks5 { addr, auth } => Self::Socks5 {
                addr: addr.clone(),
                auth: creds(auth),
            },
            Proxy::Http { addr, auth } => Self::Http {
                addr: addr.clone(),
                auth: creds(auth),
            },
            Proxy::Command(command) => Self::Command {
                command: command.clone(),
                origin,
            },
        }
    }

    /// `socks5`, `http` or `command` (logs).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Socks5 { .. } => "socks5",
            Self::Http { .. } => "http",
            Self::Command { .. } => "command",
        }
    }
}

/// The §17.1 decision for a locally-acting value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// May run.
    Approved,
    /// Must not run until the user approves it on this device.
    NeedsApproval,
}

/// The local-action approval check (§17.1).
pub trait LocalApprovals: Send + Sync + fmt::Debug {
    /// May `value` of `field` (defined by `origin.item_id`) act on this device?
    fn check(&self, field: &str, value: &str, origin: &ValueOrigin) -> Approval;

    // M2-10
    /// Was `value` denied in this session (fail without asking again)?
    fn is_blocked(&self, _field: &str, _value: &str, _origin: &ValueOrigin) -> bool {
        false
    }
}

// M2-10: the device's explicit approvals. A value of an unsaved target (no item:
// typed into this process, e.g. quick connect) is approved; a stored value needs its
// row with the exact value's hash.
impl LocalApprovals for sverb_core::resolve::approval::DeviceApprovals {
    fn check(&self, field: &str, value: &str, origin: &ValueOrigin) -> Approval {
        match origin.item_id {
            None => Approval::Approved,
            Some(item) if self.is_approved(item, field, value) => Approval::Approved,
            Some(_) => Approval::NeedsApproval,
        }
    }

    fn is_blocked(&self, field: &str, value: &str, origin: &ValueOrigin) -> bool {
        origin
            .item_id
            .is_some_and(|item| self.is_denied(item, field, value))
    }
}

/// The M2-06 stub: a value is approved when it was typed on this device
/// ([`ValueOrigin::typed_here`]). Superseded by `DeviceApprovals` (M2-10: a stamp's
/// device id alone is not trusted); kept for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct StampApprovals;

impl LocalApprovals for StampApprovals {
    fn check(&self, _field: &str, _value: &str, origin: &ValueOrigin) -> Approval {
        if origin.typed_here() {
            Approval::Approved
        } else {
            Approval::NeedsApproval
        }
    }
}

/// What the first hop connects to.
#[derive(Debug, Clone, Copy)]
pub struct HopTarget<'a> {
    /// The target's hostname or IP literal (as configured; brackets allowed).
    pub host: &'a str,
    /// The target port.
    pub port: u16,
    /// The remote user (`%r`).
    pub user: &'a str,
    /// The host's label (messages).
    pub label: &'a str,
}

/// The first hop's stream from a proxy.
#[derive(Debug)]
pub struct FirstHop {
    /// The stream to run SSH over.
    pub stream: BoxedIo,
    /// What the session info shows as the peer (`socks5 proxy:1080`, `command`).
    pub peer: String,
}

/// Split `host:port` (`[v6]:port`). `None` when there is no valid port.
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        let (host, port) = addr.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

/// Validate a proxy address (`host:port`) for the host form.
///
/// # Errors
/// A message for the field.
pub fn validate_proxy_addr(addr: &str) -> Result<(), String> {
    if split_host_port(addr).is_some() {
        Ok(())
    } else {
        Err("expected host:port (IPv6 as [addr]:port)".to_owned())
    }
}

/// `host` without IPv6 brackets.
pub(crate) fn unbracket(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// TCP to the proxy at `addr` (DNS, Happy Eyeballs, `timeout`).
pub(crate) async fn dial_proxy(
    addr: &str,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, SshError> {
    let (host, port) = split_host_port(addr).ok_or_else(|| {
        SshError::proxy(
            format!("proxy: invalid address {addr:?}"),
            vec!["expected host:port".to_owned()],
        )
    })?;
    let addrs = lookup(unbracket(&host), port).await.map_err(|err| {
        SshError::proxy(
            format!("proxy: could not resolve {host}"),
            vec![err.to_string()],
        )
    })?;
    match connect_tcp(&addrs, timeout).await {
        Ok((stream, _)) => Ok(stream),
        Err(TcpError::TimedOut) => Err(SshError::proxy(
            format!("proxy: connection to {addr} timed out"),
            Vec::new(),
        )),
        Err(TcpError::Failed(failure)) => Err(SshError::proxy(
            format!("proxy: could not connect to {addr}"),
            failure
                .errors
                .iter()
                .map(|(a, e)| format!("{a}: {e}"))
                .collect(),
        )),
    }
}

/// The stream factory for the first hop: connect through `proxy` to `target`.
/// `timeout` bounds each step (TCP, the proxy handshake).
///
/// # Errors
/// [`SshError::Proxy`] with a readable message, or [`SshError::NeedsApproval`] for a
/// ProxyCommand that was not approved on this device.
pub async fn open_first_hop(
    proxy: &ProxyConfig,
    target: HopTarget<'_>,
    timeout: Duration,
    approvals: &dyn LocalApprovals,
) -> Result<FirstHop, SshError> {
    match proxy {
        ProxyConfig::Socks5 { addr, auth } => {
            let stream =
                socks5::connect(addr, auth.as_ref(), target.host, target.port, timeout).await?;
            Ok(FirstHop {
                stream: Box::new(stream),
                peer: format!("socks5 {addr}"),
            })
        }
        ProxyConfig::Http { addr, auth } => {
            let tcp = dial_proxy(addr, timeout).await?;
            let stream = http_connect::connect(
                tcp,
                target.host,
                target.port,
                auth.as_ref(),
                http_connect::Limits::with_timeout(timeout),
            )
            .await
            .map_err(|e| e.into_ssh_error(addr))?;
            Ok(FirstHop {
                stream: Box::new(stream),
                peer: format!("http {addr}"),
            })
        }
        ProxyConfig::Command { command, origin } => {
            // M2-10: denied in this session → fail without asking again.
            if approvals.check(COMMAND_FIELD, command, origin) != Approval::Approved
                && approvals.is_blocked(COMMAND_FIELD, command, origin)
            {
                return Err(SshError::proxy(
                    format!(
                        "proxy: the ProxyCommand was {}",
                        sverb_core::resolve::approval::BLOCKED_MESSAGE
                    ),
                    vec![format!("ProxyCommand: {command}")],
                ));
            }
            if approvals.check(COMMAND_FIELD, command, origin) != Approval::Approved {
                return Err(SshError::NeedsApproval {
                    host: target.label.to_owned(),
                    command: command.clone(),
                });
            }
            let line = expand_command(command, target.host, target.port, target.user)
                .map_err(|e| SshError::proxy(format!("proxy: {e}"), Vec::new()))?;
            let stream = ProxyCommandStream::spawn(&line).map_err(|e| {
                SshError::proxy(
                    "proxy: could not start the ProxyCommand".to_owned(),
                    vec![e.to_string()],
                )
            })?;
            Ok(FirstHop {
                stream: Box::new(stream),
                peer: "ProxyCommand".to_owned(),
            })
        }
    }
}

// M2-06: end-to-end proxy tests through SshConnector.
#[cfg(test)]
mod connector_tests;
