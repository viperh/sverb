//! SOCKS5 via `tokio-socks` (SPEC §6.1.5).
//!
//! TCP to the proxy (DNS of the *proxy*, Happy Eyeballs, connect timeout), then
//! CONNECT to the target **by domain name** (ATYP `0x03`: the proxy resolves it; the
//! target is never looked up locally). IP literals are sent as addresses. Optional
//! RFC 1929 user/password. Reply codes become readable messages.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_socks::{Error as SocksError, tcp::Socks5Stream};
use tracing::debug;

use super::{ProxyCredentials, dial_proxy, unbracket};
use crate::ssh::SshError;

/// The readable message for a SOCKS failure.
pub fn socks_message(err: &SocksError) -> String {
    use SocksError as E;
    let what = match err {
        E::ConnectionRefused => "connection refused by destination",
        E::PasswordAuthFailure(_) | E::InvalidAuthValues(_) => "authentication failed",
        E::NoAcceptableAuthMethods | E::AuthorizationRequired => {
            "authentication required (no acceptable method)"
        }
        E::HostUnreachable => "destination host unreachable",
        E::NetworkUnreachable => "destination network unreachable",
        E::ConnectionNotAllowedByRuleset => "connection not allowed by the proxy's rules",
        E::TtlExpired => "TTL expired",
        E::CommandNotSupported => "CONNECT not supported by the proxy",
        E::AddressTypeNotSupported => "address type not supported by the proxy",
        E::GeneralSocksServerFailure => "general SOCKS server failure",
        E::InvalidTargetAddress(_) => "invalid target address",
        E::Io(_) => "connection to the proxy failed",
        _ => "protocol error",
    };
    format!("proxy: {what}")
}

/// Connect to `host:port` through the SOCKS5 proxy at `proxy`.
///
/// # Errors
/// [`SshError::Proxy`].
pub async fn connect(
    proxy: &str,
    auth: Option<&ProxyCredentials>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Socks5Stream<TcpStream>, SshError> {
    let tcp = dial_proxy(proxy, timeout).await?;
    let target = (unbracket(host), port);
    let handshake = async {
        match auth {
            Some(a) => {
                Socks5Stream::connect_with_password_and_socket(
                    tcp,
                    target,
                    &a.user,
                    a.password_text(),
                )
                .await
            }
            None => Socks5Stream::connect_with_socket(tcp, target).await,
        }
    };
    match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(stream)) => {
            debug!("socks5 connected");
            Ok(stream)
        }
        Ok(Err(err)) => Err(SshError::proxy(socks_message(&err), vec![err.to_string()])),
        Err(_) => Err(SshError::proxy(
            "proxy: no SOCKS5 reply within the connect timeout".to_owned(),
            Vec::new(),
        )),
    }
}
