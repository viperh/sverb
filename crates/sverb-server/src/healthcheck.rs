//! `sverb-server healthcheck`: a dependency-free probe for container
//! `HEALTHCHECK`s (distroless images have no curl).
//!
//! It sends `GET /healthz` over plain HTTP to the local listener and succeeds
//! on a 200. With built-in TLS (`SVERB_TLS_CERT` set) it only checks that the
//! port accepts connections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Probe timeout.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Rewrites a wildcard bind address to loopback.
#[must_use]
pub fn probe_addr(bind: SocketAddr) -> SocketAddr {
    match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => (Ipv4Addr::LOCALHOST, bind.port()).into(),
        IpAddr::V6(ip) if ip.is_unspecified() => (Ipv6Addr::LOCALHOST, bind.port()).into(),
        _ => bind,
    }
}

/// Probes `addr`.
///
/// # Errors
/// A human-readable reason.
pub async fn run(addr: SocketAddr, tls: bool) -> Result<(), String> {
    tokio::time::timeout(TIMEOUT, probe(addr, tls))
        .await
        .map_err(|_| format!("timed out after {}s", TIMEOUT.as_secs()))?
}

async fn probe(addr: SocketAddr, tls: bool) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    if tls {
        return Ok(());
    }
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(512);
    stream
        .take(4096)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| e.to_string())?;
    let status_line = String::from_utf8_lossy(&buf);
    let status_line = status_line.lines().next().unwrap_or_default();
    if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!("unhealthy: `{status_line}`"))
    }
}
