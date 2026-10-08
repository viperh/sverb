//! The SOCKS server handshake (§9.6, RFC 1928): drives the pure parsers in
//! [`socks`](super::socks) over a client stream and opens the `direct-tcpip` channel.
//!
//! - Methods: only no-auth (`0x00`); otherwise `05 FF` and close.
//! - Commands: CONNECT only; BIND and UDP ASSOCIATE → `0x07` and close.
//! - Address types IPv4, domain, IPv6; others → `0x08`. Domains go to the remote side
//!   unresolved (no local DNS).
//! - SOCKS4/4a: `0x5A` on success, `0x5B` on failure.
//! - Success reply `0x00` with `BND.ADDR = 0.0.0.0:0`; open failures map to `0x05`
//!   (connect failed), `0x02` (prohibited), `0x04` (unreachable), else `0x01`.
//! - The whole handshake must finish within [`SOCKS_TIMEOUT`].

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    OpenFailure, SOCKS_TIMEOUT, Tunnel, TunnelStream,
    socks::{
        self, Command, Hello, ParseError, Parsed, Reply, Request, parse_hello, parse_request5,
        reply4, reply5, select_method,
    },
};

/// Most bytes buffered while waiting for a complete message (a domain request is at
/// most 262 bytes; SOCKS4a with a user id about 520).
const MAX_HANDSHAKE: usize = 1024;

/// Why a SOCKS handshake ended without a tunnel.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    /// The client closed (or sent garbage beyond the size limit) mid-handshake.
    #[error("client closed during the SOCKS handshake")]
    Closed,
    /// No complete request within [`SOCKS_TIMEOUT`].
    #[error("SOCKS handshake timed out")]
    Timeout,
    /// Malformed message.
    #[error("malformed SOCKS message: {0}")]
    Parse(#[from] ParseError),
    /// The client offered no acceptable auth method (`05 FF` sent).
    #[error("no acceptable authentication method")]
    NoAcceptableMethod,
    /// BIND, UDP ASSOCIATE or an unknown command (`0x07` sent).
    #[error("command not supported")]
    CommandNotSupported,
    /// The channel could not be opened (the mapped reply was sent).
    #[error("{0}")]
    Open(OpenFailure),
    /// The rule is at its channel cap (`0x01` / `0x5B` sent).
    #[error("too many connections")]
    Saturated,
    /// Reading or writing the client failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Buffered reads from the client.
struct Reader<'a, S> {
    stream: &'a mut S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    async fn next<T>(&mut self, parse: impl Fn(&[u8]) -> Parsed<T>) -> Result<T, SocksError> {
        loop {
            if let Some((value, used)) = parse(&self.buf)? {
                self.buf.drain(..used);
                return Ok(value);
            }
            if self.buf.len() >= MAX_HANDSHAKE {
                return Err(SocksError::Closed);
            }
            let mut chunk = [0_u8; 512];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(SocksError::Closed);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Which protocol the client speaks (for replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V4,
    V5,
}

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, ver: Version, code: Reply) {
    let res = match ver {
        Version::V5 => stream.write_all(&reply5(code)).await,
        Version::V4 => stream.write_all(&reply4(code == Reply::Succeeded)).await,
    };
    if res.is_ok() {
        let _ = stream.flush().await;
    }
}

/// Read the client's request (negotiating the method for SOCKS5).
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut Reader<'_, S>,
) -> Result<(Version, Request), SocksError> {
    match reader.next(parse_hello).await? {
        Hello::V4(req) => Ok((Version::V4, req)),
        Hello::V5 { methods } => {
            let selected = select_method(&methods);
            reader.stream.write_all(&selected).await?;
            reader.stream.flush().await?;
            if selected[1] != socks::METHOD_NO_AUTH {
                return Err(SocksError::NoAcceptableMethod);
            }
            match reader.next(parse_request5).await {
                Ok(req) => Ok((Version::V5, req)),
                Err(SocksError::Parse(err)) => {
                    if let Some(code) = err.reply5() {
                        reply(reader.stream, Version::V5, code).await;
                    }
                    Err(SocksError::Parse(err))
                }
                Err(other) => Err(other),
            }
        }
    }
}

/// Run the handshake on `client` (from `peer`) and open the channel through
/// `tunnel`. On success the success reply has been sent and the channel is returned
/// with any bytes the client already sent after its request (to forward first).
///
/// With `saturated`, the request is read and answered with a failure (`0x01` /
/// `0x5B`) instead.
///
/// # Errors
/// See [`SocksError`]; the owed reply has been sent where the protocol has one.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    peer: SocketAddr,
    tunnel: &dyn Tunnel,
    saturated: bool,
) -> Result<(TunnelStream, Vec<u8>), SocksError> {
    let mut reader = Reader {
        stream: client,
        buf: Vec::new(),
    };
    let (ver, req) = tokio::time::timeout(SOCKS_TIMEOUT, read_request(&mut reader))
        .await
        .map_err(|_| SocksError::Timeout)??;
    let Reader { stream, buf } = reader;
    if req.command != Command::Connect {
        reply(stream, ver, Reply::CommandNotSupported).await;
        return Err(SocksError::CommandNotSupported);
    }
    if saturated {
        reply(stream, ver, Reply::GeneralFailure).await;
        return Err(SocksError::Saturated);
    }
    match tunnel.open_direct(&req.target.host(), req.port, peer).await {
        Ok(channel) => {
            reply(stream, ver, Reply::Succeeded).await;
            Ok((channel, buf))
        }
        Err(failure) => {
            reply(stream, ver, failure.socks_reply()).await;
            Err(SocksError::Open(failure))
        }
    }
}
