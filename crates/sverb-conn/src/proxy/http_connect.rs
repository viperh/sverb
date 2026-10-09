//! HTTP CONNECT, in-house (SPEC §6.1.5).
//!
//! Send `CONNECT host:port HTTP/1.1`, `Host:`, optionally `Proxy-Authorization: Basic
//! …`, then read the status line and headers up to `\r\n\r\n` (at most
//! [`MAX_HEADER_BYTES`], within a timeout). Any 2xx is success; 407 is an
//! authentication error; other codes are reported with their (sanitized) reason
//! phrase. **Bytes after the header terminator** (a server that sends its SSH banner
//! right away) are kept and replayed first by [`PrefixedStream`].

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::ProxyCredentials;
use crate::ssh::SshError;

/// The most response-header bytes accepted.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Limits of the CONNECT exchange.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Header size limit.
    pub max_header: usize,
    /// Time for the whole response.
    pub timeout: Duration,
}

impl Limits {
    /// [`MAX_HEADER_BYTES`] and `timeout`.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            max_header: MAX_HEADER_BYTES,
            timeout,
        }
    }
}

/// Why CONNECT failed.
#[derive(Debug)]
pub enum HttpConnectError {
    /// 407.
    AuthRequired {
        /// Credentials were sent.
        sent: bool,
    },
    /// A non-2xx status.
    Status {
        /// The code.
        code: u16,
        /// The sanitized reason phrase.
        reason: String,
    },
    /// The headers exceeded the limit.
    HeadersTooLarge,
    /// No complete response within the timeout.
    Timeout,
    /// Not an HTTP response.
    Malformed(String),
    /// The proxy closed the connection before the headers ended.
    Closed,
    /// I/O.
    Io(io::Error),
}

impl fmt::Display for HttpConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthRequired { sent: true } => f.write_str("proxy: authentication failed (407)"),
            Self::AuthRequired { sent: false } => {
                f.write_str("proxy: authentication required (407)")
            }
            Self::Status { code, reason } if reason.is_empty() => {
                write!(f, "proxy: CONNECT refused ({code})")
            }
            Self::Status { code, reason } => write!(f, "proxy: CONNECT refused ({code} {reason})"),
            Self::HeadersTooLarge => write!(
                f,
                "proxy: response headers too large (over {} KiB)",
                MAX_HEADER_BYTES / 1024
            ),
            Self::Timeout => f.write_str("proxy: no CONNECT response within the timeout"),
            Self::Malformed(why) => write!(f, "proxy: invalid HTTP response ({why})"),
            Self::Closed => f.write_str("proxy: connection closed during CONNECT"),
            Self::Io(err) => write!(f, "proxy: {err}"),
        }
    }
}

impl std::error::Error for HttpConnectError {}

impl HttpConnectError {
    /// As the connector's error (`addr`: the proxy, for the detail line).
    pub fn into_ssh_error(self, addr: &str) -> SshError {
        SshError::proxy(self.to_string(), vec![format!("HTTP proxy {addr}")])
    }
}

/// `host:port` for the request line (`[v6]:port`).
fn authority(host: &str, port: u16) -> String {
    let host = super::unbracket(host);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The CONNECT request for `host:port`.
pub fn connect_request(host: &str, port: u16, auth: Option<&ProxyCredentials>) -> String {
    let target = authority(host, port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(a) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            a.user,
            a.password_text()
        ));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// Printable ASCII only, at most 80 characters.
fn sanitize(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Parse the status line; `Ok(code, reason)`.
fn parse_status(head: &[u8]) -> Result<(u16, String), HttpConnectError> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(HttpConnectError::Malformed(
            "no HTTP/1.x status line".into(),
        ));
    }
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .filter(|c| (100..1000).contains(c))
        .ok_or_else(|| HttpConnectError::Malformed("bad status code".into()))?;
    Ok((code, sanitize(parts.next().unwrap_or_default())))
}

/// Run CONNECT over `stream` to `host:port`. On success the returned stream starts
/// with whatever the proxy sent after the headers.
///
/// # Errors
/// [`HttpConnectError`].
pub async fn connect<S>(
    mut stream: S,
    host: &str,
    port: u16,
    auth: Option<&ProxyCredentials>,
    limits: Limits,
) -> Result<PrefixedStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = connect_request(host, port, auth);
    let exchange = async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(HttpConnectError::Io)?;
        stream.flush().await.map_err(HttpConnectError::Io)?;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(HttpConnectError::Io)?;
            if n == 0 {
                return Err(HttpConnectError::Closed);
            }
            let searched_from = buf.len().saturating_sub(3);
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf[searched_from..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
            {
                let end = searched_from + pos + 4;
                if end > limits.max_header {
                    return Err(HttpConnectError::HeadersTooLarge);
                }
                let rest = buf.split_off(end);
                return Ok((buf, rest));
            }
            if buf.len() > limits.max_header {
                return Err(HttpConnectError::HeadersTooLarge);
            }
        }
    };
    let (head, rest) = tokio::time::timeout(limits.timeout, exchange)
        .await
        .map_err(|_| HttpConnectError::Timeout)??;
    let (code, reason) = parse_status(&head)?;
    match code {
        200..=299 => Ok(PrefixedStream::new(rest, stream)),
        407 => Err(HttpConnectError::AuthRequired {
            sent: auth.is_some(),
        }),
        _ => Err(HttpConnectError::Status { code, reason }),
    }
}

/// A stream that yields `prefix` before reading from `inner` (writes go straight to
/// `inner`).
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> fmt::Debug for PrefixedStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixedStream")
            .field("pending", &(self.prefix.len() - self.pos))
            .finish_non_exhaustive()
    }
}

impl<S> PrefixedStream<S> {
    /// `prefix` first, then `inner`.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// The early bytes not read yet.
    pub fn pending(&self) -> &[u8] {
        &self.prefix[self.pos..]
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A scripted proxy for the fuzz target: reads return `data` in `chunk`-sized pieces,
/// then end of stream; writes are swallowed.
struct FuzzProxy {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl AsyncRead for FuzzProxy {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let end = (self.pos + self.chunk)
            .min(self.data.len())
            .min(self.pos + buf.remaining());
        let piece = self.data[self.pos..end].to_vec();
        buf.put_slice(&piece);
        self.pos = end;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FuzzProxy {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The `http_connect_response` fuzz target
/// (`fuzz/fuzz_targets/http_connect_response.rs`). The first byte picks the read size
/// (1..=32 bytes, so the `\r\n\r\n` search is split at every boundary) and the header
/// limit; the rest is what the proxy answers to CONNECT. [`connect`] must never panic,
/// and on success the bytes after the headers must come back first, unchanged.
#[doc(hidden)]
pub fn fuzz_http_connect_response(data: &[u8]) {
    let Some((&first, response)) = data.split_first() else {
        return;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    let proxy = FuzzProxy {
        data: response.to_vec(),
        pos: 0,
        chunk: usize::from(first % 32) + 1,
    };
    let limits = Limits {
        max_header: if first & 0x80 != 0 {
            64
        } else {
            MAX_HEADER_BYTES
        },
        timeout: Duration::from_secs(5),
    };
    runtime.block_on(async {
        if let Ok(mut stream) = connect(proxy, "host.example", 22, None, limits).await {
            let end = response
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map_or(response.len(), |p| p + 4);
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
            assert_eq!(
                rest,
                response[end..],
                "bytes after the headers were changed"
            );
        }
    });
}

#[cfg(test)]
mod fuzz_tests {
    use proptest::prelude::*;

    use super::fuzz_http_connect_response;

    #[test]
    fn seeds() {
        for seed in [
            &b"\x00HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-x\r\n"[..],
            b"\x05HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
            b"\x1fHTTP/1.1 503 \x1b[31mno\r\n\r\n",
            b"\x80HTTP/1.1 200 OK\r\nX: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
            b"\x00HTTP/1.1 99999 x\r\n\r\n",
            b"\x00\r\n\r\n",
            b"",
        ] {
            fuzz_http_connect_response(seed);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_http_connect_response(&data);
        }

        #[test]
        fn never_panics_on_http_like_input(
            first in any::<u8>(),
            text in "(HTTP/1\\.[01] |[0-9]{1,5}| |OK|\r\n|\r|\n|:|[a-z]){0,40}",
            tail in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let mut data = vec![first];
            data.extend_from_slice(text.as_bytes());
            data.extend_from_slice(&tail);
            fuzz_http_connect_response(&data);
        }
    }
}
