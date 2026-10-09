//! The terminal-sharing client (SPEC §14): the host side ([`host`]) and the
//!
//! # Host
//!
//! [`host::start`] creates the share (`POST /v1/shares`), generates the link key
//! locally (it only ever appears in the link fragment), opens the host stream and
//! returns a [`host::HostHandle`] plus a stream of [`host::HostEvent`]s. The
//! terminal comes in through two seams that keep this crate free of the session
//! and emulator crates:
//!
//! - a [`ScreenSource`]: the emulator snapshot (taken with the emulator locked) and
//!   input injection into the session;
//! - a [`ShareFeed`] / [`FeedReceiver`] pair: the session's output tap. The UI
//!   wraps the [`ShareFeed`] into the session actor's output observer, which calls
//!   it with the emulator locked after every chunk. The feed is a bounded queue:
//!   when it is full, output is dropped and an overflow flag is set; the host task
//!   then sends every live viewer a fresh snapshot instead of blocking the session.
//!
//! # Viewer
//!
//! [`viewer::join`] opens the viewer stream for a [`ShareLink`], runs the join
//! handshake and reports [`viewer::ViewerEvent`]s (waiting for approval, the
//! snapshot, output, resizes, control changes, the end).

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use sverb_crypto::share::ShareLink;
use sverb_proto::share::ShareMode;
use tokio::sync::{Notify, mpsc};

use crate::error::SyncError;
use crate::tokens::TokenManager;

pub mod host;
pub mod viewer;

pub use host::{HostEvent, HostHandle};
pub use viewer::{ViewerEvent, ViewerHandle};

/// Queue between the session tap and the host task (chunks).
pub const FEED_CAPACITY: usize = 1024;

/// Largest `Output` frame payload; longer output is split.
pub const MAX_OUTPUT_FRAME: usize = 64 * 1024;

/// Why a share operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// The server or the socket failed.
    #[error("share connection failed: {0}")]
    Transport(String),
    /// The server refused (HTTP status and message).
    #[error("the server refused the share ({status}): {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Server message.
        message: String,
    },
    /// Not signed in to a server (hosting needs an account).
    #[error("sharing needs a sverb account on a server")]
    NotSignedIn,
    /// The share's WebSocket was closed by the server with this code.
    #[error("{}", close_message(*.0))]
    Closed(u16),
    /// A handshake or frame failed authentication or sequencing.
    #[error("Share connection integrity error")]
    Integrity,
    /// A local error (bad link, …).
    #[error("{0}")]
    Local(String),
}

impl From<SyncError> for ShareError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Api {
                status, message, ..
            } => Self::Api { status, message },
            other => Self::Transport(other.to_string()),
        }
    }
}

/// A human sentence for a share close code (`sverb_proto::share::CLOSE_*`).
#[must_use]
pub fn close_message(code: u16) -> String {
    use sverb_proto::share as p;
    match code {
        p::CLOSE_AUTH_REQUIRED => "this share requires signing in with a sverb account".into(),
        p::CLOSE_FORBIDDEN => "not allowed to host this share".into(),
        p::CLOSE_NOT_FOUND => "no such share".into(),
        p::CLOSE_SLOW_CONSUMER => "the connection was too slow".into(),
        p::CLOSE_REPLACED => "the share is hosted elsewhere now".into(),
        p::CLOSE_SHARE_ENDED => "share ended".into(),
        p::CLOSE_KICKED => "removed by the host".into(),
        p::CLOSE_SHARE_FULL => "the share is full".into(),
        other => format!("connection closed ({other})"),
    }
}

/// How the host authenticates to the server.
#[derive(Debug, Clone)]
pub enum ShareAuth {
    /// A fixed access token (tests, short-lived tools).
    Token(String),
    /// The signed-in device's tokens (refreshed as needed).
    Tokens(Arc<TokenManager>),
}

impl ShareAuth {
    /// A current access token.
    ///
    /// # Errors
    /// [`ShareError`] when no token can be obtained.
    pub async fn access(&self) -> Result<String, ShareError> {
        match self {
            Self::Token(t) => Ok(t.clone()),
            Self::Tokens(m) => Ok(m.access().await?),
        }
    }

    /// The server rejected `token`: refresh once (no-op for a fixed token).
    async fn rejected(&self, token: &str) -> Result<(), ShareError> {
        match self {
            Self::Token(_) => Ok(()),
            Self::Tokens(m) => Ok(m.refresh_after_401(token).await?),
        }
    }
}

/// How a share is set up (the start dialog, §14.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareOptions {
    /// View (default) or control.
    pub mode: ShareMode,
    /// Lifetime.
    pub expires_in: Duration,
    /// Viewers must sign in with a sverb account.
    pub require_account: bool,
    /// Admit viewers without asking (off by default; the dialog warns).
    pub skip_approval: bool,
}

impl Default for ShareOptions {
    fn default() -> Self {
        Self {
            mode: ShareMode::View,
            expires_in: Duration::from_secs(3600),
            require_account: false,
            skip_approval: false,
        }
    }
}

/// The expiries offered by the start dialog.
pub const EXPIRY_CHOICES: [Duration; 4] = [
    Duration::from_secs(15 * 60),
    Duration::from_secs(3600),
    Duration::from_secs(4 * 3600),
    Duration::from_secs(24 * 3600),
];

/// The visible screen of the shared pane (`emulator.snapshot_vt()`, §14.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// VT bytes that redraw the screen in a fresh emulator of that size.
    pub vt: Vec<u8>,
}

/// The shared pane, seen from the host task.
pub trait ScreenSource: Send + Sync + 'static {
    /// Lock the emulator, run `under_lock` (the host drains its feed there, so it
    /// knows which chunks the snapshot already contains), snapshot, unlock.
    fn snapshot(&self, under_lock: &mut dyn FnMut()) -> Screen;

    /// Write a granted viewer's input to the session (raw bytes, encoded by the
    /// viewer with its emulator's modes).
    fn inject(&self, bytes: Vec<u8>);
}

/// One event of the session tap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedEvent {
    /// Output that was just fed to the emulator.
    Output(Vec<u8>),
    /// The emulator's size (also the first event: the tap is attached).
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
}

#[derive(Debug, Default)]
struct FeedShared {
    overflow: AtomicBool,
    ended: AtomicBool,
    notify: Notify,
}

/// The session tap's sending half. Never blocks: a full queue drops the chunk and
/// flags an overflow (the host resends a snapshot). Cheap to clone.
#[derive(Debug, Clone)]
pub struct ShareFeed {
    tx: mpsc::Sender<FeedEvent>,
    shared: Arc<FeedShared>,
}

impl ShareFeed {
    /// Output just fed to the emulator.
    pub fn output(&self, bytes: &[u8]) {
        if self.tx.try_send(FeedEvent::Output(bytes.to_vec())).is_err() {
            self.shared.overflow.store(true, Ordering::Release);
            self.shared.notify.notify_one();
        }
    }

    /// The emulator's size.
    pub fn resize(&self, cols: u16, rows: u16) {
        if self.tx.try_send(FeedEvent::Resize { cols, rows }).is_err() {
            self.shared.overflow.store(true, Ordering::Release);
            self.shared.notify.notify_one();
        }
    }

    /// Test hook: behave as if a chunk had been dropped (the host resends the screen).
    #[doc(hidden)]
    pub fn mark_overflow(&self) {
        self.shared.overflow.store(true, Ordering::Release);
        self.shared.notify.notify_one();
    }

    /// The session's connection ended.
    pub fn ended(&self) {
        self.shared.ended.store(true, Ordering::Release);
        self.shared.notify.notify_one();
    }
}

/// The host task's receiving half of the tap.
#[derive(Debug)]
pub struct FeedReceiver {
    rx: mpsc::Receiver<FeedEvent>,
    shared: Arc<FeedShared>,
}

/// What [`FeedReceiver::next`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FeedNext {
    Event(FeedEvent),
    Overflow,
    Ended,
}

impl FeedReceiver {
    /// The next event, an overflow, or the end (also when every sender is gone).
    pub(crate) async fn next(&mut self) -> FeedNext {
        loop {
            if self.shared.overflow.load(Ordering::Acquire) {
                return FeedNext::Overflow;
            }
            if let Ok(ev) = self.rx.try_recv() {
                return FeedNext::Event(ev);
            }
            if self.shared.ended.load(Ordering::Acquire) {
                return FeedNext::Ended;
            }
            tokio::select! {
                ev = self.rx.recv() => match ev {
                    Some(ev) => return FeedNext::Event(ev),
                    None => return FeedNext::Ended,
                },
                () = self.shared.notify.notified() => {}
            }
        }
    }

    /// Everything queued right now (call it with the emulator locked), and whether
    /// output was dropped since the last call (the flag is cleared).
    pub(crate) fn drain(&mut self) -> (Vec<FeedEvent>, bool) {
        let mut out = Vec::new();
        while let Ok(ev) = self.rx.try_recv() {
            out.push(ev);
        }
        let overflow = self.shared.overflow.swap(false, Ordering::AcqRel);
        (out, overflow)
    }
}

/// A tap with room for `capacity` chunks ([`FEED_CAPACITY`] in production).
#[must_use]
pub fn feed_channel(capacity: usize) -> (ShareFeed, FeedReceiver) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let shared = Arc::new(FeedShared::default());
    (
        ShareFeed {
            tx,
            shared: Arc::clone(&shared),
        },
        FeedReceiver { rx, shared },
    )
}

/// `https://host[:port]` → `host[:port]` (the server part of a share link).
#[must_use]
pub fn link_server(base_url: &str) -> String {
    let b = base_url.trim().trim_end_matches('/');
    let b = b
        .strip_prefix("https://")
        .or_else(|| b.strip_prefix("http://"))
        .unwrap_or(b);
    b.split('/').next().unwrap_or(b).to_owned()
}

/// The base URL to reach the server of `link`: `known` (the server this device is
/// signed in to) when it names the same `host[:port]`, else `https://<server>`.
#[must_use]
pub fn base_url_for(link: &ShareLink, known: Option<&str>) -> String {
    match known {
        Some(k) if link_server(k).eq_ignore_ascii_case(link.server()) => {
            k.trim().trim_end_matches('/').to_owned()
        }
        _ => link.web_base_url(),
    }
}

/// `http(s)://host/…` → `ws(s)://host/v1{path}`.
pub(crate) fn ws_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let rest = if let Some(r) = base.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = base.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        base.to_owned()
    };
    format!("{rest}{}{path}", sverb_proto::version::API_PREFIX)
}

/// Same rule as the sync client: `https://`, or `http://` to a loopback host only.
pub(crate) fn check_base_url(base_url: &str) -> Result<(), ShareError> {
    let b = base_url.trim();
    if b.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = b.strip_prefix("http://") else {
        return Err(ShareError::Local(
            "the server URL must start with https://".into(),
        ));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if loopback {
        Ok(())
    } else {
        Err(ShareError::Local(
            "the server URL must start with https://".into(),
        ))
    }
}

/// The WebSocket stream type used by both sides.
pub(crate) type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Opens a share WebSocket (`ws(s)://…/v1{path}`).
pub(crate) async fn connect_ws(
    base_url: &str,
    path: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<WsStream, ShareError> {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
    check_base_url(base_url)?;
    let url = ws_url(base_url, path);
    let tls = tls.unwrap_or_else(crate::ws::default_tls);
    let config = WebSocketConfig::default()
        .max_message_size(Some(sverb_proto::share::MAX_RELAY_MESSAGE))
        .max_frame_size(Some(sverb_proto::share::MAX_RELAY_MESSAGE));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        url.as_str(),
        Some(config),
        true,
        Some(tokio_tungstenite::Connector::Rustls(tls)),
    );
    match tokio::time::timeout(Duration::from_secs(15), connect).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(e)) => Err(ShareError::Transport(e.to_string())),
        Err(_) => Err(ShareError::Transport("connect timeout".into())),
    }
}

/// A JSON text message.
pub(crate) fn text<T: serde::Serialize>(msg: &T) -> tokio_tungstenite::tungstenite::Message {
    tokio_tungstenite::tungstenite::Message::text(serde_json::to_string(msg).unwrap_or_default())
}

/// The close code of a close frame (`None` without one).
pub(crate) fn close_code(
    frame: Option<&tokio_tungstenite::tungstenite::protocol::CloseFrame>,
) -> Option<u16> {
    frame.map(|f| u16::from(f.code))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn urls() {
        assert_eq!(link_server("https://sync.example.com/"), "sync.example.com");
        assert_eq!(link_server("http://127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(
            ws_url("https://a.example:8443", "/shares/x/host"),
            "wss://a.example:8443/v1/shares/x/host"
        );
        assert_eq!(
            ws_url("http://127.0.0.1:9/", "/shares/x/join"),
            "ws://127.0.0.1:9/v1/shares/x/join"
        );
        assert!(check_base_url("https://x").is_ok());
        assert!(check_base_url("http://127.0.0.1:1").is_ok());
        assert!(check_base_url("http://[::1]:1").is_ok());
        assert!(check_base_url("http://example.com").is_err());
        let key = sverb_crypto::share::ShareKey::from_bytes([1; 32]);
        let link = ShareLink::new("127.0.0.1:5000", [2; 16], key).unwrap();
        assert_eq!(
            base_url_for(&link, Some("http://127.0.0.1:5000/")),
            "http://127.0.0.1:5000"
        );
        assert_eq!(
            base_url_for(&link, Some("https://other.example")),
            "https://127.0.0.1:5000"
        );
        assert_eq!(base_url_for(&link, None), "https://127.0.0.1:5000");
    }

    #[tokio::test]
    async fn feed_overflows_instead_of_blocking() {
        let (feed, mut rx) = feed_channel(2);
        feed.resize(80, 24);
        feed.output(b"a");
        feed.output(b"b"); // dropped
        assert_eq!(rx.next().await, FeedNext::Overflow);
        let (events, overflow) = rx.drain();
        assert!(overflow);
        assert_eq!(events.len(), 2);
        feed.output(b"c");
        assert_eq!(
            rx.next().await,
            FeedNext::Event(FeedEvent::Output(b"c".to_vec()))
        );
        feed.ended();
        assert_eq!(rx.next().await, FeedNext::Ended);
    }
}
