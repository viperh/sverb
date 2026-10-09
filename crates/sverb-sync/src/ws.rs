//! The notification WebSocket client (`/v1/ws`, SPEC §10.4, §12.5; task
//!
//! [`run`] keeps one connection to the server open until cancelled:
//!
//! * connects with tokio-tungstenite over rustls (`ring`, webpki roots, or
//!   the caller's [`rustls::ClientConfig`]), then sends
//!   `{"type":"auth","token"}` as the first message (never in the URL);
//! * emits [`WsEvent`]s for the sync engine: `Connected` once the
//!   server has accepted the token (its first message), every notification,
//!   and `Disconnected` with the delay before the next attempt;
//! * answers `ping`, sends its own `ping` every 30 s and drops the
//!   connection after 2 unanswered ones;
//! * reconnects with exponential backoff (1 s → 60 s, jittered, unbounded
//!   attempts; reset after a successful auth);
//! * on close code 4401 asks the [`TokenSource`] to refresh once and
//!   reconnects right away. A second 4401 without a successful auth in
//!   between backs off first, so a server that keeps rejecting is not
//!   hammered. [`TokenError::LoginRequired`] ends the loop with
//!   [`WsEvent::NeedsLogin`].
//!
//! Notifications are hints: the engine still pulls on its fallback timer,
//! so anything missed while disconnected is harmless (§12.5).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use sverb_proto::ws::{
    CLOSE_AUTH_REQUIRED, ClientMsg, MAX_MISSED_PONGS, PING_INTERVAL_SECS, ServerMsg,
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;

/// Reconnect backoff bounds (§12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// First delay.
    pub initial: Duration,
    /// Largest delay.
    pub max: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
        }
    }
}

/// Exponential backoff with jitter: attempt `n` (from 0) waits a uniformly
/// random time in `[base/2, base]` with `base = min(initial·2ⁿ, max)`, so
/// the delay never exceeds `max` and replicas of a fleet don't reconnect in
/// lockstep.
#[derive(Debug, Clone)]
pub struct Backoff {
    policy: BackoffPolicy,
    attempt: u32,
}

impl Backoff {
    /// A fresh backoff.
    #[must_use]
    pub const fn new(policy: BackoffPolicy) -> Self {
        Self { policy, attempt: 0 }
    }

    /// The un-jittered delay of attempt `n`.
    #[must_use]
    pub fn base(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        self.policy
            .initial
            .checked_mul(factor)
            .map_or(self.policy.max, |d| d.min(self.policy.max))
    }

    /// The next delay, jittered by `unit` in `[0, 1]` (tests pass fixed
    /// values; [`Self::next_delay`] uses a random one).
    pub fn next_with(&mut self, unit: f64) -> Duration {
        let base = self.base(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        base.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0))
    }

    /// The next delay with random jitter.
    pub fn next_delay(&mut self) -> Duration {
        self.next_with(fastrand::f64())
    }

    /// Back to the initial delay (after a successful connection).
    pub const fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Delays handed out since the last reset.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// `wss://host/v1/ws` (or `ws://` for local testing).
    pub url: String,
    /// Heartbeat period.
    pub ping_interval: Duration,
    /// Unanswered pings before reconnecting.
    pub max_missed_pongs: u32,
    /// TCP + TLS + upgrade must finish within this.
    pub connect_timeout: Duration,
    /// Reconnect backoff.
    pub backoff: BackoffPolicy,
    /// TLS settings; `None` = the `ring` provider with webpki roots. The
    /// sync engine passes the config of its HTTP client so both trust the
    /// same roots.
    pub tls: Option<Arc<rustls::ClientConfig>>,
}

impl WsConfig {
    /// The defaults for a server at `base_url` (`https://sync.example.com`
    /// → `wss://sync.example.com/v1/ws`).
    #[must_use]
    pub fn for_server(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        let url = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}/v1/ws")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}/v1/ws")
        } else {
            format!("{base}/v1/ws")
        };
        Self {
            url,
            ping_interval: Duration::from_secs(PING_INTERVAL_SECS),
            max_missed_pongs: MAX_MISSED_PONGS,
            connect_timeout: Duration::from_secs(10),
            backoff: BackoffPolicy::default(),
            tls: None,
        }
    }
}

/// Why the token source can't provide a token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The refresh token is gone or rejected: the user must log in again.
    #[error("login required")]
    LoginRequired,
    /// Temporary (network, server error): retried with backoff.
    #[error("token unavailable: {0}")]
    Transient(String),
}

/// The token manager of the sync engine.
pub trait TokenSource: Send + Sync {
    /// The current access token.
    fn access_token(&self) -> impl Future<Output = Result<String, TokenError>> + Send;

    /// Rotates the tokens (`POST /v1/auth/refresh`) after the server
    /// rejected the access token.
    fn refresh(&self) -> impl Future<Output = Result<(), TokenError>> + Send;
}

/// Why a connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Connect, TLS, upgrade or I/O failure (incl. the connect timeout).
    Io(String),
    /// The server closed with this code (not 4401).
    Closed(u16),
    /// The server closed with 4401; the tokens are refreshed.
    AuthRejected,
    /// The server missed too many pongs.
    PingTimeout,
    /// The token source failed temporarily.
    TokenUnavailable(String),
}

/// What the client tells the sync engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    /// The server accepted the token: pull now to catch up on anything
    /// missed while disconnected.
    Connected,
    /// A notification (never `ping`/`pong`).
    Notification(ServerMsg),
    /// The connection ended; the next attempt starts after `retry_in`.
    Disconnected {
        /// Why.
        reason: DisconnectReason,
        /// Delay before reconnecting (zero after a 4401 + refresh).
        retry_in: Duration,
    },
    /// The token source needs a new login; the client stopped.
    NeedsLogin,
}

/// How a session ended.
enum Outcome {
    Stop,
    AuthRejected {
        authed: bool,
    },
    Lost {
        reason: DisconnectReason,
        authed: bool,
    },
}

/// The default TLS client config: `ring` and the webpki roots.
///
/// # Panics
/// Never in practice: the `ring` provider supports the default protocol
/// versions.
#[must_use]
pub fn default_tls() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    #[allow(clippy::expect_used)]
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

async fn emit(events: &mpsc::Sender<WsEvent>, ev: WsEvent) -> bool {
    events.send(ev).await.is_ok()
}

/// Sleeps unless cancelled; `false` when cancelled.
async fn pause(cancel: &CancellationToken, d: Duration) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        () = tokio::time::sleep(d) => true,
    }
}

/// Runs the client until `cancel` fires, the event receiver is dropped or
/// the token source reports [`TokenError::LoginRequired`].
pub async fn run<T: TokenSource>(
    config: WsConfig,
    tokens: &T,
    events: mpsc::Sender<WsEvent>,
    cancel: CancellationToken,
) {
    let tls = config.tls.clone().unwrap_or_else(default_tls);
    let mut backoff = Backoff::new(config.backoff);
    // A refresh happened and no connection has authenticated since.
    let mut refreshed = false;

    while !cancel.is_cancelled() {
        let token = match tokens.access_token().await {
            Ok(t) => t,
            Err(TokenError::LoginRequired) => {
                emit(&events, WsEvent::NeedsLogin).await;
                return;
            }
            Err(TokenError::Transient(e)) => {
                let retry_in = backoff.next_delay();
                let ev = WsEvent::Disconnected {
                    reason: DisconnectReason::TokenUnavailable(e),
                    retry_in,
                };
                if !emit(&events, ev).await || !pause(&cancel, retry_in).await {
                    return;
                }
                continue;
            }
        };

        let outcome = session(&config, &tls, &token, &events, &cancel, &mut backoff).await;
        match outcome {
            Outcome::Stop => return,
            Outcome::AuthRejected { authed } => {
                if authed {
                    refreshed = false;
                }
                // Rejected again right after a refresh: back off first.
                let retry_in = if refreshed {
                    backoff.next_delay()
                } else {
                    Duration::ZERO
                };
                let ev = WsEvent::Disconnected {
                    reason: DisconnectReason::AuthRejected,
                    retry_in,
                };
                if !emit(&events, ev).await || !pause(&cancel, retry_in).await {
                    return;
                }
                match tokens.refresh().await {
                    Ok(()) => refreshed = true,
                    Err(TokenError::LoginRequired) => {
                        emit(&events, WsEvent::NeedsLogin).await;
                        return;
                    }
                    Err(TokenError::Transient(e)) => {
                        let retry_in = backoff.next_delay();
                        let ev = WsEvent::Disconnected {
                            reason: DisconnectReason::TokenUnavailable(e),
                            retry_in,
                        };
                        if !emit(&events, ev).await || !pause(&cancel, retry_in).await {
                            return;
                        }
                    }
                }
            }
            Outcome::Lost { reason, authed } => {
                if authed {
                    refreshed = false;
                }
                let retry_in = backoff.next_delay();
                let ev = WsEvent::Disconnected { reason, retry_in };
                if !emit(&events, ev).await || !pause(&cancel, retry_in).await {
                    return;
                }
            }
        }
    }
}

fn lost(reason: DisconnectReason, authed: bool) -> Outcome {
    Outcome::Lost { reason, authed }
}

fn text(msg: &ClientMsg) -> Message {
    Message::text(serde_json::to_string(msg).unwrap_or_default())
}

/// One connection.
async fn session(
    config: &WsConfig,
    tls: &Arc<rustls::ClientConfig>,
    token: &str,
    events: &mpsc::Sender<WsEvent>,
    cancel: &CancellationToken,
    backoff: &mut Backoff,
) -> Outcome {
    let ws_config = WebSocketConfig::default().max_message_size(Some(1024 * 1024));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        config.url.as_str(),
        Some(ws_config),
        true,
        Some(tokio_tungstenite::Connector::Rustls(tls.clone())),
    );
    let ws = tokio::select! {
        () = cancel.cancelled() => return Outcome::Stop,
        r = tokio::time::timeout(config.connect_timeout, connect) => match r {
            Ok(Ok((ws, _resp))) => ws,
            Ok(Err(e)) => return lost(DisconnectReason::Io(e.to_string()), false),
            Err(_) => return lost(DisconnectReason::Io("connect timeout".into()), false),
        },
    };
    let (mut tx, mut rx) = ws.split();
    if let Err(e) = tx
        .send(text(&ClientMsg::Auth {
            token: token.to_owned(),
        }))
        .await
    {
        return lost(DisconnectReason::Io(e.to_string()), false);
    }

    let mut authed = false;
    let mut awaiting_pong = false;
    let mut missed: u32 = 0;
    let start = tokio::time::Instant::now() + config.ping_interval;
    let mut ticker = tokio::time::interval_at(start, config.ping_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                let _ = tx.send(Message::Close(None)).await;
                return Outcome::Stop;
            }
            _ = ticker.tick() => {
                if awaiting_pong {
                    missed += 1;
                    if missed >= config.max_missed_pongs {
                        let _ = tx.send(Message::Close(None)).await;
                        return lost(DisconnectReason::PingTimeout, authed);
                    }
                }
                if let Err(e) = tx.send(text(&ClientMsg::Ping)).await {
                    return lost(DisconnectReason::Io(e.to_string()), authed);
                }
                awaiting_pong = true;
            }
            msg = rx.next() => {
                let msg = match msg {
                    None => return lost(DisconnectReason::Io("connection closed".into()), authed),
                    Some(Err(e)) => return lost(DisconnectReason::Io(e.to_string()), authed),
                    Some(Ok(m)) => m,
                };
                match msg {
                    Message::Text(t) => {
                        // Unknown types (newer servers) are skipped.
                        let Ok(m) = serde_json::from_str::<ServerMsg>(t.as_str()) else {
                            continue;
                        };
                        if !authed {
                            // The server's first message means the token was accepted.
                            authed = true;
                            backoff.reset();
                            if !emit(events, WsEvent::Connected).await {
                                return Outcome::Stop;
                            }
                        }
                        match m {
                            ServerMsg::Ping => {
                                if let Err(e) = tx.send(text(&ClientMsg::Pong)).await {
                                    return lost(DisconnectReason::Io(e.to_string()), authed);
                                }
                            }
                            ServerMsg::Pong => {
                                awaiting_pong = false;
                                missed = 0;
                            }
                            other => {
                                if !emit(events, WsEvent::Notification(other)).await {
                                    return Outcome::Stop;
                                }
                            }
                        }
                    }
                    Message::Close(frame) => {
                        let code = frame.map_or(1005, |f| u16::from(f.code));
                        return if code == CLOSE_AUTH_REQUIRED {
                            Outcome::AuthRejected { authed }
                        } else {
                            lost(DisconnectReason::Closed(code), authed)
                        };
                    }
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap_with_jitter_bounds() {
        let mut b = Backoff::new(BackoffPolicy::default());
        let bases: Vec<u64> = (0..10).map(|n| b.base(n).as_secs()).collect();
        assert_eq!(bases, vec![1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);
        assert_eq!(b.next_with(1.0), Duration::from_secs(1));
        assert_eq!(b.next_with(0.0), Duration::from_secs(1));
        assert_eq!(b.next_with(0.0), Duration::from_secs(2));
        // Attempts 3..=5 (8, 16, 32 s); from attempt 6 on the cap applies.
        for _ in 3..6 {
            b.next_with(0.5);
        }
        for _ in 0..100 {
            let d = b.next_delay();
            assert!(
                d >= Duration::from_secs(30) && d <= Duration::from_secs(60),
                "{d:?}"
            );
        }
        assert_eq!(b.base(u32::MAX), Duration::from_secs(60));
        b.reset();
        assert_eq!(b.attempts(), 0);
        assert!(b.next_delay() <= Duration::from_secs(1));
    }

    #[test]
    fn url_from_server_base() {
        assert_eq!(
            WsConfig::for_server("https://sync.example.com/").url,
            "wss://sync.example.com/v1/ws"
        );
        assert_eq!(
            WsConfig::for_server("http://127.0.0.1:8080").url,
            "ws://127.0.0.1:8080/v1/ws"
        );
    }

    #[test]
    fn default_tls_builds() {
        let _ = default_tls();
    }
}
