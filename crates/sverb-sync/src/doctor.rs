//! M7-04: the sync checks of `sverb doctor` (SPEC §16).
//!
//! [`probe`] runs read-only checks against the configured server and returns one
//! [`ProbeCheck`] per line of the doctor report:
//!
//! 1. **server**: `GET /healthz` answers (the server is reachable),
//! 2. **protocol**: the `Sverb-Proto` version it echoes is one this client speaks,
//! 3. **readiness**: `GET /readyz` (database and migrations on the server side),
//! 4. **clock**: the offset between this device and the server's `Date` header
//!    (warned above [`MAX_CLOCK_OFFSET_S`]; HLC ordering tolerates small skew only),
//! 5. **token**: the stored access token works on a cheap authenticated endpoint
//!    (`GET /v1/devices`). Doctor never refreshes: a refresh rotates the refresh token,
//! 6. **websocket**: `/v1/ws` connects and accepts the token (one ping round trip).
//!
//! Nothing here writes to the store or the server.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{AUTHORIZATION, DATE, HeaderMap, HeaderValue};
use sverb_proto::version::{API_PREFIX, PROTO_HEADER, PROTO_VERSION, is_supported};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::http::ApiClient;
use crate::ws::{self, DisconnectReason, TokenError, TokenSource, WsConfig, WsEvent};

/// Clock offsets above this many seconds are warned about.
pub const MAX_CLOCK_OFFSET_S: i64 = 60;

/// How a check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeLevel {
    /// Fine.
    Ok,
    /// Works, but something deserves attention.
    Warn,
    /// Broken.
    Fail,
    /// Not run (with the reason in the detail).
    Skip,
}

/// One line of the sync section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCheck {
    /// Stable id (`server`, `protocol`, `readiness`, `clock`, `token`, `websocket`).
    pub id: &'static str,
    /// The outcome.
    pub level: ProbeLevel,
    /// What was found.
    pub detail: String,
    /// What to do about it.
    pub hint: Option<String>,
}

impl ProbeCheck {
    fn new(id: &'static str, level: ProbeLevel, detail: impl Into<String>) -> Self {
        Self {
            id,
            level,
            detail: detail.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Settings for [`probe`].
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// Per-request timeout (and the WebSocket round trip's budget).
    pub timeout: Duration,
    /// TLS settings; `None` = [`ws::default_tls`].
    pub tls: Option<Arc<rustls::ClientConfig>>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            tls: None,
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Run the checks against `server_url`. `token` is the stored, unexpired access
/// token, or `Err(reason)` when it can't be used (not signed in, vault locked,
/// expired), which skips the authenticated checks with that reason.
pub async fn probe(
    server_url: &str,
    token: Result<&str, String>,
    opts: &ProbeOptions,
) -> Vec<ProbeCheck> {
    let mut checks = Vec::new();
    // Validates the URL (https, or http on loopback) like the sync engine does.
    let api = match ApiClient::new(server_url, opts.tls.clone(), opts.timeout) {
        Ok(api) => api,
        Err(e) => {
            checks.push(
                ProbeCheck::new("server", ProbeLevel::Fail, format!("{server_url}: {e}"))
                    .hint("sign in again with `sverb login --server https://…`"),
            );
            return checks;
        }
    };
    let base = api.base_url().to_owned();
    let tls = opts.tls.clone().unwrap_or_else(ws::default_tls);
    let mut headers = HeaderMap::new();
    headers.insert(PROTO_HEADER, HeaderValue::from(PROTO_VERSION));
    let http = match reqwest::Client::builder()
        .timeout(opts.timeout)
        .connect_timeout(opts.timeout)
        .default_headers(headers)
        .use_preconfigured_tls((*tls).clone())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            checks.push(ProbeCheck::new("server", ProbeLevel::Fail, e.to_string()));
            return checks;
        }
    };

    // 1. /healthz
    let sent_ms = now_ms();
    let health = http.get(format!("{base}/healthz")).send().await;
    let received_ms = now_ms();
    let resp = match health {
        Ok(r) => r,
        Err(e) => {
            checks.push(
                ProbeCheck::new(
                    "server",
                    ProbeLevel::Fail,
                    format!("{base} is unreachable: {}", transport(&e)),
                )
                .hint("check the server URL and the network; local changes stay queued"),
            );
            return checks;
        }
    };
    if !resp.status().is_success() {
        checks.push(
            ProbeCheck::new(
                "server",
                ProbeLevel::Fail,
                format!(
                    "{base} answered HTTP {} on /healthz",
                    resp.status().as_u16()
                ),
            )
            .hint("is this a sverb server? check the URL with `sverb sync --status`"),
        );
        return checks;
    }
    checks.push(ProbeCheck::new(
        "server",
        ProbeLevel::Ok,
        format!("{base} is reachable"),
    ));

    // 2. protocol version
    let proto = resp
        .headers()
        .get(PROTO_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u32>().ok());
    checks.push(protocol_check(proto));

    // 4. (computed now, reported after readiness) clock offset
    let date = resp
        .headers()
        .get(DATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let clock = clock_check(date.as_deref(), sent_ms / 2 + received_ms / 2);

    // 3. /readyz
    checks.push(match http.get(format!("{base}/readyz")).send().await {
        Ok(r) if r.status().is_success() => {
            ProbeCheck::new("readiness", ProbeLevel::Ok, "the server is ready")
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            let why = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .map(|v| {
                    let mut parts = Vec::new();
                    for key in ["database", "migrations"] {
                        if let Some(s) = v.get(key).and_then(|s| s.as_str()) {
                            parts.push(format!("{key} {s}"));
                        }
                    }
                    parts.join(", ")
                })
                .filter(|s| !s.is_empty());
            let detail = match why {
                Some(why) => format!("not ready (HTTP {status}: {why})"),
                None => format!("not ready (HTTP {status})"),
            };
            ProbeCheck::new("readiness", ProbeLevel::Warn, detail)
                .hint("the server's database or migrations need attention (server operator)")
        }
        Err(e) => ProbeCheck::new(
            "readiness",
            ProbeLevel::Warn,
            format!("/readyz failed: {}", transport(&e)),
        ),
    });
    checks.push(clock);

    // 5. token
    let token = match token {
        Ok(t) => t,
        Err(reason) => {
            checks.push(ProbeCheck::new("token", ProbeLevel::Skip, reason.clone()));
            checks.push(ProbeCheck::new("websocket", ProbeLevel::Skip, reason));
            return checks;
        }
    };
    let devices = http
        .get(format!("{base}{API_PREFIX}/devices"))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await;
    let token_ok = match devices {
        Ok(r) if r.status().is_success() => {
            checks.push(ProbeCheck::new(
                "token",
                ProbeLevel::Ok,
                "the access token is accepted",
            ));
            true
        }
        Ok(r) if matches!(r.status().as_u16(), 401 | 403) => {
            checks.push(
                ProbeCheck::new(
                    "token",
                    ProbeLevel::Fail,
                    format!(
                        "the access token was rejected (HTTP {})",
                        r.status().as_u16()
                    ),
                )
                .hint("the device may have been revoked; run `sverb login`"),
            );
            false
        }
        Ok(r) => {
            checks.push(ProbeCheck::new(
                "token",
                ProbeLevel::Warn,
                format!("GET /v1/devices answered HTTP {}", r.status().as_u16()),
            ));
            false
        }
        Err(e) => {
            checks.push(ProbeCheck::new(
                "token",
                ProbeLevel::Fail,
                format!("GET /v1/devices failed: {}", transport(&e)),
            ));
            false
        }
    };

    // 6. WebSocket
    if !token_ok {
        checks.push(ProbeCheck::new(
            "websocket",
            ProbeLevel::Skip,
            "skipped: no working token",
        ));
        return checks;
    }
    checks.push(ws_check(&base, token, tls, opts.timeout).await);
    checks
}

fn transport(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}

/// The protocol line for the `Sverb-Proto` version the server sent.
#[must_use]
pub fn protocol_check(version: Option<u32>) -> ProbeCheck {
    match version {
        Some(v) if is_supported(v) => ProbeCheck::new(
            "protocol",
            ProbeLevel::Ok,
            format!("protocol version {v} (this client speaks {PROTO_VERSION})"),
        ),
        Some(v) => ProbeCheck::new(
            "protocol",
            ProbeLevel::Fail,
            format!("protocol version {v} is not supported (this client speaks {PROTO_VERSION})"),
        )
        .hint(if v > PROTO_VERSION {
            "update sverb"
        } else {
            "the server is too old; ask its operator to update it"
        }),
        None => ProbeCheck::new(
            "protocol",
            ProbeLevel::Warn,
            "the server did not send its protocol version",
        ),
    }
}

/// The clock line: the server's `Date` header against `local_ms` (UNIX ms, taken
/// halfway through the request).
#[must_use]
pub fn clock_check(date: Option<&str>, local_ms: i64) -> ProbeCheck {
    let Some(date) = date else {
        return ProbeCheck::new("clock", ProbeLevel::Skip, "the server sent no Date header");
    };
    let Some(server_s) = parse_http_date(date) else {
        return ProbeCheck::new(
            "clock",
            ProbeLevel::Skip,
            format!("unreadable Date header {date:?}"),
        );
    };
    // `Date` has a resolution of one second.
    let offset = local_ms.div_euclid(1000) - server_s;
    if offset.abs() > MAX_CLOCK_OFFSET_S {
        let dir = if offset > 0 { "ahead of" } else { "behind" };
        ProbeCheck::new(
            "clock",
            ProbeLevel::Warn,
            format!("this clock is {} s {dir} the server", offset.abs()),
        )
        .hint("enable time synchronisation (NTP); a skewed clock misorders concurrent edits")
    } else {
        ProbeCheck::new(
            "clock",
            ProbeLevel::Ok,
            format!("offset to the server {offset:+} s"),
        )
    }
}

/// Parse an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, RFC 9110) to UNIX
/// seconds.
#[must_use]
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let (_, rest) = s.split_once(", ")?;
    let mut parts = rest.split_ascii_whitespace();
    let day: i64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.next()?.parse().ok()?;
    let mut hms = parts.next()?.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, sec) = (hms.next()??, hms.next()??, hms.next()??);
    if parts.next()? != "GMT" || !(1..=31).contains(&day) || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A token source that never refreshes (a refresh would rotate the tokens).
struct FixedToken(String);

impl TokenSource for FixedToken {
    async fn access_token(&self) -> Result<String, TokenError> {
        Ok(self.0.clone())
    }

    async fn refresh(&self) -> Result<(), TokenError> {
        Err(TokenError::LoginRequired)
    }
}

async fn ws_check(
    base: &str,
    token: &str,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> ProbeCheck {
    let mut config = WsConfig::for_server(base);
    // The first server message proves the token was accepted; a quick ping gets one.
    config.ping_interval = Duration::from_millis(200);
    config.connect_timeout = timeout;
    config.tls = Some(tls);
    let source = FixedToken(token.to_owned());
    let (tx, mut rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let client = ws::run(config, &source, tx, cancel.clone());
    tokio::pin!(client);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let outcome = loop {
        tokio::select! {
            () = &mut deadline => break Err("no answer in time".to_owned()),
            () = &mut client => break Err("the connection ended".to_owned()),
            ev = rx.recv() => match ev {
                Some(WsEvent::Connected) => break Ok(()),
                Some(WsEvent::Disconnected { reason, .. }) => break Err(match reason {
                    DisconnectReason::AuthRejected => "the token was rejected (close 4401)".to_owned(),
                    DisconnectReason::Io(e) => e,
                    DisconnectReason::Closed(code) => format!("closed by the server ({code})"),
                    DisconnectReason::PingTimeout => "no pong".to_owned(),
                    DisconnectReason::TokenUnavailable(e) => e,
                }),
                Some(WsEvent::NeedsLogin) => break Err("sign-in required".to_owned()),
                Some(WsEvent::Notification(_)) => {}
                None => break Err("the connection ended".to_owned()),
            },
        }
    };
    cancel.cancel();
    // Let the client send its close frame (bounded).
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut client).await;
    match outcome {
        Ok(()) => ProbeCheck::new(
            "websocket",
            ProbeLevel::Ok,
            "live updates connect and authenticate",
        ),
        Err(why) => ProbeCheck::new(
            "websocket",
            ProbeLevel::Warn,
            format!("live updates failed: {why}"),
        )
        .hint("a proxy may block WebSocket upgrades; sync still works by polling"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Thu, 08 Oct 2026 12:00:00 GMT"),
            Some(1_791_460_800)
        );
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 PST"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }

    // T-07: a server `Date` 5 minutes off is warned about; a few seconds are not.
    #[test]
    fn t07_clock_offset_warning() {
        let server = "Thu, 08 Oct 2026 12:00:00 GMT";
        let server_ms = 1_791_460_800_000_i64;
        let ahead = clock_check(Some(server), server_ms + 5 * 60_000);
        assert_eq!(ahead.level, ProbeLevel::Warn);
        assert_eq!(ahead.detail, "this clock is 300 s ahead of the server");
        assert!(ahead.hint.is_some());
        let behind = clock_check(Some(server), server_ms - 5 * 60_000);
        assert_eq!(behind.level, ProbeLevel::Warn);
        assert_eq!(behind.detail, "this clock is 300 s behind the server");
        let close = clock_check(Some(server), server_ms + 3_400);
        assert_eq!(close.level, ProbeLevel::Ok);
        assert_eq!(close.detail, "offset to the server +3 s");
        assert_eq!(
            clock_check(Some(server), server_ms + 60_999).level,
            ProbeLevel::Ok
        );
        assert_eq!(clock_check(None, server_ms).level, ProbeLevel::Skip);
    }

    #[test]
    fn protocol_versions() {
        assert_eq!(protocol_check(Some(PROTO_VERSION)).level, ProbeLevel::Ok);
        assert_eq!(
            protocol_check(Some(PROTO_VERSION + 1)).level,
            ProbeLevel::Fail
        );
        assert_eq!(protocol_check(None).level, ProbeLevel::Warn);
    }
}
