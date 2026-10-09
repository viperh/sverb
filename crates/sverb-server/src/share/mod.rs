//!
//! * [`sessions`]: the `share_sessions` row (PostgreSQL and in-memory);
//! * [`relay`]: the per-replica relay (host and viewer sockets, routing by
//!   `viewer_id`, kick, slow viewers, expiry and host grace);
//! * [`routes`]: `POST/DELETE /v1/shares`, the `host` and `join`
//!   WebSockets.
//!
//! The server is a blind relay: it never receives the share key (it is in
//! the link fragment) and only reads the 4-byte routing header of each
//! binary message (`sverb_proto::share::RelayEnvelope`). Payloads are never
//! logged.
//!
//! # Limits (§10.5)
//!
//! `max_viewers` and the lifetime default to and are clamped at
//! `SVERB_SHARE_MAX_VIEWERS` (10) and `SVERB_SHARE_TTL_HOURS` (24 h). Messages
//! are at most 1 MiB; each viewer has a 256-message queue.
//!
//! # Audit
//!
//! Creating a share writes a `share_started` audit event in every org the
//! owner belongs to (audit logs are per org, §10.3), none for owners
//! without orgs. The memory backend has no orgs and writes none.
//!
//! # Multiple replicas (§10.7)
//!
//! A relay lives in the memory of the replica that holds its sockets, so
//! the load balancer must route **all** of `/v1/shares/{id}/*` for one
//! share to the same replica (sticky routing, e.g. hashing the path
//! segment after `/v1/shares/`). `DELETE /v1/shares/{id}` should go there
//! too: on any other replica it still sets `closed_at`, so no new socket is
//! admitted, but the sockets already open elsewhere only close at the
//! share's expiry. Returning `409` with a replica hint is out of scope for
//! v1.
//!
//! # Not covered (v1)
//!
//! Share streams authenticate once at connect: unlike `/v1/ws`, they are
//! not closed when the access token expires or the device is revoked
//! (ending the share or kicking does that).

pub mod relay;
pub mod routes;
pub mod sessions;

use std::net::IpAddr;
use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use sverb_proto::share::HOST_GRACE_SECS;

pub use relay::{RelayFrame, Relays, end_share, run_host, run_viewer};
pub use routes::router;
pub use sessions::{ShareRow, ShareStore};

use crate::auth::AuthRuntime;
use crate::auth::store::AccessCtx;
use crate::auth::tokens::hash_presented;
use crate::config::Config;
use crate::state::AppState;

/// Longest display name kept (characters); longer ones are truncated.
pub const MAX_VIEWER_NAME_CHARS: usize = 64;

/// Share limits (§10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareLimits {
    /// Default and maximum viewers.
    pub max_viewers: u32,
    /// Default and maximum lifetime.
    pub max_ttl: Duration,
}

impl ShareLimits {
    /// The limits in `config`.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_viewers: config.limits.share_max_viewers,
            max_ttl: Duration::from_secs(u64::from(config.limits.share_ttl_hours) * 3600),
        }
    }
}

/// Socket timing (defaults from SPEC §10.4 and §14.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareTiming {
    /// The first message must arrive within this.
    pub auth_timeout: Duration,
    /// Heartbeat period.
    pub ping_interval: Duration,
    /// Unanswered pings before closing.
    pub max_missed_pongs: u32,
    /// The share ends after the host has been gone this long.
    pub host_grace: Duration,
}

impl Default for ShareTiming {
    fn default() -> Self {
        use sverb_proto::ws::{AUTH_TIMEOUT_SECS, MAX_MISSED_PONGS, PING_INTERVAL_SECS};
        Self {
            auth_timeout: Duration::from_secs(AUTH_TIMEOUT_SECS),
            ping_interval: Duration::from_secs(PING_INTERVAL_SECS),
            max_missed_pongs: MAX_MISSED_PONGS,
            host_grace: Duration::from_secs(HOST_GRACE_SECS),
        }
    }
}

/// Share state (part of `AppState`).
#[derive(Debug)]
pub struct ShareRuntime {
    store: ShareStore,
    relays: Relays,
    limits: ShareLimits,
    timing: ShareTiming,
}

impl ShareRuntime {
    /// A runtime on `store`.
    #[must_use]
    pub fn new(store: ShareStore, limits: ShareLimits, timing: ShareTiming) -> Self {
        Self {
            store,
            relays: Relays::default(),
            limits,
            timing,
        }
    }

    /// The runtime matching the auth runtime's backend.
    #[must_use]
    pub fn for_auth(auth: &AuthRuntime, config: &Config) -> Self {
        Self::new(
            ShareStore::for_auth(auth.store()),
            ShareLimits::from_config(config),
            ShareTiming::default(),
        )
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &ShareStore {
        &self.store
    }

    /// This replica's relays.
    #[must_use]
    pub const fn relays(&self) -> &Relays {
        &self.relays
    }

    /// The limits.
    #[must_use]
    pub const fn limits(&self) -> ShareLimits {
        self.limits
    }

    /// Socket timing.
    #[must_use]
    pub const fn timing(&self) -> ShareTiming {
        self.timing
    }
}

/// Validates a presented access token (unexpired, device not revoked,
/// account enabled).
pub(crate) async fn authenticate(state: &AppState, token: &str) -> Option<AccessCtx> {
    let hash = hash_presented(token)?;
    let auth = state.auth();
    auth.store().lookup_access(&hash, auth.now()).await.ok()?
}

/// The coarse IP hint shown to the host (§14.1): the /24 (IPv4) or /48
/// (IPv6) prefix. `None` for an unknown address. (No GeoIP in v1.)
#[must_use]
pub fn ip_hint(ip: IpAddr) -> Option<String> {
    let ip = ip.to_canonical();
    if ip.is_unspecified() {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v4) => Ipv4Net::new(v4, 24).ok()?.trunc().to_string(),
        IpAddr::V6(v6) => Ipv6Net::new(v6, 48).ok()?.trunc().to_string(),
    })
}

/// A viewer's display name as shown to the host: control characters
/// removed, trimmed, at most [`MAX_VIEWER_NAME_CHARS`]; empty → `None`.
#[must_use]
pub fn clean_name(name: Option<&str>) -> Option<String> {
    let cleaned: String = name?
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_VIEWER_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim_end().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn ip_hints_are_coarse() {
        let h = |s: &str| ip_hint(s.parse().unwrap());
        assert_eq!(h("198.51.100.77").as_deref(), Some("198.51.100.0/24"));
        assert_eq!(h("2001:db8:1:2::5").as_deref(), Some("2001:db8:1::/48"));
        assert_eq!(h("::ffff:203.0.113.9").as_deref(), Some("203.0.113.0/24"));
        assert_eq!(h("0.0.0.0"), None);
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name(None), None);
        assert_eq!(
            clean_name(Some("  \u{1b}[31mbob\n ")).as_deref(),
            Some("[31mbob")
        );
        assert_eq!(clean_name(Some(" \t ")), None);
        assert_eq!(
            clean_name(Some(&"x".repeat(200))).unwrap().chars().count(),
            MAX_VIEWER_NAME_CHARS
        );
    }
}
