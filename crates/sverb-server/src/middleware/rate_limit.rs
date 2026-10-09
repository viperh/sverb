//! Rate limiting with `governor` (SPEC §10.5).
//!
//! Login attempts are limited to 5 per minute per email and 50 per minute per
//! client IP (GCRA: the full burst is available at once and refills evenly
//! over the minute). The email is only known after the JSON body has been
//! parsed, so this is not a tower layer: the login handler calls
//! [`RateLimiters::check_login`] with the email and the [`ClientIp`]
//! extension.
//!
//! Keyed state grows with every new key; [`RateLimiters::spawn_cleanup`]
//! drops keys whose state has fully recovered.
//!
//! [`ClientIp`]: crate::middleware::client_ip::ClientIp

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::error::ApiError;

/// How often stale keys are dropped.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Login limits (per minute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginLimits {
    /// Attempts per email per minute (spec: 5).
    pub per_email_per_minute: NonZeroU32,
    /// Attempts per client IP per minute (spec: 50).
    pub per_ip_per_minute: NonZeroU32,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self {
            per_email_per_minute: NonZeroU32::MIN.saturating_add(4),
            per_ip_per_minute: NonZeroU32::MIN.saturating_add(49),
        }
    }
}

/// The server's keyed rate limiters.
pub struct RateLimiters {
    login_email: DefaultKeyedRateLimiter<String>,
    login_ip: DefaultKeyedRateLimiter<IpAddr>,
    clock: DefaultClock,
}

impl std::fmt::Debug for RateLimiters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiters")
            .field("login_email_keys", &self.login_email.len())
            .field("login_ip_keys", &self.login_ip.len())
            .finish()
    }
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new(LoginLimits::default())
    }
}

impl RateLimiters {
    /// Creates limiters with the given quotas.
    #[must_use]
    pub fn new(limits: LoginLimits) -> Self {
        Self {
            login_email: RateLimiter::keyed(Quota::per_minute(limits.per_email_per_minute)),
            login_ip: RateLimiter::keyed(Quota::per_minute(limits.per_ip_per_minute)),
            clock: DefaultClock::default(),
        }
    }

    /// Records one login attempt (`login/start`) for `email` from `ip`.
    ///
    /// # Errors
    /// [`ApiError::RateLimited`] with the wait time when either limit is hit.
    pub fn check_login(&self, email: &str, ip: IpAddr) -> Result<(), ApiError> {
        let now = self.clock.now();
        if let Err(not_until) = self.login_ip.check_key(&ip) {
            return Err(limited(
                "too many login attempts from this address",
                not_until.wait_time_from(now),
            ));
        }
        let key = email.trim().to_lowercase();
        if let Err(not_until) = self.login_email.check_key(&key) {
            return Err(limited(
                "too many login attempts for this account",
                not_until.wait_time_from(now),
            ));
        }
        Ok(())
    }

    /// Drops keys whose state has fully replenished.
    pub fn cleanup(&self) {
        self.login_email.retain_recent();
        self.login_email.shrink_to_fit();
        self.login_ip.retain_recent();
        self.login_ip.shrink_to_fit();
    }

    /// Runs [`Self::cleanup`] every [`CLEANUP_INTERVAL`] until the runtime
    /// shuts down.
    pub fn spawn_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                self.cleanup();
            }
        })
    }
}

fn limited(message: &str, wait: Duration) -> ApiError {
    let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    ApiError::RateLimited {
        message: message.to_owned(),
        retry_after_s: secs.max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixth_attempt_per_email_is_limited() {
        let rl = RateLimiters::default();
        let ip: IpAddr = [192, 0, 2, 1].into();
        for _ in 0..5 {
            assert!(rl.check_login("A@example.com", ip).is_ok());
        }
        // Case-insensitive key.
        match rl.check_login("a@EXAMPLE.com ", ip) {
            Err(ApiError::RateLimited { retry_after_s, .. }) => {
                assert!((1..=60).contains(&retry_after_s));
            }
            other => panic!("expected rate limit, got {other:?}"),
        }
        rl.cleanup();
    }
}
