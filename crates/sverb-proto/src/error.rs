//! The uniform API error envelope (SPEC §10.4).
//!
//! Every non-2xx response from `sverb-server` has the body
//! `{ "error": { "code": "...", "message": "...", "retry_after_s"?: n } }`.
//! `429` responses additionally carry a `Retry-After` header with the same
//! number of seconds.

use serde::{Deserialize, Serialize};

/// Machine-readable error code.
///
/// The first eight codes are the spec's list (§10.4). `Internal` is an
/// addition for unexpected server failures (5xx), which the spec does not
/// name; clients treat it like a transient error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 409: optimistic-concurrency or uniqueness conflict.
    Conflict,
    /// 403: authenticated but not allowed.
    Forbidden,
    /// 404: no such resource (or not visible to the caller).
    NotFound,
    /// 429: rate limited; see `retry_after_s`.
    RateLimited,
    /// 400 (and 413/405/…): malformed or unacceptable request.
    Invalid,
    /// 410: the requested cursor is below the GC floor (§12.2).
    Gone,
    /// 409: the vault is mid key rotation (§12.3, §13.2).
    Rotating,
    /// 401: missing, expired or revoked credentials.
    AuthRequired,
    /// 5xx: unexpected server failure (spec addition).
    Internal,
}

impl ErrorCode {
    /// Every code, in declaration order (useful for table-driven tests).
    pub const ALL: [Self; 9] = [
        Self::Conflict,
        Self::Forbidden,
        Self::NotFound,
        Self::RateLimited,
        Self::Invalid,
        Self::Gone,
        Self::Rotating,
        Self::AuthRequired,
        Self::Internal,
    ];

    /// The wire spelling, e.g. `"rate_limited"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Gone => "gone",
            Self::Rotating => "rotating",
            Self::AuthRequired => "auth_required",
            Self::Internal => "internal",
        }
    }

    /// The HTTP status the server uses for this code by default.
    #[must_use]
    pub const fn default_status(self) -> u16 {
        match self {
            Self::Conflict | Self::Rotating => 409,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::RateLimited => 429,
            Self::Invalid => 400,
            Self::Gone => 410,
            Self::AuthRequired => 401,
            Self::Internal => 500,
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The inner `error` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Human-readable message (never contains secrets).
    pub message: String,
    /// Seconds until a retry may succeed (only for `rate_limited`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// The top-level error document: `{ "error": { … } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// The error.
    pub error: ErrorBody,
}

impl ErrorEnvelope {
    /// Builds an envelope.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, retry_after_s: Option<u64>) -> Self {
        Self {
            error: ErrorBody {
                code,
                message: message.into(),
                retry_after_s,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_as_spec_strings() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    #[test]
    fn envelope_shape() {
        let env = ErrorEnvelope::new(ErrorCode::RateLimited, "slow down", Some(12));
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"error": {"code": "rate_limited", "message": "slow down", "retry_after_s": 12}})
        );
        let env = ErrorEnvelope::new(ErrorCode::NotFound, "nope", None);
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert!(v["error"].get("retry_after_s").is_none());
    }
}
