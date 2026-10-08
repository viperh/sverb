//! Protocol versioning (SPEC §20) and shared HTTP header names (§10.4).
//!
//! The HTTP API lives under `/v1`; the sync protocol is versioned separately
//! through the `Sverb-Proto` request/response header. The server accepts the
//! current version `N` and the previous one `N-1`. A request without the
//! header is treated as speaking the current version.

/// Header carrying the sync protocol version, sent by clients and echoed by
/// the server.
pub const PROTO_HEADER: &str = "sverb-proto";

/// Current protocol version (`N`).
pub const PROTO_VERSION: u32 = 1;

/// Oldest protocol version the server still accepts (`N-1`).
pub const MIN_SUPPORTED_PROTO_VERSION: u32 = PROTO_VERSION - 1;

/// Request-ID header, accepted from clients and echoed in every response.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Path prefix of the versioned HTTP API.
pub const API_PREFIX: &str = "/v1";

/// Whether a client speaking `version` can be served.
// The lower bound is 0 while `PROTO_VERSION` is 1; keep the check for later versions.
#[allow(clippy::absurd_extreme_comparisons)]
#[must_use]
pub const fn is_supported(version: u32) -> bool {
    version >= MIN_SUPPORTED_PROTO_VERSION && version <= PROTO_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_n_and_n_minus_one_only() {
        assert!(is_supported(PROTO_VERSION));
        assert!(is_supported(PROTO_VERSION - 1));
        assert!(!is_supported(PROTO_VERSION + 1));
        assert!(!is_supported(5));
    }
}
