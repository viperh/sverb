//! Request IDs (SPEC §10.4).
//!
//! An incoming `x-request-id` is kept when it is 1–128 characters of
//! `[A-Za-z0-9-]`; otherwise (absent or invalid) a fresh UUIDv7 replaces it.
//! The effective ID is stored as a [`RequestId`] extension, written back into
//! the request headers, attached to the request's log span (see
//! [`crate::app`]) and echoed in the response.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use sverb_proto::version::REQUEST_ID_HEADER;

/// Maximum accepted length of a client-supplied request ID.
pub const MAX_LEN: usize = 128;

/// The effective request ID of the current request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

/// Whether a client-supplied ID is acceptable.
#[must_use]
pub fn is_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Assigns, records and echoes the request ID.
pub async fn layer(mut req: Request, next: Next) -> Response {
    let supplied = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid(s))
        .map(str::to_owned);
    let id = supplied.unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    // Both branches produce visible ASCII, so this cannot fail.
    let value = HeaderValue::from_str(&id).ok();
    if let Some(v) = &value {
        req.headers_mut().insert(REQUEST_ID_HEADER, v.clone());
    }
    req.extensions_mut().insert(RequestId(id));
    let mut resp = next.run(req).await;
    if let Some(v) = value {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity() {
        assert!(is_valid("abc-123-XYZ"));
        assert!(is_valid(&"a".repeat(128)));
        assert!(!is_valid(&"a".repeat(129)));
        assert!(!is_valid(""));
        assert!(!is_valid("has space"));
        assert!(!is_valid("semi;colon"));
        assert!(!is_valid("ünï"));
    }
}
