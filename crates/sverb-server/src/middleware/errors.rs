//! Turns every non-JSON error response into the uniform envelope
//! (SPEC §10.4 "all endpoints").
//!
//! Handlers already return envelopes through [`ApiError`]. Responses produced
//! elsewhere (the router's 404/405, axum extractor rejections, the body-limit
//! layer's 413, the timeout layer's 408, panics turned into 500) are plain
//! text or empty; this layer rewrites them, keeping the status code.
//!
//! [`ApiError`]: crate::error::ApiError

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sverb_proto::ErrorCode;

use crate::app::BODY_LIMIT;
use crate::error::envelope_response;

/// Longest plain-text rejection message copied into the envelope.
const MAX_PASSTHROUGH: usize = 512;

fn is_json(resp: &Response) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json"))
}

/// Code and fallback message for a bare status.
#[must_use]
pub fn classify(status: StatusCode) -> (ErrorCode, String) {
    match status {
        StatusCode::UNAUTHORIZED => (ErrorCode::AuthRequired, "authentication required".into()),
        StatusCode::FORBIDDEN => (ErrorCode::Forbidden, "forbidden".into()),
        StatusCode::NOT_FOUND => (ErrorCode::NotFound, "not found".into()),
        StatusCode::METHOD_NOT_ALLOWED => (ErrorCode::Invalid, "method not allowed".into()),
        StatusCode::REQUEST_TIMEOUT => (ErrorCode::Invalid, "request timed out".into()),
        StatusCode::CONFLICT => (ErrorCode::Conflict, "conflict".into()),
        StatusCode::GONE => (ErrorCode::Gone, "gone".into()),
        StatusCode::PAYLOAD_TOO_LARGE => (
            ErrorCode::Invalid,
            format!(
                "request body too large (limit {} MiB)",
                BODY_LIMIT / (1024 * 1024)
            ),
        ),
        StatusCode::TOO_MANY_REQUESTS => (ErrorCode::RateLimited, "too many requests".into()),
        s if s.is_server_error() => (ErrorCode::Internal, "internal server error".into()),
        _ => (ErrorCode::Invalid, "invalid request".into()),
    }
}

/// The normalising middleware.
pub async fn layer(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) || is_json(&resp) {
        return resp;
    }
    let (code, fallback) = classify(status);
    // Keep the specific text of extractor rejections ("Failed to deserialize
    // the JSON body …"); server errors and size/timeout errors use fixed text.
    let passthrough = code == ErrorCode::Invalid
        && !matches!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::REQUEST_TIMEOUT
        );
    let (parts, body) = resp.into_parts();
    let message = if passthrough {
        match axum::body::to_bytes(body, MAX_PASSTHROUGH).await {
            Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).trim().to_owned(),
            _ => fallback,
        }
    } else {
        drop::<Body>(body);
        fallback
    };
    let retry_after = parts
        .headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let mut out = envelope_response(status, code, message, retry_after);
    // Keep headers set by inner layers (CORS, request id, …) except the
    // body-describing ones.
    let keep = |name: &header::HeaderName| {
        name != header::CONTENT_TYPE
            && name != header::CONTENT_LENGTH
            && name != header::CONTENT_ENCODING
    };
    for name in parts.headers.keys().filter(|n| keep(n)) {
        out.headers_mut().remove(name);
    }
    for (name, value) in parts.headers.iter().filter(|(n, _)| keep(n)) {
        out.headers_mut().append(name.clone(), value.clone());
    }
    out
}
