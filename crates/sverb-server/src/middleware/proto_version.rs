//! `Sverb-Proto` negotiation (SPEC §20).
//!
//! The server supports the current protocol version `N` and `N-1`. A missing
//! header means "current". A malformed or unsupported version is rejected
//! with `400 invalid`. Every response carries `Sverb-Proto: N`.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sverb_proto::version::{MIN_SUPPORTED_PROTO_VERSION, PROTO_HEADER, PROTO_VERSION};

use crate::error::ApiError;

/// The protocol version the client speaks (stored as a request extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientProto(pub u32);

/// Parses the header value (`None` = header absent).
///
/// # Errors
/// [`ApiError::Invalid`] for malformed, too old or too new versions.
// `MIN_SUPPORTED_PROTO_VERSION` is 0 today, so the "too old" branch is dead
// until the protocol reaches version 2.
#[allow(clippy::absurd_extreme_comparisons)]
pub fn negotiate(header: Option<&HeaderValue>) -> Result<ClientProto, ApiError> {
    let Some(raw) = header else {
        return Ok(ClientProto(PROTO_VERSION));
    };
    let v: u32 = raw
        .to_str()
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| ApiError::Invalid("malformed Sverb-Proto header".into()))?;
    if v < MIN_SUPPORTED_PROTO_VERSION {
        return Err(ApiError::Invalid(format!(
            "client protocol too old: Sverb-Proto {v}, server supports \
             {MIN_SUPPORTED_PROTO_VERSION}..={PROTO_VERSION}; update sverb"
        )));
    }
    if v > PROTO_VERSION {
        return Err(ApiError::Invalid(format!(
            "client protocol too new: Sverb-Proto {v}, server supports \
             {MIN_SUPPORTED_PROTO_VERSION}..={PROTO_VERSION}; upgrade the server"
        )));
    }
    Ok(ClientProto(v))
}

/// Rejects unsupported versions and stamps `Sverb-Proto` on the response.
pub async fn layer(mut req: Request, next: Next) -> Response {
    let mut resp = match negotiate(req.headers().get(PROTO_HEADER)) {
        Ok(proto) => {
            req.extensions_mut().insert(proto);
            next.run(req).await
        }
        Err(err) => err.into_response(),
    };
    resp.headers_mut()
        .insert(PROTO_HEADER, HeaderValue::from(PROTO_VERSION));
    resp
}
