//! The API error type and its mapping to the uniform JSON envelope
//! (SPEC §10.4).
//!
//! Handlers return `Result<_, ApiError>`. Every variant maps to one
//! [`ErrorCode`] and HTTP status; `RateLimited` also sets `Retry-After`.
//! Unexpected failures become `Internal`, whose cause is logged but never
//! sent to the client.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sverb_proto::{ErrorCode, ErrorEnvelope};

/// Boxed cause of an internal error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An API error, rendered as `{ "error": { "code", "message", "retry_after_s"? } }`.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 409 `conflict`.
    #[error("{0}")]
    Conflict(String),
    /// 403 `forbidden`.
    #[error("{0}")]
    Forbidden(String),
    /// 404 `not_found`.
    #[error("{0}")]
    NotFound(String),
    /// 429 `rate_limited` with `Retry-After`.
    #[error("{message}")]
    RateLimited {
        /// Human-readable message.
        message: String,
        /// Seconds until the client may retry (at least 1).
        retry_after_s: u64,
    },
    /// 400 `invalid`.
    #[error("{0}")]
    Invalid(String),
    /// 413 `invalid`: the request body exceeds the limit.
    #[error("{0}")]
    TooLarge(String),
    /// 410 `gone`.
    #[error("{0}")]
    Gone(String),
    /// 409 `rotating`.
    #[error("{0}")]
    Rotating(String),
    /// 401 `auth_required`.
    #[error("{0}")]
    AuthRequired(String),
    /// 500 `internal`; the cause is logged, not returned.
    #[error("internal server error")]
    Internal(#[source] BoxError),
}

impl ApiError {
    /// Wraps any error as `Internal`.
    pub fn internal(err: impl Into<BoxError>) -> Self {
        Self::Internal(err.into())
    }

    /// The envelope code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::Forbidden(_) => ErrorCode::Forbidden,
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::Invalid(_) | Self::TooLarge(_) => ErrorCode::Invalid,
            Self::Gone(_) => ErrorCode::Gone,
            Self::Rotating(_) => ErrorCode::Rotating,
            Self::AuthRequired(_) => ErrorCode::AuthRequired,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Conflict(_) | Self::Rotating(_) => StatusCode::CONFLICT,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Gone(_) => StatusCode::GONE,
            Self::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Builds an envelope response; `retry_after_s` also sets `Retry-After`.
#[must_use]
pub fn envelope_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    retry_after_s: Option<u64>,
) -> Response {
    let mut resp = (
        status,
        Json(ErrorEnvelope::new(code, message, retry_after_s)),
    )
        .into_response();
    if let Some(secs) = retry_after_s {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    resp
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        match self {
            Self::Internal(cause) => {
                tracing::error!(error = %cause, "internal error");
                envelope_response(status, code, "internal server error", None)
            }
            Self::RateLimited {
                message,
                retry_after_s,
            } => envelope_response(status, code, message, Some(retry_after_s.max(1))),
            other => envelope_response(status, code, other.to_string(), None),
        }
    }
}

impl From<sqlx_core::Error> for ApiError {
    fn from(err: sqlx_core::Error) -> Self {
        Self::internal(err)
    }
}
