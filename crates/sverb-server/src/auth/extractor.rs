//! The bearer-token extractor (§10.4).
//!
//! `Authorization: Bearer <access token>` → SHA-256 lookup; the token must
//! be an unexpired access token of an unrevoked device of an enabled
//! account. Anything else is `401 auth_required`. Add [`AuthCtx`] as a
//! handler argument to require authentication.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use super::tokens::hash_presented;
use crate::error::ApiError;
use crate::state::AppState;

/// The authenticated caller: user and device.
pub type AuthCtx = super::store::AccessCtx;

fn unauthorized() -> ApiError {
    ApiError::AuthRequired("missing, expired or revoked access token".into())
}

/// The bearer token of a request, if the header is well-formed.
#[must_use]
pub fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

impl FromRequestParts<AppState> for AuthCtx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(ctx) = parts.extensions.get::<Self>() {
            return Ok(*ctx);
        }
        let hash = bearer(parts)
            .and_then(hash_presented)
            .ok_or_else(unauthorized)?;
        let auth = state.auth();
        let ctx = auth
            .store()
            .lookup_access(&hash, auth.now())
            .await?
            .ok_or_else(unauthorized)?;
        parts.extensions.insert(ctx);
        Ok(ctx)
    }
}
