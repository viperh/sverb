//! Ops endpoints (SPEC §10.4): `/healthz`, `/readyz`, `/metrics`.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::db::{self, MigrationStatus};
use crate::error::ApiError;
use crate::state::AppState;

/// `/healthz` and `/readyz`, plus `/metrics` when a metrics token is set.
/// With only `SVERB_METRICS_BIND`, `/metrics` is served by
/// [`metrics_router`] on that address instead.
pub fn router(state: &AppState) -> Router<AppState> {
    let r = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));
    if state.config().metrics_token.is_some() {
        r.route("/metrics", get(metrics))
    } else {
        r
    }
}

/// The router for the dedicated metrics listener (still token-guarded when
/// a token is configured).
pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Process liveness: always 200.
pub async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: database reachable, migrations current, nothing degraded.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let (ready, detail) = match db::migration_status(state.db()).await {
        Err(e) => {
            tracing::warn!(error = %e, "readiness: database unreachable");
            (false, json!({ "database": "unreachable" }))
        }
        Ok(MigrationStatus::Current) => {
            (true, json!({ "database": "ok", "migrations": "current" }))
        }
        Ok(MigrationStatus::Pending(v)) => (
            false,
            json!({ "database": "ok", "migrations": "pending", "pending": v }),
        ),
        Ok(MigrationStatus::Mismatch(m)) => (
            false,
            json!({ "database": "ok", "migrations": "mismatch", "reason": m }),
        ),
    };
    let degraded = state.readiness().degraded();
    let ready = ready && degraded.is_empty();
    let mut body = detail;
    body["status"] = json!(if ready { "ready" } else { "not_ready" });
    if !degraded.is_empty() {
        body["degraded"] = json!(degraded);
    }
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Prometheus text exposition, guarded by `SVERB_METRICS_TOKEN` when set.
///
/// # Errors
/// `401 auth_required` without the right bearer token.
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(expected) = &state.config().metrics_token {
        let ok = bearer(&headers)
            .is_some_and(|got| bool::from(got.as_bytes().ct_eq(expected.0.as_bytes())));
        if !ok {
            return Err(ApiError::AuthRequired("metrics token required".into()));
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics().render(),
    )
        .into_response())
}
