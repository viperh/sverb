//! `/v1/devices`: device registry and revocation (§10.2.7).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use sverb_proto::auth::DeviceView;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::state::AppState;

/// `/devices` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(list))
        .route("/devices/{id}", delete(revoke))
}

async fn list(
    State(state): State<AppState>,
    ctx: AuthCtx,
) -> Result<Json<Vec<DeviceView>>, ApiError> {
    let rows = state.auth().store().list_devices(ctx.user_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|d| DeviceView {
                current: d.id == ctx.device_id,
                id: d.id,
                name: d.name,
                platform: d.platform,
                created_at: d.created_at,
                last_seen_at: d.last_seen_at,
                revoked_at: d.revoked_at,
            })
            .collect(),
    ))
}

/// Revokes a device: `revoked_at` is set and its tokens are deleted, so its
/// access token fails from the next request on.
async fn revoke(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = state.auth();
    if !auth
        .store()
        .revoke_device(ctx.user_id, id, auth.now())
        .await?
    {
        return Err(ApiError::NotFound("no such device".into()));
    }
    tracing::info!(user_id = %ctx.user_id, device_id = %id, by = %ctx.device_id, "device revoked");
    // M4-05: the device's open sockets close with 4401 right away.
    state.ws().device_revoked(ctx.user_id, id);
    Ok(StatusCode::NO_CONTENT)
}
