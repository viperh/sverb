//! M5-04: `POST /v1/vaults/{id}/rotate` (SPEC §10.4, §13.2). The rules live in
//! [`crate::sync::rotation`]; this handler adds, after a commit, the
//! `vault_changed` hint (the items have fresh revisions), `vault_access
//! rotated` to every member, and the `vault.rotated` audit row (§13.5).

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use sverb_proto::rotation::{RotateRequest, RotateResponse};
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::state::AppState;
use crate::sync::shared::kinds;

/// The rotate route (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new().route("/vaults/{id}/rotate", post(rotate))
}

async fn rotate(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault): Path<Uuid>,
    Json(req): Json<RotateRequest>,
) -> Result<Json<RotateResponse>, ApiError> {
    let sync = state.sync();
    let now = state.auth().now();
    match req {
        RotateRequest::Begin { new_key_version } => {
            let r = sync
                .store()
                .rotation_begin(vault, ctx, new_key_version, now)
                .await?;
            tracing::info!(
                %vault, by = %ctx.user_id, new_key_version, resumed = r.resumed,
                replaced_abandoned = r.replaced_abandoned, "vault key rotation begun"
            );
            Ok(Json(r))
        }
        RotateRequest::Upload { items } => {
            let r = sync.store().rotation_upload(vault, ctx, &items).await?;
            tracing::debug!(%vault, n = items.len(), staged = r.staged, "rotation chunk staged");
            Ok(Json(r))
        }
        RotateRequest::Commit { wrapped_keys } => {
            let c = sync
                .store()
                .rotation_commit(vault, ctx, &wrapped_keys, now)
                .await?;
            let head = c.response.head_revision;
            if c.items > 0 {
                sync.notify(vault, head);
            }
            state.ws().vault_rotated(vault);
            if let Some(org) = c.org_id {
                let meta = serde_json::json!({
                    "key_version": c.response.key_version,
                    "items": c.items,
                    "members": wrapped_keys.len(),
                });
                if let Err(e) = state
                    .orgs()
                    .record(
                        org,
                        Some(ctx.user_id),
                        kinds::VAULT_ROTATED,
                        Some(vault),
                        meta,
                        now,
                    )
                    .await
                {
                    tracing::warn!(error = %e, %org, "rotation audit event not recorded");
                }
            }
            tracing::info!(
                %vault, by = %ctx.user_id, key_version = c.response.key_version,
                items = c.items, head, "vault key rotation committed"
            );
            Ok(Json(c.response))
        }
    }
}
