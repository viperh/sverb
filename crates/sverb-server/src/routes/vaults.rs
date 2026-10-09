//! `/v1/vaults`: vault list, pull and push (SPEC §10.4, §12.2, §12.3; task
//! M4-04). The logic lives in [`crate::sync`]; these handlers do auth,
//! extraction, metrics and the post-commit notification.
//!
//! `POST /v1/vaults` (create a shared vault, org admin+) is M5-02's
//! `super::shared_vaults::create`.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use sverb_proto::sync::{PullQuery, PullResponse, PushRequest, PushResponse, VaultView};
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::metrics::{
    SYNC_PULL_BYTES_TOTAL, SYNC_PULL_ITEMS_TOTAL, SYNC_PUSH_BYTES_TOTAL, SYNC_PUSH_ITEMS_TOTAL,
};
use crate::state::AppState;
use crate::sync::{pull, push, rev_from_wire};

/// `/vaults` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vaults", get(list).post(super::shared_vaults::create)) // M5-02: POST
        .route("/vaults/{id}/changes", get(pull_changes).post(push_changes))
}

async fn list(
    State(state): State<AppState>,
    ctx: AuthCtx,
) -> Result<Json<Vec<VaultView>>, ApiError> {
    let mut views = state.sync().store().list_vaults(ctx.user_id).await?;
    // M5-04: abandoned rotations (15 min, server clock) prompt a restart.
    crate::sync::rotation::mark_abandoned(&mut views, state.auth().now());
    Ok(Json(views))
}

async fn pull_changes(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault_id): Path<Uuid>,
    Query(q): Query<PullQuery>,
) -> Result<Json<PullResponse>, ApiError> {
    let limit = pull::page_size(q.limit)?;
    let page = state
        .sync()
        .store()
        .pull(ctx.user_id, vault_id, rev_from_wire(q.since), limit)
        .await?;
    let bytes: usize = page.items.iter().map(|i| i.envelope.len()).sum();
    metrics::counter!(SYNC_PULL_ITEMS_TOTAL).increment(page.items.len() as u64);
    metrics::counter!(SYNC_PULL_BYTES_TOTAL).increment(bytes as u64);
    Ok(Json(page))
}

async fn push_changes(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, ApiError> {
    push::validate_batch(&req.changes)?;
    let sync = state.sync();
    let outcome = sync
        .store()
        .push(
            ctx,
            vault_id,
            &req.changes,
            sync.limits(),
            state.auth().now(),
        )
        .await?;
    if let Some(head) = outcome.new_head {
        // After commit (M4-05 fans this out).
        sync.notify(vault_id, head);
        let (items, bytes) = req
            .changes
            .iter()
            .zip(&outcome.results)
            .filter(|(_, r)| r.revision.is_some())
            .fold((0u64, 0u64), |(n, b), (c, _)| {
                (n + 1, b + c.envelope.len() as u64)
            });
        metrics::counter!(SYNC_PUSH_ITEMS_TOTAL).increment(items);
        metrics::counter!(SYNC_PUSH_BYTES_TOTAL).increment(bytes);
        tracing::debug!(%vault_id, head, accepted = items, "push committed");
        // M5-02: item-level audit of shared vaults (ids only, §13.5).
        let ids: Vec<Uuid> = req
            .changes
            .iter()
            .zip(&outcome.results)
            .filter(|(_, r)| r.revision.is_some())
            .map(|(c, _)| c.id)
            .collect();
        super::shared_vaults::audit_push(&state, ctx.user_id, vault_id, &ids).await;
    }
    Ok(Json(PushResponse {
        results: outcome.results,
    }))
}
