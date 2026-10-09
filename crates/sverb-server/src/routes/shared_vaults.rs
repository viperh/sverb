//! M5-02: shared vault routes (SPEC §10.4, §13.1, §13.2; DTOs in
//! [`sverb_proto::vaults`]). The rules live in [`crate::sync::shared`]; these
//! handlers add the audit rows (§13.5) and the `vault_access` notifications
//! (M4-05) after the change committed.
//!
//! `POST /v1/vaults` is routed from [`super::vaults`] (same path as the list).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use sverb_proto::sync::VaultView;
use sverb_proto::vaults::{CreateVaultRequest, GrantRequest, OrgVaultView, VaultMembersView};
use sverb_proto::ws::AccessChange;
use uuid::Uuid;

use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::state::AppState;
use crate::sync::shared::{NewSharedVault, kinds, push_audit_meta};

/// The member and org-vault routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vaults/{id}/members", get(members))
        .route(
            "/vaults/{id}/members/{user}",
            axum::routing::put(grant).delete(revoke),
        )
        .route("/orgs/{id}/vaults", get(org_vaults))
}

/// Records an audit event; a failure is logged (the change already committed).
async fn audit(
    state: &AppState,
    org: Uuid,
    actor: Uuid,
    kind: &str,
    target: Uuid,
    meta: serde_json::Value,
) {
    let now = state.auth().now();
    if let Err(e) = state
        .orgs()
        .record(org, Some(actor), kind, Some(target), meta, now)
        .await
    {
        tracing::warn!(error = %e, %org, kind, "audit event not recorded");
    }
}

/// `POST /v1/vaults`: creates a shared vault (org admin+).
pub(crate) async fn create(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<VaultView>, ApiError> {
    let new = NewSharedVault {
        id: req.id,
        org_id: req.org_id,
        name_enc: req.name_enc,
        creator: ctx.user_id,
        grant: req.self_grant,
    };
    let view = state.sync().store().create_shared_vault(&new).await?;
    let meta = serde_json::json!({ "key_version": view.key_version });
    audit(
        &state,
        new.org_id,
        ctx.user_id,
        kinds::VAULT_CREATED,
        new.id,
        meta,
    )
    .await;
    // The creator's other devices adopt the vault.
    state
        .ws()
        .vault_access(ctx.user_id, new.id, AccessChange::Granted);
    tracing::info!(vault_id = %new.id, org_id = %new.org_id, by = %ctx.user_id, "shared vault created");
    Ok(Json(view))
}

async fn members(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(vault): Path<Uuid>,
) -> Result<Json<VaultMembersView>, ApiError> {
    Ok(Json(
        state
            .sync()
            .store()
            .vault_members(vault, ctx.user_id)
            .await?,
    ))
}

async fn grant(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path((vault, user)): Path<(Uuid, Uuid)>,
    Json(req): Json<GrantRequest>,
) -> Result<StatusCode, ApiError> {
    let org = state
        .sync()
        .store()
        .grant_member(vault, ctx.user_id, user, &req)
        .await?;
    let meta = serde_json::json!({ "vault": vault, "permission": req.permission });
    audit(&state, org, ctx.user_id, kinds::VAULT_GRANTED, user, meta).await;
    state.ws().vault_access(user, vault, AccessChange::Granted);
    tracing::info!(vault_id = %vault, user_id = %user, by = %ctx.user_id, permission = req.permission.as_str(), "vault access granted");
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path((vault, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let r = state
        .sync()
        .store()
        .revoke_member(vault, ctx.user_id, user)
        .await?;
    let meta = serde_json::json!({ "vault": vault, "left": user == ctx.user_id });
    audit(
        &state,
        r.org_id,
        ctx.user_id,
        kinds::VAULT_REVOKED,
        user,
        meta,
    )
    .await;
    state.ws().vault_access(user, vault, AccessChange::Revoked);
    tracing::info!(vault_id = %vault, user_id = %user, by = %ctx.user_id, rows = r.rows, "vault access revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn org_vaults(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(org): Path<Uuid>,
) -> Result<Json<Vec<OrgVaultView>>, ApiError> {
    Ok(Json(
        state.sync().store().org_vaults(org, ctx.user_id).await?,
    ))
}

/// After a push to a shared vault committed: one audit row with the accepted
/// item ids (§13.5: ids and the actor, never content). Personal vaults are not
/// audited.
pub(crate) async fn audit_push(state: &AppState, actor: Uuid, vault: Uuid, items: &[Uuid]) {
    if items.is_empty() {
        return;
    }
    match state.sync().store().shared_vault_org(vault).await {
        Ok(Some(org)) => {
            audit(
                state,
                org,
                actor,
                kinds::ITEMS_PUSHED,
                vault,
                push_audit_meta(items),
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, %vault, "push audit skipped"),
    }
}
