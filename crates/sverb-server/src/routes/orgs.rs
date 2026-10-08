//! M5-01: `/v1/orgs`, `/v1/invites/{token}/accept`, `/v1/users/{id}/public-keys`
//! (SPEC §10.4 "Orgs and members", §13.1, §13.2, §13.5; DTOs in
//! [`sverb_proto::orgs`]).
//!
//! An org the caller does not belong to is `404` (its existence is not
//! revealed); a role that may not act is `403`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use chrono::Duration;
use sverb_proto::orgs::{
    AuditEventView, AuditPage, AuditQuery, CreateInviteRequest, CreateOrgRequest, InviteAccepted,
    InviteCreated, MAX_AUDIT_PAGE, MemberView, OrgView, Role, UpdateMemberRequest,
};
use sverb_proto::users::UserPublicKeys;
use uuid::Uuid;

use crate::admin::invite::invite_link;
use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::orgs::{self, INVITE_TTL_DAYS, NewInvite, OrgRow};
use crate::registration::{generate_token, hash_token, normalize_email};
use crate::state::AppState;

/// The org, invite and public-key routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/orgs", post(create).get(list))
        .route("/orgs/{id}/members", get(members))
        .route(
            "/orgs/{id}/members/{user}",
            patch(set_role).delete(remove_member),
        )
        .route("/orgs/{id}/invites", post(invite))
        .route("/orgs/{id}/audit", get(audit))
        .route("/invites/{token}/accept", post(accept))
        .route("/users/{id}/public-keys", get(public_keys))
}

fn view(o: OrgRow) -> OrgView {
    OrgView {
        id: o.id,
        name: o.name,
        role: o.role,
        created_at: o.created_at,
    }
}

/// The caller's role in `org`; `404` when not a member.
async fn require_member(state: &AppState, org: Uuid, user: Uuid) -> Result<Role, ApiError> {
    state
        .orgs()
        .role_of(org, user)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such org".into()))
}

async fn create(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgView>, ApiError> {
    let name = orgs::org_name(&req.name)?;
    let now = state.auth().now();
    let org = state
        .orgs()
        .create_org(Uuid::now_v7(), &name, ctx.user_id, now)
        .await?;
    tracing::info!(user_id = %ctx.user_id, org_id = %org.id, "org created");
    Ok(Json(view(org)))
}

async fn list(State(state): State<AppState>, ctx: AuthCtx) -> Result<Json<Vec<OrgView>>, ApiError> {
    let orgs = state.orgs().list_orgs(ctx.user_id).await?;
    Ok(Json(orgs.into_iter().map(view).collect()))
}

async fn members(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(org): Path<Uuid>,
) -> Result<Json<Vec<MemberView>>, ApiError> {
    require_member(&state, org, ctx.user_id).await?;
    let rows = state.orgs().members(org).await?;
    Ok(Json(
        rows.into_iter()
            .map(|m| MemberView {
                user_id: m.user_id,
                email: m.email,
                role: m.role,
            })
            .collect(),
    ))
}

async fn set_role(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path((org, user)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let now = state.auth().now();
    state
        .orgs()
        .set_role(org, ctx.user_id, user, req.role, now)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path((org, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let now = state.auth().now();
    let revoked = state
        .orgs()
        .remove_member(org, ctx.user_id, user, now)
        .await?;
    tracing::info!(org_id = %org, user_id = %user, by = %ctx.user_id, revoked, "org member removed");
    Ok(StatusCode::NO_CONTENT)
}

async fn invite(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(org): Path<Uuid>,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<InviteCreated>, ApiError> {
    let actor = require_member(&state, org, ctx.user_id).await?;
    orgs::check_invite(actor, req.role)?;
    let email = req
        .email
        .as_deref()
        .filter(|e| !e.trim().is_empty())
        .map(normalize_email)
        .transpose()?;
    let token = generate_token();
    let link = invite_link(&state.config().public_url, &token);
    let now = state.auth().now();
    let mailer = state.mailer();
    let mailed = email.is_some() && mailer.enabled();
    let inv = NewInvite {
        id: Uuid::now_v7(),
        org_id: org,
        email: email.clone(),
        role: req.role,
        token_hash: hash_token(&token),
        created_by: ctx.user_id,
        expires_at: now + Duration::days(INVITE_TTL_DAYS),
        mailed,
    };
    state.orgs().create_invite(&inv, now).await?;
    let mut emailed = false;
    if let (true, Some(to)) = (mailed, &email) {
        let org_name = state
            .orgs()
            .list_orgs(ctx.user_id)
            .await?
            .into_iter()
            .find(|o| o.id == org)
            .map(|o| o.name)
            .unwrap_or_default();
        match mailer.org_invite(to, &org_name, &link).await {
            Ok(()) => emailed = true,
            // The invite exists: hand the link to the inviter instead.
            Err(e) => tracing::warn!(error = %e, invite = %inv.id, "invite mail failed"),
        }
    }
    Ok(Json(InviteCreated {
        id: inv.id,
        org_id: org,
        email,
        role: inv.role,
        expires_at: inv.expires_at,
        link: (!emailed).then_some(link),
        emailed,
    }))
}

async fn accept(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(token): Path<String>,
) -> Result<Json<InviteAccepted>, ApiError> {
    let user = state
        .auth()
        .store()
        .user_by_id(ctx.user_id)
        .await?
        .ok_or_else(|| ApiError::AuthRequired("unknown account".into()))?;
    let now = state.auth().now();
    let (org_id, role) = state
        .orgs()
        .accept_invite(hash_token(&token), ctx.user_id, &user.email, now)
        .await?;
    tracing::info!(user_id = %ctx.user_id, %org_id, "org invite accepted");
    Ok(Json(InviteAccepted { org_id, role }))
}

async fn audit(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(org): Path<Uuid>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditPage>, ApiError> {
    let actor = require_member(&state, org, ctx.user_id).await?;
    orgs::check_audit(actor)?;
    let limit = q.limit.unwrap_or(50).clamp(1, MAX_AUDIT_PAGE);
    let rows = state.orgs().audit_page(org, q.before, limit + 1).await?;
    let more = rows.len() > limit as usize;
    let events: Vec<AuditEventView> = rows
        .into_iter()
        .take(limit as usize)
        .map(|a| AuditEventView {
            id: a.id,
            kind: a.kind,
            actor: a.actor,
            target: a.target,
            at: a.at,
            meta: a.meta,
        })
        .collect();
    let next_before = if more {
        events.last().map(|e| e.id)
    } else {
        None
    };
    Ok(Json(AuditPage {
        events,
        next_before,
    }))
}

/// `GET /v1/users/{id}/public-keys`: only for users sharing an org with the caller
/// (or the caller); anyone else is `404` (§13.3).
async fn public_keys(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(user): Path<Uuid>,
) -> Result<Json<UserPublicKeys>, ApiError> {
    let not_found = || ApiError::NotFound("no such user".into());
    if !state.orgs().share_an_org(ctx.user_id, user).await? {
        return Err(not_found());
    }
    let store = state.auth().store();
    let keys = store.account_keys(user).await?.ok_or_else(not_found)?;
    let email = store.user_by_id(user).await?.map(|u| u.email);
    Ok(Json(UserPublicKeys {
        user_id: user,
        email,
        x25519_pub: keys.x25519_pub,
        ed25519_pub: keys.ed25519_pub,
    }))
}
