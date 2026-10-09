//! Vault key rotation on the server (SPEC §13.2 steps 1–5, §10.3
//! `vaults.rotation` / `items_rotation_staging`; DTOs in
//! [`sverb_proto::rotation`]).
//!
//! The server never sees a vault key: the rotating client re-encrypts every
//! item under VK′ and uploads the envelopes; the server only checks that the
//! swap is complete and applies it atomically.
//!
//! * **begin**: the caller manages the vault (explicit `manage` or org
//!   owner/admin); `new_key_version == key_version + 1`; no other rotation is
//!   active, or the active one is abandoned (its staging is discarded). The
//!   same client (user **and** device) calling `begin` again resumes its
//!   rotation. Sets `rotation = {by, device, new_key_version, started_at}`
//!   under the vault row lock, so a push that is mid-transaction commits
//!   first and every later push gets `409 rotating`.
//! * **upload**: the rotating client stages chunks (upsert by id) of items
//!   that exist in `items`.
//! * **commit**, one transaction under the vault row lock: staging must cover
//!   every item of the vault (else `400` with the missing count and nothing
//!   changes); the staged envelopes replace the items with fresh, gap-free
//!   revisions `head+1 ..= head+n` (in the old revision order, §12.1); the
//!   grants are replaced by one row per remaining member at the new key
//!   version (every user that held a grant must get one; org owners/admins may
//!   get one; nobody else); `key_version` moves on; `rotation` and the
//!   staging are cleared. The route then notifies `vault_changed` and
//!   `vault_access rotated`.
//! * **abandonment**: [`ROTATION_ABANDON_SECS`] after `started_at`
//!   ([`is_abandoned`]); `GET /v1/vaults` reports it ([`mark_abandoned`]) and
//!   [`SyncStore::discard_abandoned_rotations`] (`admin gc`) clears it.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::{PgConnection, PgPool};
use sverb_proto::orgs::Role;
use sverb_proto::rotation::{
    MAX_ROTATION_CHUNK, ROTATION_ABANDON_SECS, RotateResponse, RotatedItem, RotationGrant,
};
use sverb_proto::sync::{MAX_BATCH_BYTES, MAX_ENVELOPE_BYTES, Permission, VaultView};
use uuid::Uuid;

use super::shared::{
    can_manage, check_grant_bytes, kv_to_db, mem_shared, mem_visible, pg_perm, pg_role,
};
use super::{Res, SyncStore, kv_to_wire, rev_to_wire, vault_not_found};
use crate::auth::store::AccessCtx;
use crate::auth::store::mem::{MemData, MemMember};
use crate::error::ApiError;

// ------------------------------------------------------------------- state

/// `vaults.rotation` (§13.2: `{by, new_key_version, started_at}`, plus the
/// rotating device so only that client resumes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationState {
    /// The rotating user.
    pub by: Uuid,
    /// Their device (`None` for rows written without it).
    pub device: Option<Uuid>,
    /// The key version being rotated to.
    pub new_key_version: i32,
    /// When `begin` ran.
    pub started_at: DateTime<Utc>,
}

impl RotationState {
    /// Parses the JSON column (`None` when malformed).
    #[must_use]
    pub fn parse(v: &serde_json::Value) -> Option<Self> {
        let by = v.get("by")?.as_str()?.parse().ok()?;
        let device = v
            .get("device")
            .and_then(serde_json::Value::as_str)
            .and_then(|d| d.parse().ok());
        let new_key_version = i32::try_from(v.get("new_key_version")?.as_i64()?).ok()?;
        let started_at = DateTime::parse_from_rfc3339(v.get("started_at")?.as_str()?)
            .ok()?
            .with_timezone(&Utc);
        Some(Self {
            by,
            device,
            new_key_version,
            started_at,
        })
    }

    /// The JSON column.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "by": self.by,
            "device": self.device,
            "new_key_version": self.new_key_version,
            "started_at": self.started_at.to_rfc3339(),
        })
    }

    /// Whether `ctx` is the client running this rotation.
    #[must_use]
    pub fn is_run_by(&self, ctx: AccessCtx) -> bool {
        self.by == ctx.user_id && self.device.is_none_or(|d| d == ctx.device_id)
    }
}

/// Whether a rotation started at `started_at` is abandoned at `now` (§13.2:
/// 15 minutes).
#[must_use]
pub fn is_abandoned(started_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(started_at).num_seconds() >= ROTATION_ABANDON_SECS
}

/// Sets [`sverb_proto::sync::RotationView::abandoned`] in a vault listing.
pub fn mark_abandoned(views: &mut [VaultView], now: DateTime<Utc>) {
    for r in views.iter_mut().filter_map(|v| v.rotation.as_mut()) {
        r.abandoned = r
            .started_at
            .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0))
            .is_some_and(|s| is_abandoned(s, now));
    }
}

/// A malformed `rotation` column counts as abandoned (so it can be cleared).
fn parse_or_abandoned(v: &serde_json::Value) -> RotationState {
    RotationState::parse(v).unwrap_or(RotationState {
        by: Uuid::nil(),
        device: None,
        new_key_version: 0,
        started_at: DateTime::<Utc>::UNIX_EPOCH,
    })
}

// ------------------------------------------------------------------- rules

/// What `begin` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginDecision {
    /// No rotation is running: start one.
    Start,
    /// The caller's own rotation: keep it (and its staging).
    Resume,
    /// Someone else's abandoned rotation: discard its staging, start anew.
    ReplaceAbandoned,
}

/// The `begin` rules (shared by both backends).
///
/// # Errors
/// `Invalid` (not current + 1), `Rotating` (another client's active
/// rotation).
pub fn decide_begin(
    key_version: i32,
    rotation: Option<&serde_json::Value>,
    ctx: AccessCtx,
    new_key_version: u32,
    now: DateTime<Utc>,
) -> Res<BeginDecision> {
    let nkv = kv_to_db(new_key_version)?;
    if Some(nkv) != key_version.checked_add(1) {
        return Err(ApiError::Invalid(format!(
            "new_key_version must be {} (the vault is at key version {key_version})",
            i64::from(key_version) + 1
        )));
    }
    let Some(r) = rotation else {
        return Ok(BeginDecision::Start);
    };
    let state = parse_or_abandoned(r);
    if state.is_run_by(ctx) && state.new_key_version == nkv {
        return Ok(BeginDecision::Resume);
    }
    if is_abandoned(state.started_at, now) || state.new_key_version != nkv {
        return Ok(BeginDecision::ReplaceAbandoned);
    }
    Err(ApiError::Rotating(
        "another client is rotating this vault's key; retry after it finishes or after 15 \
         minutes without progress"
            .into(),
    ))
}

/// The running rotation, checked to belong to `ctx`.
fn own_rotation(rotation: Option<&serde_json::Value>, ctx: AccessCtx) -> Res<RotationState> {
    let r = rotation.ok_or_else(|| ApiError::Invalid("no key rotation is running".into()))?;
    let state = parse_or_abandoned(r);
    if !state.is_run_by(ctx) {
        return Err(ApiError::Rotating(
            "the key rotation is run by another client".into(),
        ));
    }
    Ok(state)
}

/// Shape checks of an upload chunk.
///
/// # Errors
/// `Invalid`.
pub fn validate_upload(items: &[RotatedItem]) -> Res<()> {
    if items.len() > MAX_ROTATION_CHUNK {
        return Err(ApiError::Invalid(format!(
            "too many items in one upload: {} (max {MAX_ROTATION_CHUNK})",
            items.len()
        )));
    }
    let total: usize = items.iter().map(|i| i.envelope.len()).sum();
    if total > MAX_BATCH_BYTES {
        return Err(ApiError::Invalid(format!(
            "upload too large: {total} envelope bytes (max {MAX_BATCH_BYTES})"
        )));
    }
    let mut seen = HashSet::with_capacity(items.len());
    for i in items {
        if !seen.insert(i.id) {
            return Err(ApiError::Invalid(format!(
                "item {} appears more than once in the upload",
                i.id
            )));
        }
        if i.envelope.is_empty() || i.envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(ApiError::Invalid(format!(
                "the envelope of item {} is empty or exceeds 1 MiB",
                i.id
            )));
        }
    }
    Ok(())
}

/// One grant row to insert at commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// Member.
    pub user: Uuid,
    /// Their permission (kept from their newest grant; `manage` for org
    /// admins without one).
    pub permission: Permission,
    /// Wrapped VK′.
    pub wrapped: Vec<u8>,
    /// Committer's signature.
    pub signature: Vec<u8>,
}

/// The commit plan (shared by both backends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPlan {
    /// Item ids in their new revision order (old revision ascending); item
    /// `k` (0-based) gets `head + 1 + k`.
    pub order: Vec<Uuid>,
    /// The new head revision.
    pub new_head: i64,
    /// The grants at the new key version.
    pub grants: Vec<NewGrant>,
}

/// The commit rules.
///
/// * `items`: `(id, revision)` of every item of the vault;
/// * `staged`: staged id → key version;
/// * `members`: every user holding a grant → their newest permission;
/// * `admins`: the org's owners and admins.
///
/// # Errors
/// `Invalid`: incomplete staging (with the missing count), a staged item
/// under another key version, wrapped keys missing a member (or the
/// committer), naming a non-member, duplicated, or malformed.
#[allow(clippy::too_many_arguments)]
pub fn plan_commit(
    items: &[(Uuid, i64)],
    staged: &HashMap<Uuid, i32>,
    new_key_version: i32,
    head: i64,
    members: &BTreeMap<Uuid, Permission>,
    admins: &HashSet<Uuid>,
    committer: Uuid,
    wrapped_keys: &[RotationGrant],
) -> Res<CommitPlan> {
    let missing = items
        .iter()
        .filter(|(id, _)| staged.get(id) != Some(&new_key_version))
        .count();
    if missing > 0 {
        return Err(ApiError::Invalid(format!(
            "rotation staging is incomplete: {missing} of {} items missing; upload them before \
             committing",
            items.len()
        )));
    }
    let mut seen = HashSet::new();
    let mut grants = Vec::with_capacity(wrapped_keys.len());
    for g in wrapped_keys {
        if !seen.insert(g.user) {
            return Err(ApiError::Invalid(format!(
                "user {} has more than one wrapped key",
                g.user
            )));
        }
        check_grant_bytes(&g.wrapped, &g.signature)?;
        let permission = match members.get(&g.user) {
            Some(p) => *p,
            None if admins.contains(&g.user) => Permission::Manage,
            None => {
                return Err(ApiError::Invalid(format!(
                    "user {} is not a member of this vault",
                    g.user
                )));
            }
        };
        grants.push(NewGrant {
            user: g.user,
            permission,
            wrapped: g.wrapped.clone(),
            signature: g.signature.clone(),
        });
    }
    let without = members.keys().filter(|u| !seen.contains(u)).count();
    if without > 0 {
        return Err(ApiError::Invalid(format!(
            "wrapped keys are missing for {without} remaining member(s)"
        )));
    }
    if !seen.contains(&committer) {
        return Err(ApiError::Invalid(
            "the committer's own wrapped key is missing".into(),
        ));
    }
    let mut sorted: Vec<(Uuid, i64)> = items.to_vec();
    sorted.sort_by_key(|(id, rev)| (*rev, *id));
    let n = i64::try_from(sorted.len()).unwrap_or(i64::MAX);
    Ok(CommitPlan {
        order: sorted.into_iter().map(|(id, _)| id).collect(),
        new_head: head.saturating_add(n),
        grants,
    })
}

/// What a commit did (for the route's audit row and notifications).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    /// The response.
    pub response: RotateResponse,
    /// The vault's org.
    pub org_id: Option<Uuid>,
    /// Items rotated.
    pub items: u64,
}

fn response(kv: i32, nkv: i32, head: i64, staged: usize) -> RotateResponse {
    RotateResponse {
        key_version: kv_to_wire(kv),
        new_key_version: kv_to_wire(nkv),
        head_revision: rev_to_wire(head),
        staged: staged as u64,
        resumed: false,
        replaced_abandoned: false,
    }
}

// ------------------------------------------------------------ in-memory model

fn mem_manage(d: &MemData, vault: Uuid, user: Uuid) -> Res<Uuid> {
    let (_, org) = mem_shared(d, vault)?;
    let (role, perm) = mem_visible(d, vault, org, user)?;
    if !can_manage(role, perm) {
        return Err(ApiError::Forbidden(
            "only members with manage rotate a vault key".into(),
        ));
    }
    Ok(org)
}

fn mem_staged_count(d: &MemData, vault: Uuid) -> usize {
    d.rotation_staging
        .range((vault, Uuid::nil())..=(vault, Uuid::max()))
        .count()
}

fn mem_clear_staging(d: &mut MemData, vault: Uuid) {
    d.rotation_staging.retain(|(v, _), _| *v != vault);
}

fn mem_begin(
    d: &mut MemData,
    vault: Uuid,
    ctx: AccessCtx,
    nkv: u32,
    now: DateTime<Utc>,
) -> Res<RotateResponse> {
    mem_manage(d, vault, ctx.user_id)?;
    let v = d.vaults.get(&vault).ok_or_else(vault_not_found)?.clone();
    let decision = decide_begin(v.key_version, v.rotation.as_ref(), ctx, nkv, now)?;
    let nkv = kv_to_db(nkv)?;
    if decision != BeginDecision::Resume {
        mem_clear_staging(d, vault);
        let state = RotationState {
            by: ctx.user_id,
            device: Some(ctx.device_id),
            new_key_version: nkv,
            started_at: now,
        };
        if let Some(v) = d.vaults.get_mut(&vault) {
            v.rotation = Some(state.to_json());
        }
    }
    let mut r = response(
        v.key_version,
        nkv,
        v.head_revision,
        mem_staged_count(d, vault),
    );
    r.resumed = decision == BeginDecision::Resume;
    r.replaced_abandoned = decision == BeginDecision::ReplaceAbandoned;
    Ok(r)
}

fn mem_upload(
    d: &mut MemData,
    vault: Uuid,
    ctx: AccessCtx,
    items: &[RotatedItem],
) -> Res<RotateResponse> {
    mem_manage(d, vault, ctx.user_id)?;
    let v = d.vaults.get(&vault).ok_or_else(vault_not_found)?.clone();
    let state = own_rotation(v.rotation.as_ref(), ctx)?;
    if let Some(i) = items.iter().find(|i| !d.items.contains_key(&(vault, i.id))) {
        return Err(ApiError::Invalid(format!(
            "item {} is not in this vault",
            i.id
        )));
    }
    for i in items {
        d.rotation_staging
            .insert((vault, i.id), (state.new_key_version, i.envelope.clone()));
    }
    Ok(response(
        v.key_version,
        state.new_key_version,
        v.head_revision,
        mem_staged_count(d, vault),
    ))
}

fn mem_commit(
    d: &mut MemData,
    vault: Uuid,
    ctx: AccessCtx,
    wrapped_keys: &[RotationGrant],
    now: DateTime<Utc>,
) -> Res<Committed> {
    let org = mem_manage(d, vault, ctx.user_id)?;
    let v = d.vaults.get(&vault).ok_or_else(vault_not_found)?.clone();
    let state = own_rotation(v.rotation.as_ref(), ctx)?;
    let nkv = state.new_key_version;
    let items: Vec<(Uuid, i64)> = d
        .items
        .range((vault, Uuid::nil())..=(vault, Uuid::max()))
        .map(|((_, id), i)| (*id, i.revision))
        .collect();
    let staged: HashMap<Uuid, i32> = d
        .rotation_staging
        .range((vault, Uuid::nil())..=(vault, Uuid::max()))
        .map(|((_, id), (kv, _))| (*id, *kv))
        .collect();
    let mut members: BTreeMap<Uuid, (i32, Permission)> = BTreeMap::new();
    for m in d.vault_members.iter().filter(|m| m.vault_id == vault) {
        let p = Permission::parse(&m.permission).unwrap_or(Permission::Read);
        let e = members.entry(m.user_id).or_insert((m.key_version, p));
        if m.key_version >= e.0 {
            *e = (m.key_version, p);
        }
    }
    let members: BTreeMap<Uuid, Permission> =
        members.into_iter().map(|(u, (_, p))| (u, p)).collect();
    let admins: HashSet<Uuid> = d
        .org_members
        .iter()
        .filter(|((o, _), r)| *o == org && **r >= Role::Admin)
        .map(|((_, u), _)| *u)
        .collect();
    let plan = plan_commit(
        &items,
        &staged,
        nkv,
        v.head_revision,
        &members,
        &admins,
        ctx.user_id,
        wrapped_keys,
    )?;
    // Apply (the whole closure is one atomic step of the model).
    for (k, id) in plan.order.iter().enumerate() {
        let Some((_, env)) = d.rotation_staging.remove(&(vault, *id)) else {
            continue;
        };
        if let Some(item) = d.items.get_mut(&(vault, *id)) {
            item.revision = v.head_revision + 1 + i64::try_from(k).unwrap_or(i64::MAX);
            item.key_version = nkv;
            item.envelope = env;
            item.updated_at = now;
            item.updated_by_device = Some(ctx.device_id);
        }
    }
    mem_clear_staging(d, vault);
    d.vault_members.retain(|m| m.vault_id != vault);
    for g in &plan.grants {
        d.vault_members.push(MemMember {
            vault_id: vault,
            user_id: g.user,
            permission: g.permission.as_str().to_owned(),
            key_version: nkv,
            wrapped_vault_key: g.wrapped.clone(),
            wrapped_by: ctx.user_id,
            signature: g.signature.clone(),
        });
    }
    if let Some(row) = d.vaults.get_mut(&vault) {
        row.key_version = nkv;
        row.head_revision = plan.new_head;
        row.rotation = None;
    }
    Ok(Committed {
        response: response(nkv, nkv, plan.new_head, 0),
        org_id: Some(org),
        items: plan.order.len() as u64,
    })
}

fn mem_discard_abandoned(d: &mut MemData, now: DateTime<Utc>) -> Vec<Uuid> {
    let stale: Vec<Uuid> = d
        .vaults
        .iter()
        .filter(|(_, v)| {
            v.rotation
                .as_ref()
                .is_some_and(|r| is_abandoned(parse_or_abandoned(r).started_at, now))
        })
        .map(|(id, _)| *id)
        .collect();
    for id in &stale {
        mem_clear_staging(d, *id);
        if let Some(v) = d.vaults.get_mut(id) {
            v.rotation = None;
        }
    }
    stale
}

// ------------------------------------------------------------------ PostgreSQL

/// `(org, key_version, head, rotation)` of a shared vault, row-locked.
async fn pg_locked(
    conn: &mut PgConnection,
    vault: Uuid,
) -> Res<(Uuid, i32, i64, Option<serde_json::Value>)> {
    let r: Option<(String, Option<Uuid>, i32, i64, Option<serde_json::Value>)> = query_as(
        "SELECT kind, org_id, key_version, head_revision, rotation FROM vaults \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(vault)
    .fetch_optional(&mut *conn)
    .await?;
    match r {
        Some((kind, Some(org), kv, head, rot)) if kind == "shared" => Ok((org, kv, head, rot)),
        _ => Err(vault_not_found()),
    }
}

async fn pg_manage(conn: &mut PgConnection, vault: Uuid, org: Uuid, user: Uuid) -> Res<()> {
    let role = pg_role(conn, org, user).await?;
    let perm = pg_perm(conn, vault, user).await?;
    if role.is_none() || (perm.is_none() && !can_manage(role, None)) {
        return Err(vault_not_found());
    }
    if !can_manage(role, perm) {
        return Err(ApiError::Forbidden(
            "only members with manage rotate a vault key".into(),
        ));
    }
    Ok(())
}

async fn pg_staged_count(conn: &mut PgConnection, vault: Uuid) -> Res<usize> {
    let (n,): (i64,) = query_as("SELECT count(*) FROM items_rotation_staging WHERE vault_id = $1")
        .bind(vault)
        .fetch_one(&mut *conn)
        .await?;
    Ok(usize::try_from(n).unwrap_or(0))
}

async fn pg_begin(
    pool: &PgPool,
    vault: Uuid,
    ctx: AccessCtx,
    nkv: u32,
    now: DateTime<Utc>,
) -> Res<RotateResponse> {
    let mut tx = pool.begin().await?;
    let (org, kv, head, rot) = pg_locked(&mut tx, vault).await?;
    pg_manage(&mut tx, vault, org, ctx.user_id).await?;
    let decision = decide_begin(kv, rot.as_ref(), ctx, nkv, now)?;
    let nkv = kv_to_db(nkv)?;
    if decision != BeginDecision::Resume {
        query("DELETE FROM items_rotation_staging WHERE vault_id = $1")
            .bind(vault)
            .execute(&mut *tx)
            .await?;
        let state = RotationState {
            by: ctx.user_id,
            device: Some(ctx.device_id),
            new_key_version: nkv,
            started_at: now,
        };
        query("UPDATE vaults SET rotation = $2 WHERE id = $1")
            .bind(vault)
            .bind(state.to_json())
            .execute(&mut *tx)
            .await?;
    }
    let staged = pg_staged_count(&mut tx, vault).await?;
    tx.commit().await?;
    let mut r = response(kv, nkv, head, staged);
    r.resumed = decision == BeginDecision::Resume;
    r.replaced_abandoned = decision == BeginDecision::ReplaceAbandoned;
    Ok(r)
}

async fn pg_upload(
    pool: &PgPool,
    vault: Uuid,
    ctx: AccessCtx,
    items: &[RotatedItem],
) -> Res<RotateResponse> {
    let mut tx = pool.begin().await?;
    // A shared lock is enough: it only has to exclude a concurrent commit or
    // re-begin, which take the row FOR UPDATE.
    let r: Option<(String, Option<Uuid>, i32, i64, Option<serde_json::Value>)> = query_as(
        "SELECT kind, org_id, key_version, head_revision, rotation FROM vaults \
         WHERE id = $1 FOR SHARE",
    )
    .bind(vault)
    .fetch_optional(&mut *tx)
    .await?;
    let (org, kv, head, rot) = match r {
        Some((kind, Some(org), kv, head, rot)) if kind == "shared" => (org, kv, head, rot),
        _ => return Err(vault_not_found()),
    };
    pg_manage(&mut tx, vault, org, ctx.user_id).await?;
    let state = own_rotation(rot.as_ref(), ctx)?;
    let ids: Vec<Uuid> = items.iter().map(|i| i.id).collect();
    let (known,): (i64,) =
        query_as("SELECT count(*) FROM items WHERE vault_id = $1 AND id = ANY($2)")
            .bind(vault)
            .bind(&ids)
            .fetch_one(&mut *tx)
            .await?;
    if usize::try_from(known).unwrap_or(0) != ids.len() {
        return Err(ApiError::Invalid(
            "the upload names items that are not in this vault".into(),
        ));
    }
    for i in items {
        query(
            "INSERT INTO items_rotation_staging (vault_id, id, key_version, envelope) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (vault_id, id) DO UPDATE SET \
             key_version = EXCLUDED.key_version, envelope = EXCLUDED.envelope",
        )
        .bind(vault)
        .bind(i.id)
        .bind(state.new_key_version)
        .bind(&i.envelope)
        .execute(&mut *tx)
        .await?;
    }
    let staged = pg_staged_count(&mut tx, vault).await?;
    tx.commit().await?;
    Ok(response(kv, state.new_key_version, head, staged))
}

async fn pg_commit(
    pool: &PgPool,
    vault: Uuid,
    ctx: AccessCtx,
    wrapped_keys: &[RotationGrant],
    now: DateTime<Utc>,
) -> Res<Committed> {
    let mut tx = pool.begin().await?;
    let (org, _kv, head, rot) = pg_locked(&mut tx, vault).await?;
    pg_manage(&mut tx, vault, org, ctx.user_id).await?;
    let state = own_rotation(rot.as_ref(), ctx)?;
    let nkv = state.new_key_version;
    let items: Vec<(Uuid, i64)> =
        query_as("SELECT id, revision FROM items WHERE vault_id = $1 ORDER BY revision FOR UPDATE")
            .bind(vault)
            .fetch_all(&mut *tx)
            .await?;
    let staged: Vec<(Uuid, Option<i32>)> =
        query_as("SELECT id, key_version FROM items_rotation_staging WHERE vault_id = $1")
            .bind(vault)
            .fetch_all(&mut *tx)
            .await?;
    let staged: HashMap<Uuid, i32> = staged
        .into_iter()
        .filter_map(|(id, kv)| kv.map(|kv| (id, kv)))
        .collect();
    let rows: Vec<(Uuid, Option<String>, i32)> = query_as(
        "SELECT user_id, permission, key_version FROM vault_members WHERE vault_id = $1 \
         ORDER BY key_version",
    )
    .bind(vault)
    .fetch_all(&mut *tx)
    .await?;
    let mut members = BTreeMap::new();
    for (user, perm, _) in rows {
        members.insert(user, super::push::parse_permission(perm.as_deref())?);
    }
    let admins: Vec<(Uuid,)> = query_as(
        "SELECT user_id FROM org_members WHERE org_id = $1 AND role IN ('owner', 'admin')",
    )
    .bind(org)
    .fetch_all(&mut *tx)
    .await?;
    let admins: HashSet<Uuid> = admins.into_iter().map(|(u,)| u).collect();
    let plan = plan_commit(
        &items,
        &staged,
        nkv,
        head,
        &members,
        &admins,
        ctx.user_id,
        wrapped_keys,
    )?;
    // §12.1: take the revisions with the vault row lock held.
    let n = i64::try_from(plan.order.len()).unwrap_or(i64::MAX);
    let (new_head,): (i64,) = query_as(
        "UPDATE vaults SET head_revision = head_revision + $2, key_version = $3, rotation = NULL \
         WHERE id = $1 RETURNING head_revision",
    )
    .bind(vault)
    .bind(n)
    .bind(nkv)
    .fetch_one(&mut *tx)
    .await?;
    query(
        "UPDATE items i SET envelope = s.envelope, key_version = $2, \
                revision = $3 + o.ord, updated_at = $4, updated_by_device = $5 \
         FROM items_rotation_staging s, \
              unnest($6::uuid[]) WITH ORDINALITY AS o(id, ord) \
         WHERE i.vault_id = $1 AND s.vault_id = $1 AND s.id = i.id AND o.id = i.id",
    )
    .bind(vault)
    .bind(nkv)
    .bind(head)
    .bind(now)
    .bind(ctx.device_id)
    .bind(&plan.order)
    .execute(&mut *tx)
    .await?;
    query("DELETE FROM items_rotation_staging WHERE vault_id = $1")
        .bind(vault)
        .execute(&mut *tx)
        .await?;
    query("DELETE FROM vault_members WHERE vault_id = $1")
        .bind(vault)
        .execute(&mut *tx)
        .await?;
    for g in &plan.grants {
        query(
            "INSERT INTO vault_members \
             (vault_id, user_id, permission, key_version, wrapped_vault_key, wrapped_by, signature) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(vault)
        .bind(g.user)
        .bind(g.permission.as_str())
        .bind(nkv)
        .bind(&g.wrapped)
        .bind(ctx.user_id)
        .bind(&g.signature)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Committed {
        response: response(nkv, nkv, new_head, 0),
        org_id: Some(org),
        items: plan.order.len() as u64,
    })
}

/// `admin gc`: clears the abandoned rotations and their staging. Returns the
/// affected vaults.
///
/// # Errors
/// Database errors.
pub async fn pg_discard_abandoned(pool: &PgPool, now: DateTime<Utc>) -> Res<Vec<Uuid>> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(Uuid, Option<serde_json::Value>)> =
        query_as("SELECT id, rotation FROM vaults WHERE rotation IS NOT NULL FOR UPDATE")
            .fetch_all(&mut *tx)
            .await?;
    let stale: Vec<Uuid> = rows
        .into_iter()
        .filter(|(_, r)| {
            r.as_ref()
                .is_none_or(|r| is_abandoned(parse_or_abandoned(r).started_at, now))
        })
        .map(|(id, _)| id)
        .collect();
    if !stale.is_empty() {
        query("DELETE FROM items_rotation_staging WHERE vault_id = ANY($1)")
            .bind(&stale)
            .execute(&mut *tx)
            .await?;
        query("UPDATE vaults SET rotation = NULL WHERE id = ANY($1)")
            .bind(&stale)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(stale)
}

// ------------------------------------------------------------------- dispatch

impl SyncStore {
    /// `begin` (§13.2 step 1).
    ///
    /// # Errors
    /// `404`, `403`, `400` (key version), `409 rotating` (active elsewhere).
    pub async fn rotation_begin(
        &self,
        vault: Uuid,
        ctx: AccessCtx,
        new_key_version: u32,
        now: DateTime<Utc>,
    ) -> Res<RotateResponse> {
        match self {
            Self::Postgres(pool) => pg_begin(pool, vault, ctx, new_key_version, now).await,
            Self::Memory(m) => {
                // The vault row lock: a push mid-transaction commits first.
                let lock = m.row_lock(vault);
                let _row = lock.lock().await;
                m.db()
                    .with_data(|d| mem_begin(d, vault, ctx, new_key_version, now))
            }
        }
    }

    /// `upload` (§13.2 step 3): stages a validated chunk.
    ///
    /// # Errors
    /// `404`, `403`, `400` (no rotation, unknown item, shape), `409 rotating`
    /// (another client's rotation).
    pub async fn rotation_upload(
        &self,
        vault: Uuid,
        ctx: AccessCtx,
        items: &[RotatedItem],
    ) -> Res<RotateResponse> {
        validate_upload(items)?;
        match self {
            Self::Postgres(pool) => pg_upload(pool, vault, ctx, items).await,
            Self::Memory(m) => m.db().with_data(|d| mem_upload(d, vault, ctx, items)),
        }
    }

    /// `commit` (§13.2 step 4), all or nothing.
    ///
    /// # Errors
    /// `404`, `403`, `400` ([`plan_commit`]), `409 rotating`.
    pub async fn rotation_commit(
        &self,
        vault: Uuid,
        ctx: AccessCtx,
        wrapped_keys: &[RotationGrant],
        now: DateTime<Utc>,
    ) -> Res<Committed> {
        match self {
            Self::Postgres(pool) => pg_commit(pool, vault, ctx, wrapped_keys, now).await,
            Self::Memory(m) => {
                let lock = m.row_lock(vault);
                let _row = lock.lock().await;
                m.db()
                    .with_data(|d| mem_commit(d, vault, ctx, wrapped_keys, now))
            }
        }
    }

    /// Clears every abandoned rotation and its staging (§13.2 step 5, `admin
    /// gc`). Returns the affected vaults.
    ///
    /// # Errors
    /// Database errors.
    pub async fn discard_abandoned_rotations(&self, now: DateTime<Utc>) -> Res<Vec<Uuid>> {
        match self {
            Self::Postgres(pool) => pg_discard_abandoned(pool, now).await,
            Self::Memory(m) => Ok(m.db().with_data(|d| mem_discard_abandoned(d, now))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn ctx(u: u128, d: u128) -> AccessCtx {
        AccessCtx {
            user_id: Uuid::from_u128(u),
            device_id: Uuid::from_u128(d),
        }
    }

    fn running(by: AccessCtx, at: DateTime<Utc>) -> serde_json::Value {
        RotationState {
            by: by.user_id,
            device: Some(by.device_id),
            new_key_version: 2,
            started_at: at,
        }
        .to_json()
    }

    #[test]
    fn begin_rules() {
        let now = Utc::now();
        let alice = ctx(1, 10);
        let r = running(alice, now);
        assert!(matches!(
            decide_begin(1, None, alice, 3, now),
            Err(ApiError::Invalid(_))
        ));
        assert_eq!(
            decide_begin(1, None, alice, 2, now).unwrap(),
            BeginDecision::Start
        );
        assert_eq!(
            decide_begin(1, Some(&r), alice, 2, now).unwrap(),
            BeginDecision::Resume
        );
        // Alice's other device and another user wait while it is active…
        assert!(matches!(
            decide_begin(1, Some(&r), ctx(1, 11), 2, now),
            Err(ApiError::Rotating(_))
        ));
        let later = now + Duration::minutes(14);
        assert!(matches!(
            decide_begin(1, Some(&r), ctx(2, 20), 2, later),
            Err(ApiError::Rotating(_))
        ));
        // …and take over once it is abandoned.
        let later = now + Duration::minutes(15);
        assert_eq!(
            decide_begin(1, Some(&r), ctx(2, 20), 2, later).unwrap(),
            BeginDecision::ReplaceAbandoned
        );
        assert_eq!(
            RotationState::parse(&r).unwrap().started_at.timestamp(),
            now.timestamp()
        );
    }

    #[test]
    fn commit_rules() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let i1 = Uuid::from_u128(100);
        let i2 = Uuid::from_u128(101);
        let items = vec![(i2, 5), (i1, 3)];
        let members = BTreeMap::from([(a, Permission::Manage), (b, Permission::Write)]);
        let admins = HashSet::from([c]);
        let g = |user| RotationGrant {
            user,
            wrapped: vec![1; 80],
            signature: vec![2; 64],
        };
        let staged = HashMap::from([(i1, 2)]);
        let err = plan_commit(&items, &staged, 2, 5, &members, &admins, a, &[g(a), g(b)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 of 2 items missing"), "{err}");
        let staged = HashMap::from([(i1, 2), (i2, 2)]);
        assert!(plan_commit(&items, &staged, 2, 5, &members, &admins, a, &[g(a)]).is_err());
        assert!(
            plan_commit(
                &items,
                &staged,
                2,
                5,
                &members,
                &admins,
                a,
                &[g(a), g(b), g(Uuid::from_u128(9))]
            )
            .is_err()
        );
        let p = plan_commit(
            &items,
            &staged,
            2,
            5,
            &members,
            &admins,
            a,
            &[g(a), g(b), g(c)],
        )
        .unwrap();
        assert_eq!(p.order, vec![i1, i2]);
        assert_eq!(p.new_head, 7);
        assert_eq!(p.grants[2].permission, Permission::Manage);
    }
}
