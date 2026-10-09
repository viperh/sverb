//! M5-02: shared vaults (SPEC §13.1, §13.2): creation, grants, revocation and
//! the membership listings, on both backends.
//!
//! The rules (checked under the same lock / in the same transaction as the
//! change):
//! * **create**: the caller is an org `admin` or `owner`; the vault starts with
//!   the caller's self-grant at permission `manage`;
//! * **grant** (`PUT …/members/{user}`): the granter has `manage` on the vault
//!   (an explicit grant) or is an org owner/admin (implicit `manage`, §13.1); the
//!   target is a member of the vault's org; the grant wraps the vault's
//!   **current** key version; no rotation is running;
//! * **revoke** (`DELETE …/members/{user}`): a `manage` member or org admin, or
//!   the member leaving; every key version's row goes (the revoking client then
//!   rotates the vault key, M5-04 [`super::rotation`]);
//! * **visibility**: a vault the caller has no grant on and no implicit
//!   `manage` for is `404` (its existence is not revealed).
//!
//! The server only stores what the client signed; it never sees a vault key.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::{PgConnection, PgPool};
use sverb_proto::auth::GrantUpload;
use sverb_proto::orgs::Role;
use sverb_proto::sync::{Permission, VaultKind, VaultView};
use sverb_proto::vaults::{
    GrantRequest, MAX_NAME_ENC_BYTES, OrgVaultView, VaultMemberView, VaultMembersView,
};
use uuid::Uuid;

use super::vaults::{MembershipRow, build_views};
use super::{Res, SyncStore, kv_to_wire, vault_not_found};
use crate::auth::store::mem::{MemData, MemMember, MemVault};
use crate::error::ApiError;

/// Audit event kinds of shared vaults (§13.5; metadata only).
pub mod kinds {
    /// A shared vault was created (target: the vault).
    pub const VAULT_CREATED: &str = "vault.created";
    /// A member was granted access or their permission changed (target: the
    /// user; meta: vault, permission).
    pub const VAULT_GRANTED: &str = "vault.member_granted";
    /// A member's access was revoked (target: the user; meta: vault).
    pub const VAULT_REVOKED: &str = "vault.member_revoked";
    // M5-04
    /// The vault key was rotated (target: the vault; meta: key version, item
    /// count).
    pub const VAULT_ROTATED: &str = "vault.rotated";
    /// Items of a shared vault were pushed (target: the vault; meta: item ids
    /// only, never content).
    pub const ITEMS_PUSHED: &str = "vault.items_pushed";
}

/// Ed25519 signature length.
const SIGNATURE_LEN: usize = 64;

/// A shared vault to create.
#[derive(Debug, Clone)]
pub struct NewSharedVault {
    /// Client-generated id.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Sealed name.
    pub name_enc: Vec<u8>,
    /// The creator.
    pub creator: Uuid,
    /// The creator's self-grant.
    pub grant: GrantUpload,
}

/// What a revoke did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    /// The vault's org (for the audit row).
    pub org_id: Uuid,
    /// Grant rows removed.
    pub rows: u64,
}

fn forbidden(what: &str) -> ApiError {
    ApiError::Forbidden(format!("you can't {what} on this vault"))
}

pub(super) fn check_grant_bytes(wrapped: &[u8], signature: &[u8]) -> Res<()> {
    if wrapped.is_empty() || wrapped.len() > 1024 {
        return Err(ApiError::Invalid("malformed wrapped vault key".into()));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(ApiError::Invalid("a grant signature has 64 bytes".into()));
    }
    Ok(())
}

/// Validates a create request (shape only; roles are checked by the backend).
///
/// # Errors
/// [`ApiError::Invalid`].
pub fn validate_create(v: &NewSharedVault) -> Res<()> {
    if v.name_enc.is_empty() || v.name_enc.len() > MAX_NAME_ENC_BYTES {
        return Err(ApiError::Invalid("malformed encrypted vault name".into()));
    }
    if v.grant.key_version == 0 || i32::try_from(v.grant.key_version).is_err() {
        return Err(ApiError::Invalid("key versions start at 1".into()));
    }
    check_grant_bytes(&v.grant.wrapped_vault_key, &v.grant.signature)
}

/// May someone with org role `role` and explicit permission `perm` manage
/// (grant, revoke) the vault? (§13.1: owners and admins implicitly.)
#[must_use]
pub fn can_manage(role: Option<Role>, perm: Option<Permission>) -> bool {
    role.is_some_and(|r| r >= Role::Admin) || perm == Some(Permission::Manage)
}

pub(super) fn kv_to_db(kv: u32) -> Res<i32> {
    i32::try_from(kv).map_err(|_| ApiError::Invalid("key version out of range".into()))
}

// ------------------------------------------------------------- in-memory model

pub(super) fn mem_perm(d: &MemData, vault: Uuid, user: Uuid) -> Option<Permission> {
    d.vault_members
        .iter()
        .filter(|m| m.vault_id == vault && m.user_id == user)
        .max_by_key(|m| m.key_version)
        .and_then(|m| Permission::parse(&m.permission))
}

/// The shared vault `vault` with its org, or `404`.
pub(super) fn mem_shared(d: &MemData, vault: Uuid) -> Res<(MemVault, Uuid)> {
    let v = d.vaults.get(&vault).ok_or_else(vault_not_found)?;
    match (v.personal, v.org_id) {
        (false, Some(org)) => Ok((v.clone(), org)),
        _ => Err(vault_not_found()),
    }
}

/// The caller's (role, explicit permission) on `vault`; `404` when the vault
/// is invisible to them.
pub(super) fn mem_visible(
    d: &MemData,
    vault: Uuid,
    org: Uuid,
    user: Uuid,
) -> Res<(Option<Role>, Option<Permission>)> {
    let role = d.org_members.get(&(org, user)).copied();
    let perm = mem_perm(d, vault, user);
    if role.is_none() || (perm.is_none() && !can_manage(role, None)) {
        return Err(vault_not_found());
    }
    Ok((role, perm))
}

fn mem_view(d: &MemData, vault: Uuid, user: Uuid) -> Vec<VaultView> {
    let Some(v) = d.vaults.get(&vault) else {
        return Vec::new();
    };
    let rows = d
        .vault_members
        .iter()
        .filter(|m| m.vault_id == vault && m.user_id == user)
        .map(|m| MembershipRow {
            vault_id: vault,
            kind: VaultKind::Shared,
            org_id: v.org_id,
            name_enc: v.name_enc.clone(),
            key_version: v.key_version,
            head_revision: v.head_revision,
            rotation: v.rotation.clone(),
            permission: Permission::parse(&m.permission).unwrap_or(Permission::Read),
            grant_key_version: m.key_version,
            wrapped_vault_key: m.wrapped_vault_key.clone(),
            wrapped_by: m.wrapped_by,
            signature: m.signature.clone(),
        })
        .collect();
    build_views(rows)
}

fn mem_create(d: &mut MemData, v: &NewSharedVault) -> Res<VaultView> {
    let role = d
        .org_members
        .get(&(v.org_id, v.creator))
        .copied()
        .ok_or_else(|| ApiError::NotFound("no such org".into()))?;
    if role < Role::Admin {
        return Err(ApiError::Forbidden(
            "only org owners and admins create shared vaults".into(),
        ));
    }
    if d.vaults.contains_key(&v.id) {
        return Err(ApiError::Conflict("a vault with this id exists".into()));
    }
    let kv = kv_to_db(v.grant.key_version)?;
    d.vaults.insert(
        v.id,
        MemVault::shared(Some(v.org_id), v.name_enc.clone(), kv),
    );
    d.vault_members.push(MemMember {
        vault_id: v.id,
        user_id: v.creator,
        permission: Permission::Manage.as_str().to_owned(),
        key_version: kv,
        wrapped_vault_key: v.grant.wrapped_vault_key.clone(),
        wrapped_by: v.creator,
        signature: v.grant.signature.clone(),
    });
    mem_view(d, v.id, v.creator)
        .pop()
        .ok_or_else(|| ApiError::internal(std::io::Error::other("created vault vanished")))
}

fn mem_members(d: &MemData, vault: Uuid, caller: Uuid) -> Res<VaultMembersView> {
    let (v, org) = mem_shared(d, vault)?;
    mem_visible(d, vault, org, caller)?;
    let created_by = d
        .vault_members
        .iter()
        .filter(|m| m.vault_id == vault && m.wrapped_by == m.user_id)
        .min_by_key(|m| m.key_version)
        .map(|m| m.user_id);
    let mut members: Vec<VaultMemberView> = d
        .org_members
        .iter()
        .filter(|((o, _), _)| *o == org)
        .map(|((_, user), role)| {
            let rows: Vec<&MemMember> = d
                .vault_members
                .iter()
                .filter(|m| m.vault_id == vault && m.user_id == *user)
                .collect();
            let newest = rows.iter().max_by_key(|m| m.key_version);
            VaultMemberView {
                user_id: *user,
                email: d.users.get(user).map(|u| u.email.clone()),
                org_role: *role,
                permission: newest.and_then(|m| Permission::parse(&m.permission)),
                has_key: rows.iter().any(|m| m.key_version == v.key_version),
                granted_by: newest.map(|m| m.wrapped_by),
            }
        })
        .collect();
    sort_members(&mut members);
    Ok(VaultMembersView {
        vault_id: vault,
        org_id: org,
        key_version: kv_to_wire(v.key_version),
        created_by,
        members,
    })
}

fn sort_members(members: &mut [VaultMemberView]) {
    members.sort_by(|a, b| {
        let ea = a.email.as_deref().unwrap_or_default().to_lowercase();
        let eb = b.email.as_deref().unwrap_or_default().to_lowercase();
        ea.cmp(&eb).then(a.user_id.cmp(&b.user_id))
    });
}

fn mem_grant(
    d: &mut MemData,
    vault: Uuid,
    granter: Uuid,
    target: Uuid,
    req: &GrantRequest,
) -> Res<Uuid> {
    let (v, org) = mem_shared(d, vault)?;
    let (role, perm) = mem_visible(d, vault, org, granter)?;
    if !can_manage(role, perm) {
        return Err(forbidden("grant access"));
    }
    if !d.org_members.contains_key(&(org, target)) {
        return Err(ApiError::Invalid(
            "access can only be granted to members of the vault's org".into(),
        ));
    }
    if v.rotation.is_some() {
        return Err(ApiError::Rotating("a key rotation is in progress".into()));
    }
    let kv = kv_to_db(req.key_version)?;
    if kv != v.key_version {
        return Err(ApiError::Invalid(format!(
            "stale key version {} (the vault is at {})",
            req.key_version, v.key_version
        )));
    }
    check_grant_bytes(&req.wrapped_vault_key, &req.signature)?;
    d.vault_members
        .retain(|m| !(m.vault_id == vault && m.user_id == target && m.key_version == kv));
    for m in d
        .vault_members
        .iter_mut()
        .filter(|m| m.vault_id == vault && m.user_id == target)
    {
        req.permission.as_str().clone_into(&mut m.permission);
    }
    d.vault_members.push(MemMember {
        vault_id: vault,
        user_id: target,
        permission: req.permission.as_str().to_owned(),
        key_version: kv,
        wrapped_vault_key: req.wrapped_vault_key.clone(),
        wrapped_by: granter,
        signature: req.signature.clone(),
    });
    Ok(org)
}

fn mem_revoke(d: &mut MemData, vault: Uuid, actor: Uuid, target: Uuid) -> Res<Revoked> {
    let (_, org) = mem_shared(d, vault)?;
    let (role, perm) = mem_visible(d, vault, org, actor)?;
    if actor != target && !can_manage(role, perm) {
        return Err(forbidden("revoke access"));
    }
    let before = d.vault_members.len();
    d.vault_members
        .retain(|m| !(m.vault_id == vault && m.user_id == target));
    let rows = u64::try_from(before - d.vault_members.len()).unwrap_or(u64::MAX);
    if rows == 0 {
        return Err(ApiError::NotFound("no such vault member".into()));
    }
    Ok(Revoked { org_id: org, rows })
}

fn mem_org_vaults(d: &MemData, org: Uuid, user: Uuid) -> Res<Vec<OrgVaultView>> {
    let role = d
        .org_members
        .get(&(org, user))
        .copied()
        .ok_or_else(|| ApiError::NotFound("no such org".into()))?;
    let mut out = Vec::new();
    for (id, v) in d
        .vaults
        .iter()
        .filter(|(_, v)| !v.personal && v.org_id == Some(org))
    {
        let perm = mem_perm(d, *id, user);
        let effective = if role >= Role::Admin {
            Some(Permission::Manage)
        } else {
            perm
        };
        let Some(permission) = effective else {
            continue;
        };
        out.push(OrgVaultView {
            id: *id,
            name_enc: v.name_enc.clone(),
            key_version: kv_to_wire(v.key_version),
            permission,
            has_key: d
                .vault_members
                .iter()
                .any(|m| m.vault_id == *id && m.user_id == user && m.key_version == v.key_version),
        });
    }
    Ok(out)
}

// ------------------------------------------------------------------ PostgreSQL

pub(super) async fn pg_role(conn: &mut PgConnection, org: Uuid, user: Uuid) -> Res<Option<Role>> {
    let r: Option<(String,)> =
        query_as("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(r.and_then(|(r,)| Role::parse(&r)))
}

pub(super) async fn pg_perm(
    conn: &mut PgConnection,
    vault: Uuid,
    user: Uuid,
) -> Res<Option<Permission>> {
    let r: Option<(Option<String>,)> = query_as(
        "SELECT permission FROM vault_members WHERE vault_id = $1 AND user_id = $2 \
         ORDER BY key_version DESC LIMIT 1",
    )
    .bind(vault)
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(r.and_then(|(p,)| p.as_deref().and_then(Permission::parse)))
}

/// `(org, key_version, rotating)` of the shared vault, locked (`FOR UPDATE`).
async fn pg_shared_locked(conn: &mut PgConnection, vault: Uuid) -> Res<(Uuid, i32, bool)> {
    let r: Option<(String, Option<Uuid>, i32, bool)> = query_as(
        "SELECT kind, org_id, key_version, rotation IS NOT NULL FROM vaults WHERE id = $1 FOR UPDATE",
    )
    .bind(vault)
    .fetch_optional(&mut *conn)
    .await?;
    match r {
        Some((kind, Some(org), kv, rot)) if kind == "shared" => Ok((org, kv, rot)),
        _ => Err(vault_not_found()),
    }
}

pub(super) async fn pg_visible(
    conn: &mut PgConnection,
    vault: Uuid,
    org: Uuid,
    user: Uuid,
) -> Res<(Option<Role>, Option<Permission>)> {
    let role = pg_role(conn, org, user).await?;
    let perm = pg_perm(conn, vault, user).await?;
    if role.is_none() || (perm.is_none() && !can_manage(role, None)) {
        return Err(vault_not_found());
    }
    Ok((role, perm))
}

async fn pg_create(pool: &PgPool, v: &NewSharedVault) -> Res<VaultView> {
    let mut tx = pool.begin().await?;
    let role = pg_role(&mut tx, v.org_id, v.creator)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such org".into()))?;
    if role < Role::Admin {
        return Err(ApiError::Forbidden(
            "only org owners and admins create shared vaults".into(),
        ));
    }
    let kv = kv_to_db(v.grant.key_version)?;
    let inserted = query(
        "INSERT INTO vaults (id, kind, owner_user_id, org_id, key_version, name_enc) \
         VALUES ($1, 'shared', NULL, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
    )
    .bind(v.id)
    .bind(v.org_id)
    .bind(kv)
    .bind(&v.name_enc)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(ApiError::Conflict("a vault with this id exists".into()));
    }
    query(
        "INSERT INTO vault_members \
         (vault_id, user_id, permission, key_version, wrapped_vault_key, wrapped_by, signature) \
         VALUES ($1, $2, 'manage', $3, $4, $2, $5)",
    )
    .bind(v.id)
    .bind(v.creator)
    .bind(kv)
    .bind(&v.grant.wrapped_vault_key)
    .bind(&v.grant.signature)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::vaults::pg_list(pool, v.creator)
        .await?
        .into_iter()
        .find(|view| view.id == v.id)
        .ok_or_else(|| ApiError::internal(std::io::Error::other("created vault vanished")))
}

async fn pg_members(pool: &PgPool, vault: Uuid, caller: Uuid) -> Res<VaultMembersView> {
    let mut conn = pool.acquire().await?;
    let r: Option<(String, Option<Uuid>, i32)> =
        query_as("SELECT kind, org_id, key_version FROM vaults WHERE id = $1")
            .bind(vault)
            .fetch_optional(&mut *conn)
            .await?;
    let (org, kv) = match r {
        Some((kind, Some(org), kv)) if kind == "shared" => (org, kv),
        _ => return Err(vault_not_found()),
    };
    pg_visible(&mut conn, vault, org, caller).await?;
    let rows: Vec<(
        Uuid,
        String,
        String,
        Option<String>,
        Option<i32>,
        Option<Uuid>,
        bool,
    )> = query_as(
        "SELECT om.user_id, om.role, u.email, m.permission, m.key_version, m.wrapped_by, \
                    EXISTS (SELECT 1 FROM vault_members k WHERE k.vault_id = $1 \
                            AND k.user_id = om.user_id AND k.key_version = $3) \
             FROM org_members om JOIN users u ON u.id = om.user_id \
             LEFT JOIN LATERAL (SELECT permission, key_version, wrapped_by FROM vault_members \
                                WHERE vault_id = $1 AND user_id = om.user_id \
                                ORDER BY key_version DESC LIMIT 1) m ON TRUE \
             WHERE om.org_id = $2",
    )
    .bind(vault)
    .bind(org)
    .bind(kv)
    .fetch_all(&mut *conn)
    .await?;
    let created: Option<(Uuid,)> = query_as(
        "SELECT user_id FROM vault_members WHERE vault_id = $1 AND wrapped_by = user_id \
         ORDER BY key_version LIMIT 1",
    )
    .bind(vault)
    .fetch_optional(&mut *conn)
    .await?;
    let mut members: Vec<VaultMemberView> = rows
        .into_iter()
        .filter_map(|(user, role, email, perm, _, by, has_key)| {
            Some(VaultMemberView {
                user_id: user,
                email: Some(email),
                org_role: Role::parse(&role)?,
                permission: perm.as_deref().and_then(Permission::parse),
                has_key,
                granted_by: by,
            })
        })
        .collect();
    sort_members(&mut members);
    Ok(VaultMembersView {
        vault_id: vault,
        org_id: org,
        key_version: kv_to_wire(kv),
        created_by: created.map(|(u,)| u),
        members,
    })
}

async fn pg_grant(
    pool: &PgPool,
    vault: Uuid,
    granter: Uuid,
    target: Uuid,
    req: &GrantRequest,
) -> Res<Uuid> {
    let mut tx = pool.begin().await?;
    let (org, current, rotating) = pg_shared_locked(&mut tx, vault).await?;
    let (role, perm) = pg_visible(&mut tx, vault, org, granter).await?;
    if !can_manage(role, perm) {
        return Err(forbidden("grant access"));
    }
    if pg_role(&mut tx, org, target).await?.is_none() {
        return Err(ApiError::Invalid(
            "access can only be granted to members of the vault's org".into(),
        ));
    }
    if rotating {
        return Err(ApiError::Rotating("a key rotation is in progress".into()));
    }
    let kv = kv_to_db(req.key_version)?;
    if kv != current {
        return Err(ApiError::Invalid(format!(
            "stale key version {} (the vault is at {current})",
            req.key_version
        )));
    }
    check_grant_bytes(&req.wrapped_vault_key, &req.signature)?;
    query(
        "INSERT INTO vault_members \
         (vault_id, user_id, permission, key_version, wrapped_vault_key, wrapped_by, signature) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (vault_id, user_id, key_version) DO UPDATE SET \
         permission = EXCLUDED.permission, wrapped_vault_key = EXCLUDED.wrapped_vault_key, \
         wrapped_by = EXCLUDED.wrapped_by, signature = EXCLUDED.signature",
    )
    .bind(vault)
    .bind(target)
    .bind(req.permission.as_str())
    .bind(kv)
    .bind(&req.wrapped_vault_key)
    .bind(granter)
    .bind(&req.signature)
    .execute(&mut *tx)
    .await?;
    query("UPDATE vault_members SET permission = $3 WHERE vault_id = $1 AND user_id = $2")
        .bind(vault)
        .bind(target)
        .bind(req.permission.as_str())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(org)
}

async fn pg_revoke(pool: &PgPool, vault: Uuid, actor: Uuid, target: Uuid) -> Res<Revoked> {
    let mut tx = pool.begin().await?;
    let (org, _, _) = pg_shared_locked(&mut tx, vault).await?;
    let (role, perm) = pg_visible(&mut tx, vault, org, actor).await?;
    if actor != target && !can_manage(role, perm) {
        return Err(forbidden("revoke access"));
    }
    let rows = query("DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2")
        .bind(vault)
        .bind(target)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if rows == 0 {
        return Err(ApiError::NotFound("no such vault member".into()));
    }
    tx.commit().await?;
    Ok(Revoked { org_id: org, rows })
}

async fn pg_org_vaults(pool: &PgPool, org: Uuid, user: Uuid) -> Res<Vec<OrgVaultView>> {
    let mut conn = pool.acquire().await?;
    let role = pg_role(&mut conn, org, user)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such org".into()))?;
    let rows: Vec<(Uuid, Vec<u8>, i32, Option<String>, bool)> = query_as(
        "SELECT v.id, v.name_enc, v.key_version, \
                (SELECT permission FROM vault_members m WHERE m.vault_id = v.id AND m.user_id = $2 \
                 ORDER BY key_version DESC LIMIT 1), \
                EXISTS (SELECT 1 FROM vault_members m WHERE m.vault_id = v.id AND m.user_id = $2 \
                        AND m.key_version = v.key_version) \
         FROM vaults v WHERE v.kind = 'shared' AND v.org_id = $1 ORDER BY v.id",
    )
    .bind(org)
    .bind(user)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, name_enc, kv, perm, has_key)| {
            let perm = perm.as_deref().and_then(Permission::parse);
            let permission = if role >= Role::Admin {
                Some(Permission::Manage)
            } else {
                perm
            }?;
            Some(OrgVaultView {
                id,
                name_enc,
                key_version: kv_to_wire(kv),
                permission,
                has_key,
            })
        })
        .collect())
}

async fn pg_vault_org(pool: &PgPool, vault: Uuid) -> Res<Option<Uuid>> {
    let r: Option<(Option<Uuid>,)> =
        query_as("SELECT org_id FROM vaults WHERE id = $1 AND kind = 'shared'")
            .bind(vault)
            .fetch_optional(pool)
            .await?;
    Ok(r.and_then(|(o,)| o))
}

// ------------------------------------------------------------------- dispatch

impl SyncStore {
    /// Creates a shared vault with its creator's `manage` self-grant; returns the
    /// creator's view of it.
    ///
    /// # Errors
    /// `404` (not in the org), `403` (not an admin), `409` (id exists),
    /// `400` ([`validate_create`]).
    pub async fn create_shared_vault(&self, v: &NewSharedVault) -> Res<VaultView> {
        validate_create(v)?;
        match self {
            Self::Postgres(pool) => pg_create(pool, v).await,
            Self::Memory(m) => m.db().with_data(|d| mem_create(d, v)),
        }
    }

    /// The org's members with their permission on `vault`.
    ///
    /// # Errors
    /// `404` when the caller can't see the vault.
    pub async fn vault_members(&self, vault: Uuid, caller: Uuid) -> Res<VaultMembersView> {
        match self {
            Self::Postgres(pool) => pg_members(pool, vault, caller).await,
            Self::Memory(m) => m.db().with_data(|d| mem_members(d, vault, caller)),
        }
    }

    /// Stores `granter`'s grant for `target`; returns the vault's org.
    ///
    /// # Errors
    /// `404`, `403` (no `manage`), `400` (not an org member, stale key version,
    /// malformed), `409 rotating`.
    pub async fn grant_member(
        &self,
        vault: Uuid,
        granter: Uuid,
        target: Uuid,
        req: &GrantRequest,
    ) -> Res<Uuid> {
        match self {
            Self::Postgres(pool) => pg_grant(pool, vault, granter, target, req).await,
            Self::Memory(m) => m
                .db()
                .with_data(|d| mem_grant(d, vault, granter, target, req)),
        }
    }

    /// Removes every grant of `target` on `vault`.
    ///
    /// # Errors
    /// `404` (no vault, not visible, not a member), `403`.
    pub async fn revoke_member(&self, vault: Uuid, actor: Uuid, target: Uuid) -> Res<Revoked> {
        match self {
            Self::Postgres(pool) => pg_revoke(pool, vault, actor, target).await,
            Self::Memory(m) => m.db().with_data(|d| mem_revoke(d, vault, actor, target)),
        }
    }

    /// The org's shared vaults visible to `user` (all of them for owners and
    /// admins, with `has_key = false` where they hold no grant yet).
    ///
    /// # Errors
    /// `404` (not in the org).
    pub async fn org_vaults(&self, org: Uuid, user: Uuid) -> Res<Vec<OrgVaultView>> {
        match self {
            Self::Postgres(pool) => pg_org_vaults(pool, org, user).await,
            Self::Memory(m) => m.db().with_data(|d| mem_org_vaults(d, org, user)),
        }
    }

    /// The org of a shared vault (`None` for personal or unknown vaults).
    ///
    /// # Errors
    /// Database errors.
    pub async fn shared_vault_org(&self, vault: Uuid) -> Res<Option<Uuid>> {
        match self {
            Self::Postgres(pool) => pg_vault_org(pool, vault).await,
            Self::Memory(m) => Ok(m.db().with_data(|d| {
                d.vaults
                    .get(&vault)
                    .filter(|v| !v.personal)
                    .and_then(|v| v.org_id)
            })),
        }
    }
}

/// The audit metadata of a push: only the accepted item ids (§13.5).
#[must_use]
pub fn push_audit_meta(item_ids: &[Uuid]) -> serde_json::Value {
    serde_json::json!({ "items": item_ids, "count": item_ids.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_rules() {
        assert!(can_manage(Some(Role::Admin), None));
        assert!(can_manage(Some(Role::Owner), Some(Permission::Read)));
        assert!(can_manage(Some(Role::Member), Some(Permission::Manage)));
        assert!(!can_manage(Some(Role::Member), Some(Permission::Write)));
        assert!(!can_manage(None, None));
    }
}
