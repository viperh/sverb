//! `GET /v1/vaults` (§10.4): the caller's vaults with permission, head
//! revision and every wrapped key version still present (several during a
//! rotation, §13.2).

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use std::collections::BTreeMap;

use sqlx_core::query_as::query_as;
use sqlx_postgres::PgPool;
use sverb_proto::sync::{Permission, RotationView, VaultGrant, VaultKind, VaultView};
use uuid::Uuid;

use super::{Res, kv_to_wire, rev_to_wire};
use crate::error::ApiError;

/// One `vaults ⋈ vault_members` row.
#[derive(Debug, Clone)]
pub struct MembershipRow {
    /// Vault id.
    pub vault_id: Uuid,
    /// Kind.
    pub kind: VaultKind,
    /// Org.
    pub org_id: Option<Uuid>,
    /// Encrypted name.
    pub name_enc: Vec<u8>,
    /// Current key version.
    pub key_version: i32,
    /// Head revision.
    pub head_revision: i64,
    /// `vaults.rotation`.
    pub rotation: Option<serde_json::Value>,
    /// Membership permission.
    pub permission: Permission,
    /// The grant's key version.
    pub grant_key_version: i32,
    /// Wrapped vault key.
    pub wrapped_vault_key: Vec<u8>,
    /// Granter.
    pub wrapped_by: Uuid,
    /// Signature.
    pub signature: Vec<u8>,
}

/// The view of `vaults.rotation` (§13.2: `{by, new_key_version,
/// started_at}`).
#[must_use]
pub fn rotation_view(rotation: Option<&serde_json::Value>) -> Option<RotationView> {
    rotation.map(|r| RotationView {
        in_progress: true,
        new_key_version: r
            .get("new_key_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
    })
}

/// Groups membership rows into views, ordered by vault id; grants ascend
/// by key version and the permission is the newest grant's.
#[must_use]
pub fn build_views(mut rows: Vec<MembershipRow>) -> Vec<VaultView> {
    rows.sort_by_key(|r| (r.vault_id, r.grant_key_version));
    let mut out: BTreeMap<Uuid, VaultView> = BTreeMap::new();
    for r in rows {
        let view = out.entry(r.vault_id).or_insert_with(|| VaultView {
            id: r.vault_id,
            kind: r.kind,
            org_id: r.org_id,
            name_enc: r.name_enc.clone(),
            key_version: kv_to_wire(r.key_version),
            head_revision: rev_to_wire(r.head_revision),
            permission: r.permission,
            grants: Vec::new(),
            rotation: rotation_view(r.rotation.as_ref()),
        });
        view.permission = r.permission;
        view.grants.push(VaultGrant {
            key_version: kv_to_wire(r.grant_key_version),
            wrapped_vault_key: r.wrapped_vault_key,
            wrapped_by: r.wrapped_by,
            signature: r.signature,
        });
    }
    out.into_values().collect()
}

fn bad(what: &str, v: &str) -> ApiError {
    ApiError::internal(std::io::Error::other(format!(
        "bad {what} {v:?} in database"
    )))
}

/// The PostgreSQL listing.
///
/// # Errors
/// Database errors.
pub async fn pg_list(pool: &PgPool, user_id: Uuid) -> Res<Vec<VaultView>> {
    let rows: Vec<(
        Uuid,
        String,
        Option<Uuid>,
        Vec<u8>,
        i32,
        i64,
        Option<serde_json::Value>,
        Option<String>,
        i32,
        Vec<u8>,
        Uuid,
        Vec<u8>,
    )> = query_as(
        "SELECT v.id, v.kind, v.org_id, v.name_enc, v.key_version, v.head_revision, v.rotation, \
                m.permission, m.key_version, m.wrapped_vault_key, m.wrapped_by, m.signature \
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id \
         WHERE m.user_id = $1 ORDER BY v.id, m.key_version",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(
            |(id, kind, org, name, kv, head, rot, perm, gkv, wrapped, by, sig)| {
                Ok(MembershipRow {
                    vault_id: id,
                    kind: VaultKind::parse(&kind).ok_or_else(|| bad("vault kind", &kind))?,
                    org_id: org,
                    name_enc: name,
                    key_version: kv,
                    head_revision: head,
                    rotation: rot,
                    permission: super::push::parse_permission(perm.as_deref())?,
                    grant_key_version: gkv,
                    wrapped_vault_key: wrapped,
                    wrapped_by: by,
                    signature: sig,
                })
            },
        )
        .collect::<Res<Vec<_>>>()?;
    Ok(build_views(rows))
}
