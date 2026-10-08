//! Push (§12.3): batch limits, the per-change decision (shared by both
//! backends) and the PostgreSQL transaction (§12.1 locking, see the
//! [module docs](super)).
//!
//! Request-level outcomes, in the order they are checked:
//! 1. batch shape ([`validate_batch`]): more than 500 changes, more than
//!    8 MiB of envelopes, or a duplicate item id → `400 invalid`;
//! 2. not a member / no such vault → `404 not_found`;
//! 3. `read` permission → `403 forbidden` (§13.2; per-item `forbidden` is
//!    reserved for future per-item ACLs);
//! 4. rotation in progress → `409 rotating`;
//! 5. any change with `key_version != vaults.key_version` → `400 invalid`
//!    (the client's vault key is stale: it refreshes `GET /v1/vaults`).
//!
//! Per change ([`plan`]), in batch order: envelope over 1 MiB →
//! `too_large`; stale `base_revision` → `conflict` with `current`; growth
//! beyond the quota → `too_large` "quota exceeded"; otherwise `ok`.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::PgPool;
use sverb_proto::sync::{
    ENVELOPE_TOO_LARGE_MESSAGE, MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_ENVELOPE_BYTES, Permission,
    PushChange, PushResult, PushStatus, QUOTA_EXCEEDED_MESSAGE, RemoteItem, VaultKind,
};
use uuid::Uuid;

use super::quota::{self, QuotaBudget};
use super::{PushOutcome, Res, SyncLimits, VaultAccess, remote_item, rev_to_wire};
use crate::auth::store::AccessCtx;
use crate::error::ApiError;

/// Checks the batch shape (§10.5) before touching the database.
///
/// # Errors
/// `Invalid` for more than [`MAX_BATCH_ITEMS`] changes, more than
/// [`MAX_BATCH_BYTES`] of envelopes in total, or a duplicate item id.
pub fn validate_batch(changes: &[PushChange]) -> Res<()> {
    if changes.len() > MAX_BATCH_ITEMS {
        return Err(ApiError::Invalid(format!(
            "too many changes in one push: {} (max {MAX_BATCH_ITEMS})",
            changes.len()
        )));
    }
    let total: usize = changes.iter().map(|c| c.envelope.len()).sum();
    if total > MAX_BATCH_BYTES {
        return Err(ApiError::Invalid(format!(
            "push batch too large: {total} envelope bytes (max {MAX_BATCH_BYTES})"
        )));
    }
    let mut seen = HashSet::with_capacity(changes.len());
    if let Some(dup) = changes.iter().find(|c| !seen.insert(c.id)) {
        return Err(ApiError::Invalid(format!(
            "item {} appears more than once in the batch",
            dup.id
        )));
    }
    Ok(())
}

/// The request-level checks made under the vault lock (steps 3–5 of the
/// module docs).
///
/// # Errors
/// `Forbidden`, `Rotating`, `Invalid`.
pub fn check_access(access: &VaultAccess, changes: &[PushChange]) -> Res<()> {
    if !access.permission.can_write() {
        return Err(ApiError::Forbidden(
            "read-only access to this vault: pushes are not allowed".into(),
        ));
    }
    if access.rotating {
        return Err(ApiError::Rotating(
            "a key rotation is in progress; retry after it completes".into(),
        ));
    }
    if let Some(c) = changes
        .iter()
        .find(|c| i64::from(c.key_version) != i64::from(access.key_version))
    {
        return Err(ApiError::Invalid(format!(
            "item {} uses key version {} but the vault is at key version {}; \
             refresh the vault keys and re-encrypt",
            c.id, c.key_version, access.key_version
        )));
    }
    Ok(())
}

/// The decision for one change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Accept: gets the next revision.
    Accept,
    /// Stale base: the current server item (`None` if absent).
    Conflict(Option<RemoteItem>),
    /// Rejected for size: the message.
    TooLarge(&'static str),
}

/// Decides every change of a batch (§12.3) against the current items
/// (`existing`, read under the vault lock) and the quota budget.
///
/// A change is accepted iff its envelope fits, `existing.revision ==
/// base_revision` (or the item is absent and `base_revision == 0`), and
/// accepting it keeps the budget within its limit (changes that don't grow
/// usage always fit). Accepted changes update the budget, so the batch never
/// goes beyond the quota, even partially.
#[must_use]
pub fn plan(
    changes: &[PushChange],
    existing: &HashMap<Uuid, RemoteItem>,
    mut budget: QuotaBudget,
) -> Vec<Decision> {
    changes
        .iter()
        .map(|c| {
            if c.envelope.len() > MAX_ENVELOPE_BYTES {
                return Decision::TooLarge(ENVELOPE_TOO_LARGE_MESSAGE);
            }
            let current = existing.get(&c.id);
            let base_ok = match current {
                Some(cur) => cur.revision == c.base_revision,
                None => c.base_revision == 0,
            };
            if !base_ok {
                return Decision::Conflict(current.cloned());
            }
            let old = current.map_or(0, |cur| cur.envelope.len() as u64);
            if !budget.try_replace(old, c.envelope.len() as u64) {
                return Decision::TooLarge(QUOTA_EXCEEDED_MESSAGE);
            }
            Decision::Accept
        })
        .collect()
}

/// Number of accepted changes.
#[must_use]
pub fn accepted(decisions: &[Decision]) -> i64 {
    decisions
        .iter()
        .filter(|d| matches!(d, Decision::Accept))
        .count() as i64
}

/// Assigns `new_head - n + 1 ..= new_head` to the accepted changes in batch
/// order and builds the results. Returns the results and, per change, the
/// assigned revision (accepted ones only).
#[must_use]
pub fn assign(
    changes: &[PushChange],
    decisions: Vec<Decision>,
    new_head: i64,
) -> (Vec<PushResult>, Vec<Option<i64>>) {
    let mut next = new_head - accepted(&decisions) + 1;
    let mut revs = Vec::with_capacity(changes.len());
    let results = changes
        .iter()
        .zip(decisions)
        .map(|(c, d)| {
            let mut r = PushResult {
                id: c.id,
                status: PushStatus::Ok,
                revision: None,
                current: None,
                message: None,
            };
            match d {
                Decision::Accept => {
                    r.revision = Some(rev_to_wire(next));
                    revs.push(Some(next));
                    next += 1;
                }
                Decision::Conflict(current) => {
                    r.status = PushStatus::Conflict;
                    r.current = current;
                    revs.push(None);
                }
                Decision::TooLarge(msg) => {
                    r.status = PushStatus::TooLarge;
                    r.message = Some(msg.to_owned());
                    revs.push(None);
                }
            }
            r
        })
        .collect();
    (results, revs)
}

// --------------------------------------------------------------- postgres

/// The caller's permission in a vault, if a member (highest key version's
/// row wins; all rows of one member carry the same permission in practice).
pub(super) const PERMISSION_SQL: &str = "SELECT permission FROM vault_members \
     WHERE vault_id = $1 AND user_id = $2 ORDER BY key_version DESC LIMIT 1";

/// `vault_members.permission` is nullable in the schema; a NULL (never
/// written by sverb) is treated as the least privilege.
pub(super) fn parse_permission(p: Option<&str>) -> Res<Permission> {
    match p {
        None => Ok(Permission::Read),
        Some(p) => Permission::parse(p).ok_or_else(|| {
            ApiError::internal(std::io::Error::other(format!("bad permission {p:?}")))
        }),
    }
}

/// The PostgreSQL push: one transaction per batch, vault row locked first
/// and held until commit (§12.1, module docs of [`super`]).
///
/// # Errors
/// As [`super::SyncStore::push`].
pub async fn pg_push(
    pool: &PgPool,
    ctx: AccessCtx,
    vault_id: Uuid,
    changes: &[PushChange],
    limits: SyncLimits,
    now: DateTime<Utc>,
) -> Res<PushOutcome> {
    // Cheap membership pre-check without any lock, so non-members can't
    // queue on (or even probe) the vault row.
    let pre: Option<(Option<String>,)> = query_as(PERMISSION_SQL)
        .bind(vault_id)
        .bind(ctx.user_id)
        .fetch_optional(pool)
        .await?;
    if pre.is_none() {
        return Err(super::vault_not_found());
    }

    let mut tx = pool.begin().await?;

    // 1. The vault row lock (held until COMMIT/ROLLBACK). Every later
    //    statement runs in READ COMMITTED with a fresh snapshot taken after
    //    the lock was granted, so it sees every earlier push's commit.
    let row: Option<(String, Option<Uuid>, i32, bool, i64)> = query_as(
        "SELECT kind, owner_user_id, key_version, rotation IS NOT NULL, head_revision \
         FROM vaults WHERE id = $1 FOR UPDATE",
    )
    .bind(vault_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((kind, owner_user_id, key_version, rotating, head_revision)) = row else {
        return Err(super::vault_not_found());
    };
    // Membership again, now under the lock (a revoke may have committed).
    let perm: Option<(Option<String>,)> = query_as(PERMISSION_SQL)
        .bind(vault_id)
        .bind(ctx.user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((perm,)) = perm else {
        return Err(super::vault_not_found());
    };
    let access = VaultAccess {
        kind: VaultKind::parse(&kind).ok_or_else(|| {
            ApiError::internal(std::io::Error::other(format!("bad vault kind {kind:?}")))
        })?,
        owner_user_id,
        key_version,
        rotating,
        head_revision,
        permission: parse_permission(perm.as_deref())?,
    };
    check_access(&access, changes)?;
    if changes.is_empty() {
        return Ok(PushOutcome {
            results: Vec::new(),
            new_head: None,
        });
    }

    // 2. Current versions of the batch's items (locked too, in id order so
    //    concurrent lockers of the same rows (GC, rotation) can't deadlock
    //    with us in a different order).
    let ids: Vec<Uuid> = changes.iter().map(|c| c.id).collect();
    let rows: Vec<(Uuid, i64, i32, Vec<u8>, bool)> = query_as(
        "SELECT id, revision, key_version, envelope, deleted FROM items \
         WHERE vault_id = $1 AND id = ANY($2) ORDER BY id FOR UPDATE",
    )
    .bind(vault_id)
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    let existing: HashMap<Uuid, RemoteItem> = rows
        .into_iter()
        .map(|(id, rev, kv, env, del)| (id, remote_item(id, rev, kv, env, del)))
        .collect();

    // 3. Decide (quota usage read under the same lock).
    let budget = quota::pg_budget(&mut tx, vault_id, &access, limits).await?;
    let decisions = plan(changes, &existing, budget);
    let n = accepted(&decisions);
    if n == 0 {
        // Nothing to write: no revision consumed, no notification.
        tx.rollback().await?;
        let (results, _) = assign(changes, decisions, head_revision);
        return Ok(PushOutcome {
            results,
            new_head: None,
        });
    }

    // 4. Reserve exactly n revisions (§12.1's statement; the row is
    //    already ours, so this cannot interleave with another push).
    let (new_head,): (i64,) = query_as(
        "UPDATE vaults SET head_revision = head_revision + $2 WHERE id = $1 \
         RETURNING head_revision",
    )
    .bind(vault_id)
    .bind(n)
    .fetch_one(&mut *tx)
    .await?;
    let (results, revs) = assign(changes, decisions, new_head);

    // 5. Upsert the accepted items in one statement. Tombstones keep their
    //    envelope (§10.3).
    let mut a_ids = Vec::new();
    let mut a_revs = Vec::new();
    let mut a_envs: Vec<Vec<u8>> = Vec::new();
    let mut a_del = Vec::new();
    for (c, rev) in changes.iter().zip(&revs) {
        if let Some(rev) = rev {
            a_ids.push(c.id);
            a_revs.push(*rev);
            a_envs.push(c.envelope.clone());
            a_del.push(c.deleted);
        }
    }
    query(
        "INSERT INTO items \
           (vault_id, id, revision, key_version, envelope, deleted, updated_at, updated_by_device) \
         SELECT $1, u.id, u.revision, $2, u.envelope, u.deleted, $3, $4 \
         FROM UNNEST($5::uuid[], $6::bigint[], $7::bytea[], $8::bool[]) \
           AS u(id, revision, envelope, deleted) \
         ON CONFLICT (vault_id, id) DO UPDATE SET \
           revision = EXCLUDED.revision, key_version = EXCLUDED.key_version, \
           envelope = EXCLUDED.envelope, deleted = EXCLUDED.deleted, \
           updated_at = EXCLUDED.updated_at, updated_by_device = EXCLUDED.updated_by_device",
    )
    .bind(vault_id)
    .bind(key_version)
    .bind(now)
    .bind(ctx.device_id)
    .bind(&a_ids)
    .bind(&a_revs)
    .bind(&a_envs)
    .bind(&a_del)
    .execute(&mut *tx)
    .await?;

    // 6. Commit (releases the vault lock); the caller notifies afterwards.
    tx.commit().await?;
    Ok(PushOutcome {
        results,
        new_head: Some(rev_to_wire(new_head)),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn change(id: Uuid, base: u64, len: usize) -> PushChange {
        PushChange {
            id,
            base_revision: base,
            key_version: 1,
            envelope: vec![7; len],
            deleted: false,
        }
    }

    #[test]
    fn rejected_changes_consume_no_revisions() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut existing = HashMap::new();
        existing.insert(b, remote_item(b, 4, 1, vec![1], false));
        let changes = vec![change(a, 0, 3), change(b, 3, 3), change(c, 0, 3)];
        let d = plan(&changes, &existing, QuotaBudget::unlimited());
        assert_eq!(accepted(&d), 2);
        let (res, revs) = assign(&changes, d, 12);
        assert_eq!(res[0].revision, Some(11));
        assert_eq!(res[1].status, PushStatus::Conflict);
        assert_eq!(res[1].current.as_ref().unwrap().revision, 4);
        assert_eq!(res[2].revision, Some(12));
        assert_eq!(revs, vec![Some(11), None, Some(12)]);
    }

    #[test]
    fn quota_is_never_exceeded_partially() {
        let changes: Vec<_> = (0..4).map(|_| change(Uuid::now_v7(), 0, 40)).collect();
        let d = plan(&changes, &HashMap::new(), QuotaBudget::new(10, 100));
        assert_eq!(
            d,
            vec![
                Decision::Accept,
                Decision::Accept,
                Decision::TooLarge(QUOTA_EXCEEDED_MESSAGE),
                Decision::TooLarge(QUOTA_EXCEEDED_MESSAGE),
            ]
        );
        // Shrinking an item always fits, even when over quota.
        let id = Uuid::now_v7();
        let mut existing = HashMap::new();
        existing.insert(id, remote_item(id, 1, 1, vec![0; 50], false));
        let d = plan(&[change(id, 1, 10)], &existing, QuotaBudget::new(500, 100));
        assert_eq!(d, vec![Decision::Accept]);
    }

    #[test]
    fn batch_shape() {
        let id = Uuid::now_v7();
        assert!(validate_batch(&[change(id, 0, 1), change(id, 0, 1)]).is_err());
        let many: Vec<_> = (0..=MAX_BATCH_ITEMS)
            .map(|_| change(Uuid::now_v7(), 0, 0))
            .collect();
        assert!(validate_batch(&many).is_err());
        assert!(validate_batch(&many[1..]).is_ok());
        let big = vec![
            change(Uuid::now_v7(), 0, MAX_BATCH_BYTES / 2),
            change(Uuid::now_v7(), 0, MAX_BATCH_BYTES / 2 + 1),
        ];
        assert!(validate_batch(&big).is_err());
    }
}
