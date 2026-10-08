//! Pull (§12.2): `GET /v1/vaults/{id}/changes?since=&limit=`.
//!
//! Returns the items with `revision > since` in ascending revision order,
//! at most `limit` of them, plus the head revision of the same snapshot.
//! Any membership permission may pull, also during a key rotation (§13.2).
//! `410 Gone` when `since` is below the GC floor (and not 0): purged
//! tombstones between `since` and the floor can no longer be delivered, so
//! the client must resync from 0.
//!
//! PostgreSQL: one `REPEATABLE READ, READ ONLY` transaction, so the floor,
//! the head and the page come from one snapshot. Because pushes commit in
//! revision order (vault row lock, see [`super`]), every snapshot holds a
//! gap-free prefix of the revision history.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::PgPool;
use sverb_proto::sync::{MAX_PULL_LIMIT, PullResponse, RemoteItem};
use uuid::Uuid;

use super::{Res, remote_item, rev_to_wire};
use crate::error::ApiError;

/// The page size for a requested `limit` (default and cap
/// [`MAX_PULL_LIMIT`]).
///
/// # Errors
/// `Invalid` for 0.
pub fn page_size(limit: Option<u32>) -> Res<u32> {
    match limit {
        None => Ok(MAX_PULL_LIMIT),
        Some(0) => Err(ApiError::Invalid("limit must be at least 1".into())),
        Some(n) => Ok(n.min(MAX_PULL_LIMIT)),
    }
}

/// `410 Gone` when `since` is below the GC floor (§12.2); `since = 0` is
/// always allowed (that is the full resync).
///
/// # Errors
/// `Gone`.
pub fn check_floor(since: i64, gc_floor_revision: i64) -> Res<()> {
    if since != 0 && since < gc_floor_revision {
        return Err(ApiError::Gone(format!(
            "changes before revision {gc_floor_revision} were garbage-collected; \
             resync from since=0"
        )));
    }
    Ok(())
}

/// Builds the response from up to `limit + 1` rows (the extra row only
/// tells whether there is more).
#[must_use]
pub fn page(mut items: Vec<RemoteItem>, head_revision: i64, limit: u32) -> PullResponse {
    let limit = limit as usize;
    let more = items.len() > limit;
    items.truncate(limit);
    PullResponse {
        items,
        head_revision: rev_to_wire(head_revision),
        more,
    }
}

/// The PostgreSQL pull.
///
/// # Errors
/// As [`super::SyncStore::pull`].
pub async fn pg_pull(
    pool: &PgPool,
    user_id: Uuid,
    vault_id: Uuid,
    since: i64,
    limit: u32,
) -> Res<PullResponse> {
    let mut tx = pool.begin().await?;
    query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let vault: Option<(i64, i64)> = query_as(
        "SELECT v.head_revision, v.gc_floor_revision FROM vaults v \
         WHERE v.id = $1 AND EXISTS \
           (SELECT 1 FROM vault_members m WHERE m.vault_id = v.id AND m.user_id = $2)",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((head, floor)) = vault else {
        return Err(super::vault_not_found());
    };
    check_floor(since, floor)?;
    let rows: Vec<(Uuid, i64, i32, Vec<u8>, bool)> = query_as(
        "SELECT id, revision, key_version, envelope, deleted FROM items \
         WHERE vault_id = $1 AND revision > $2 ORDER BY revision ASC LIMIT $3",
    )
    .bind(vault_id)
    .bind(since)
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let items = rows
        .into_iter()
        .map(|(id, rev, kv, env, del)| remote_item(id, rev, kv, env, del))
        .collect();
    Ok(page(items, head, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_floor() {
        assert_eq!(page_size(None).ok(), Some(500));
        assert_eq!(page_size(Some(10_000)).ok(), Some(500));
        assert_eq!(page_size(Some(7)).ok(), Some(7));
        assert!(page_size(Some(0)).is_err());
        assert!(check_floor(0, 10).is_ok());
        assert!(check_floor(10, 10).is_ok());
        assert!(matches!(check_floor(9, 10), Err(ApiError::Gone(_))));
    }
}
