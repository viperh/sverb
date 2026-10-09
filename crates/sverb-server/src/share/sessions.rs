//!
//! Like [`crate::sync::SyncStore`], two backends with the same behaviour:
//! PostgreSQL, and an in-memory model for tests without a database. Only
//! the session row is persisted; the live relay (sockets, viewer ids) is
//! per replica, in memory ([`super::relay`]).

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::PgPool;
use sverb_proto::share::ShareMode;
use uuid::Uuid;

use crate::auth::AuthStore;
use crate::error::ApiError;

type Res<T> = Result<T, ApiError>;

/// One `share_sessions` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRow {
    /// Id (UUIDv7, server-generated).
    pub id: Uuid,
    /// The host's account.
    pub owner_user_id: Uuid,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Hard end.
    pub expires_at: DateTime<Utc>,
    /// View or control.
    pub mode: ShareMode,
    /// Viewer cap.
    pub max_viewers: u32,
    /// Viewers must authenticate.
    pub require_account: bool,
    /// Set once the share ended (deleted, host gone, expired).
    pub closed_at: Option<DateTime<Utc>>,
}

impl ShareRow {
    /// Still usable at `now` (not closed, not expired).
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.closed_at.is_none() && self.expires_at > now
    }
}

/// The in-memory model.
#[derive(Debug, Default)]
pub struct MemShares {
    rows: Mutex<HashMap<Uuid, ShareRow>>,
}

impl MemShares {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, ShareRow>> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn insert(&self, row: &ShareRow) -> Res<()> {
        let mut rows = self.lock();
        if rows.contains_key(&row.id) {
            return Err(ApiError::Conflict("share id taken".into()));
        }
        rows.insert(row.id, row.clone());
        Ok(())
    }

    fn get(&self, id: Uuid) -> Option<ShareRow> {
        self.lock().get(&id).cloned()
    }

    fn close(&self, id: Uuid, at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let mut rows = self.lock();
        let row = rows.get_mut(&id)?;
        Some(*row.closed_at.get_or_insert(at))
    }

    fn purge(&self, now: DateTime<Utc>) -> u64 {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|_, r| r.is_live(now));
        (before - rows.len()) as u64
    }
}

/// The persistence backend for shares.
#[derive(Debug, Clone)]
pub enum ShareStore {
    /// PostgreSQL.
    Postgres(PgPool),
    /// In-memory model (tests).
    Memory(Arc<MemShares>),
}

fn bad(what: &str, v: &str) -> ApiError {
    ApiError::internal(std::io::Error::other(format!(
        "bad {what} {v:?} in database"
    )))
}

impl ShareStore {
    /// The share backend matching an auth backend.
    #[must_use]
    pub fn for_auth(auth: &AuthStore) -> Self {
        match auth {
            AuthStore::Postgres(pool) => Self::Postgres(pool.clone()),
            AuthStore::Memory(_) => Self::Memory(Arc::new(MemShares::default())),
        }
    }

    /// Stores a new share and, for an owner who belongs to orgs, a
    /// `share_started` audit event in each of them (PostgreSQL only: the
    /// memory model has no orgs). One transaction.
    ///
    /// # Errors
    /// `Conflict` (id taken), database errors.
    pub async fn create(&self, row: &ShareRow) -> Res<()> {
        match self {
            Self::Memory(m) => m.insert(row),
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                query(
                    "INSERT INTO share_sessions \
                     (id, owner_user_id, created_at, expires_at, mode, max_viewers, require_account) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(row.id)
                .bind(row.owner_user_id)
                .bind(row.created_at)
                .bind(row.expires_at)
                .bind(row.mode.as_str())
                .bind(i32::try_from(row.max_viewers).unwrap_or(i32::MAX))
                .bind(row.require_account)
                .execute(&mut *tx)
                .await?;
                let meta = serde_json::json!({
                    "mode": row.mode.as_str(),
                    "expires_at": row.expires_at,
                    "max_viewers": row.max_viewers,
                    "require_account": row.require_account,
                });
                query(
                    "INSERT INTO audit_events (org_id, actor_user_id, kind, target, at, meta) \
                     SELECT org_id, $1, 'share_started', $2, $3, $4 \
                     FROM org_members WHERE user_id = $1",
                )
                .bind(row.owner_user_id)
                .bind(row.id)
                .bind(row.created_at)
                .bind(meta)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(())
            }
        }
    }

    /// A share by id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get(&self, id: Uuid) -> Res<Option<ShareRow>> {
        match self {
            Self::Memory(m) => Ok(m.get(id)),
            Self::Postgres(pool) => {
                let row: Option<(
                    Option<Uuid>,
                    Option<DateTime<Utc>>,
                    Option<DateTime<Utc>>,
                    Option<String>,
                    Option<i32>,
                    bool,
                    Option<DateTime<Utc>>,
                )> = query_as(
                    "SELECT owner_user_id, created_at, expires_at, mode, max_viewers, \
                            require_account, closed_at \
                     FROM share_sessions WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(pool)
                .await?;
                let Some((owner, created, expires, mode, max, require_account, closed_at)) = row
                else {
                    return Ok(None);
                };
                let mode_s = mode.unwrap_or_default();
                Ok(Some(ShareRow {
                    id,
                    owner_user_id: owner.ok_or_else(|| bad("share owner", "NULL"))?,
                    created_at: created.unwrap_or(DateTime::<Utc>::MIN_UTC),
                    // A row without expiry counts as expired.
                    expires_at: expires.unwrap_or(DateTime::<Utc>::MIN_UTC),
                    mode: ShareMode::parse(&mode_s).ok_or_else(|| bad("share mode", &mode_s))?,
                    max_viewers: max.and_then(|m| u32::try_from(m).ok()).unwrap_or(0),
                    require_account,
                    closed_at,
                }))
            }
        }
    }

    /// Marks a share closed at `at` (idempotent: an earlier `closed_at`
    /// stays). Returns the effective `closed_at`, `None` for an unknown id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn close(&self, id: Uuid, at: DateTime<Utc>) -> Res<Option<DateTime<Utc>>> {
        match self {
            Self::Memory(m) => Ok(m.close(id, at)),
            Self::Postgres(pool) => {
                let row: Option<(Option<DateTime<Utc>>,)> = query_as(
                    "UPDATE share_sessions SET closed_at = COALESCE(closed_at, $2) \
                     WHERE id = $1 RETURNING closed_at",
                )
                .bind(id)
                .bind(at)
                .fetch_optional(pool)
                .await?;
                Ok(row.and_then(|(c,)| c))
            }
        }
    }

    /// Deletes closed and expired shares (what `admin gc` does on
    /// PostgreSQL, see [`crate::admin::gc`]). Returns the count.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_finished(&self, now: DateTime<Utc>) -> Res<u64> {
        match self {
            Self::Memory(m) => Ok(m.purge(now)),
            Self::Postgres(pool) => Ok(query(
                "DELETE FROM share_sessions WHERE closed_at IS NOT NULL OR expires_at < $1",
            )
            .bind(now)
            .execute(pool)
            .await?
            .rows_affected()),
        }
    }
}
