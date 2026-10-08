//! Tombstone GC (§12.2): purge tombstones whose last write is older than
//! the horizon (`tombstone_horizon_days`, default 90) and raise
//! `vaults.gc_floor_revision` to the highest purged revision, per vault in
//! one transaction. Pulls with `0 < since < gc_floor_revision` then get
//! `410 Gone` and the client resyncs from 0.
//!
//! Runs from `sverb-server admin gc` ([`crate::admin::gc::run`]) and,
//! unless `gc_interval_hours = 0`, from a background job in the server
//! ([`spawn_background`]; every replica may run it, the per-vault lock makes
//! concurrent runs harmless).

use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::PgPool;
use uuid::Uuid;

use super::SyncStore;
use crate::state::AppState;

/// What a tombstone GC run removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcOutcome {
    /// Tombstones deleted.
    pub purged_tombstones: u64,
    /// Vaults whose floor was raised.
    pub vaults: u64,
}

/// The cutoff for `horizon_days` before `now`.
#[must_use]
pub fn cutoff(now: DateTime<Utc>, horizon_days: u32) -> DateTime<Utc> {
    now - TimeDelta::days(i64::from(horizon_days))
}

/// The PostgreSQL purge. Each vault is handled in its own transaction that
/// first takes the vault row lock (the same lock pushes take), so a push
/// that is rewriting a tombstone right now is never raced: GC sees either
/// the tombstone before the push (and the push then conflicts, because the
/// item vanished) or the pushed version (no longer an old tombstone).
///
/// # Errors
/// Database errors.
pub async fn pg_purge_tombstones(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> Result<GcOutcome, sqlx_core::Error> {
    let candidates: Vec<Uuid> =
        query_scalar("SELECT DISTINCT vault_id FROM items WHERE deleted AND updated_at < $1")
            .bind(cutoff)
            .fetch_all(pool)
            .await?;
    let mut out = GcOutcome::default();
    for vault_id in candidates {
        let mut tx = pool.begin().await?;
        let locked: Option<Uuid> = query_scalar("SELECT id FROM vaults WHERE id = $1 FOR UPDATE")
            .bind(vault_id)
            .fetch_optional(&mut *tx)
            .await?;
        if locked.is_none() {
            tx.rollback().await?;
            continue;
        }
        let (purged, max_rev): (i64, Option<i64>) = query_as(
            "WITH purged AS ( \
               DELETE FROM items WHERE vault_id = $1 AND deleted AND updated_at < $2 \
               RETURNING revision) \
             SELECT count(*)::BIGINT, max(revision) FROM purged",
        )
        .bind(vault_id)
        .bind(cutoff)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(max_rev) = max_rev {
            query(
                "UPDATE vaults SET gc_floor_revision = GREATEST(gc_floor_revision, $2) \
                 WHERE id = $1",
            )
            .bind(vault_id)
            .bind(max_rev)
            .execute(&mut *tx)
            .await?;
            out.vaults += 1;
            out.purged_tombstones += u64::try_from(purged).unwrap_or(0);
        }
        tx.commit().await?;
    }
    Ok(out)
}

/// One background GC pass: the whole `admin gc` on PostgreSQL, tombstones
/// only on the in-memory model.
async fn run_once(state: &AppState) {
    let config = state.config();
    match state.sync().store() {
        SyncStore::Postgres(pool) => match crate::admin::gc::run(pool, config).await {
            Ok(r) => tracing::info!(
                expired_tokens = r.expired_tokens,
                expired_invites = r.expired_invites,
                finished_shares = r.finished_shares,
                purged_tombstones = r.purged_tombstones,
                "background gc finished"
            ),
            Err(e) => tracing::warn!(error = %e, "background gc failed"),
        },
        store @ SyncStore::Memory(_) => {
            let c = cutoff(state.auth().now(), config.limits.tombstone_horizon_days);
            if let Err(e) = store.gc_tombstones(c).await {
                tracing::warn!(error = %e, "background gc failed");
            }
        }
    }
}

/// Spawns the periodic GC job (`gc_interval_hours`, 0 = off). The first
/// pass runs one interval after start.
#[must_use]
pub fn spawn_background(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    let hours = state.config().limits.gc_interval_hours;
    if hours == 0 {
        return None;
    }
    let period = Duration::from_secs(u64::from(hours) * 3600);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            run_once(&state).await;
        }
    }))
}
