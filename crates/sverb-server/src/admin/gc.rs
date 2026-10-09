//! `admin gc` (SPEC §10.6): purge expired and finished state.
//!
//! M4-01 covers expired tokens, expired unaccepted invites and finished
//! share sessions; M4-04 adds tombstones older than
//! `SVERB_TOMBSTONE_HORIZON_DAYS`, raising `vaults.gc_floor_revision`
//! ([`crate::sync::gc`]); M5-04 clears abandoned key rotations (older than
//! 15 minutes) and their staging ([`crate::sync::rotation`]).

use sqlx_postgres::PgPool;

use super::AdminError;
use crate::config::Config;

/// What [`run`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    /// Expired access/refresh tokens.
    pub expired_tokens: u64,
    /// Expired invites that were never accepted.
    pub expired_invites: u64,
    /// Closed or expired share sessions.
    pub finished_shares: u64,
    /// M4-04: tombstones purged.
    pub purged_tombstones: u64,
    /// M4-04: vaults whose GC floor was raised.
    pub gc_floor_vaults: u64,
    /// M5-04: abandoned key rotations discarded.
    pub abandoned_rotations: u64,
}

/// Runs every GC step, each in its own statement.
///
/// # Errors
/// Database errors.
pub async fn run(pool: &PgPool, config: &Config) -> Result<GcReport, AdminError> {
    let expired_tokens =
        sqlx_core::query::query("DELETE FROM auth_tokens WHERE expires_at < now()")
            .execute(pool)
            .await?
            .rows_affected();
    let expired_invites = sqlx_core::query::query(
        "DELETE FROM invites WHERE accepted_at IS NULL AND expires_at < now()",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let finished_shares = sqlx_core::query::query(
        "DELETE FROM share_sessions WHERE closed_at IS NOT NULL OR expires_at < now()",
    )
    .execute(pool)
    .await?
    .rows_affected();
    // M4-04: tombstones (one transaction per vault).
    let cutoff = crate::sync::gc::cutoff(chrono::Utc::now(), config.limits.tombstone_horizon_days);
    let tombstones = crate::sync::gc::pg_purge_tombstones(pool, cutoff).await?;
    // M5-04: abandoned key rotations (§13.2 step 5).
    let abandoned = crate::sync::rotation::pg_discard_abandoned(pool, chrono::Utc::now()).await?;
    Ok(GcReport {
        abandoned_rotations: abandoned.len() as u64,
        expired_tokens,
        expired_invites,
        finished_shares,
        purged_tombstones: tombstones.purged_tombstones,
        gc_floor_vaults: tombstones.vaults,
    })
}
