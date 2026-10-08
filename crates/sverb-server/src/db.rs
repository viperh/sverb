//! Postgres pool and migrations (SPEC §10.3).
//!
//! Queries are runtime-checked (`sqlx_core::query*`), so building never needs
//! a database. Migrations live in `migrations/server/` and are embedded into
//! the binary with `include_str!`; add new files to [`MIGRATIONS`] in order.
//! The bookkeeping table is sqlx's standard `_sqlx_migrations`, so the
//! `sqlx` CLI can inspect it too.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;

use sqlx_core::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx_postgres::{PgPool, PgPoolOptions};

/// Embedded migrations: `(version, description, sql)`.
pub const MIGRATIONS: &[(i64, &str, &str)] = &[
    (
        1,
        "init",
        include_str!("../../../migrations/server/0001_init.sql"),
    ),
    // M4-02: login states, TOTP replay step, reauth tokens, recovery codes.
    (
        2,
        "login_states",
        include_str!("../../../migrations/server/0002_login_states.sql"),
    ),
    // M4-04: tombstone GC index.
    (
        3,
        "sync",
        include_str!("../../../migrations/server/0003_sync.sql"),
    ),
    // M6-01: share_sessions.require_account.
    (
        4,
        "share",
        include_str!("../../../migrations/server/0004_share.sql"),
    ),
];

/// The migrator over [`MIGRATIONS`].
#[must_use]
pub fn migrator() -> Migrator {
    let migrations: Vec<Migration> = MIGRATIONS
        .iter()
        .map(|&(version, description, sql)| {
            Migration::new(
                version,
                Cow::Borrowed(description),
                MigrationType::Simple,
                Cow::Borrowed(sql),
                false,
            )
        })
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

fn pool_options() -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(5))
}

/// Connects to Postgres (fails fast when the database is unreachable).
///
/// # Errors
/// Connection or URL errors.
pub async fn connect(url: &str) -> Result<PgPool, sqlx_core::Error> {
    pool_options().connect(url).await
}

/// Creates a pool that connects on first use (used by tests that never touch
/// the database).
///
/// # Errors
/// Malformed URLs.
pub fn connect_lazy(url: &str) -> Result<PgPool, sqlx_core::Error> {
    pool_options().connect_lazy(url)
}

/// Applies all pending migrations.
///
/// # Errors
/// Database errors, or a checksum mismatch with an already-applied file.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    migrator().run(pool).await
}

/// How the database schema compares with the embedded migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Every embedded migration is applied.
    Current,
    /// These versions still have to be applied.
    Pending(Vec<i64>),
    /// The database is in a state this binary must not touch (failed or
    /// edited migration, or a newer schema than this binary knows).
    Mismatch(String),
}

/// Compares `_sqlx_migrations` with [`MIGRATIONS`] without modifying anything.
///
/// # Errors
/// Database errors.
pub async fn migration_status(pool: &PgPool) -> Result<MigrationStatus, sqlx_core::Error> {
    let has_table: bool =
        sqlx_core::query_scalar::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    let known: BTreeMap<i64, Vec<u8>> = migrator()
        .iter()
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect();
    if !has_table {
        return Ok(MigrationStatus::Pending(known.keys().copied().collect()));
    }
    let applied: Vec<(i64, bool, Vec<u8>)> = sqlx_core::query_as::query_as(
        "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await?;
    for (version, success, checksum) in &applied {
        if !success {
            return Ok(MigrationStatus::Mismatch(format!(
                "migration {version} is marked as failed (dirty); fix the database manually"
            )));
        }
        match known.get(version) {
            None => {
                return Ok(MigrationStatus::Mismatch(format!(
                    "database has migration {version}, which this sverb-server does not know \
                     (was it downgraded?)"
                )));
            }
            Some(expected) if expected != checksum => {
                return Ok(MigrationStatus::Mismatch(format!(
                    "migration {version} was modified after it was applied (checksum mismatch)"
                )));
            }
            Some(_) => {}
        }
    }
    let pending: Vec<i64> = known
        .keys()
        .copied()
        .filter(|v| !applied.iter().any(|(a, _, _)| a == v))
        .collect();
    Ok(if pending.is_empty() {
        MigrationStatus::Current
    } else {
        MigrationStatus::Pending(pending)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ordered_and_embedded() {
        let m = migrator();
        let versions: Vec<i64> = m.iter().map(|m| m.version).collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(versions, sorted);
        assert!(MIGRATIONS[0].2.contains("CREATE TABLE server_secrets"));
        assert!(
            MIGRATIONS[0]
                .2
                .contains("CREATE EXTENSION IF NOT EXISTS citext")
        );
        assert!(MIGRATIONS[0].2.contains("CREATE TABLE settings"));
    }
}
