//! Versioned schema migrations (SPEC §5.2, M1-03 §2.3).
//!
//! The SQL lives in `crates/sverb-store/migrations/` (inside the crate so
//! `cargo package` works); `migrations/client/` at the repository root links to it.
//! Migration `N` sets `PRAGMA user_version = N`. `0002` is M2-10's
//! `local_approvals`; `0003` is M5-03's `pinned_keys`.

use rusqlite_migration::{M, Migrations};

/// The migrations this build knows, in order.
pub const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    // M2-10: the device-local allowlist of locally-acting values (§17.1).
    include_str!("../migrations/0002_local_approvals.sql"),
    // M5-03: TOFU pins of account public keys (§13.3).
    include_str!("../migrations/0003_pinned_keys.sql"),
];

/// The latest schema version (`PRAGMA user_version`) this build knows.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// The persistent tables created by the migrations. No table in this list ever
/// holds decrypted data.
pub const TABLES: &[&str] = &[
    "meta",
    "vaults",
    "items",
    "outbox",
    "device_local",
    "sync_state",
    // M2-10
    "local_approvals",
    // M5-03
    "pinned_keys",
];

/// Builds the migration set, plus `extra` steps (tests only).
pub(crate) fn migrations(extra: &[&'static str]) -> Migrations<'static> {
    Migrations::new(
        MIGRATIONS
            .iter()
            .chain(extra.iter())
            .copied()
            .map(M::up)
            .collect(),
    )
}
