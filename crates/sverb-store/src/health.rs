//! A read-only health check of the client database for `sverb doctor`.
//!
//! [`inspect`] opens the file with `SQLITE_OPEN_READ_ONLY` (no migrations, no
//! PRAGMAs that write) and reports `PRAGMA user_version` against
//! [`SCHEMA_VERSION`] and the result of `PRAGMA quick_check`. It never creates the
//! file: a missing database is the caller's concern.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::db::BUSY_TIMEOUT_MS;
use crate::error::Result;
use crate::schema::SCHEMA_VERSION;

/// At most this many `quick_check` problems are reported.
pub const MAX_PROBLEMS: usize = 10;

/// What [`inspect`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbHealth {
    /// `PRAGMA user_version` of the file.
    pub schema_version: i64,
    /// The schema this build migrates to.
    pub supported_version: i64,
    /// `PRAGMA quick_check` problems; empty when it said `ok`.
    pub problems: Vec<String>,
}

impl DbHealth {
    /// The file comes from a newer sverb.
    #[must_use]
    pub fn is_newer(&self) -> bool {
        self.schema_version > self.supported_version
    }

    /// The file still has migrations to run (they run when sverb opens it).
    #[must_use]
    pub fn needs_migration(&self) -> bool {
        self.schema_version < self.supported_version
    }

    /// `quick_check` said `ok`.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Inspect the database at `path` without modifying it. Blocking: from async
/// code call it inside `spawn_blocking`.
///
/// # Errors
/// The file can't be opened read-only, or is not a database
/// ([`crate::StoreError::Corrupt`]).
pub fn inspect(path: &Path) -> Result<DbHealth> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    let schema_version = conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?;
    let mut stmt = conn.prepare("PRAGMA quick_check")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut problems = Vec::new();
    for row in rows {
        let row = row?;
        if row != "ok" && problems.len() < MAX_PROBLEMS {
            problems.push(row);
        }
    }
    Ok(DbHealth {
        schema_version,
        supported_version: SCHEMA_VERSION,
        problems,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::{Store, SystemClock};

    #[test]
    fn inspects_a_current_database_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sverb.db");
        drop(Store::open_at(&path, Arc::new(SystemClock)).unwrap());
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let health = inspect(&path).unwrap();
        assert_eq!(health.schema_version, SCHEMA_VERSION);
        assert!(health.is_intact(), "{:?}", health.problems);
        assert!(!health.is_newer() && !health.needs_migration());
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
    }

    #[test]
    fn missing_or_garbage_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(inspect(&dir.path().join("none.db")).is_err());
        let junk = dir.path().join("junk.db");
        std::fs::write(&junk, vec![0x5a; 8192]).unwrap();
        assert!(inspect(&junk).is_err());
        assert!(!dir.path().join("none.db").exists(), "never created");
    }
}
