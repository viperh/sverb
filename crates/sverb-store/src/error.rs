//! Store errors.

use rusqlite::ErrorCode;
use sverb_core::model::ItemId;
use thiserror::Error;

/// Errors returned by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The database was written by a newer sverb. It was not modified.
    #[error(
        "This database was created by a newer sverb (schema {found}). Please update sverb. \
         (this build supports schema {supported})"
    )]
    NewerSchema {
        /// `PRAGMA user_version` found in the file.
        found: i64,
        /// The latest schema version this build knows.
        supported: i64,
    },

    /// Another connection or process held a lock for longer than `busy_timeout`.
    #[error("the database is busy (another sverb process may be writing); try again")]
    Busy,

    /// The item comes from a newer item schema and must not be overwritten
    /// (SPEC §4.1, `sverb_core::model::migrate`).
    #[error("item {0} was written by a newer sverb and is read-only; update sverb to edit it")]
    ReadOnlyItem(ItemId),

    /// The addressed row does not exist.
    #[error("not found")]
    NotFound,

    /// The file is not a SQLite database or is damaged.
    #[error(
        "the database is corrupt: {0}. Restore it from a backup (or move it away to start fresh)"
    )]
    Corrupt(String),

    /// A value handed to the store does not look like an encrypted envelope.
    /// The store refuses it so plaintext cannot reach disk by mistake.
    #[error("refusing to store an invalid item envelope: {0}")]
    InvalidEnvelope(&'static str),

    /// A migration failed for a reason other than a SQLite error. The database
    /// stays at its previous version (migrations are transactional).
    #[error("database migration failed: {0}")]
    Migration(String),

    /// Filesystem error while preparing the database file.
    #[error("database file: {0}")]
    Io(#[from] std::io::Error),

    /// Any other SQLite error.
    #[error(transparent)]
    Sqlite(rusqlite::Error),

    /// A blocking task panicked or was cancelled.
    #[error("store task failed: {0}")]
    Task(String),
}

/// Convenience alias.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        match err.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Self::Busy,
            Some(ErrorCode::DatabaseCorrupt) => {
                Self::Corrupt("database disk image is malformed".into())
            }
            Some(ErrorCode::NotADatabase) => Self::Corrupt("file is not a SQLite database".into()),
            _ => Self::Sqlite(err),
        }
    }
}

impl From<rusqlite_migration::Error> for StoreError {
    fn from(err: rusqlite_migration::Error) -> Self {
        match err {
            rusqlite_migration::Error::RusqliteError { err, .. } => err.into(),
            other => Self::Migration(other.to_string()),
        }
    }
}
