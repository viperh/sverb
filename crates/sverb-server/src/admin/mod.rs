//! Admin operations behind `sverb-server admin …` (SPEC §10.6).
//!
//! Each function works on a pool and returns data; the CLI ([`crate::cli`])
//! does the printing, so integration tests can call these directly.

pub mod gc;
pub mod invite;
pub mod user;

/// Admin command errors.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// Database failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx_core::Error),
    /// The named user does not exist.
    #[error("no user with email {0}")]
    NoSuchUser(String),
    /// Invalid input (e.g. a malformed email).
    #[error("{0}")]
    Invalid(String),
}

impl From<crate::error::ApiError> for AdminError {
    fn from(e: crate::error::ApiError) -> Self {
        Self::Invalid(e.to_string())
    }
}
