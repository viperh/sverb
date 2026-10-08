//! Errors of the sync engine (M4-07).

use sverb_proto::ErrorCode;

/// Why a sync step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// Sync is not set up on this device (no `sync_state.server_url`, no
    /// tokens). There is no default server (§1.1).
    #[error("sync is not configured: {0}")]
    NotConfigured(&'static str),
    /// The refresh token was rejected (or reused): the user must sign in
    /// again (M4-08). Sync pauses.
    #[error("sign-in required")]
    NeedsLogin,
    /// The server could not be reached (connect, TLS, timeout, broken body).
    #[error("server unreachable: {0}")]
    Transport(String),
    /// The server answered with an error envelope (§10.4).
    #[error("server error {status} ({}): {message}", code.map_or("unknown", ErrorCode::as_str))]
    Api {
        /// HTTP status.
        status: u16,
        /// The envelope's code, if the body was one.
        code: Option<ErrorCode>,
        /// The envelope's message (never contains secrets).
        message: String,
    },
    /// The local database failed.
    #[error("local storage: {0}")]
    Store(String),
    /// Local key material is unusable (wrong LMK, corrupt wrapped key).
    #[error("local keys: {0}")]
    Crypto(String),
}

impl SyncError {
    /// Transient: the device is offline or the server is temporarily failing
    /// (transport errors, 5xx, 429). Retried with backoff; status `offline`.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::Api { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }

    /// The envelope code of an API error.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Api { code, .. } => *code,
            _ => None,
        }
    }

    /// An API error with this HTTP status.
    #[must_use]
    pub const fn is_status(&self, status: u16) -> bool {
        matches!(self, Self::Api { status: s, .. } if *s == status)
    }
}

impl From<sverb_store::StoreError> for SyncError {
    fn from(e: sverb_store::StoreError) -> Self {
        Self::Store(e.to_string())
    }
}
