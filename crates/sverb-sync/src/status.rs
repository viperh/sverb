//! What the engine tells the UI (§12.5): the sync status shown in the top bar
//! and status bar, and events (applied remote changes, toasts).

use std::fmt;

use sverb_core::model::{ItemId, VaultId};

/// The sync status (§12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Local-only: sync is not set up (or the build has no sync).
    Disabled,
    /// Everything is pushed and the last pull succeeded.
    Synced,
    /// A sync cycle is running.
    Syncing,
    /// The server is unreachable; `pending` local changes are queued
    /// (offline edits queue indefinitely).
    Offline {
        /// Outbox rows.
        pending: u64,
    },
    /// Something needs attention (an item that can't be pushed, an item that
    /// can't be decrypted, a vault key that can't be refreshed).
    Error {
        /// Human-readable summary.
        message: String,
    },
    /// The refresh token was rejected: sign in again (M4-08). Sync is paused.
    NeedsLogin,
}

impl SyncStatus {
    /// The short form for the status bar: `⟳ synced`, `syncing`,
    /// `offline (3 pending)`, `error`.
    #[must_use]
    pub fn short(&self) -> String {
        match self {
            Self::Disabled => "local-only".into(),
            Self::Synced => "⟳ synced".into(),
            Self::Syncing => "syncing".into(),
            Self::Offline { pending } => format!("offline ({pending} pending)"),
            Self::Error { .. } => "error".into(),
            Self::NeedsLogin => "sign-in required".into(),
        }
    }
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error { message } => write!(f, "error: {message}"),
            other => f.write_str(&other.short()),
        }
    }
}

/// Toast severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    /// Informational (e.g. a resurrected item).
    Info,
    /// Something to look at (clock skew).
    Warn,
    /// A change could not be uploaded.
    Error,
}

/// An event for the UI (`UiEvent::Sync`, M4-09) or the headless CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    /// The status changed.
    Status(SyncStatus),
    /// Remote changes were committed locally: update the search index for
    /// these items (M1-05) and refresh the views.
    Applied {
        /// The vault.
        vault: VaultId,
        /// Items written (replaced or merged), tombstones included.
        items: Vec<ItemId>,
    },
    /// A toast.
    Toast {
        /// Severity.
        level: ToastLevel,
        /// Text.
        message: String,
    },
    /// The account only has read access to `vault`: these local changes were
    /// kept locally and not uploaded. The UI offers "Revert to server
    /// version" and "Copy to personal vault" (M4-09).
    ReadOnly {
        /// The vault.
        vault: VaultId,
        /// The blocked items.
        items: Vec<ItemId>,
    },
}
