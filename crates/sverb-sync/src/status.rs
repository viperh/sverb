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
    /// The refresh token was rejected: sign in again. Sync is paused.
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

/// An event for the UI (`UiEvent::Sync`) or the headless CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    /// The status changed.
    Status(SyncStatus),
    /// Remote changes were committed locally: update the search index for
    /// these items and refresh the views.
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
    /// A stamp from another device was ahead of this clock. Sent once per
    /// device per engine; the TUI shows "Clock skew detected on device X"
    /// once per device per session.
    ClockSkew {
        /// The other device (short id).
        device: String,
        /// How far ahead its stamp was.
        ahead_secs: u64,
    },
    /// The account only has read access to `vault`: these local changes were
    /// kept locally and not uploaded. The UI offers "Revert to server
    /// version" and "Copy to personal vault".
    ReadOnly {
        /// The vault.
        vault: VaultId,
        /// The blocked items.
        items: Vec<ItemId>,
    },
    /// A shared vault was granted to this account, verified and stored locally
    /// (its key is wrapped under the LMK); its items follow as `Applied`. The UI
    /// loads the new key and lists the vault.
    VaultAdded {
        /// The vault.
        vault: VaultId,
        /// Its name, opened with the vault key.
        name: Option<String>,
    },
    /// A vault's key was rotated and this device switched to the new key (its
    /// local items were re-sealed; the rotated items follow as `Applied`). The UI
    /// reloads the vault key.
    KeyRotated {
        /// The vault.
        vault: VaultId,
        /// The new key version.
        key_version: u32,
    },
    /// A key rotation of a vault this account manages was abandoned (15 minutes
    /// without a commit, §13.2): pushes stay paused until it is restarted. The UI
    /// prompts to restart it. Sent once per vault per engine.
    RotationAbandoned {
        /// The vault.
        vault: VaultId,
    },
}
