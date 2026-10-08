//! M4-09: what this device knows about its sync setup, without contacting the
//! server or unlocking: the Settings → Sync panel and `sverb sync --status`.
//!
//! The time of the last successful cycle is kept in `meta`
//! ([`META_LAST_SYNC`], UNIX ms as decimal text); the engine records it after
//! every cycle that finished without an error.

use std::time::{SystemTime, UNIX_EPOCH};

use sverb_core::model::VaultId;
use sverb_store::{Store, VaultKind};

use crate::account::load_account;
use crate::error::SyncError;

/// `meta` key: UNIX ms of the last successful sync cycle.
pub const META_LAST_SYNC: &str = "sync_last_ok";

/// Queued local changes of one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPending {
    /// The vault.
    pub vault: VaultId,
    /// Personal or shared (`None` for an outbox row whose vault is gone).
    pub kind: Option<VaultKind>,
    /// Outbox rows.
    pub pending: u64,
}

/// The local sync state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalSyncInfo {
    /// `sync_state.server_url`; `None` in local-only mode (§1.1).
    pub server_url: Option<String>,
    /// Tokens are stored (the device is signed in).
    pub signed_in: bool,
    /// `meta.account.email`.
    pub email: Option<String>,
    /// UNIX ms of the last successful cycle.
    pub last_sync_ms: Option<i64>,
    /// Pending changes per vault (only vaults with some).
    pub pending: Vec<VaultPending>,
}

impl LocalSyncInfo {
    /// Whether sync is set up (a server URL is stored). `false` is local-only mode.
    #[must_use]
    pub fn connected(&self) -> bool {
        self.server_url.is_some()
    }

    /// All pending changes.
    #[must_use]
    pub fn pending_total(&self) -> u64 {
        self.pending.iter().map(|p| p.pending).sum()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Records a successful cycle now. Failures are logged, never fatal.
pub(crate) async fn record_sync(store: &Store) {
    let value = now_ms().to_string().into_bytes();
    if let Err(e) = store.set_meta(META_LAST_SYNC, value).await {
        tracing::warn!(error = %e, "cannot record the last sync time");
    }
}

/// Reads the local sync state (no network, no keys needed).
///
/// # Errors
/// [`SyncError::Store`].
pub async fn local_info(store: &Store) -> Result<LocalSyncInfo, SyncError> {
    let state = store.get_sync_state().await?;
    let server_url = state.as_ref().and_then(|s| s.server_url.clone());
    let signed_in = state.as_ref().is_some_and(|s| s.tokens_enc.is_some());
    let email = match load_account(store).await {
        Ok(a) => a.map(|a| a.email),
        Err(e) => {
            tracing::debug!(error = %e, "no readable account record");
            None
        }
    };
    let last_sync_ms = store
        .get_meta(META_LAST_SYNC)
        .await?
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|v| v.trim().parse().ok());
    let vaults = store.list_vaults().await?;
    let pending = store
        .pending_by_vault()
        .await?
        .into_iter()
        .map(|(vault, pending)| VaultPending {
            vault,
            kind: vaults.iter().find(|v| v.id == vault).map(|v| v.kind),
            pending,
        })
        .collect();
    Ok(LocalSyncInfo {
        server_url,
        signed_in,
        email,
        last_sync_ms,
        pending,
    })
}
