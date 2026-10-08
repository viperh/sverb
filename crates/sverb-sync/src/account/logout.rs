//! Disconnect (`sverb logout`, Settings → Sync → Disconnect; §1.1,
//! §11.2.1, M4-08 §2.8).
//!
//! * The tokens are revoked server-side (`POST /v1/auth/logout`); offline,
//!   the local part still runs and the report says so.
//! * Shared vaults are removed from the device (they belong to the org).
//! * The personal vault and the password stay. Its items are reset to
//!   "never synced" (`revision = 0`, dirty, `base_revision = 0`, cursor 0),
//!   so a later registration or login behaves like 2.1 / 2.2 (the server
//!   merges identical items, so re-logging in creates no duplicates).
//! * `sync_state` and `meta.account` are cleared.
//!
//! Without `--keep-local` the caller then wipes the local database (a fresh
//! start; the binary deletes the files after confirmation).

use sverb_crypto::Key32;
use sverb_store::{Store, VaultKind};

use super::local;
use super::{AccountConfig, AccountError};
use crate::error::SyncError;
use crate::tokens::TokenManager;

/// What [`logout`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutReport {
    /// The server revoked the tokens. `false`: it was unreachable or the
    /// tokens were already invalid.
    pub revoked: bool,
    /// Why the revocation did not happen.
    pub revoke_error: Option<String>,
    /// Shared vaults removed from this device.
    pub shared_removed: usize,
    /// Personal items kept (now queued for a later upload).
    pub kept_items: u64,
}

async fn revoke(
    store: &Store,
    lmk: &Key32,
    url: &str,
    cfg: &AccountConfig,
) -> Result<(), SyncError> {
    let api = cfg
        .client(url)
        .map_err(|e| SyncError::Transport(e.to_string()))?;
    let tokens = TokenManager::load(store.clone(), lmk.clone(), api.clone()).await?;
    let token = tokens.access().await?;
    api.post_v1_empty::<()>("/auth/logout", None, Some(&token))
        .await
}

/// Logs this device out and keeps the personal data (see the module docs).
///
/// # Errors
/// [`AccountError::Local`].
pub async fn logout(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
) -> Result<LogoutReport, AccountError> {
    let mut report = LogoutReport::default();
    let state = store.get_sync_state().await?;
    match state.as_ref().and_then(|s| s.server_url.as_deref()) {
        Some(url) if state.as_ref().is_some_and(|s| s.tokens_enc.is_some()) => {
            match revoke(store, lmk, url, cfg).await {
                Ok(()) => report.revoked = true,
                Err(e) => {
                    tracing::warn!(error = %e, "could not revoke the tokens; logging out locally");
                    report.revoke_error = Some(e.to_string());
                }
            }
        }
        _ => report.revoke_error = Some("not signed in".into()),
    }
    let (removed, kept) = store
        .write(|w| {
            let mut removed = 0;
            let mut kept = 0;
            for row in w.as_read().list_vaults()? {
                match row.kind {
                    VaultKind::Shared => {
                        w.delete_vault(row.id)?;
                        removed += 1;
                    }
                    VaultKind::Personal => kept += w.reset_sync(row.id)?,
                }
            }
            w.clear_sync_state()?;
            local::clear_account(w)?;
            Ok((removed, kept))
        })
        .await?;
    report.shared_removed = removed;
    report.kept_items = kept;
    tracing::info!(
        revoked = report.revoked,
        shared_removed = removed,
        "logged out"
    );
    Ok(report)
}
