//! M4-09: the account's devices (Settings → Devices, `sverb devices`; §10.2.7).
//!
//! Listing and revoking need the unlocked vault (the tokens are sealed under
//! the LMK). Revoking **this** device is a logout: the server drops its
//! tokens, then the local part of [`logout`](super::logout()) runs (shared
//! vaults removed, personal data kept, `sync_state` cleared).

use sverb_crypto::Key32;
use sverb_proto::auth::DeviceView;
use sverb_store::Store;
use uuid::Uuid;

use super::logout::{LogoutReport, logout};
use super::{AccountConfig, AccountError};
use crate::error::SyncError;
use crate::http::ApiClient;
use crate::tokens::TokenManager;

/// What [`revoke_device`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoked {
    /// Another device was revoked.
    Other,
    /// This device was revoked and logged out locally.
    ThisDevice(LogoutReport),
}

async fn session(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
) -> Result<TokenManager, AccountError> {
    let url = store
        .get_sync_state()
        .await?
        .and_then(|s| s.server_url)
        .ok_or(AccountError::NotSignedIn)?;
    let api = cfg.client(&url)?;
    Ok(TokenManager::load(store.clone(), lmk.clone(), api).await?)
}

/// Runs `f` with an access token; refreshes once after a 401.
async fn call<T, F, Fut>(tokens: &TokenManager, f: F) -> Result<T, SyncError>
where
    F: Fn(ApiClient, String) -> Fut,
    Fut: Future<Output = Result<T, SyncError>>,
{
    let token = tokens.access().await?;
    match f(tokens.api().clone(), token.clone()).await {
        Err(e) if e.is_status(401) => {
            tokens.refresh_after_401(&token).await?;
            let token = tokens.access().await?;
            f(tokens.api().clone(), token).await
        }
        other => other,
    }
}

/// `GET /v1/devices`, revoked devices left out, this device first, then by
/// creation time.
///
/// # Errors
/// [`AccountError::NotSignedIn`], [`AccountError::Unreachable`], …
pub async fn list_devices(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
) -> Result<Vec<DeviceView>, AccountError> {
    let tokens = session(store, lmk, cfg).await?;
    let mut list = call(&tokens, |api, t| async move { api.list_devices(&t).await }).await?;
    list.retain(|d| d.revoked_at.is_none());
    list.sort_by(|a, b| {
        b.current
            .cmp(&a.current)
            .then(a.created_at.cmp(&b.created_at))
            .then(a.id.cmp(&b.id))
    });
    Ok(list)
}

/// `DELETE /v1/devices/{id}`. Revoking this device also logs it out locally.
///
/// # Errors
/// [`AccountError::NotSignedIn`], [`AccountError::Unreachable`],
/// [`AccountError::Sync`] (`404` for an unknown device), …
pub async fn revoke_device(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    device: Uuid,
) -> Result<Revoked, AccountError> {
    let tokens = session(store, lmk, cfg).await?;
    let list = call(&tokens, |api, t| async move { api.list_devices(&t).await }).await?;
    let current = list.iter().any(|d| d.id == device && d.current);
    call(&tokens, |api, t| async move { api.revoke_device(&t, device).await }).await?;
    drop(tokens);
    if !current {
        return Ok(Revoked::Other);
    }
    // The server already dropped this device's tokens: the logout's own
    // revocation fails (and is reported), the local part runs.
    let mut report = logout(store, lmk, cfg).await?;
    report.revoked = true;
    report.revoke_error = None;
    Ok(Revoked::ThisDevice(report))
}
