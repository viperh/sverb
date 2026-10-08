//! Online password change (§11.2.1, M4-08 §2.4).
//!
//! 1. OPAQUE login with the old password (`purpose: reauth`) proves
//!    knowledge (the account keys come from the device's copy under the
//!    LMK).
//! 2. A new OPAQUE record and the bundle re-sealed under the new AKEK are
//!    uploaded **atomically** (`POST /v1/account/password`, version + 1). The
//!    server notifies the other devices (`account_changed`) and revokes their
//!    tokens.
//! 3. The LMK is re-wrapped under the new password (new salt) and
//!    `meta.account` moves to the new version, in one local transaction.
//!
//! The server must be reachable: offline, the change is refused before
//! anything happens. For a crash between 2 and 3, see the recovery path in
//! the [module docs](super).
//!
//! In local-only mode only the LMK is re-wrapped (M1-04
//! `VaultEngine::change_password`); the UI routes here when sync is set up.

use sverb_crypto::Key32;
use sverb_crypto::account::{derive_akek, seal_private_bundle};
use sverb_crypto::opaque::client_registration_start;
use sverb_crypto::random::os_rng;
use sverb_proto::auth::{
    KeyVersionResponse, LoginDevice, LoginPurpose, PasswordChangeRequest, PasswordStartRequest,
    PasswordStartResponse, ReauthResponse,
};
use sverb_store::Store;
use zeroize::Zeroizing;

use super::local::{self, LocalAccount};
use super::login::opaque_login;
use super::{AccountConfig, AccountError, require_strong};
use crate::error::SyncError;
use crate::tokens::TokenManager;

/// The message for an offline attempt (T-08).
pub const NEEDS_SERVER: &str =
    "changing the password of a synced account needs the server; connect and try again";

/// Changes the account (and local master) password. Returns the new
/// `account_keys.version`.
///
/// # Errors
/// [`AccountError::Unreachable`] (with [`NEEDS_SERVER`]) when the server
/// can't be reached, [`AccountError::LoginFailed`] for a wrong old password,
/// [`AccountError::WeakPassword`], [`AccountError::NotSignedIn`].
pub async fn change_password(
    store: &Store,
    lmk: &Key32,
    old_password: &str,
    new_password: &str,
    totp: Option<String>,
    cfg: &AccountConfig,
) -> Result<u32, AccountError> {
    require_strong(new_password)?;
    let state = store
        .get_sync_state()
        .await?
        .filter(|s| s.tokens_enc.is_some())
        .ok_or(AccountError::NotSignedIn)?;
    let url = state.server_url.ok_or(AccountError::NotSignedIn)?;
    let (acct, keys) = local::load_account_keys(store, lmk)
        .await?
        .ok_or(AccountError::NotSignedIn)?;
    let api = cfg.client(&url)?;
    let offline = |e: SyncError| match e {
        SyncError::Transport(m) => AccountError::Unreachable(format!("{NEEDS_SERVER} ({m})")),
        other => other.into(),
    };
    api.probe().await.map_err(offline)?;
    let tokens = TokenManager::load(store.clone(), lmk.clone(), api.clone()).await?;
    let access = tokens.access().await.map_err(offline)?;

    // 1. Reauth with the old password; open the current bundle with it.
    let (old_export, reauth): (_, ReauthResponse) = opaque_login(
        &api,
        &acct.email,
        old_password,
        cfg,
        LoginPurpose::Reauth,
        LoginDevice::default(),
        totp,
    )
    .await?;
    drop(old_export);
    if reauth.user_id != acct.user_id {
        return Err(AccountError::Local(
            "the server answered for a different account".into(),
        ));
    }
    let uid = *reauth.user_id.as_bytes();
    let version = acct.key_version;

    // 2. New OPAQUE record + re-sealed bundle, uploaded atomically.
    let mut rng = os_rng();
    let (reg, request) = client_registration_start(&mut rng, new_password.as_bytes())?;
    let start: PasswordStartResponse = api
        .post_v1(
            "/account/password/start",
            &PasswordStartRequest {
                registration_request: request,
            },
            Some(&access),
        )
        .await?;
    let ksf = cfg.ksf.clone();
    let pw = Zeroizing::new(new_password.to_owned());
    let fin = tokio::task::spawn_blocking(move || {
        reg.finish(
            &mut os_rng(),
            pw.as_bytes(),
            &start.registration_response,
            &ksf,
        )
    })
    .await
    .map_err(|e| AccountError::Local(e.to_string()))??;
    let new_version = version + 1;
    let bundle = seal_private_bundle(
        &derive_akek(&fin.export_key),
        &uid,
        new_version,
        &keys,
        &mut rng,
    )?;
    let resp: KeyVersionResponse = api
        .post_v1(
            "/account/password",
            &PasswordChangeRequest {
                reauth_token: reauth.reauth_token.clone(),
                registration_upload: fin.upload.clone(),
                private_bundle_enc: bundle,
                version: new_version,
            },
            Some(&access),
        )
        .await?;

    // 3. Local re-wrap and the new version, in one transaction.
    let wrap = local::wrap_lmk(lmk, new_password, cfg.kdf_cost).await?;
    let acct = LocalAccount {
        key_version: resp.version,
        ..acct
    };
    let keys_enc = local::seal_local_keys(lmk, &acct, &keys)?;
    store
        .write(move |w| {
            local::write_lmk_wrap(w, &wrap)?;
            local::write_account(w, &acct, &keys_enc)
        })
        .await?;
    tracing::info!(version = resp.version, "account password changed");
    Ok(resp.version)
}
