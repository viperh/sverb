//! The device side of an account: the local master password (LMK wrap,
//! M1-04 format), the account keys kept under the LMK, and `meta.account`.

use serde::{Deserialize, Serialize};
use sverb_core::model::{DeviceId, Hlc, HlcClock, VaultId};
use sverb_core::vault::{Argon2Cost, KdfParams};
use sverb_crypto::Key32;
use sverb_crypto::account::{AccountKeys, open_private_bundle, seal_private_bundle};
use sverb_crypto::kdf::{argon2id, hkdf_key32};
use sverb_crypto::random::{os_rng, random_salt16};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key32, wrap_key};
use sverb_store::meta::keys;
use sverb_store::{Store, VaultKind, VaultRow, WriteTx};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::AccountError;

/// `meta` key of [`LocalAccount`] (JSON).
pub const META_ACCOUNT: &str = "account";
/// `meta` key of the account keys sealed under the LMK.
pub const META_ACCOUNT_KEYS: &str = "account_keys_enc";

const LOCAL_KEYS_INFO: &[u8] = b"sverb/local-account-keys/v1";

/// The account this device is signed in to (`meta.account`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccount {
    /// Server user id.
    pub user_id: Uuid,
    /// Account email.
    pub email: String,
    /// `account_keys.version` this device last saw (bumped by password
    /// changes and recovery).
    pub key_version: u32,
}

/// `meta.account`, if this device is signed in (or was, before a crash).
///
/// # Errors
/// [`AccountError::Local`].
pub async fn load_account(store: &Store) -> Result<Option<LocalAccount>, AccountError> {
    let raw = store.get_meta(META_ACCOUNT).await?;
    raw.map(|b| {
        serde_json::from_slice(&b).map_err(|e| AccountError::Local(format!("meta.account: {e}")))
    })
    .transpose()
}

fn local_keys_kek(lmk: &Key32) -> Key32 {
    hkdf_key32(lmk.expose_secret(), None, LOCAL_KEYS_INFO)
}

/// Seals the account keys for `meta.account_keys_enc`.
pub(crate) fn seal_local_keys(
    lmk: &Key32,
    acct: &LocalAccount,
    keys: &AccountKeys,
) -> Result<Vec<u8>, AccountError> {
    Ok(seal_private_bundle(
        &local_keys_kek(lmk),
        acct.user_id.as_bytes(),
        acct.key_version,
        keys,
        &mut os_rng(),
    )?)
}

/// The account and its keys, opened with the LMK (`None` when not signed in).
///
/// # Errors
/// [`AccountError::Local`] / [`AccountError::Crypto`].
pub async fn load_account_keys(
    store: &Store,
    lmk: &Key32,
) -> Result<Option<(LocalAccount, AccountKeys)>, AccountError> {
    let Some(acct) = load_account(store).await? else {
        return Ok(None);
    };
    let Some(enc) = store.get_meta(META_ACCOUNT_KEYS).await? else {
        return Ok(None);
    };
    let keys = open_private_bundle(
        &local_keys_kek(lmk),
        acct.user_id.as_bytes(),
        acct.key_version,
        &enc,
    )?;
    Ok(Some((acct, keys)))
}

/// Writes `meta.account` and the sealed keys (inside a transaction).
pub(crate) fn write_account(
    w: &WriteTx<'_>,
    acct: &LocalAccount,
    keys_enc: &[u8],
) -> sverb_store::Result<()> {
    let json = serde_json::to_vec(acct)
        .map_err(|e| sverb_store::StoreError::Corrupt(format!("meta.account: {e}")))?;
    w.set_meta(META_ACCOUNT, &json)?;
    w.set_meta(META_ACCOUNT_KEYS, keys_enc)
}

/// Removes `meta.account` and the sealed keys (inside a transaction).
pub(crate) fn clear_account(w: &WriteTx<'_>) -> sverb_store::Result<()> {
    w.delete_meta(META_ACCOUNT)?;
    w.delete_meta(META_ACCOUNT_KEYS)
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AccountError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AccountError::Local(format!("background task failed: {e}")))
}

/// Tries `password` against `meta.lmk_wrapped_pw`: `Some(lmk)` when it is the
/// local master password, `None` when not. This is a probe (it does not count
/// toward the unlock backoff): the account flows use it to verify the current
/// password (registration) and to detect a differing account password
/// (login).
///
/// # Errors
/// [`AccountError::Local`] when the vault is not initialized or `meta.kdf`
/// is corrupt.
pub async fn try_local_password(
    store: &Store,
    password: &str,
) -> Result<Option<Key32>, AccountError> {
    let (kdf, wrapped) = store
        .read(|r| Ok((r.get_meta(keys::KDF)?, r.get_meta(keys::LMK_WRAPPED_PW)?)))
        .await?;
    let (Some(kdf), Some(wrapped)) = (kdf, wrapped) else {
        return Err(AccountError::Local(
            "sverb is not initialized; set a master password first".into(),
        ));
    };
    let params = KdfParams::from_cbor(&kdf).map_err(|e| AccountError::Local(e.to_string()))?;
    let pw = Zeroizing::new(password.as_bytes().to_vec());
    let kek = blocking(move || argon2id(&pw, &params.argon2()))
        .await?
        .map_err(|e| AccountError::Local(format!("meta.kdf: {e}")))?;
    Ok(unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped).ok())
}

/// A new password wrap of `lmk` (new salt): `(meta.kdf, meta.lmk_wrapped_pw)`.
///
/// # Errors
/// [`AccountError::Crypto`].
pub(crate) async fn wrap_lmk(
    lmk: &Key32,
    password: &str,
    cost: Argon2Cost,
) -> Result<(Vec<u8>, Vec<u8>), AccountError> {
    let params = cost.with_salt(random_salt16(&mut os_rng()));
    let pw = Zeroizing::new(password.as_bytes().to_vec());
    let kek = blocking(move || argon2id(&pw, &params.argon2())).await??;
    let wrapped = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut os_rng())?;
    Ok((params.to_cbor(), wrapped))
}

/// Stores a wrap from [`wrap_lmk`] (inside a transaction) and clears the
/// unlock backoff. The keyring wrap (same LMK) is left alone.
pub(crate) fn write_lmk_wrap(
    w: &WriteTx<'_>,
    wrap: &(Vec<u8>, Vec<u8>),
) -> sverb_store::Result<()> {
    w.set_meta(keys::KDF, &wrap.0)?;
    w.set_meta(keys::LMK_WRAPPED_PW, &wrap.1)?;
    w.delete_meta(keys::UNLOCK_FAILURES)?;
    w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
}

/// The local personal vault and its key.
///
/// # Errors
/// [`AccountError::Local`] when there is none or its key does not unwrap.
pub(crate) async fn personal_vault(
    store: &Store,
    lmk: &Key32,
) -> Result<(VaultRow, Key32), AccountError> {
    let rows = store.list_vaults().await?;
    let row = rows
        .into_iter()
        .find(|r| r.kind == VaultKind::Personal)
        .ok_or_else(|| AccountError::Local("there is no personal vault".into()))?;
    let vk = unwrap_vault_key(lmk, &row)?;
    Ok((row, vk))
}

/// Unwraps `row.wrapped_key` with the LMK.
pub(crate) fn unwrap_vault_key(lmk: &Key32, row: &VaultRow) -> Result<Key32, AccountError> {
    unwrap_key32(
        lmk,
        &WrapPurpose::VaultKey(*row.id.as_bytes()),
        &row.wrapped_key,
    )
    .map_err(|e| AccountError::Local(format!("vault {} key: {e}", row.id.short())))
}

/// Wraps a vault key under the LMK for `vaults.wrapped_key`.
pub(crate) fn wrap_vault_key(
    lmk: &Key32,
    vault: VaultId,
    vk: &Key32,
) -> Result<Vec<u8>, AccountError> {
    Ok(wrap_key(
        lmk,
        &WrapPurpose::VaultKey(*vault.as_bytes()),
        vk.expose_secret(),
        &mut os_rng(),
    )?)
}

/// The device id and HLC from `meta` (M1-04), for stamping local writes.
pub(crate) async fn device_clock(store: &Store) -> Result<(DeviceId, HlcClock), AccountError> {
    let (device, hlc) = store
        .read(|r| Ok((r.get_meta(keys::DEVICE_ID)?, r.get_meta(keys::HLC_LAST)?)))
        .await?;
    let device = device
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map_or_else(DeviceId::new, DeviceId::from_bytes);
    let last = hlc
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map_or(Hlc::ZERO, |b| Hlc::from_u64(u64::from_be_bytes(b)));
    Ok((device, HlcClock::default().with_last(last)))
}
