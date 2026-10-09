//!
//! 1. [`request_recovery_code`]: the server mails a one-time code (or the
//!    operator issues it with `sverb-server admin user recovery-code`).
//! 2. [`recover_account`]: email + code + the 24 words + a new password
//!    (zxcvbn ≥ 3) → `recovery/start` returns the `recovery_bundle`, which
//!    the recovery key opens; the account keys are re-sealed under the new
//!    AKEK (version + 1) and the upload is signed with the account Ed25519
//!    key; `recovery` replaces the OPAQUE record and revokes every device.
//! 3. The device then signs in again with the new password
//!    ([`super::start_login`]). If it has local data it must be unlocked
//!    first (old password or OS keyring); the login re-wraps the LMK under
//!    the new password. A device that can't unlock its local data can only
//!    wipe it and log in fresh (the data is on the server).

use sverb_crypto::account::{derive_akek, seal_private_bundle};
use sverb_crypto::opaque::{client_registration_start, recovery_proof_message};
use sverb_crypto::random::os_rng;
use sverb_crypto::recovery::{open_recovery_bundle, recovery_key_from_mnemonic};
use sverb_crypto::sign;
use sverb_proto::auth::{
    KeyVersionResponse, RecoveryCodeRequest, RecoveryFinishRequest, RecoveryStartRequest,
    RecoveryStartResponse,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{AccountConfig, AccountError, probe_server, require_strong};
use crate::error::SyncError;

/// The result of a recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// The account.
    pub user_id: Uuid,
    /// The new `account_keys.version`.
    pub key_version: u32,
}

/// Asks the server to mail a recovery code to `email` (202 whether or not
/// the account exists).
///
/// # Errors
/// [`AccountError::Unreachable`] and other transport errors.
pub async fn request_recovery_code(
    server_url: &str,
    email: &str,
    cfg: &AccountConfig,
) -> Result<(), AccountError> {
    let api = probe_server(server_url, cfg).await?;
    api.post_v1_empty(
        "/account/recovery/code",
        Some(&RecoveryCodeRequest {
            email: email.trim().to_owned(),
        }),
        None,
    )
    .await?;
    Ok(())
}

fn code_error(e: SyncError) -> AccountError {
    match e {
        SyncError::Api { status: 401, .. } => AccountError::BadRecoveryCode,
        SyncError::Api { status: 403, .. } => {
            AccountError::BadRecoveryPhrase("the server rejected the recovery proof".into())
        }
        other => other.into(),
    }
}

/// Resets the account password with the recovery phrase (step 2 above).
///
/// # Errors
/// [`AccountError::BadRecoveryPhrase`] (unparsable phrase, or it does not
/// open the bundle), [`AccountError::BadRecoveryCode`],
/// [`AccountError::WeakPassword`], [`AccountError::Unreachable`].
pub async fn recover_account(
    server_url: &str,
    email: &str,
    code: &str,
    words: &str,
    new_password: &str,
    cfg: &AccountConfig,
) -> Result<Recovered, AccountError> {
    require_strong(new_password)?;
    let recovery = recovery_key_from_mnemonic(words)
        .map_err(|e| AccountError::BadRecoveryPhrase(e.to_string()))?;
    let api = probe_server(server_url, cfg).await?;
    let email = email.trim().to_owned();
    let mut rng = os_rng();
    let (reg, request) = client_registration_start(&mut rng, new_password.as_bytes())?;
    let start: RecoveryStartResponse = api
        .post_v1(
            "/account/recovery/start",
            &RecoveryStartRequest {
                email: email.clone(),
                code: code.trim().to_owned(),
                registration_request: request,
            },
            None,
        )
        .await
        .map_err(code_error)?;
    let uid = *start.user_id.as_bytes();
    let keys = open_recovery_bundle(&recovery, &uid, &start.recovery_bundle_enc).map_err(|_| {
        AccountError::BadRecoveryPhrase(
            "this recovery phrase does not belong to the account".into(),
        )
    })?;
    let ksf = cfg.ksf.clone();
    let pw = Zeroizing::new(new_password.to_owned());
    let response = start.registration_response.clone();
    let fin = tokio::task::spawn_blocking(move || {
        reg.finish(&mut os_rng(), pw.as_bytes(), &response, &ksf)
    })
    .await
    .map_err(|e| AccountError::Local(e.to_string()))??;
    let version = start.version + 1;
    let bundle = seal_private_bundle(
        &derive_akek(&fin.export_key),
        &uid,
        version,
        &keys,
        &mut rng,
    )?;
    let msg = recovery_proof_message(&uid, version, &fin.upload, &bundle);
    let signature = sign::sign(keys.ed25519_signing_key(), &msg);
    let resp: KeyVersionResponse = api
        .post_v1(
            "/account/recovery",
            &RecoveryFinishRequest {
                email,
                code: code.trim().to_owned(),
                registration_upload: fin.upload.clone(),
                private_bundle_enc: bundle,
                version,
                signature: signature.to_vec(),
            },
            None,
        )
        .await
        .map_err(code_error)?;
    tracing::info!(user_id = %start.user_id, version = resp.version, "account recovered");
    Ok(Recovered {
        user_id: start.user_id,
        key_version: resp.version,
    })
}
