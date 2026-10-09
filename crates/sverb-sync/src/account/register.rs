//! Local-only → new account (§11.2.1).
//!
//! 1. [`prepare_registration`]: probe the server, verify the **current**
//!    master password locally (it unwraps the LMK), generate the account
//!    keypairs and the recovery key. Nothing is sent yet.
//! 2. The UI shows the 24 words once and makes the user re-type three of
//!    them ([`super::RecoveryConfirm`]).
//! 3. [`finish_registration`]: OPAQUE registration with that password, the
//!    sealed bundles, the personal vault's self-grant (same vault id, VK and
//!    item ids) and the device; then `sync_state`, `meta.account`, and every
//!    item marked dirty with `base_revision = 0`, so the sync engine uploads
//!    everything.
//!
//! A crash after the server accepted `register/finish` but before the local
//! commit leaves the account without a signed-in device: logging in
//! ([`super::start_login`]) finds the local vault is the account's personal
//! vault and simply signs in.

use std::fmt;

use sverb_core::model::{DeviceId, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::account::{AccountKeys, derive_akek, generate_account_keys, seal_private_bundle};
use sverb_crypto::envelope::seal_item;
use sverb_crypto::grant::self_grant;
use sverb_crypto::opaque::client_registration_start;
use sverb_crypto::random::os_rng;
use sverb_crypto::recovery::{
    RecoveryKey, RecoveryMnemonic, recovery_key_generate, seal_recovery_bundle,
};
use sverb_proto::ErrorCode;
use sverb_proto::auth::{
    AccountKeysUpload, GrantUpload, PersonalVaultUpload, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse, SessionResponse,
};
use sverb_store::Store;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::local::{self, LocalAccount};
use super::{AccountConfig, AccountError, probe_server, require_strong};
use crate::error::SyncError;
use crate::http::ApiClient;
use crate::tokens::TokenManager;

/// The account keys' first version.
const FIRST_KEY_VERSION: u32 = 1;

/// The plaintext personal-vault name sealed into `name_enc`.
pub const PERSONAL_VAULT_NAME: &str = "Personal";

/// An invite or first-admin setup token for a server that is not `open`.
#[derive(Clone, PartialEq, Eq)]
pub enum RegistrationToken {
    /// An instance or org invite.
    Invite(String),
    /// The one-time setup token printed by `sverb-server` on first start.
    Setup(String),
}

impl fmt::Debug for RegistrationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invite(_) => f.write_str("Invite([REDACTED])"),
            Self::Setup(_) => f.write_str("Setup([REDACTED])"),
        }
    }
}

impl RegistrationToken {
    fn split(token: Option<&Self>) -> (Option<String>, Option<String>) {
        match token {
            Some(Self::Invite(t)) => (Some(t.clone()), None),
            Some(Self::Setup(t)) => (None, Some(t.clone())),
            None => (None, None),
        }
    }
}

/// Step 1 done: keys and recovery key generated, password verified.
pub struct PreparedRegistration {
    api: ApiClient,
    email: String,
    password: Zeroizing<String>,
    lmk: Key32,
    vault: VaultId,
    vk: Key32,
    vault_key_version: u32,
    keys: AccountKeys,
    recovery: RecoveryKey,
    mnemonic: RecoveryMnemonic,
}

impl fmt::Debug for PreparedRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedRegistration")
            .field("server", &self.api.base_url())
            .field("email", &self.email)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl PreparedRegistration {
    /// The 24 recovery words, to show **once** (never log them).
    #[must_use]
    pub fn recovery_words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }

    /// The recovery phrase as one string (zeroized on drop).
    #[must_use]
    pub fn recovery_phrase(&self) -> Zeroizing<String> {
        self.mnemonic.phrase()
    }

    /// The personal vault that becomes the account's personal vault.
    #[must_use]
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    /// The LMK the password unwrapped (to start the sync engine afterwards).
    #[must_use]
    pub const fn lmk(&self) -> &Key32 {
        &self.lmk
    }

    /// The server.
    #[must_use]
    pub fn server_url(&self) -> &str {
        self.api.base_url()
    }
}

/// The result of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The new account.
    pub user_id: Uuid,
    /// This device, as the server knows it.
    pub device_id: Uuid,
    /// The personal vault (unchanged id).
    pub vault: VaultId,
    /// Items queued for upload.
    pub queued: u64,
}

/// Step 1 (§2.1.1–3): probe `server_url`, verify `password` is the current
/// local master password (zxcvbn ≥ 3), and generate the account keys and the
/// recovery key.
///
/// # Errors
/// [`AccountError::Unreachable`] / [`AccountError::IncompatibleServer`],
/// [`AccountError::WrongLocalPassword`], [`AccountError::WeakPassword`],
/// [`AccountError::Local`] (not initialized, already signed in, no personal
/// vault).
pub async fn prepare_registration(
    store: &Store,
    server_url: &str,
    email: &str,
    password: &str,
    cfg: &AccountConfig,
) -> Result<PreparedRegistration, AccountError> {
    let email = email.trim().to_owned();
    if email.is_empty() || !email.contains('@') {
        return Err(AccountError::Local("enter a valid email address".into()));
    }
    if store
        .get_sync_state()
        .await?
        .is_some_and(|s| s.tokens_enc.is_some())
    {
        return Err(AccountError::Local(
            "this device is already signed in; log out first".into(),
        ));
    }
    let api = probe_server(server_url, cfg).await?;
    let lmk = local::try_local_password(store, password)
        .await?
        .ok_or(AccountError::WrongLocalPassword)?;
    // password now also protects the server-side bundle.
    require_strong(password)?;
    let (row, vk) = local::personal_vault(store, &lmk).await?;
    let mut rng = os_rng();
    let keys = generate_account_keys(&mut rng);
    let (recovery, mnemonic) = recovery_key_generate(&mut rng);
    Ok(PreparedRegistration {
        api,
        email,
        password: Zeroizing::new(password.to_owned()),
        lmk,
        vault: row.id,
        vk,
        vault_key_version: row.key_version,
        keys,
        recovery,
        mnemonic,
    })
}

fn register_error(e: SyncError) -> AccountError {
    match &e {
        SyncError::Api {
            status: 403,
            message,
            ..
        } => AccountError::InviteRequired(message.clone()),
        SyncError::Api {
            code: Some(ErrorCode::Conflict),
            ..
        } => AccountError::AlreadyRegistered,
        _ => e.into(),
    }
}

/// `name_enc` of the personal vault: the name sealed like an item envelope
/// with the vault id as item id (so it is bound to this vault).
pub(crate) fn seal_vault_name(
    vk: &Key32,
    vault: VaultId,
    kv: u32,
    name: &str,
) -> Result<Vec<u8>, AccountError> {
    Ok(seal_item(
        vk,
        vault.as_bytes(),
        vault.as_bytes(),
        kv,
        name.as_bytes(),
        &mut os_rng(),
    )?)
}

/// Step 3 (§2.1.4–7): OPAQUE registration and upload, then the local commit.
/// Call it only after the recovery words were confirmed. On
/// [`AccountError::InviteRequired`] ask for a token and call again with the
/// same `prepared`.
///
/// # Errors
/// [`AccountError::InviteRequired`], [`AccountError::AlreadyRegistered`],
/// [`AccountError::Unreachable`], [`AccountError::Local`].
pub async fn finish_registration(
    store: &Store,
    prepared: &PreparedRegistration,
    token: Option<&RegistrationToken>,
    cfg: &AccountConfig,
) -> Result<Registered, AccountError> {
    let p = prepared;
    let mut rng = os_rng();
    let (invite_token, setup_token) = RegistrationToken::split(token);
    let (state, request) = client_registration_start(&mut rng, p.password.as_bytes())?;
    let start: RegisterStartResponse = p
        .api
        .post_v1(
            "/auth/register/start",
            &RegisterStartRequest {
                email: p.email.clone(),
                registration_request: request,
                invite_token: invite_token.clone(),
                setup_token: setup_token.clone(),
            },
            None,
        )
        .await
        .map_err(register_error)?;
    let ksf = cfg.ksf.clone();
    let password = p.password.clone();
    let response = start.registration_response.clone();
    let fin = tokio::task::spawn_blocking(move || {
        state.finish(&mut os_rng(), password.as_bytes(), &response, &ksf)
    })
    .await
    .map_err(|e| AccountError::Local(e.to_string()))??;
    let user_id = start.user_id;
    let uid = *user_id.as_bytes();
    let akek = derive_akek(&fin.export_key);
    let private = seal_private_bundle(&akek, &uid, FIRST_KEY_VERSION, &p.keys, &mut rng)?;
    let rbundle = seal_recovery_bundle(&p.recovery, &uid, &p.keys, &mut rng)?;
    let grant = self_grant(
        &p.vk,
        p.vault.as_bytes(),
        p.vault_key_version,
        &uid,
        &p.keys,
        &mut rng,
    )?;
    let pubk = p.keys.public();
    let req = RegisterFinishRequest {
        email: p.email.clone(),
        user_id,
        registration_upload: fin.upload.clone(),
        account_keys: AccountKeysUpload {
            x25519_pub: pubk.x25519.to_vec(),
            ed25519_pub: pubk.ed25519.to_vec(),
            private_bundle_enc: private,
            recovery_bundle_enc: rbundle,
            version: FIRST_KEY_VERSION,
        },
        personal_vault: PersonalVaultUpload {
            id: p.vault.uuid(),
            name_enc: seal_vault_name(&p.vk, p.vault, p.vault_key_version, PERSONAL_VAULT_NAME)?,
            self_grant: GrantUpload {
                wrapped_vault_key: grant.wrapped,
                signature: grant.signature.to_vec(),
                key_version: p.vault_key_version,
            },
        },
        device: cfg.device.clone(),
        invite_token,
        setup_token,
    };
    let session: SessionResponse = p
        .api
        .post_v1("/auth/register/finish", &req, None)
        .await
        .map_err(register_error)?;

    let acct = LocalAccount {
        user_id,
        email: p.email.clone(),
        key_version: FIRST_KEY_VERSION,
    };
    let keys_enc = local::seal_local_keys(&p.lmk, &acct, &p.keys)?;
    let vault = p.vault;
    let queued = store
        .write(move |w| {
            local::write_account(w, &acct, &keys_enc)?;
            w.reset_sync(vault)
        })
        .await?;
    TokenManager::save_login(
        store,
        &p.lmk,
        p.api.base_url(),
        Some(DeviceId::from_uuid(session.device_id)),
        &session.tokens,
    )
    .await?;
    tracing::info!(%user_id, queued, "registered; the personal vault will be uploaded");
    Ok(Registered {
        user_id,
        device_id: session.device_id,
        vault,
        queued,
    })
}
