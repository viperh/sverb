//! Account flows (§11.2, §11.2.1, §1.1; task M4-08): connect a local vault
//! to a sync account and manage it.
//!
//! | Flow | Module | Entry points |
//! |---|---|---|
//! | Local-only → new account (2.1) | [`register`] | [`prepare_registration`], [`finish_registration`] |
//! | Log in, with or without local data (2.2, 2.3, 2.5) | [`login`] | [`start_login`], [`LoginSession::commit`] |
//! | Duplicate preview and id-remapping import (2.2) | [`merge_local`] | [`ImportPreview`] |
//! | Online password change (2.4) | [`password`] | [`change_password`] |
//! | Forgotten password with the recovery key (2.7) | [`recovery`] | [`recover_account`] |
//! | Disconnect (2.8) | [`logout`] | [`logout()`](logout::logout) |
//! | Devices (M4-09) | [`devices`] | [`list_devices`], [`revoke_device`] |
//! | Orgs, invites, audit (M5-01) | [`teams`] | [`teams::list_orgs`], [`teams::invite`], … |
//! | Wizard state machines for the UI | [`wizard`] | [`RecoveryConfirm`], [`RegisterWizard`] |
//!
//! # One password (§11.2.1)
//! The account password is the local master password. Registration uses the
//! **current** master password (verified by unwrapping the LMK). Logging in
//! with a password that does not unwrap the LMK re-wraps the LMK under it
//! (new salt), after the UI has warned "Your local master password will be
//! changed to your account password".
//!
//! # Local state
//! * `sync_state`: server URL, server-assigned device id, tokens (under the
//!   LMK, M4-07).
//! * `meta.account`: `{user_id, email, key_version}` (JSON, not secret).
//! * `meta.account_keys_enc`: the account X25519/Ed25519 keys, sealed like a
//!   `private_bundle` under `HKDF(LMK, "sverb/local-account-keys/v1")`, so an
//!   unlocked device can open new grants (key rotation, shared vaults) with
//!   [`GrantKeySource`] without asking for the password.
//!
//! # Crash between a server-side password change and the local re-wrap (2.4)
//! The server already has the new OPAQUE record and bundle (version + 1), the
//! LMK is still wrapped under the old password. Local unlock keeps working
//! with the old password (it never contacts the server). Sync then fails with
//! `NeedsLogin` once the tokens are refreshed (or `meta.account.key_version`
//! is behind the server's), and logging in with the **new** password takes
//! the 2.5 path: OPAQUE succeeds, the new password does not unwrap the LMK,
//! so the LMK is re-wrapped under it. No data is lost.

use std::sync::Arc;
use std::time::Duration;

use sverb_core::vault::{Argon2Cost, check_strength};
use sverb_crypto::opaque::SverbKsf;
use sverb_proto::ErrorCode;
use sverb_proto::auth::DeviceInfo;

use crate::error::SyncError;
use crate::http::{ApiClient, HTTP_TIMEOUT};

// M4-09: list / revoke devices.
pub mod devices;
pub mod grants;
pub mod local;
pub mod login;
pub mod logout;
pub mod merge_local;
pub mod password;
pub mod recovery;
pub mod register;
// M5-01: orgs, members, invites, the audit log.
pub mod teams;
pub mod wizard;

pub use devices::{Revoked, list_devices, revoke_device};
pub use grants::{GrantKeySource, TrustedGranters};
pub use local::{LocalAccount, load_account, load_account_keys};
pub use login::{LoggedIn, LoginRequest, LoginSession, start_login};
pub use logout::{LogoutReport, logout};
pub use merge_local::{DuplicateChoice, DuplicateRow, ImportPreview};
pub use password::change_password;
pub use recovery::{Recovered, recover_account, request_recovery_code};
pub use register::{
    PreparedRegistration, Registered, RegistrationToken, finish_registration, prepare_registration,
};
pub use wizard::{
    FinishError, RecoveryConfirm, RegisterStep, RegisterWizard, WizardEffect, WizardInput,
};

/// The warning shown before a login re-wraps the LMK (§11.2.1).
pub const PASSWORD_ADOPT_WARNING: &str =
    "Your local master password will be changed to your account password";

/// Shown at signup next to the recovery phrase (§11.2, required).
pub const RECOVERY_WARNING: &str = "Without this recovery key and without any logged-in device, \
     your data is unrecoverable.";

/// Settings shared by every flow.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// The OPAQUE key-stretching function (production: `SverbKsf::default()`;
    /// test suites use the cheap test variant on both sides).
    pub ksf: Arc<SverbKsf>,
    /// Argon2id cost of a new local password wrap (re-wrap of the LMK).
    pub kdf_cost: Argon2Cost,
    /// This device, as registered on the server.
    pub device: DeviceInfo,
    /// TLS for the HTTP client (`None`: `ring` + webpki roots).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// HTTP request timeout.
    pub http_timeout: Duration,
}

impl AccountConfig {
    /// Production settings for a device called `device_name`.
    #[must_use]
    pub fn new(device_name: impl Into<String>) -> Self {
        Self {
            ksf: Arc::new(SverbKsf::default()),
            kdf_cost: Argon2Cost::PRODUCTION,
            device: DeviceInfo {
                name: device_name.into(),
                platform: std::env::consts::OS.to_owned(),
            },
            tls: None,
            http_timeout: HTTP_TIMEOUT,
        }
    }

    pub(crate) fn client(&self, server_url: &str) -> Result<ApiClient, AccountError> {
        Ok(ApiClient::new(
            server_url,
            self.tls.clone(),
            self.http_timeout,
        )?)
    }
}

/// Why an account flow failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    /// The server can't be reached (the flow needs it online).
    #[error("the server is unreachable: {0}")]
    Unreachable(String),
    /// The server speaks a protocol version this client does not support.
    #[error("incompatible server: {0}")]
    IncompatibleServer(String),
    /// The local master password is wrong.
    #[error("wrong master password")]
    WrongLocalPassword,
    /// OPAQUE failed: wrong email or password (the server can't tell which).
    #[error("invalid email or password")]
    LoginFailed,
    /// The account has TOTP enabled; ask for the code and retry.
    #[error("this account requires a TOTP code")]
    TotpRequired,
    /// Registration on this server needs an invite or setup token.
    #[error("registration requires an invite: {0}")]
    InviteRequired(String),
    /// An account with this email (or vault id) already exists.
    #[error("an account with this email already exists")]
    AlreadyRegistered,
    /// The new password is too weak (zxcvbn score below 3).
    #[error("{0}")]
    WeakPassword(String),
    /// The recovery phrase does not parse, or does not open the bundle.
    #[error("invalid recovery phrase: {0}")]
    BadRecoveryPhrase(String),
    /// The recovery code is wrong or expired.
    #[error("invalid or expired recovery code")]
    BadRecoveryCode,
    /// This device is not signed in to a server.
    #[error("not signed in to a sync server")]
    NotSignedIn,
    /// The local data is not in the expected state.
    #[error("local vault: {0}")]
    Local(String),
    /// A grant or bundle does not verify / decrypt.
    #[error("account keys: {0}")]
    Crypto(String),
    /// Any other server or client error.
    #[error(transparent)]
    Sync(SyncError),
}

impl From<SyncError> for AccountError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Transport(m) => Self::Unreachable(m),
            SyncError::NeedsLogin => Self::NotSignedIn,
            SyncError::Crypto(m) => Self::Crypto(m),
            SyncError::Store(m) => Self::Local(m),
            SyncError::NotConfigured(m) => Self::Local(m.to_owned()),
            other @ SyncError::Api { .. } => Self::Sync(other),
        }
    }
}

impl From<sverb_store::StoreError> for AccountError {
    fn from(e: sverb_store::StoreError) -> Self {
        Self::Local(e.to_string())
    }
}

impl From<sverb_crypto::CryptoError> for AccountError {
    fn from(e: sverb_crypto::CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl AccountError {
    /// Whether retrying later might help (server down or rate limited).
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Unreachable(_) => true,
            Self::Sync(e) => e.is_offline(),
            _ => false,
        }
    }
}

/// zxcvbn ≥ 3 for a password that will protect the account (§11.2.1).
pub(crate) fn require_strong(password: &str) -> Result<(), AccountError> {
    check_strength(password, &["sverb"])
        .map(drop)
        .map_err(|w| AccountError::WeakPassword(w.to_string()))
}

/// Maps a `401 auth_required` from the login endpoints.
pub(crate) fn login_error(e: SyncError) -> AccountError {
    match &e {
        SyncError::Api {
            status: 401,
            message,
            ..
        } if message.starts_with(sverb_proto::auth::TOTP_REQUIRED_HINT) => {
            AccountError::TotpRequired
        }
        SyncError::Api {
            code: Some(ErrorCode::AuthRequired),
            ..
        }
        | SyncError::Api { status: 401, .. } => AccountError::LoginFailed,
        _ => e.into(),
    }
}

/// Checks the server is up and speaks a supported protocol version
/// (`GET /healthz`, `Sverb-Proto` response header).
///
/// # Errors
/// [`AccountError::Unreachable`], [`AccountError::IncompatibleServer`],
/// [`AccountError::Local`] for a URL that is not `https://` (loopback
/// `http://` is allowed for development).
pub async fn probe_server(
    server_url: &str,
    cfg: &AccountConfig,
) -> Result<ApiClient, AccountError> {
    let api = cfg.client(server_url)?;
    match api.probe().await {
        Ok(Some(v)) if !sverb_proto::version::is_supported(v) => Err(
            AccountError::IncompatibleServer(format!("server protocol version {v}")),
        ),
        Ok(_) => Ok(api),
        Err(SyncError::Api { status, .. }) => Err(AccountError::IncompatibleServer(format!(
            "{server_url} does not look like a sverb server (HTTP {status} on /healthz)"
        ))),
        Err(e) => Err(e.into()),
    }
}
