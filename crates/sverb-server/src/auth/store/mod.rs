//! Persistence for authentication, accounts and devices.
//!
//! [`AuthStore`] has two backends with the same behaviour:
//! * [`AuthStore::Postgres`] (production, [`pg`]): every multi-row change
//!   is one transaction, row locks serialize refresh-token rotation, and
//!   registration runs [`crate::registration::authorize`] inside the
//!   transaction that creates the account;
//! * [`AuthStore::Memory`] ([`mem`]): an in-process model used by the
//!   HTTP tests that run without PostgreSQL. It validates before it
//!   mutates, so every operation is atomic too, and it supports failure
//!   injection.
//!
//! Time is always passed in (`now`) from the injectable clock.

pub mod mem;
pub mod pg;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;
use uuid::Uuid;

use super::tokens::{IssuedTokens, TokenHash};
use crate::error::ApiError;
use crate::registration::{RegistrationCredential, RegistrationGrant};

/// A device to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    /// New id (UUIDv7).
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
}

/// Which device a login is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceChoice {
    /// Resume this device if it belongs to the user and is not revoked,
    /// otherwise create `fallback`.
    Existing(Uuid, NewDevice),
    /// Create a device.
    New(NewDevice),
}

/// An `account_keys` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeysRow {
    /// X25519 public key.
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key.
    pub ed25519_pub: Vec<u8>,
    /// Private bundle (under AKEK).
    pub private_bundle_enc: Vec<u8>,
    /// Recovery bundle (under the recovery key).
    pub recovery_bundle_enc: Option<Vec<u8>>,
    /// Version.
    pub version: i32,
}

/// Everything registration creates.
#[derive(Debug, Clone)]
pub struct NewAccount {
    /// User id.
    pub user_id: Uuid,
    /// Normalised email.
    pub email: String,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Account keys.
    pub keys: AccountKeysRow,
    /// Personal vault id (client-generated).
    pub vault_id: Uuid,
    /// Vault name under the vault key.
    pub vault_name_enc: Vec<u8>,
    /// Self-grant: wrapped vault key.
    pub grant_wrapped: Vec<u8>,
    /// Self-grant: signature.
    pub grant_signature: Vec<u8>,
    /// Vault key version.
    pub grant_key_version: i32,
    /// The registering device.
    pub device: NewDevice,
}

/// What login needs to know about an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginUser {
    /// Id.
    pub id: Uuid,
    /// Email.
    pub email: String,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Disabled by an admin.
    pub disabled: bool,
    /// Instance admin.
    pub is_instance_admin: bool,
    /// Sealed TOTP secret when TOTP is enabled.
    pub totp_secret_enc: Option<Vec<u8>>,
}

/// A stored OPAQUE login state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStateRow {
    /// Handle given to the client.
    pub id: Uuid,
    /// The account; `None` for an unknown email (dummy record).
    pub user_id: Option<Uuid>,
    /// Sealed `ServerLoginState`.
    pub state_enc: Vec<u8>,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
}

/// An authenticated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessCtx {
    /// The account.
    pub user_id: Uuid,
    /// The device the access token is bound to.
    pub device_id: Uuid,
}

/// Result of presenting a refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Rotated: the new pair is stored in the same family.
    Rotated(AccessCtx),
    /// The token had already been used: its whole family was revoked.
    Reused {
        /// The device the family belonged to.
        device_id: Uuid,
        /// The account, if the device still exists.
        user_id: Option<Uuid>,
        /// The revoked family.
        family: Uuid,
    },
    /// Unknown, expired, or for a revoked device or disabled account.
    Invalid,
}

/// A `devices` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Id.
    pub id: Uuid,
    /// Name.
    pub name: Option<String>,
    /// Platform.
    pub platform: Option<String>,
    /// Created.
    pub created_at: Option<DateTime<Utc>>,
    /// Last seen.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// TOTP columns of a user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TotpState {
    /// Enabled secret (sealed).
    pub secret_enc: Option<Vec<u8>>,
    /// Pending secret awaiting confirmation (sealed).
    pub pending_enc: Option<Vec<u8>>,
}

/// What the recovery flow needs after a valid code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryInfo {
    /// Account.
    pub user_id: Uuid,
    /// Normalised email.
    pub email: String,
    /// Recovery bundle.
    pub recovery_bundle_enc: Option<Vec<u8>>,
    /// Current account key version.
    pub version: i32,
    /// Ed25519 public key (verifies the recovery proof).
    pub ed25519_pub: Vec<u8>,
}

/// The replacement credentials of a password change or recovery.
#[derive(Debug, Clone)]
pub struct NewCredentials {
    /// New OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Re-sealed private bundle.
    pub private_bundle_enc: Vec<u8>,
    /// Must be the current version + 1.
    pub version: i32,
}

/// Maximum failed attempts per recovery code before it is discarded.
pub const RECOVERY_CODE_MAX_ATTEMPTS: i32 = 5;

/// The auth persistence backend (see the module docs).
#[derive(Debug, Clone)]
pub enum AuthStore {
    /// PostgreSQL.
    Postgres(PgPool),
    /// In-memory model (tests).
    Memory(Arc<mem::MemStore>),
}

macro_rules! dispatch {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        match $self {
            AuthStore::Postgres(pool) => pg::$method(pool, $($arg),*).await,
            AuthStore::Memory(m) => m.$method($($arg),*),
        }
    };
}

impl AuthStore {
    /// Runs the registration policy check without consuming anything
    /// (register/start).
    ///
    /// # Errors
    /// [`ApiError::Forbidden`] when registration is not allowed.
    pub async fn check_registration(
        &self,
        email: &str,
        cred: RegistrationCredential<'_>,
    ) -> Result<(), ApiError> {
        dispatch!(self, check_registration(email, cred))
    }

    /// Creates the user, account keys, personal vault with self-grant,
    /// device and tokens atomically, consuming the invite or setup token.
    ///
    /// # Errors
    /// `Forbidden` (policy), `Conflict` (email, user id or vault id taken).
    pub async fn register(
        &self,
        acct: &NewAccount,
        cred: RegistrationCredential<'_>,
        tokens: &IssuedTokens,
        family: Uuid,
        now: DateTime<Utc>,
    ) -> Result<RegistrationGrant, ApiError> {
        dispatch!(self, register(acct, cred, tokens, family, now))
    }

    /// Looks a user up by email (case-insensitive).
    ///
    /// # Errors
    /// Database errors.
    pub async fn user_by_email(&self, email: &str) -> Result<Option<LoginUser>, ApiError> {
        dispatch!(self, user_by_email(email))
    }

    /// Looks a user up by id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn user_by_id(&self, id: Uuid) -> Result<Option<LoginUser>, ApiError> {
        dispatch!(self, user_by_id(id))
    }

    /// Stores a login state (and drops expired ones).
    ///
    /// # Errors
    /// Database errors.
    pub async fn put_login_state(
        &self,
        row: &LoginStateRow,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, put_login_state(row, now))
    }

    /// Removes and returns an unexpired login state (single use).
    ///
    /// # Errors
    /// Database errors.
    pub async fn take_login_state(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<LoginStateRow>, ApiError> {
        dispatch!(self, take_login_state(id, now))
    }

    /// Resumes or creates the device and issues a new token family for it
    /// (the device's previous tokens are revoked). Returns the device id.
    ///
    /// # Errors
    /// Database errors.
    pub async fn start_session(
        &self,
        user_id: Uuid,
        device: &DeviceChoice,
        tokens: &IssuedTokens,
        family: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Uuid, ApiError> {
        dispatch!(self, start_session(user_id, device, tokens, family, now))
    }

    /// The account keys.
    ///
    /// # Errors
    /// Database errors.
    pub async fn account_keys(&self, user_id: Uuid) -> Result<Option<AccountKeysRow>, ApiError> {
        dispatch!(self, account_keys(user_id))
    }

    /// Resolves an access token: unexpired, device not revoked, user not
    /// disabled. Updates `last_seen_at` (throttled).
    ///
    /// # Errors
    /// Database errors.
    pub async fn lookup_access(
        &self,
        hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Result<Option<AccessCtx>, ApiError> {
        dispatch!(self, lookup_access(hash, now))
    }

    /// The expiry of a valid access token (same conditions as
    /// [`Self::lookup_access`], without touching `last_seen_at`). The
    /// WebSocket closes with 4401 at this instant.
    ///
    /// # Errors
    /// Database errors.
    pub async fn access_expires_at(
        &self,
        hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, ApiError> {
        dispatch!(self, access_expires_at(hash, now))
    }

    /// Rotates a refresh token (or detects reuse and revokes the family).
    ///
    /// # Errors
    /// Database errors.
    pub async fn refresh(
        &self,
        hash: &TokenHash,
        new: &IssuedTokens,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, ApiError> {
        dispatch!(self, refresh(hash, new, now))
    }

    /// Deletes all tokens of a device (logout).
    ///
    /// # Errors
    /// Database errors.
    pub async fn logout(&self, device_id: Uuid) -> Result<(), ApiError> {
        dispatch!(self, logout(device_id))
    }

    /// The user's devices, oldest first.
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_devices(&self, user_id: Uuid) -> Result<Vec<DeviceRow>, ApiError> {
        dispatch!(self, list_devices(user_id))
    }

    /// Revokes a device of the user (sets `revoked_at`, deletes its tokens).
    /// `false` when the user has no such device.
    ///
    /// # Errors
    /// Database errors.
    pub async fn revoke_device(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, ApiError> {
        dispatch!(self, revoke_device(user_id, device_id, now))
    }

    /// TOTP columns.
    ///
    /// # Errors
    /// Database errors.
    pub async fn totp_state(&self, user_id: Uuid) -> Result<TotpState, ApiError> {
        dispatch!(self, totp_state(user_id))
    }

    /// Stores (or clears) a pending TOTP secret.
    ///
    /// # Errors
    /// Database errors.
    pub async fn set_totp_pending(
        &self,
        user_id: Uuid,
        pending_enc: Option<&[u8]>,
    ) -> Result<(), ApiError> {
        dispatch!(self, set_totp_pending(user_id, pending_enc))
    }

    /// Enables TOTP with `secret_enc` and records `step` as used.
    ///
    /// # Errors
    /// Database errors.
    pub async fn enable_totp(
        &self,
        user_id: Uuid,
        secret_enc: &[u8],
        step: i64,
    ) -> Result<(), ApiError> {
        dispatch!(self, enable_totp(user_id, secret_enc, step))
    }

    /// Disables TOTP.
    ///
    /// # Errors
    /// Database errors.
    pub async fn disable_totp(&self, user_id: Uuid) -> Result<(), ApiError> {
        dispatch!(self, disable_totp(user_id))
    }

    /// Atomically accepts `step` if it is newer than the last accepted one.
    ///
    /// # Errors
    /// Database errors.
    pub async fn consume_totp_step(&self, user_id: Uuid, step: i64) -> Result<bool, ApiError> {
        dispatch!(self, consume_totp_step(user_id, step))
    }

    /// Stores a reauth token hash.
    ///
    /// # Errors
    /// Database errors.
    pub async fn insert_reauth(
        &self,
        hash: &TokenHash,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, insert_reauth(hash, user_id, expires_at))
    }

    /// Password change (§11.2.1), atomically: consumes the reauth token,
    /// checks `version = current + 1`, replaces the OPAQUE record and the
    /// private bundle, and deletes the tokens of every **other** device.
    ///
    /// # Errors
    /// `AuthRequired` (reauth token), `Conflict` (version), database errors.
    pub async fn change_password(
        &self,
        ctx: AccessCtx,
        reauth: &TokenHash,
        new: &NewCredentials,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, change_password(ctx, reauth, new, now))
    }

    /// Stores a recovery code for `email` (replacing any previous one).
    /// `None` for an unknown email.
    ///
    /// # Errors
    /// Database errors.
    pub async fn issue_recovery_code(
        &self,
        email: &str,
        code_hash: &TokenHash,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<Uuid>, ApiError> {
        dispatch!(self, issue_recovery_code(email, code_hash, expires_at))
    }

    /// Checks a recovery code without consuming it; a wrong code counts as
    /// a failed attempt (the code is discarded after
    /// [`RECOVERY_CODE_MAX_ATTEMPTS`]).
    ///
    /// # Errors
    /// Database errors.
    pub async fn check_recovery_code(
        &self,
        email: &str,
        code_hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Result<Option<RecoveryInfo>, ApiError> {
        dispatch!(self, check_recovery_code(email, code_hash, now))
    }

    /// Recovery (§10.4), atomically: consumes the code, checks the version,
    /// replaces the record and bundle, and deletes **all** tokens.
    ///
    /// # Errors
    /// `AuthRequired` (code), `Conflict` (version), database errors.
    pub async fn finish_recovery(
        &self,
        user_id: Uuid,
        code_hash: &TokenHash,
        new: &NewCredentials,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, finish_recovery(user_id, code_hash, new, now))
    }

    /// Deletes the account atomically: consumes the reauth token, deletes
    /// the personal vaults with their items and members, the user's
    /// memberships, devices, tokens and the user; shared vaults stay.
    ///
    /// # Errors
    /// `AuthRequired` (reauth token), database errors.
    pub async fn delete_account(
        &self,
        user_id: Uuid,
        reauth: &TokenHash,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, delete_account(user_id, reauth, now))
    }

    /// Reads a sealed `server_secrets` value.
    ///
    /// # Errors
    /// Database errors.
    pub async fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, ApiError> {
        dispatch!(self, get_secret(name))
    }

    /// Inserts a sealed `server_secrets` value unless the row exists (first
    /// writer wins across replicas).
    ///
    /// # Errors
    /// Database errors.
    pub async fn insert_secret_if_absent(&self, name: &str, value: &[u8]) -> Result<(), ApiError> {
        dispatch!(self, insert_secret_if_absent(name, value))
    }

    /// Appends an audit event (metadata only).
    ///
    /// # Errors
    /// Database errors.
    pub async fn audit(
        &self,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        dispatch!(self, audit(actor, kind, target, meta, now))
    }
}
