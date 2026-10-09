//! Authentication, account and device DTOs (SPEC §10.4, §11.2; task M4-02).
//!
//! Binary fields (OPAQUE messages, keys, bundles, grants) are base64url
//! without padding ([`crate::b64`]). Tokens are opaque base64url strings.
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/auth/register/start` | [`RegisterStartRequest`] | [`RegisterStartResponse`] |
//! | `POST /v1/auth/register/finish` | [`RegisterFinishRequest`] | [`SessionResponse`] |
//! | `POST /v1/auth/login/start` | [`LoginStartRequest`] | [`LoginStartResponse`] |
//! | `POST /v1/auth/login/finish` | [`LoginFinishRequest`] | [`SessionResponse`] or [`ReauthResponse`] |
//! | `POST /v1/auth/refresh` | [`RefreshRequest`] | [`TokenPair`] |
//! | `POST /v1/auth/logout` | – | 204 |
//! | `GET /v1/devices` | – | `[`[`DeviceView`]`]` |
//! | `DELETE /v1/devices/{id}` | – | 204 |
//! | `POST /v1/account/totp` | [`TotpRequest`] | [`TotpSetupResponse`] / [`TotpStatus`] |
//! | `DELETE /v1/account/totp` | [`TotpRequest`] | 204 |
//! | `POST /v1/account/password/start` | [`PasswordStartRequest`] | [`PasswordStartResponse`] |
//! | `POST /v1/account/password` | [`PasswordChangeRequest`] | [`KeyVersionResponse`] |
//! | `POST /v1/account/recovery/code` | [`RecoveryCodeRequest`] | 202 |
//! | `POST /v1/account/recovery/start` | [`RecoveryStartRequest`] | [`RecoveryStartResponse`] |
//! | `POST /v1/account/recovery` | [`RecoveryFinishRequest`] | [`KeyVersionResponse`] |
//! | `DELETE /v1/account` | [`AccountDeleteRequest`] | 204 |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Message prefix of the `auth_required` error when the account has TOTP
/// enabled and no code was sent; clients prompt for a code when they see it.
pub const TOTP_REQUIRED_HINT: &str = "totp_required";

/// Message of the generic login failure (identical for unknown email, wrong
/// password and disabled account, §10.4).
pub const LOGIN_FAILED_MESSAGE: &str = "invalid email or password";

// ------------------------------------------------------------ registration

/// `POST /v1/auth/register/start`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Account email.
    pub email: String,
    /// OPAQUE `RegistrationRequest`.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
    /// Invite token (instance or org invite), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    /// The bootstrap setup token (first account only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}

/// Response to [`RegisterStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE `RegistrationResponse`.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
    /// A fresh user id proposed by the server. The client binds its private
    /// bundle (AAD) and the personal-vault self-grant (signature) to it and
    /// sends it back in [`RegisterFinishRequest::user_id`].
    pub user_id: Uuid,
}

/// Public keys and encrypted bundles uploaded at registration (§11.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysUpload {
    /// X25519 public key (32 B).
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key (32 B).
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
    /// `private_bundle` sealed under AKEK.
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// `recovery_bundle` sealed under the recovery key.
    #[serde(with = "crate::b64")]
    pub recovery_bundle_enc: Vec<u8>,
    /// Account key version; 1 at registration.
    pub version: u32,
}

/// A signed, HPKE-wrapped vault key (§11.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantUpload {
    /// `wrapped_vault_key` (sverb-crypto `hpke` wire format).
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// Ed25519 signature (64 B) over `sig_grant(vault, member, key_version, wrapped)`.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Vault key version; 1 at registration.
    pub key_version: u32,
}

/// The personal vault created at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalVaultUpload {
    /// Client-generated UUIDv7 (the local vault id survives, §10.3).
    pub id: Uuid,
    /// Vault name encrypted under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// The owner's self-grant.
    pub self_grant: GrantUpload,
}

/// A device as described by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable name ("laptop").
    pub name: String,
    /// Platform ("linux", "macos", …).
    pub platform: String,
}

/// `POST /v1/auth/register/finish`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    /// Account email (same as in start).
    pub email: String,
    /// The user id from [`RegisterStartResponse::user_id`].
    pub user_id: Uuid,
    /// OPAQUE `RegistrationUpload` (becomes the stored record).
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// Keys and bundles.
    pub account_keys: AccountKeysUpload,
    /// The personal vault and its self-grant.
    pub personal_vault: PersonalVaultUpload,
    /// This device.
    pub device: DeviceInfo,
    /// Invite token (checked and consumed here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    /// Setup token (checked and consumed here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
}

// ------------------------------------------------------------------- login

/// `POST /v1/auth/login/start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// Account email.
    pub email: String,
    /// OPAQUE `CredentialRequest` (KE1).
    #[serde(with = "crate::b64")]
    pub credential_request: Vec<u8>,
}

/// Response to [`LoginStartRequest`] (same shape for unknown emails).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// OPAQUE `CredentialResponse` (KE2).
    #[serde(with = "crate::b64")]
    pub credential_response: Vec<u8>,
    /// Handle of the server-side login state (expires after 60 s).
    pub login_state_id: Uuid,
}

/// What a login is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPurpose {
    /// A normal login: creates or resumes a device and issues tokens.
    #[default]
    Login,
    /// A fresh proof of the password for a sensitive operation (password
    /// change, account deletion): returns a short-lived `reauth_token` and no
    /// session tokens.
    Reauth,
}

/// The device a login is for: an existing device id of this account, or a
/// new device.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoginDevice {
    /// Existing, unrevoked device of this account to resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Name for a new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Platform for a new device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// `POST /v1/auth/login/finish`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    /// From [`LoginStartResponse`].
    pub login_state_id: Uuid,
    /// OPAQUE `CredentialFinalization` (KE3).
    #[serde(with = "crate::b64")]
    pub credential_finalization: Vec<u8>,
    /// Current TOTP code, when the account has TOTP enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// The device (ignored for [`LoginPurpose::Reauth`]).
    #[serde(default)]
    pub device: LoginDevice,
    /// Login or reauth.
    #[serde(default)]
    pub purpose: LoginPurpose,
}

/// Access and refresh token (§10.4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPair {
    /// Bearer token for API calls (15 min).
    pub access_token: String,
    /// Single-use refresh token (30 days, rotated on every use).
    pub refresh_token: String,
    /// Access-token lifetime in seconds.
    pub access_expires_in_s: u64,
    /// Refresh-token lifetime in seconds.
    pub refresh_expires_in_s: u64,
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPair")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("access_expires_in_s", &self.access_expires_in_s)
            .field("refresh_expires_in_s", &self.refresh_expires_in_s)
            .finish()
    }
}

/// The account key material a device needs after login (§11.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysView {
    /// X25519 public key.
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key.
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
    /// `private_bundle` sealed under AKEK (bound to `version`).
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// Account key version.
    pub version: u32,
}

/// Successful registration or login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The account.
    pub user_id: Uuid,
    /// The device the tokens are bound to.
    pub device_id: Uuid,
    /// Tokens.
    pub tokens: TokenPair,
    /// Account keys.
    pub account_keys: AccountKeysView,
    /// Whether the account is the instance admin.
    #[serde(default)]
    pub is_instance_admin: bool,
}

/// Successful [`LoginPurpose::Reauth`] login.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReauthResponse {
    /// The account.
    pub user_id: Uuid,
    /// Single-use proof of a fresh login (5 minutes).
    pub reauth_token: String,
    /// Lifetime in seconds.
    pub reauth_expires_in_s: u64,
}

impl std::fmt::Debug for ReauthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReauthResponse")
            .field("user_id", &self.user_id)
            .field("reauth_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// `POST /v1/auth/refresh`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// The current refresh token.
    pub refresh_token: String,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshRequest([REDACTED])")
    }
}

// ----------------------------------------------------------------- devices

/// One entry of `GET /v1/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceView {
    /// Device id.
    pub id: Uuid,
    /// Name.
    pub name: Option<String>,
    /// Platform.
    pub platform: Option<String>,
    /// Creation time.
    pub created_at: Option<DateTime<Utc>>,
    /// Last token use (updated at most every 5 minutes).
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Whether this is the calling device.
    pub current: bool,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
}

// ----------------------------------------------------------------- account

/// `POST|DELETE /v1/account/totp`.
///
/// `POST` without `code` starts enabling (the server generates a secret and
/// returns [`TotpSetupResponse`]); `POST` with `code` confirms it
/// ([`TotpStatus`]). `DELETE` requires a current `code`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TotpRequest {
    /// Current 6-digit code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// A pending TOTP secret for the authenticator app.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    /// `otpauth://totp/…` URI (for a QR code).
    pub otpauth_uri: String,
    /// The secret in base32 (manual entry).
    pub secret_base32: String,
}

impl std::fmt::Debug for TotpSetupResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSetupResponse([REDACTED])")
    }
}

/// TOTP state after a confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpStatus {
    /// Whether login now requires a code.
    pub enabled: bool,
}

/// `POST /v1/account/password/start`: OPAQUE registration step 1 for the
/// new password (authenticated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStartRequest {
    /// OPAQUE `RegistrationRequest` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
}

/// Response to [`PasswordStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStartResponse {
    /// OPAQUE `RegistrationResponse`.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
}

/// `POST /v1/account/password` (§11.2.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordChangeRequest {
    /// From a [`LoginPurpose::Reauth`] login within the last 5 minutes.
    pub reauth_token: String,
    /// OPAQUE `RegistrationUpload` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// `private_bundle` re-sealed under the new AKEK and `version`.
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// Must be the current account key version + 1.
    pub version: u32,
}

impl std::fmt::Debug for PasswordChangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordChangeRequest")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// The account key version after a password change or recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVersionResponse {
    /// New `account_keys.version`.
    pub version: u32,
}

/// `POST /v1/account/recovery/code`: mail a one-time recovery code (only
/// when SMTP is configured; the response is 202 either way).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCodeRequest {
    /// Account email.
    pub email: String,
}

/// `POST /v1/account/recovery/start`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStartRequest {
    /// Account email.
    pub email: String,
    /// One-time recovery code (mailed, or issued with
    /// `sverb-server admin user recovery-code`).
    pub code: String,
    /// OPAQUE `RegistrationRequest` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_request: Vec<u8>,
}

impl std::fmt::Debug for RecoveryStartRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryStartRequest")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// Response to [`RecoveryStartRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStartResponse {
    /// The account.
    pub user_id: Uuid,
    /// `recovery_bundle` sealed under the recovery key.
    #[serde(with = "crate::b64")]
    pub recovery_bundle_enc: Vec<u8>,
    /// OPAQUE `RegistrationResponse` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_response: Vec<u8>,
    /// Current account key version (the new one must be this + 1).
    pub version: u32,
}

/// `POST /v1/account/recovery`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryFinishRequest {
    /// Account email.
    pub email: String,
    /// The same one-time code (consumed here).
    pub code: String,
    /// OPAQUE `RegistrationUpload` for the new password.
    #[serde(with = "crate::b64")]
    pub registration_upload: Vec<u8>,
    /// `private_bundle` sealed under the new AKEK and `version`.
    #[serde(with = "crate::b64")]
    pub private_bundle_enc: Vec<u8>,
    /// Current version + 1.
    pub version: u32,
    /// Ed25519 signature with the account key (from the recovery bundle)
    /// over `sverb_crypto::opaque::recovery_proof_message`.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for RecoveryFinishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryFinishRequest")
            .field("email", &self.email)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// `DELETE /v1/account`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeleteRequest {
    /// From a [`LoginPurpose::Reauth`] login within the last 5 minutes.
    pub reauth_token: String,
}

impl std::fmt::Debug for AccountDeleteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountDeleteRequest([REDACTED])")
    }
}

// M7-05 (SPEC §17 "Secrets in logs"): the request DTOs that carry one-time tokens or a
// TOTP code print them as `[REDACTED]`.
fn redacted(v: &Option<String>) -> &'static str {
    if v.is_some() {
        "Some([REDACTED])"
    } else {
        "None"
    }
}

impl std::fmt::Debug for RegisterStartRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterStartRequest")
            .field("email", &self.email)
            .field("invite_token", &redacted(&self.invite_token))
            .field("setup_token", &redacted(&self.setup_token))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RegisterFinishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterFinishRequest")
            .field("email", &self.email)
            .field("user_id", &self.user_id)
            .field("device", &self.device)
            .field("invite_token", &redacted(&self.invite_token))
            .field("setup_token", &redacted(&self.setup_token))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LoginFinishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFinishRequest")
            .field("login_state_id", &self.login_state_id)
            .field("totp", &redacted(&self.totp))
            .field("device", &self.device)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn binary_fields_are_base64url_unpadded() {
        let req = LoginStartRequest {
            email: "a@example.com".into(),
            credential_request: vec![0xfb, 0xff],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["credential_request"], "-_8");
        let back: LoginStartRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
        assert!(
            serde_json::from_str::<LoginStartRequest>(
                r#"{"email":"a@b.c","credential_request":"-_8="}"#
            )
            .is_err()
        );
    }

    #[test]
    fn login_finish_defaults() {
        let id = Uuid::nil();
        let req: LoginFinishRequest = serde_json::from_value(serde_json::json!({
            "login_state_id": id,
            "credential_finalization": "AA",
        }))
        .unwrap();
        assert_eq!(req.purpose, LoginPurpose::Login);
        assert_eq!(req.device, LoginDevice::default());
        assert!(req.totp.is_none());
        let reauth: LoginPurpose = serde_json::from_str(r#""reauth""#).unwrap();
        assert_eq!(reauth, LoginPurpose::Reauth);
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let t = TokenPair {
            access_token: "AAAA-secret".into(),
            refresh_token: "BBBB-secret".into(),
            access_expires_in_s: 900,
            refresh_expires_in_s: 1,
        };
        assert!(!format!("{t:?}").contains("secret"));
    }
}
