//! `/v1/auth/*`: registration, login, token refresh, logout (§10.4).
//!
//! # Enumeration resistance
//! `login/start` answers every syntactically valid email the same way: a
//! known account gets a KE2 from its record, an unknown one a KE2 from a
//! dummy record (`ServerLogin::start` with `None`), both with a stored login
//! state. `login/finish` then fails with the same status and body
//! ([`LOGIN_FAILED_MESSAGE`]) for an unknown email, a wrong password and a
//! disabled account. Only after the password has been verified does the
//! TOTP step answer differently (`totp_required` / `totp_invalid`).

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use sverb_crypto::account::BUNDLE_LEN;
use sverb_crypto::grant::{Grant, verify_grant};
use sverb_crypto::opaque::{credential_identifier, registration_finish};
use sverb_crypto::random::os_rng;
use sverb_proto::auth::{
    AccountKeysView, LOGIN_FAILED_MESSAGE, LoginDevice, LoginFinishRequest, LoginPurpose,
    LoginStartRequest, LoginStartResponse, ReauthResponse, RefreshRequest, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse, SessionResponse, TOTP_REQUIRED_HINT,
};
use uuid::Uuid;

use crate::auth::store::{
    AccountKeysRow, DeviceChoice, LoginStateRow, LoginUser, NewAccount, NewDevice, RefreshOutcome,
};
use crate::auth::tokens::{
    self, IssuedTokens, LOGIN_STATE_TTL, NewToken, REAUTH_TTL, hash_presented,
};
use crate::auth::{AuthCtx, opaque, totp};
use crate::error::ApiError;
use crate::middleware::client_ip::ClientIp;
use crate::registration::{self, RegistrationCredential};
use crate::state::AppState;

/// Longest accepted device name or platform.
pub const MAX_DEVICE_FIELD: usize = 128;
/// Largest accepted encrypted vault name.
pub const MAX_VAULT_NAME_ENC: usize = 4096;

/// `/auth/...` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register/start", post(register_start))
        .route("/auth/register/finish", post(register_finish))
        .route("/auth/login/start", post(login_start))
        .route("/auth/login/finish", post(login_finish))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
}

fn login_failed() -> ApiError {
    ApiError::AuthRequired(LOGIN_FAILED_MESSAGE.into())
}

fn credential<'a>(
    setup_token: Option<&'a str>,
    invite_token: Option<&'a str>,
) -> RegistrationCredential<'a> {
    match (setup_token, invite_token) {
        (Some(t), _) => RegistrationCredential::SetupToken(t),
        (None, Some(t)) => RegistrationCredential::InviteToken(t),
        (None, None) => RegistrationCredential::None,
    }
}

/// Validates a device name or platform; empty → `"unknown"`.
///
/// # Errors
/// `Invalid` for overlong values or control characters.
pub fn device_field(raw: Option<&str>, what: &str) -> Result<String, ApiError> {
    let v = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");
    if v.chars().count() > MAX_DEVICE_FIELD || v.chars().any(char::is_control) {
        return Err(ApiError::Invalid(format!(
            "device {what} must be at most {MAX_DEVICE_FIELD} printable characters"
        )));
    }
    Ok(v.to_owned())
}

fn fixed32(bytes: &[u8], what: &str) -> Result<[u8; 32], ApiError> {
    bytes
        .try_into()
        .map_err(|_| ApiError::Invalid(format!("{what} must be 32 bytes")))
}

/// Checks a register/finish body and builds the rows to insert. Verifies
/// the OPAQUE upload, key and bundle sizes, and the self-grant signature
/// against the uploaded Ed25519 key.
///
/// # Errors
/// `Invalid` naming the offending field.
pub fn validate_registration(req: &RegisterFinishRequest) -> Result<NewAccount, ApiError> {
    let email = registration::normalize_email(&req.email)?;
    if req.user_id.is_nil() || req.personal_vault.id.is_nil() {
        return Err(ApiError::Invalid("ids must not be nil".into()));
    }
    let opaque_record = registration_finish(&req.registration_upload)
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration upload".into()))?;
    let k = &req.account_keys;
    fixed32(&k.x25519_pub, "x25519_pub")?;
    let ed_pub = fixed32(&k.ed25519_pub, "ed25519_pub")?;
    if k.version != 1 {
        return Err(ApiError::Invalid("account key version must be 1".into()));
    }
    if k.private_bundle_enc.len() != BUNDLE_LEN || k.recovery_bundle_enc.len() != BUNDLE_LEN {
        return Err(ApiError::Invalid(format!(
            "private and recovery bundles must be {BUNDLE_LEN} bytes"
        )));
    }
    let v = &req.personal_vault;
    if v.name_enc.is_empty() || v.name_enc.len() > MAX_VAULT_NAME_ENC {
        return Err(ApiError::Invalid("invalid encrypted vault name".into()));
    }
    let g = &v.self_grant;
    if g.key_version != 1 {
        return Err(ApiError::Invalid("vault key version must be 1".into()));
    }
    let signature: [u8; 64] = g
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Invalid("grant signature must be 64 bytes".into()))?;
    let grant = Grant {
        wrapped: g.wrapped_vault_key.clone(),
        signature,
    };
    Grant::from_bytes(&grant.to_bytes())
        .map_err(|_| ApiError::Invalid("malformed wrapped vault key".into()))?;
    verify_grant(
        &grant,
        v.id.as_bytes(),
        req.user_id.as_bytes(),
        g.key_version,
        &ed_pub,
    )
    .map_err(|_| ApiError::Invalid("self-grant signature does not verify".into()))?;
    Ok(NewAccount {
        user_id: req.user_id,
        email,
        opaque_record,
        keys: AccountKeysRow {
            x25519_pub: k.x25519_pub.clone(),
            ed25519_pub: k.ed25519_pub.clone(),
            private_bundle_enc: k.private_bundle_enc.clone(),
            recovery_bundle_enc: Some(k.recovery_bundle_enc.clone()),
            version: 1,
        },
        vault_id: v.id,
        vault_name_enc: v.name_enc.clone(),
        grant_wrapped: g.wrapped_vault_key.clone(),
        grant_signature: g.signature.clone(),
        grant_key_version: 1,
        device: NewDevice {
            id: Uuid::now_v7(),
            name: device_field(Some(&req.device.name), "name")?,
            platform: device_field(Some(&req.device.platform), "platform")?,
        },
    })
}

/// The wire form of the account keys.
#[must_use]
pub fn keys_view(k: AccountKeysRow) -> AccountKeysView {
    AccountKeysView {
        x25519_pub: k.x25519_pub,
        ed25519_pub: k.ed25519_pub,
        private_bundle_enc: k.private_bundle_enc,
        version: u32::try_from(k.version).unwrap_or(0),
    }
}

async fn register_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, ApiError> {
    let email = registration::normalize_email(&req.email)?;
    state.rate_limits().check_login(&email, ip)?;
    let cred = credential(req.setup_token.as_deref(), req.invite_token.as_deref());
    let auth = state.auth();
    auth.store().check_registration(&email, cred).await?;
    let setup = auth.server_setup(state.secrets()).await?;
    let registration_response = setup
        .registration_start(&req.registration_request, &credential_identifier(&email))
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration request".into()))?;
    Ok(Json(RegisterStartResponse {
        registration_response,
        user_id: Uuid::now_v7(),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    let acct = validate_registration(&req)?;
    let cred = credential(req.setup_token.as_deref(), req.invite_token.as_deref());
    let auth = state.auth();
    let now = auth.now();
    let tokens = IssuedTokens::issue(now);
    let grant = auth
        .store()
        .register(&acct, cred, &tokens, Uuid::now_v7(), now)
        .await?;
    if let Some(invite) = grant.org_invite {
        // The org membership for the invite presented at registration.
        match state
            .orgs()
            .accept_invite_id(invite, acct.user_id, now)
            .await
        {
            Ok((org_id, role)) => {
                tracing::info!(user_id = %acct.user_id, %invite, %org_id, %role, "registered with an org invite");
            }
            // The account exists either way; the invite can be accepted again later.
            Err(e) => {
                tracing::warn!(user_id = %acct.user_id, %invite, error = %e, "org invite not applied")
            }
        }
    }
    tracing::info!(
        user_id = %acct.user_id,
        instance_admin = grant.is_instance_admin,
        "account registered"
    );
    Ok(Json(SessionResponse {
        user_id: acct.user_id,
        device_id: acct.device.id,
        tokens: tokens.to_pair(),
        account_keys: keys_view(acct.keys),
        is_instance_admin: grant.is_instance_admin,
    }))
}

async fn login_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let email = registration::normalize_email(&req.email)?;
    state.rate_limits().check_login(&email, ip)?;
    let auth = state.auth();
    let setup = auth.server_setup(state.secrets()).await?;
    let user = auth.store().user_by_email(&email).await?;
    let cred_id = credential_identifier(&email);
    let mut rng = os_rng();
    let started = match &user {
        Some(u) => setup
            .login_start(
                &mut rng,
                Some(&u.opaque_record),
                &req.credential_request,
                &cred_id,
            )
            .or_else(|_| {
                // A bad request fails again below; a corrupt record is logged
                // and answered like an unknown account.
                let r = setup.login_start(&mut rng, None, &req.credential_request, &cred_id);
                if r.is_ok() {
                    tracing::error!(user_id = %u.id, "stored OPAQUE record does not parse");
                }
                r
            }),
        None => setup.login_start(&mut rng, None, &req.credential_request, &cred_id),
    };
    let (credential_response, server_state) =
        started.map_err(|_| ApiError::Invalid("malformed OPAQUE credential request".into()))?;
    let id = Uuid::now_v7();
    let now = auth.now();
    let row = LoginStateRow {
        id,
        user_id: user.map(|u| u.id),
        state_enc: opaque::seal_login_state(state.secrets(), id, &server_state)?,
        expires_at: now + LOGIN_STATE_TTL,
    };
    auth.store().put_login_state(&row, now).await?;
    Ok(Json(LoginStartResponse {
        credential_response,
        login_state_id: id,
    }))
}

/// Verifies KE3 against the stored state; every failure is the generic one.
async fn verify_login(state: &AppState, req: &LoginFinishRequest) -> Result<LoginUser, ApiError> {
    let auth = state.auth();
    let row = auth
        .store()
        .take_login_state(req.login_state_id, auth.now())
        .await?
        .ok_or_else(login_failed)?;
    let server_state = opaque::open_login_state(state.secrets(), row.id, &row.state_enc)
        .ok_or_else(login_failed)?;
    let verified = server_state.finish(&req.credential_finalization).is_ok();
    let user = match row.user_id {
        Some(id) => auth.store().user_by_id(id).await?,
        None => None,
    };
    match user {
        Some(u) if verified && !u.disabled => Ok(u),
        Some(u) if verified => {
            tracing::warn!(user_id = %u.id, "login with the correct password for a disabled account");
            Err(login_failed())
        }
        _ => Err(login_failed()),
    }
}

/// The second factor, after the password has been verified.
///
/// # Errors
/// `AuthRequired` with a `totp_required` or `totp_invalid` message.
pub async fn check_totp(
    state: &AppState,
    user: &LoginUser,
    code: Option<&str>,
) -> Result<(), ApiError> {
    let Some(enc) = &user.totp_secret_enc else {
        return Ok(());
    };
    let Some(code) = code else {
        return Err(ApiError::AuthRequired(format!(
            "{TOTP_REQUIRED_HINT}: this account requires a TOTP code; log in again with `totp`"
        )));
    };
    let invalid =
        || ApiError::AuthRequired("totp_invalid: invalid or already used TOTP code".into());
    let secret = state
        .secrets()
        .open(&crate::routes::account::totp_aad(user.id), enc)
        .ok_or_else(|| ApiError::internal(std::io::Error::other("TOTP secret does not decrypt")))?;
    let auth = state.auth();
    let now = u64::try_from(auth.now().timestamp()).unwrap_or(0);
    let step = totp::verify(&secret, code, now).ok_or_else(invalid)?;
    let step = i64::try_from(step).map_err(|_| invalid())?;
    if auth.store().consume_totp_step(user.id, step).await? {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn device_choice(d: &LoginDevice) -> Result<DeviceChoice, ApiError> {
    let new = NewDevice {
        id: Uuid::now_v7(),
        name: device_field(d.name.as_deref(), "name")?,
        platform: device_field(d.platform.as_deref(), "platform")?,
    };
    Ok(match d.id {
        Some(id) => DeviceChoice::Existing(id, new),
        None => DeviceChoice::New(new),
    })
}

async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Response, ApiError> {
    let user = verify_login(&state, &req).await?;
    check_totp(&state, &user, req.totp.as_deref()).await?;
    let auth = state.auth();
    let now = auth.now();
    match req.purpose {
        LoginPurpose::Reauth => {
            let token = NewToken::generate();
            auth.store()
                .insert_reauth(&token.hash, user.id, now + REAUTH_TTL)
                .await?;
            Ok(Json(ReauthResponse {
                user_id: user.id,
                reauth_token: token.wire.to_string(),
                reauth_expires_in_s: tokens::secs(REAUTH_TTL),
            })
            .into_response())
        }
        LoginPurpose::Login => {
            let choice = device_choice(&req.device)?;
            let issued = IssuedTokens::issue(now);
            let device_id = auth
                .store()
                .start_session(user.id, &choice, &issued, Uuid::now_v7(), now)
                .await?;
            let keys =
                auth.store().account_keys(user.id).await?.ok_or_else(|| {
                    ApiError::internal(std::io::Error::other("account keys missing"))
                })?;
            tracing::info!(user_id = %user.id, %device_id, "login");
            // A new device shows in the audit log of the user's orgs.
            if !matches!(&choice, DeviceChoice::Existing(id, _) if *id == device_id) {
                state
                    .orgs()
                    .record_for_user_orgs(
                        user.id,
                        crate::orgs::kinds::DEVICE_ADDED,
                        Some(device_id),
                        now,
                    )
                    .await?;
            }
            Ok(Json(SessionResponse {
                user_id: user.id,
                device_id,
                tokens: issued.to_pair(),
                account_keys: keys_view(keys),
                is_instance_admin: user.is_instance_admin,
            })
            .into_response())
        }
    }
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Response, ApiError> {
    let invalid = || ApiError::AuthRequired("invalid or expired refresh token".into());
    let hash = hash_presented(&req.refresh_token).ok_or_else(invalid)?;
    let auth = state.auth();
    let now = auth.now();
    let issued = IssuedTokens::issue(now);
    match auth.store().refresh(&hash, &issued, now).await? {
        RefreshOutcome::Rotated(_) => Ok(Json(issued.to_pair()).into_response()),
        RefreshOutcome::Reused {
            device_id,
            user_id,
            family,
        } => {
            tracing::warn!(%device_id, %family, "refresh token reuse detected: token family revoked");
            auth.store()
                .audit(
                    user_id,
                    "refresh_token_reuse",
                    Some(device_id),
                    serde_json::json!({ "family": family, "device_id": device_id }),
                    now,
                )
                .await?;
            Err(ApiError::AuthRequired(
                "refresh token reuse detected; this device must log in again".into(),
            ))
        }
        RefreshOutcome::Invalid => Err(invalid()),
    }
}

async fn logout(State(state): State<AppState>, ctx: AuthCtx) -> Result<StatusCode, ApiError> {
    state.auth().store().logout(ctx.device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_fields() {
        assert_eq!(device_field(None, "name").ok().as_deref(), Some("unknown"));
        assert_eq!(
            device_field(Some("  "), "name").ok().as_deref(),
            Some("unknown")
        );
        assert_eq!(
            device_field(Some(" laptop "), "name").ok().as_deref(),
            Some("laptop")
        );
        assert!(device_field(Some("a\nb"), "name").is_err());
        assert!(device_field(Some(&"x".repeat(129)), "name").is_err());
    }

    #[test]
    fn credentials_prefer_the_setup_token() {
        assert_eq!(
            credential(Some("s"), Some("i")),
            RegistrationCredential::SetupToken("s")
        );
        assert_eq!(
            credential(None, Some("i")),
            RegistrationCredential::InviteToken("i")
        );
        assert_eq!(credential(None, None), RegistrationCredential::None);
    }
}
