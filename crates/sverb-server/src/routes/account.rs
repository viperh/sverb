//! `/v1/account*`: TOTP, password change, recovery, deletion (§10.4,
//! §11.2.1).
//!
//! # Fresh-login proof (reauth)
//! Password change and account deletion need a `reauth_token` from a
//! `login/finish` with `purpose: "reauth"` in the last 5 minutes (single use),
//! in addition to the bearer token.
//!
//! # Recovery (sverb proposal; the spec leaves authentication open)
//! 1. A one-time code reaches the user: mailed by
//!    `POST /v1/account/recovery/code` when SMTP is configured, otherwise
//!    issued by the operator with `sverb-server admin user recovery-code`.
//! 2. `POST /v1/account/recovery/start {email, code, registration_request}`
//!    returns the `recovery_bundle_enc` and an OPAQUE registration response
//!    for the new password. Wrong codes count; 5 failures discard the code.
//! 3. The client opens the bundle with the recovery key, re-seals the
//!    private bundle under the new AKEK and signs
//!    `sverb_crypto::opaque::recovery_proof_message` with the account
//!    Ed25519 key, which proves it holds the recovery key (or a device
//!    key).
//! 4. `POST /v1/account/recovery` checks code and signature, replaces the
//!    record and bundle (`version + 1`) and revokes every device's tokens.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use sverb_crypto::account::BUNDLE_LEN;
use sverb_crypto::opaque::{credential_identifier, recovery_proof_message, registration_finish};
use sverb_crypto::sign;
use sverb_proto::auth::{
    AccountDeleteRequest, KeyVersionResponse, PasswordChangeRequest, PasswordStartRequest,
    PasswordStartResponse, RecoveryCodeRequest, RecoveryFinishRequest, RecoveryStartRequest,
    RecoveryStartResponse, TotpRequest, TotpSetupResponse, TotpStatus,
};
use uuid::Uuid;

use crate::auth::store::{NewCredentials, RecoveryInfo};
use crate::auth::tokens::{
    RECOVERY_CODE_TTL, generate_recovery_code, hash_presented, hash_recovery_code,
};
use crate::auth::{AuthCtx, totp};
use crate::error::ApiError;
use crate::middleware::client_ip::ClientIp;
use crate::registration;
use crate::state::AppState;

/// `/account...` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/account", axum::routing::delete(delete_account))
        .route("/account/totp", post(totp_enable).delete(totp_disable))
        .route("/account/password/start", post(password_start))
        .route("/account/password", post(password_change))
        .route("/account/recovery/code", post(recovery_code))
        .route("/account/recovery/start", post(recovery_start))
        .route("/account/recovery", post(recovery_finish))
}

/// AAD of an enabled TOTP secret.
#[must_use]
pub fn totp_aad(user_id: Uuid) -> Vec<u8> {
    let mut aad = b"sverb/totp/v1".to_vec();
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn totp_pending_aad(user_id: Uuid) -> Vec<u8> {
    let mut aad = b"sverb/totp-pending/v1".to_vec();
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn unix_now(state: &AppState) -> u64 {
    u64::try_from(state.auth().now().timestamp()).unwrap_or(0)
}

fn reauth_hash(token: &str) -> Result<[u8; 32], ApiError> {
    hash_presented(token).ok_or_else(|| {
        ApiError::AuthRequired(
            "a fresh login is required (reauth token missing, used or expired)".into(),
        )
    })
}

fn new_credentials(upload: &[u8], bundle: &[u8], version: u32) -> Result<NewCredentials, ApiError> {
    let opaque_record = registration_finish(upload)
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration upload".into()))?;
    if bundle.len() != BUNDLE_LEN {
        return Err(ApiError::Invalid(format!(
            "private_bundle_enc must be {BUNDLE_LEN} bytes"
        )));
    }
    let version =
        i32::try_from(version).map_err(|_| ApiError::Invalid("version out of range".into()))?;
    Ok(NewCredentials {
        opaque_record,
        private_bundle_enc: bundle.to_vec(),
        version,
    })
}

/// M4-05: tells the user's other devices over WebSocket
/// (`{"type":"account_changed","key_version"}`); `origin` is not notified.
fn notify_account_changed(state: &AppState, user_id: Uuid, version: u32, origin: Option<Uuid>) {
    tracing::info!(%user_id, key_version = version, "account_changed");
    state.ws().account_changed(user_id, version, origin);
}

/// `POST /v1/account/totp`: without `code`, start enabling (new pending
/// secret, otpauth URI); with `code`, confirm the pending secret.
async fn totp_enable(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<TotpRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse as _;
    let store = state.auth().store();
    let current = store.totp_state(ctx.user_id).await?;
    if current.secret_enc.is_some() {
        return Err(ApiError::Conflict(
            "TOTP is already enabled; disable it first".into(),
        ));
    }
    match req.code {
        None => {
            let user = store
                .user_by_id(ctx.user_id)
                .await?
                .ok_or_else(|| ApiError::NotFound("account not found".into()))?;
            let secret = totp::generate_secret();
            let sealed = state
                .secrets()
                .seal(&totp_pending_aad(ctx.user_id), &secret)
                .map_err(ApiError::internal)?;
            store.set_totp_pending(ctx.user_id, Some(&sealed)).await?;
            Ok(Json(TotpSetupResponse {
                otpauth_uri: totp::otpauth_uri(&secret, &user.email),
                secret_base32: totp::base32(&secret),
            })
            .into_response())
        }
        Some(code) => {
            let pending = current
                .pending_enc
                .ok_or_else(|| ApiError::Invalid("no TOTP setup in progress".into()))?;
            let secret = state
                .secrets()
                .open(&totp_pending_aad(ctx.user_id), &pending)
                .ok_or_else(|| ApiError::internal(std::io::Error::other("TOTP secret")))?;
            let step = totp::verify(&secret, &code, unix_now(&state))
                .and_then(|s| i64::try_from(s).ok())
                .ok_or_else(|| ApiError::Invalid("invalid TOTP code".into()))?;
            let sealed = state
                .secrets()
                .seal(&totp_aad(ctx.user_id), &secret)
                .map_err(ApiError::internal)?;
            store.enable_totp(ctx.user_id, &sealed, step).await?;
            tracing::info!(user_id = %ctx.user_id, "TOTP enabled");
            Ok(Json(TotpStatus { enabled: true }).into_response())
        }
    }
}

/// `DELETE /v1/account/totp {code}`.
async fn totp_disable(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<TotpRequest>,
) -> Result<StatusCode, ApiError> {
    let store = state.auth().store();
    let current = store.totp_state(ctx.user_id).await?;
    let Some(enc) = current.secret_enc else {
        return Err(ApiError::Invalid("TOTP is not enabled".into()));
    };
    let invalid = || ApiError::Forbidden("invalid or already used TOTP code".into());
    let code = req.code.ok_or_else(invalid)?;
    let secret = state
        .secrets()
        .open(&totp_aad(ctx.user_id), &enc)
        .ok_or_else(|| ApiError::internal(std::io::Error::other("TOTP secret")))?;
    let step = totp::verify(&secret, &code, unix_now(&state))
        .and_then(|s| i64::try_from(s).ok())
        .ok_or_else(invalid)?;
    if !store.consume_totp_step(ctx.user_id, step).await? {
        return Err(invalid());
    }
    store.disable_totp(ctx.user_id).await?;
    tracing::info!(user_id = %ctx.user_id, "TOTP disabled");
    Ok(StatusCode::NO_CONTENT)
}

async fn password_start(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<PasswordStartRequest>,
) -> Result<Json<PasswordStartResponse>, ApiError> {
    let auth = state.auth();
    let user = auth
        .store()
        .user_by_id(ctx.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("account not found".into()))?;
    let setup = auth.server_setup(state.secrets()).await?;
    let registration_response = setup
        .registration_start(
            &req.registration_request,
            &credential_identifier(&user.email),
        )
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration request".into()))?;
    Ok(Json(PasswordStartResponse {
        registration_response,
    }))
}

/// `POST /v1/account/password` (§11.2.1).
async fn password_change(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<PasswordChangeRequest>,
) -> Result<Json<KeyVersionResponse>, ApiError> {
    let reauth = reauth_hash(&req.reauth_token)?;
    let new = new_credentials(
        &req.registration_upload,
        &req.private_bundle_enc,
        req.version,
    )?;
    let auth = state.auth();
    auth.store()
        .change_password(ctx, &reauth, &new, auth.now())
        .await?;
    tracing::info!(user_id = %ctx.user_id, version = req.version, "password changed");
    notify_account_changed(&state, ctx.user_id, req.version, Some(ctx.device_id));
    Ok(Json(KeyVersionResponse {
        version: req.version,
    }))
}

/// Issues a recovery code for `email` (admin CLI and the mail endpoint).
/// `None` for an unknown email.
///
/// # Errors
/// Database errors.
pub async fn issue_recovery_code(
    state_store: &crate::auth::AuthStore,
    email: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, ApiError> {
    let code = generate_recovery_code();
    let issued = state_store
        .issue_recovery_code(email, &hash_recovery_code(&code), now + RECOVERY_CODE_TTL)
        .await?;
    Ok(issued.map(|_| code.to_string()))
}

/// `POST /v1/account/recovery/code`: 202 whether or not the account exists.
async fn recovery_code(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryCodeRequest>,
) -> Result<StatusCode, ApiError> {
    let email = registration::normalize_email(&req.email)?;
    state.rate_limits().check_login(&email, ip)?;
    let Some(smtp) = state.config().smtp.clone() else {
        tracing::info!("recovery code requested without SMTP: the operator must issue it");
        return Ok(StatusCode::ACCEPTED);
    };
    let auth = state.auth();
    if let Some(code) = issue_recovery_code(auth.store(), &email, auth.now()).await? {
        let body = format!(
            "A recovery of your sverb account was requested.\n\n\
             Recovery code: {code}\n\n\
             Enter it in sverb together with your recovery phrase. The code expires in 24 \
             hours. If you did not ask for this, ignore this mail.\n"
        );
        tokio::spawn(async move {
            if let Err(e) = crate::mail::send(&smtp, &email, "Your sverb recovery code", body).await
            {
                tracing::warn!(error = %e, "could not mail a recovery code");
            }
        });
    }
    Ok(StatusCode::ACCEPTED)
}

async fn checked_code(
    state: &AppState,
    ip: std::net::IpAddr,
    email: &str,
    code: &str,
) -> Result<(String, [u8; 32], RecoveryInfo), ApiError> {
    let email = registration::normalize_email(email)?;
    state.rate_limits().check_login(&email, ip)?;
    let hash = hash_recovery_code(code);
    let auth = state.auth();
    let info = auth
        .store()
        .check_recovery_code(&email, &hash, auth.now())
        .await?
        .ok_or_else(|| ApiError::AuthRequired("invalid or expired recovery code".into()))?;
    Ok((email, hash, info))
}

async fn recovery_start(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryStartRequest>,
) -> Result<Json<RecoveryStartResponse>, ApiError> {
    let (email, _, info) = checked_code(&state, ip, &req.email, &req.code).await?;
    let recovery_bundle_enc = info
        .recovery_bundle_enc
        .ok_or_else(|| ApiError::NotFound("this account has no recovery bundle".into()))?;
    let setup = state.auth().server_setup(state.secrets()).await?;
    let registration_response = setup
        .registration_start(&req.registration_request, &credential_identifier(&email))
        .map_err(|_| ApiError::Invalid("malformed OPAQUE registration request".into()))?;
    Ok(Json(RecoveryStartResponse {
        user_id: info.user_id,
        recovery_bundle_enc,
        registration_response,
        version: u32::try_from(info.version).unwrap_or(0),
    }))
}

async fn recovery_finish(
    State(state): State<AppState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(req): Json<RecoveryFinishRequest>,
) -> Result<Json<KeyVersionResponse>, ApiError> {
    let (_, hash, info) = checked_code(&state, ip, &req.email, &req.code).await?;
    let new = new_credentials(
        &req.registration_upload,
        &req.private_bundle_enc,
        req.version,
    )?;
    let ed_pub: [u8; 32] = info
        .ed25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal(std::io::Error::other("stored ed25519_pub")))?;
    let sig: [u8; 64] = req
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Invalid("signature must be 64 bytes".into()))?;
    let msg = recovery_proof_message(
        info.user_id.as_bytes(),
        req.version,
        &req.registration_upload,
        &req.private_bundle_enc,
    );
    sign::verify(&ed_pub, &msg, &sig)
        .map_err(|_| ApiError::Forbidden("recovery proof signature does not verify".into()))?;
    let auth = state.auth();
    auth.store()
        .finish_recovery(info.user_id, &hash, &new, auth.now())
        .await?;
    tracing::info!(user_id = %info.user_id, version = req.version, "account recovered");
    notify_account_changed(&state, info.user_id, req.version, None);
    Ok(Json(KeyVersionResponse {
        version: req.version,
    }))
}

/// `DELETE /v1/account`.
async fn delete_account(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<AccountDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    let reauth = reauth_hash(&req.reauth_token)?;
    let auth = state.auth();
    auth.store()
        .delete_account(ctx.user_id, &reauth, auth.now())
        .await?;
    tracing::info!(user_id = %ctx.user_id, "account deleted");
    Ok(StatusCode::NO_CONTENT)
}
