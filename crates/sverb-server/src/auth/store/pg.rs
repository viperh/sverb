//! PostgreSQL backend of [`super::AuthStore`]. Runtime-checked queries
//! (`sqlx_core::query*`); timestamps are bound from the injectable clock.

// Row tuples are how runtime-checked queries return columns.
#![allow(clippy::type_complexity)]

use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::{PgConnection, PgPool};
use uuid::Uuid;

use super::{
    AccessCtx, AccountKeysRow, DeviceChoice, DeviceRow, LoginStateRow, LoginUser, NewAccount,
    NewCredentials, RECOVERY_CODE_MAX_ATTEMPTS, RecoveryInfo, RefreshOutcome, TotpState,
};
use crate::auth::tokens::{IssuedTokens, LAST_SEEN_THROTTLE, TokenHash};
use crate::error::ApiError;
use crate::registration::{self, RegistrationCredential, RegistrationGrant};

type Res<T> = Result<T, ApiError>;

fn is_unique_violation(e: &sqlx_core::Error) -> bool {
    matches!(e, sqlx_core::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

async fn insert_tokens(
    conn: &mut PgConnection,
    device_id: Uuid,
    tokens: &IssuedTokens,
    family: Uuid,
) -> Res<()> {
    for rec in tokens.records() {
        query(
            "INSERT INTO auth_tokens (token_hash, device_id, kind, expires_at, family, used_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)",
        )
        .bind(&rec.hash[..])
        .bind(device_id)
        .bind(rec.kind.as_str())
        .bind(rec.expires_at)
        .bind(family)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn insert_device(
    conn: &mut PgConnection,
    user_id: Uuid,
    d: &super::NewDevice,
    now: DateTime<Utc>,
) -> Res<()> {
    query(
        "INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at, revoked_at) \
         VALUES ($1, $2, $3, $4, $5, $5, NULL)",
    )
    .bind(d.id)
    .bind(user_id)
    .bind(&d.name)
    .bind(&d.platform)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn check_registration(
    pool: &PgPool,
    email: &str,
    cred: RegistrationCredential<'_>,
) -> Res<()> {
    let mut tx = pool.begin().await?;
    registration::authorize(&mut tx, email, cred).await?;
    // Policy check only: undo any token consumption.
    tx.rollback().await?;
    Ok(())
}

pub(super) async fn register(
    pool: &PgPool,
    a: &NewAccount,
    cred: RegistrationCredential<'_>,
    tokens: &IssuedTokens,
    family: Uuid,
    now: DateTime<Utc>,
) -> Res<RegistrationGrant> {
    let mut tx = pool.begin().await?;
    let grant = registration::authorize(&mut tx, &a.email, cred).await?;
    let conflict = |what: &str| ApiError::Conflict(format!("{what} already exists"));

    query(
        "INSERT INTO users (id, email, created_at, is_instance_admin, opaque_record) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(a.user_id)
    .bind(&a.email)
    .bind(now)
    .bind(grant.is_instance_admin)
    .bind(&a.opaque_record)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            conflict("an account with this email or id")
        } else {
            e.into()
        }
    })?;
    query(
        "INSERT INTO account_keys \
         (user_id, x25519_pub, ed25519_pub, private_bundle_enc, recovery_bundle_enc, version) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(a.user_id)
    .bind(&a.keys.x25519_pub)
    .bind(&a.keys.ed25519_pub)
    .bind(&a.keys.private_bundle_enc)
    .bind(&a.keys.recovery_bundle_enc)
    .bind(a.keys.version)
    .execute(&mut *tx)
    .await?;
    query(
        "INSERT INTO vaults (id, kind, owner_user_id, org_id, key_version, name_enc) \
         VALUES ($1, 'personal', $2, NULL, $3, $4)",
    )
    .bind(a.vault_id)
    .bind(a.user_id)
    .bind(a.grant_key_version)
    .bind(&a.vault_name_enc)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            conflict("a vault with this id")
        } else {
            e.into()
        }
    })?;
    query(
        "INSERT INTO vault_members \
         (vault_id, user_id, permission, key_version, wrapped_vault_key, wrapped_by, signature) \
         VALUES ($1, $2, 'manage', $3, $4, $2, $5)",
    )
    .bind(a.vault_id)
    .bind(a.user_id)
    .bind(a.grant_key_version)
    .bind(&a.grant_wrapped)
    .bind(&a.grant_signature)
    .execute(&mut *tx)
    .await?;
    insert_device(&mut tx, a.user_id, &a.device, now).await?;
    insert_tokens(&mut tx, a.device.id, tokens, family).await?;
    tx.commit().await?;
    Ok(grant)
}

type UserTuple = (Uuid, String, Vec<u8>, bool, bool, Option<Vec<u8>>);

fn login_user(t: UserTuple) -> LoginUser {
    LoginUser {
        id: t.0,
        email: t.1,
        opaque_record: t.2,
        disabled: t.3,
        is_instance_admin: t.4,
        totp_secret_enc: t.5,
    }
}

const USER_COLS: &str =
    "id, email::text, opaque_record, disabled, is_instance_admin, totp_secret_enc";

pub(super) async fn user_by_email(pool: &PgPool, email: &str) -> Res<Option<LoginUser>> {
    let row: Option<UserTuple> = query_as(&format!(
        "SELECT {USER_COLS} FROM users WHERE email = $1::citext"
    ))
    .bind(email.trim())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(login_user))
}

pub(super) async fn user_by_id(pool: &PgPool, id: Uuid) -> Res<Option<LoginUser>> {
    let row: Option<UserTuple> = query_as(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(login_user))
}

pub(super) async fn put_login_state(
    pool: &PgPool,
    row: &LoginStateRow,
    now: DateTime<Utc>,
) -> Res<()> {
    query("DELETE FROM login_states WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await?;
    query("INSERT INTO login_states (id, user_id, state_enc, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.state_enc)
        .bind(row.expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn take_login_state(
    pool: &PgPool,
    id: Uuid,
    now: DateTime<Utc>,
) -> Res<Option<LoginStateRow>> {
    let row: Option<(Uuid, Option<Uuid>, Vec<u8>, DateTime<Utc>)> = query_as(
        "DELETE FROM login_states WHERE id = $1 RETURNING id, user_id, state_enc, expires_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .filter(|r| r.3 > now)
        .map(|(id, user_id, state_enc, expires_at)| LoginStateRow {
            id,
            user_id,
            state_enc,
            expires_at,
        }))
}

pub(super) async fn start_session(
    pool: &PgPool,
    user_id: Uuid,
    device: &DeviceChoice,
    tokens: &IssuedTokens,
    family: Uuid,
    now: DateTime<Utc>,
) -> Res<Uuid> {
    let mut tx = pool.begin().await?;
    let device_id = match device {
        DeviceChoice::Existing(id, fallback) => {
            let resumed: Option<Uuid> = query_scalar(
                "UPDATE devices SET last_seen_at = $3 \
                 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id",
            )
            .bind(id)
            .bind(user_id)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            match resumed {
                Some(id) => {
                    query("DELETE FROM auth_tokens WHERE device_id = $1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    id
                }
                None => {
                    insert_device(&mut tx, user_id, fallback, now).await?;
                    fallback.id
                }
            }
        }
        DeviceChoice::New(d) => {
            insert_device(&mut tx, user_id, d, now).await?;
            d.id
        }
    };
    insert_tokens(&mut tx, device_id, tokens, family).await?;
    tx.commit().await?;
    Ok(device_id)
}

pub(super) async fn account_keys(pool: &PgPool, user_id: Uuid) -> Res<Option<AccountKeysRow>> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, i32)> = query_as(
        "SELECT x25519_pub, ed25519_pub, private_bundle_enc, recovery_bundle_enc, version \
         FROM account_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| AccountKeysRow {
        x25519_pub: r.0,
        ed25519_pub: r.1,
        private_bundle_enc: r.2,
        recovery_bundle_enc: r.3,
        version: r.4,
    }))
}

pub(super) async fn lookup_access(
    pool: &PgPool,
    hash: &TokenHash,
    now: DateTime<Utc>,
) -> Res<Option<AccessCtx>> {
    let row: Option<(Uuid, Uuid, Option<DateTime<Utc>>)> = query_as(
        "SELECT d.user_id, d.id, d.last_seen_at FROM auth_tokens t \
         JOIN devices d ON d.id = t.device_id \
         JOIN users u ON u.id = d.user_id \
         WHERE t.token_hash = $1 AND t.kind = 'access' AND t.expires_at > $2 \
           AND d.revoked_at IS NULL AND NOT u.disabled",
    )
    .bind(&hash[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    let Some((user_id, device_id, last_seen)) = row else {
        return Ok(None);
    };
    if last_seen.is_none_or(|t| t + LAST_SEEN_THROTTLE <= now) {
        query(
            "UPDATE devices SET last_seen_at = $2 \
             WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at <= $3)",
        )
        .bind(device_id)
        .bind(now)
        .bind(now - LAST_SEEN_THROTTLE)
        .execute(pool)
        .await?;
    }
    Ok(Some(AccessCtx { user_id, device_id }))
}

// M4-05
pub(super) async fn access_expires_at(
    pool: &PgPool,
    hash: &TokenHash,
    now: DateTime<Utc>,
) -> Res<Option<DateTime<Utc>>> {
    Ok(query_scalar(
        "SELECT t.expires_at FROM auth_tokens t \
         JOIN devices d ON d.id = t.device_id \
         JOIN users u ON u.id = d.user_id \
         WHERE t.token_hash = $1 AND t.kind = 'access' AND t.expires_at > $2 \
           AND d.revoked_at IS NULL AND NOT u.disabled",
    )
    .bind(&hash[..])
    .bind(now)
    .fetch_optional(pool)
    .await?)
}

pub(super) async fn refresh(
    pool: &PgPool,
    hash: &TokenHash,
    new: &IssuedTokens,
    now: DateTime<Utc>,
) -> Res<RefreshOutcome> {
    let mut tx = pool.begin().await?;
    // The row lock serializes concurrent presentations of the same token:
    // the second one sees `used_at` and triggers reuse detection.
    let row: Option<(Uuid, Uuid, Option<DateTime<Utc>>, DateTime<Utc>)> = query_as(
        "SELECT device_id, family, used_at, expires_at FROM auth_tokens \
         WHERE token_hash = $1 AND kind = 'refresh' FOR UPDATE",
    )
    .bind(&hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    let Some((device_id, family, used_at, expires_at)) = row else {
        return Ok(RefreshOutcome::Invalid);
    };
    if used_at.is_some() {
        query("DELETE FROM auth_tokens WHERE family = $1")
            .bind(family)
            .execute(&mut *tx)
            .await?;
        let user_id: Option<Uuid> = query_scalar("SELECT user_id FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
        tx.commit().await?;
        return Ok(RefreshOutcome::Reused {
            device_id,
            user_id,
            family,
        });
    }
    if expires_at <= now {
        return Ok(RefreshOutcome::Invalid);
    }
    let user_id: Option<Uuid> = query_scalar(
        "SELECT d.user_id FROM devices d JOIN users u ON u.id = d.user_id \
         WHERE d.id = $1 AND d.revoked_at IS NULL AND NOT u.disabled",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(RefreshOutcome::Invalid);
    };
    query("UPDATE auth_tokens SET used_at = $2 WHERE token_hash = $1")
        .bind(&hash[..])
        .bind(now)
        .execute(&mut *tx)
        .await?;
    insert_tokens(&mut tx, device_id, new, family).await?;
    query("UPDATE devices SET last_seen_at = $2 WHERE id = $1")
        .bind(device_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(RefreshOutcome::Rotated(AccessCtx { user_id, device_id }))
}

pub(super) async fn logout(pool: &PgPool, device_id: Uuid) -> Res<()> {
    query("DELETE FROM auth_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn list_devices(pool: &PgPool, user_id: Uuid) -> Res<Vec<DeviceRow>> {
    type Row = (
        Uuid,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    );
    let rows: Vec<Row> = query_as(
        "SELECT id, name, platform, created_at, last_seen_at, revoked_at FROM devices \
         WHERE user_id = $1 ORDER BY created_at, id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceRow {
            id: r.0,
            name: r.1,
            platform: r.2,
            created_at: r.3,
            last_seen_at: r.4,
            revoked_at: r.5,
        })
        .collect())
}

pub(super) async fn revoke_device(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> Res<bool> {
    let mut tx = pool.begin().await?;
    let found: Option<Uuid> = query_scalar(
        "UPDATE devices SET revoked_at = COALESCE(revoked_at, $3) \
         WHERE id = $1 AND user_id = $2 RETURNING id",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if found.is_none() {
        return Ok(false);
    }
    query("DELETE FROM auth_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub(super) async fn totp_state(pool: &PgPool, user_id: Uuid) -> Res<TotpState> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> =
        query_as("SELECT totp_secret_enc, totp_pending_enc FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .map(|(secret_enc, pending_enc)| TotpState {
            secret_enc,
            pending_enc,
        })
        .unwrap_or_default())
}

pub(super) async fn set_totp_pending(
    pool: &PgPool,
    user_id: Uuid,
    pending_enc: Option<&[u8]>,
) -> Res<()> {
    query("UPDATE users SET totp_pending_enc = $2 WHERE id = $1")
        .bind(user_id)
        .bind(pending_enc)
        .execute(pool)
        .await?;
    Ok(())
}

pub(super) async fn enable_totp(
    pool: &PgPool,
    user_id: Uuid,
    secret_enc: &[u8],
    step: i64,
) -> Res<()> {
    query(
        "UPDATE users SET totp_secret_enc = $2, totp_pending_enc = NULL, totp_last_step = $3 \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(secret_enc)
    .bind(step)
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn disable_totp(pool: &PgPool, user_id: Uuid) -> Res<()> {
    query(
        "UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_last_step = NULL \
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn consume_totp_step(pool: &PgPool, user_id: Uuid, step: i64) -> Res<bool> {
    let n = query(
        "UPDATE users SET totp_last_step = $2 \
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub(super) async fn insert_reauth(
    pool: &PgPool,
    hash: &TokenHash,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Res<()> {
    query("INSERT INTO reauth_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(&hash[..])
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

async fn consume_reauth(
    conn: &mut PgConnection,
    user_id: Uuid,
    hash: &TokenHash,
    now: DateTime<Utc>,
) -> Res<()> {
    let ok: Option<DateTime<Utc>> = query_scalar(
        "DELETE FROM reauth_tokens WHERE token_hash = $1 AND user_id = $2 RETURNING expires_at",
    )
    .bind(&hash[..])
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    match ok {
        Some(exp) if exp > now => Ok(()),
        _ => Err(ApiError::AuthRequired(
            "a fresh login is required (reauth token missing, used or expired)".into(),
        )),
    }
}

async fn replace_credentials(
    conn: &mut PgConnection,
    user_id: Uuid,
    new: &NewCredentials,
) -> Res<()> {
    let current: Option<i32> =
        query_scalar("SELECT version FROM account_keys WHERE user_id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(current) = current else {
        return Err(ApiError::NotFound("account not found".into()));
    };
    if current.checked_add(1) != Some(new.version) {
        return Err(ApiError::Conflict(format!(
            "account key version must be {} (current version + 1)",
            current.saturating_add(1)
        )));
    }
    query("UPDATE users SET opaque_record = $2 WHERE id = $1")
        .bind(user_id)
        .bind(&new.opaque_record)
        .execute(&mut *conn)
        .await?;
    query("UPDATE account_keys SET private_bundle_enc = $2, version = $3 WHERE user_id = $1")
        .bind(user_id)
        .bind(&new.private_bundle_enc)
        .bind(new.version)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(super) async fn change_password(
    pool: &PgPool,
    ctx: AccessCtx,
    reauth: &TokenHash,
    new: &NewCredentials,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut tx = pool.begin().await?;
    consume_reauth(&mut tx, ctx.user_id, reauth, now).await?;
    replace_credentials(&mut tx, ctx.user_id, new).await?;
    query(
        "DELETE FROM auth_tokens WHERE device_id IN \
         (SELECT id FROM devices WHERE user_id = $1 AND id <> $2)",
    )
    .bind(ctx.user_id)
    .bind(ctx.device_id)
    .execute(&mut *tx)
    .await?;
    query("DELETE FROM reauth_tokens WHERE user_id = $1")
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await?;
    audit_in(
        &mut tx,
        Some(ctx.user_id),
        "password_changed",
        Some(ctx.user_id),
        serde_json::json!({ "version": new.version, "device_id": ctx.device_id }),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn issue_recovery_code(
    pool: &PgPool,
    email: &str,
    code_hash: &TokenHash,
    expires_at: DateTime<Utc>,
) -> Res<Option<Uuid>> {
    let user: Option<Uuid> = query_scalar("SELECT id FROM users WHERE email = $1::citext")
        .bind(email.trim())
        .fetch_optional(pool)
        .await?;
    let Some(user_id) = user else {
        return Ok(None);
    };
    query(
        "INSERT INTO recovery_codes (user_id, code_hash, expires_at, attempts) \
         VALUES ($1, $2, $3, 0) \
         ON CONFLICT (user_id) DO UPDATE SET code_hash = EXCLUDED.code_hash, \
           expires_at = EXCLUDED.expires_at, attempts = 0",
    )
    .bind(user_id)
    .bind(&code_hash[..])
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(Some(user_id))
}

pub(super) async fn check_recovery_code(
    pool: &PgPool,
    email: &str,
    code_hash: &TokenHash,
    now: DateTime<Utc>,
) -> Res<Option<RecoveryInfo>> {
    let mut tx = pool.begin().await?;
    type Row = (
        Uuid,
        String,
        bool,
        Vec<u8>,
        DateTime<Utc>,
        Option<Vec<u8>>,
        i32,
        Vec<u8>,
    );
    let row: Option<Row> = query_as(
        "SELECT u.id, u.email::text, u.disabled, c.code_hash, c.expires_at, \
                k.recovery_bundle_enc, k.version, k.ed25519_pub \
         FROM users u JOIN recovery_codes c ON c.user_id = u.id \
         JOIN account_keys k ON k.user_id = u.id \
         WHERE u.email = $1::citext FOR UPDATE OF c",
    )
    .bind(email.trim())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, email, disabled, stored, expires_at, bundle, version, ed_pub)) = row else {
        return Ok(None);
    };
    let matches: bool = subtle::ConstantTimeEq::ct_eq(&stored[..], &code_hash[..]).into();
    if !matches || expires_at <= now || disabled {
        query("UPDATE recovery_codes SET attempts = attempts + 1 WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        query("DELETE FROM recovery_codes WHERE user_id = $1 AND (attempts >= $2 OR expires_at <= $3)")
            .bind(user_id)
            .bind(RECOVERY_CODE_MAX_ATTEMPTS)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(None);
    }
    tx.commit().await?;
    Ok(Some(RecoveryInfo {
        user_id,
        email,
        recovery_bundle_enc: bundle,
        version,
        ed25519_pub: ed_pub,
    }))
}

pub(super) async fn finish_recovery(
    pool: &PgPool,
    user_id: Uuid,
    code_hash: &TokenHash,
    new: &NewCredentials,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut tx = pool.begin().await?;
    let consumed: Option<DateTime<Utc>> = query_scalar(
        "DELETE FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 RETURNING expires_at",
    )
    .bind(user_id)
    .bind(&code_hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    if !consumed.is_some_and(|exp| exp > now) {
        return Err(ApiError::AuthRequired(
            "invalid or expired recovery code".into(),
        ));
    }
    replace_credentials(&mut tx, user_id, new).await?;
    query("DELETE FROM auth_tokens WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    query("DELETE FROM reauth_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    audit_in(
        &mut tx,
        Some(user_id),
        "account_recovered",
        Some(user_id),
        serde_json::json!({ "version": new.version }),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn delete_account(
    pool: &PgPool,
    user_id: Uuid,
    reauth: &TokenHash,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut tx = pool.begin().await?;
    consume_reauth(&mut tx, user_id, reauth, now).await?;
    let personal = "SELECT id FROM vaults WHERE kind = 'personal' AND owner_user_id = $1";
    for stmt in [
        format!("DELETE FROM items WHERE vault_id IN ({personal})"),
        format!("DELETE FROM items_rotation_staging WHERE vault_id IN ({personal})"),
        format!("DELETE FROM vault_members WHERE vault_id IN ({personal})"),
        "DELETE FROM vaults WHERE kind = 'personal' AND owner_user_id = $1".to_owned(),
        // Memberships in shared vaults go; the vaults and their items stay.
        "DELETE FROM vault_members WHERE user_id = $1".to_owned(),
        "DELETE FROM org_members WHERE user_id = $1".to_owned(),
        "DELETE FROM share_sessions WHERE owner_user_id = $1".to_owned(),
        "DELETE FROM auth_tokens WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)"
            .to_owned(),
        "DELETE FROM login_states WHERE user_id = $1".to_owned(),
        "DELETE FROM devices WHERE user_id = $1".to_owned(),
        "DELETE FROM account_keys WHERE user_id = $1".to_owned(),
        "DELETE FROM users WHERE id = $1".to_owned(),
    ] {
        query(&stmt).bind(user_id).execute(&mut *tx).await?;
    }
    audit_in(
        &mut tx,
        Some(user_id),
        "account_deleted",
        Some(user_id),
        serde_json::json!({}),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn get_secret(pool: &PgPool, name: &str) -> Res<Option<Vec<u8>>> {
    Ok(
        query_scalar("SELECT value_enc FROM server_secrets WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?,
    )
}

pub(super) async fn insert_secret_if_absent(pool: &PgPool, name: &str, value: &[u8]) -> Res<()> {
    query(
        "INSERT INTO server_secrets (name, value_enc) VALUES ($1, $2) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

async fn audit_in(
    conn: &mut PgConnection,
    actor: Option<Uuid>,
    kind: &str,
    target: Option<Uuid>,
    meta: serde_json::Value,
    now: DateTime<Utc>,
) -> Res<()> {
    query(
        "INSERT INTO audit_events (org_id, actor_user_id, kind, target, at, meta) \
         VALUES (NULL, $1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(kind)
    .bind(target)
    .bind(now)
    .bind(meta)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn audit(
    pool: &PgPool,
    actor: Option<Uuid>,
    kind: &str,
    target: Option<Uuid>,
    meta: serde_json::Value,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut conn = pool.acquire().await?;
    audit_in(&mut conn, actor, kind, target, meta, now).await
}
