//! `admin user list | disable | recovery-code` (`create` is an invite, see
//! [`super::invite`]).

use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;

use super::AdminError;

/// One row of `admin user list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    /// Email.
    pub email: String,
    /// Registration time.
    pub created_at: DateTime<Utc>,
    /// Disabled by an admin.
    pub disabled: bool,
    /// Instance admin (registered with the setup token).
    pub is_instance_admin: bool,
    /// Devices that are not revoked.
    pub devices: i64,
}

/// Lists all users, oldest first.
///
/// # Errors
/// Database errors.
pub async fn list(pool: &PgPool) -> Result<Vec<UserSummary>, AdminError> {
    let rows: Vec<(String, DateTime<Utc>, bool, bool, i64)> = sqlx_core::query_as::query_as(
        "SELECT u.email::text, u.created_at, u.disabled, u.is_instance_admin, \
                (SELECT count(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) \
         FROM users u ORDER BY u.created_at, u.email",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(email, created_at, disabled, is_instance_admin, devices)| UserSummary {
                email,
                created_at,
                disabled,
                is_instance_admin,
                devices,
            },
        )
        .collect())
}

/// Result of [`disable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disabled {
    /// Auth tokens deleted.
    pub tokens_revoked: u64,
}

/// Disables a user and revokes all their tokens (one transaction).
///
/// # Errors
/// [`AdminError::NoSuchUser`]; database errors.
pub async fn disable(pool: &PgPool, email: &str) -> Result<Disabled, AdminError> {
    let email = email.trim();
    let mut tx = pool.begin().await?;
    let id: Option<uuid::Uuid> = sqlx_core::query_scalar::query_scalar(
        "UPDATE users SET disabled = true WHERE email = $1::citext RETURNING id",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(id) = id else {
        return Err(AdminError::NoSuchUser(email.to_owned()));
    };
    let revoked = sqlx_core::query::query(
        "DELETE FROM auth_tokens WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // M4-05: the CLI is another process; NOTIFY (delivered at commit) closes
    // the user's open sockets on every replica.
    crate::ws::pg_notify::notify_in(&mut tx, &crate::ws::BusEvent::UserDisabled { user_id: id })
        .await?;
    tx.commit().await?;
    Ok(Disabled {
        tokens_revoked: revoked,
    })
}

/// M4-02: issues a one-time recovery code (24 h) for `email` and returns it.
/// Only its hash is stored; a new code replaces the previous one.
///
/// # Errors
/// [`AdminError::NoSuchUser`]; database errors.
pub async fn recovery_code(
    pool: &PgPool,
    email: &str,
) -> Result<zeroize::Zeroizing<String>, AdminError> {
    let email = crate::registration::normalize_email(email)?;
    let store = crate::auth::AuthStore::Postgres(pool.clone());
    let code = crate::routes::account::issue_recovery_code(&store, &email, Utc::now())
        .await
        .map_err(|e| match e {
            crate::error::ApiError::Internal(cause) => AdminError::Invalid(cause.to_string()),
            other => AdminError::from(other),
        })?;
    code.map(zeroize::Zeroizing::new)
        .ok_or(AdminError::NoSuchUser(email))
}
