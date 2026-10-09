use sqlx_core::executor::Executor;
use sqlx_postgres::Postgres;

/// `open` | `invite-only` | `closed`.
pub const REGISTRATION_MODE: &str = "registration_mode";
/// Hex SHA-256 of the one-time setup token (present until it is used).
pub const SETUP_TOKEN_HASH: &str = "setup_token_hash";

/// Reads a setting.
///
/// # Errors
/// Database errors.
pub async fn get<'e, E>(db: E, key: &str) -> Result<Option<String>, sqlx_core::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx_core::query_scalar::query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
}

/// Inserts or replaces a setting.
///
/// # Errors
/// Database errors.
pub async fn set<'e, E>(db: E, key: &str, value: &str) -> Result<(), sqlx_core::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx_core::query::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

/// Deletes a setting.
///
/// # Errors
/// Database errors.
pub async fn delete<'e, E>(db: E, key: &str) -> Result<(), sqlx_core::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx_core::query::query("DELETE FROM settings WHERE key = $1")
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}
