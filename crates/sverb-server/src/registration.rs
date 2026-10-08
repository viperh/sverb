//! Registration policy and first-start bootstrap (SPEC §10.6).
//!
//! * Registration mode lives in `settings.registration_mode`
//!   (`invite-only` after the first migration).
//! * On start, while no user exists, [`bootstrap`] creates a fresh one-time
//!   **setup token** (only its SHA-256 is stored) for the operator to read
//!   from the log. A new token replaces the previous one on every start until
//!   someone registers, so the latest log line is always valid.
//! * [`authorize`] is the single policy check the registration endpoint
//!   (M4-02) runs inside its transaction, before creating the user.

use std::str::FromStr;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use sqlx_postgres::{PgConnection, PgPool};
use sverb_crypto::random;
use uuid::Uuid;

use crate::error::ApiError;
use crate::settings;

/// Who may register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Anyone.
    Open,
    /// Only with an invite or the setup token (the default).
    InviteOnly,
    /// Nobody.
    Closed,
}

impl RegistrationMode {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InviteOnly => "invite-only",
            Self::Closed => "closed",
        }
    }
}

impl std::fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RegistrationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "open" => Ok(Self::Open),
            "invite-only" | "invite_only" => Ok(Self::InviteOnly),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "unknown registration mode `{other}` (open, invite-only, closed)"
            )),
        }
    }
}

/// Reads the registration mode (an unknown stored value counts as `closed`,
/// the safe choice).
///
/// # Errors
/// Database errors.
pub async fn mode(conn: &mut PgConnection) -> Result<RegistrationMode, sqlx_core::Error> {
    Ok(settings::get(&mut *conn, settings::REGISTRATION_MODE)
        .await?
        .map_or(RegistrationMode::InviteOnly, |v| {
            v.parse().unwrap_or(RegistrationMode::Closed)
        }))
}

/// Sets the registration mode.
///
/// # Errors
/// Database errors.
pub async fn set_mode(pool: &PgPool, mode: RegistrationMode) -> Result<(), sqlx_core::Error> {
    settings::set(pool, settings::REGISTRATION_MODE, mode.as_str()).await
}

/// A fresh 256-bit token, base64url without padding.
#[must_use]
pub fn generate_token() -> String {
    let key = random::random_key32(&mut random::os_rng());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.expose_secret())
}

/// SHA-256 of a token (how setup and invite tokens are stored).
#[must_use]
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.trim().as_bytes()).into()
}

/// Normalises an email: trims it, requires `local@domain`, lowercases the
/// domain (CITEXT makes comparisons case-insensitive anyway).
///
/// # Errors
/// [`ApiError::Invalid`] for anything that is not `local@domain`.
pub fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let s = raw.trim();
    let bad = || ApiError::Invalid("invalid email address".into());
    let (local, domain) = s.split_once('@').ok_or_else(bad)?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || s.len() > 254
        || s.chars().any(|c| c.is_whitespace() || c.is_control())
        || !domain.contains('.') && domain != "localhost"
    {
        return Err(bad());
    }
    Ok(format!("{local}@{}", domain.to_lowercase()))
}

/// First-start bootstrap: while no user exists, stores the hash of a new
/// setup token and returns the token (for [`log_setup_token`]).
///
/// # Errors
/// Database errors.
pub async fn bootstrap(pool: &PgPool) -> Result<Option<String>, sqlx_core::Error> {
    let has_users: bool =
        sqlx_core::query_scalar::query_scalar("SELECT EXISTS (SELECT 1 FROM users)")
            .fetch_one(pool)
            .await?;
    if has_users {
        return Ok(None);
    }
    let token = generate_token();
    settings::set(
        pool,
        settings::SETUP_TOKEN_HASH,
        &hex::encode(hash_token(&token)),
    )
    .await?;
    Ok(Some(token))
}

/// Logs the setup token at `warn` with instructions (SPEC §10.6).
pub fn log_setup_token(token: &str, public_url: &str) {
    tracing::warn!(
        setup_token = token,
        server = public_url,
        "no accounts exist yet: register the first account against this server and enter \
         this one-time setup token when sverb asks for it; that account becomes the instance \
         admin. A new token is generated on every start until one is used"
    );
}

/// What the registrant presented besides email and password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCredential<'a> {
    /// Nothing.
    None,
    /// The bootstrap setup token.
    SetupToken(&'a str),
    /// An invite token (instance invite from `admin invite`, or an org
    /// invite, M5-01).
    InviteToken(&'a str),
}

/// The outcome of a successful [`authorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistrationGrant {
    /// The account becomes the instance admin (setup token used).
    pub is_instance_admin: bool,
    /// The instance invite that was consumed.
    pub instance_invite: Option<Uuid>,
    /// A valid, still-pending org invite; M5-01 accepts it after the account
    /// exists (adds the membership and sets `accepted_at`).
    pub org_invite: Option<Uuid>,
}

/// Decides whether `email` may register, consuming single-use tokens.
///
/// Must run inside the transaction that creates the user, so a failed
/// registration rolls the token consumption back and two concurrent
/// registrations can't both use the same token (the second one blocks on the
/// row lock and then finds the token gone).
///
/// Rules: `closed` rejects everything; a setup token must match and makes
/// the account instance admin; an invite must be unexpired, unaccepted and
/// (when it names one) for this email; with nothing presented only `open`
/// mode allows registration.
///
/// # Errors
/// [`ApiError::Forbidden`] when not allowed; database errors as `Internal`.
pub async fn authorize(
    conn: &mut PgConnection,
    email: &str,
    credential: RegistrationCredential<'_>,
) -> Result<RegistrationGrant, ApiError> {
    if mode(&mut *conn).await? == RegistrationMode::Closed {
        return Err(ApiError::Forbidden(
            "registration is closed on this server".into(),
        ));
    }
    match credential {
        RegistrationCredential::SetupToken(token) => {
            let consumed: Option<String> = sqlx_core::query_scalar::query_scalar(
                "DELETE FROM settings WHERE key = $1 AND value = $2 RETURNING key",
            )
            .bind(settings::SETUP_TOKEN_HASH)
            .bind(hex::encode(hash_token(token)))
            .fetch_optional(&mut *conn)
            .await?;
            if consumed.is_none() {
                return Err(ApiError::Forbidden(
                    "invalid or already used setup token".into(),
                ));
            }
            Ok(RegistrationGrant {
                is_instance_admin: true,
                ..RegistrationGrant::default()
            })
        }
        RegistrationCredential::InviteToken(token) => {
            let hash = hash_token(token).to_vec();
            let instance: Option<Uuid> = sqlx_core::query_scalar::query_scalar(
                "UPDATE invites SET accepted_at = now() \
                 WHERE token_hash = $1 AND org_id IS NULL AND accepted_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > now()) \
                   AND (email IS NULL OR email = $2::citext) \
                 RETURNING id",
            )
            .bind(&hash)
            .bind(email)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(id) = instance {
                return Ok(RegistrationGrant {
                    instance_invite: Some(id),
                    ..RegistrationGrant::default()
                });
            }
            let org: Option<Uuid> = sqlx_core::query_scalar::query_scalar(
                "SELECT id FROM invites \
                 WHERE token_hash = $1 AND org_id IS NOT NULL AND accepted_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > now()) \
                   AND (email IS NULL OR email = $2::citext) \
                 FOR UPDATE",
            )
            .bind(&hash)
            .bind(email)
            .fetch_optional(&mut *conn)
            .await?;
            match org {
                Some(id) => Ok(RegistrationGrant {
                    org_invite: Some(id),
                    ..RegistrationGrant::default()
                }),
                None => Err(ApiError::Forbidden(
                    "invalid, expired or already used invite".into(),
                )),
            }
        }
        RegistrationCredential::None => match mode(&mut *conn).await? {
            RegistrationMode::Open => Ok(RegistrationGrant::default()),
            _ => Err(ApiError::Forbidden(
                "registration on this server requires an invite".into(),
            )),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mode_roundtrip() {
        for m in [
            RegistrationMode::Open,
            RegistrationMode::InviteOnly,
            RegistrationMode::Closed,
        ] {
            assert_eq!(m.as_str().parse::<RegistrationMode>().unwrap(), m);
        }
        assert!("whatever".parse::<RegistrationMode>().is_err());
    }

    #[test]
    fn tokens_are_random_and_hash_stably() {
        let a = generate_token();
        assert_ne!(a, generate_token());
        assert_eq!(a.len(), 43);
        assert_eq!(hash_token(&a), hash_token(&format!(" {a}\n")));
    }

    #[test]
    fn email_normalisation() {
        assert_eq!(
            normalize_email("  Alice@Example.COM ").unwrap(),
            "Alice@example.com"
        );
        assert!(normalize_email("no-at-sign").is_err());
        assert!(normalize_email("a@b@c.d").is_err());
        assert!(normalize_email("@example.com").is_err());
        assert!(normalize_email("a b@example.com").is_err());
        assert!(normalize_email("a@nodot").is_err());
    }
}
