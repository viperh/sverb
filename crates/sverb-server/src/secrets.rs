//! At-rest encryption of `server_secrets` (SPEC §10.3, §10.7).
//!
//! Key: `HKDF-SHA256(ikm = SVERB_SERVER_SECRET, info = "sverb/server-secret/v1")`.
//! Values are XChaCha20-Poly1305 from `sverb-crypto`, stored as
//! `nonce (24 bytes) || ciphertext`, with the row name as AAD so rows can't
//! be swapped. The same key encrypts other server-side secrets (TOTP seeds,
//! M4-02) through [`ServerSecrets::seal`] with their own AAD.
//!
//! On startup [`ServerSecrets::verify_or_init`] writes a canary row (first
//! start) and then decrypts every row. A failure means the configured secret
//! is not the one the database was created with, and the server refuses to
//! start ([`SecretsError::WrongSecret`]).

use sqlx_postgres::PgPool;
use sverb_crypto::keys::{NONCE_LEN, Nonce24};
use sverb_crypto::{Key32, aead, kdf, random};
use zeroize::Zeroizing;

use crate::config::ServerSecret;

/// HKDF `info` for the server-secret key.
pub const SERVER_SECRET_INFO: &[u8] = b"sverb/server-secret/v1";
/// Name of the canary row written on first start.
pub const CANARY_NAME: &str = "secret_check";
/// Name of the OPAQUE `ServerSetup` row (written by M4-02).
pub const OPAQUE_SERVER_SETUP: &str = "opaque_server_setup";
const CANARY_PLAINTEXT: &[u8] = b"sverb server secret check v1";

/// Errors from `server_secrets`.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// Database failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx_core::Error),
    /// A row can't be decrypted with the configured secret.
    #[error(
        "cannot decrypt server_secrets row `{name}` with the configured SVERB_SERVER_SECRET: \
         it is not the secret this database was created with. Restore the original secret; \
         the database and SVERB_SERVER_SECRET must be backed up and restored together \
         (SPEC §10.7). Refusing to start."
    )]
    WrongSecret {
        /// The row that failed.
        name: String,
    },
    /// Encryption failed (only for absurdly large values).
    #[error("encryption failed: {0}")]
    Crypto(#[from] sverb_crypto::CryptoError),
}

/// The derived key plus helpers for the `server_secrets` table.
pub struct ServerSecrets {
    key: Key32,
}

impl std::fmt::Debug for ServerSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSecrets([REDACTED])")
    }
}

impl ServerSecrets {
    /// Derives the key from the configured secret.
    #[must_use]
    pub fn new(secret: &ServerSecret) -> Self {
        Self {
            key: kdf::hkdf_key32(secret.expose(), None, SERVER_SECRET_INFO),
        }
    }

    /// Encrypts `plaintext` bound to `aad`; returns `nonce || ciphertext`.
    ///
    /// # Errors
    /// [`SecretsError::Crypto`].
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretsError> {
        let nonce = random::random_nonce24(&mut random::os_rng());
        let ct = aead::seal(&self.key, &nonce, aad, plaintext)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts a value from [`Self::seal`]; `None` when it is malformed or
    /// was not sealed with this key and AAD.
    #[must_use]
    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        aead::open(&self.key, &Nonce24::from_bytes(nonce), aad, ct).ok()
    }

    /// Inserts or replaces the row `name`.
    ///
    /// # Errors
    /// Database or crypto errors.
    pub async fn put(&self, pool: &PgPool, name: &str, value: &[u8]) -> Result<(), SecretsError> {
        let enc = self.seal(name.as_bytes(), value)?;
        sqlx_core::query::query(
            "INSERT INTO server_secrets (name, value_enc) VALUES ($1, $2) \
             ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc",
        )
        .bind(name)
        .bind(enc)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Reads and decrypts the row `name`.
    ///
    /// # Errors
    /// Database errors, or [`SecretsError::WrongSecret`].
    pub async fn get(
        &self,
        pool: &PgPool,
        name: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecretsError> {
        let row: Option<Vec<u8>> = sqlx_core::query_scalar::query_scalar(
            "SELECT value_enc FROM server_secrets WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;
        match row {
            None => Ok(None),
            Some(blob) => self
                .open(name.as_bytes(), &blob)
                .map(Some)
                .ok_or_else(|| SecretsError::WrongSecret { name: name.into() }),
        }
    }

    /// Writes the canary on first start, then checks that every row decrypts.
    ///
    /// # Errors
    /// [`SecretsError::WrongSecret`] naming the first row that fails.
    pub async fn verify_or_init(&self, pool: &PgPool) -> Result<(), SecretsError> {
        let canary = self.seal(CANARY_NAME.as_bytes(), CANARY_PLAINTEXT)?;
        sqlx_core::query::query(
            "INSERT INTO server_secrets (name, value_enc) VALUES ($1, $2) \
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(CANARY_NAME)
        .bind(canary)
        .execute(pool)
        .await?;
        let rows: Vec<(String, Vec<u8>)> = sqlx_core::query_as::query_as(
            "SELECT name, value_enc FROM server_secrets ORDER BY name",
        )
        .fetch_all(pool)
        .await?;
        for (name, blob) in rows {
            if self.open(name.as_bytes(), &blob).is_none() {
                return Err(SecretsError::WrongSecret { name });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secrets(byte: &str) -> ServerSecrets {
        ServerSecrets::new(&ServerSecret::parse(&byte.repeat(32)).unwrap())
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let s = secrets("11");
        let blob = s.seal(b"opaque_server_setup", b"payload").unwrap();
        assert_eq!(
            s.open(b"opaque_server_setup", &blob).unwrap().as_slice(),
            b"payload"
        );
        assert!(s.open(b"other_row", &blob).is_none());
        assert!(secrets("22").open(b"opaque_server_setup", &blob).is_none());
        assert!(s.open(b"x", &blob[..10]).is_none());
    }
}
