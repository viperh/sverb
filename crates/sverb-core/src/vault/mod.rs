//! The vault's pure logic (SPEC §5.3, §11.2, §11.2.1).
//!
//! Everything here is UI-agnostic and I/O-free: KDF parameters and their `meta`
//! encoding, the persisted unlock backoff, the lock state machine and the auto-lock
//! rule, master-password strength (zxcvbn), and the [`keyring::KeyringStore`] seam
//! the vault service uses for keyring unlock. The service that runs Argon2, talks to
//! the store and the OS keyring, and owns the keys lives in
//! `sverb_tui::services::vault`.
//!
//! # Key hierarchy (local)
//! - **LMK**: 256 random bits, generated on first run. It wraps each vault key
//!   (`vaults.wrapped_key`, purpose `VaultKey(vault_id)`) and the sync tokens.
//! - **Password KEK** = `Argon2id(password, salt, m, t, p)`; `meta.kdf` holds
//!   [`KdfParams`] and `meta.lmk_wrapped_pw = wrap(KEK, Lmk, LMK)`.
//! - **Keyring KEK** (optional): 32 random bytes in the OS keyring under
//!   [`KEYRING_SERVICE`] / [`keyring_account`]; `meta.lmk_wrapped_keyring` wraps the
//!   LMK under it.
//! - A wrong password is detected by AEAD failure. No verifier is stored.

pub mod keyring;
pub mod lock;
pub mod password;
pub mod unlock;

use std::fmt;
use std::time::Duration;

use sverb_crypto::CryptoError;
use sverb_crypto::kdf::Argon2Params;

pub use self::keyring::{KeyringError, KeyringStore, MemKeyring, NoKeyring};
pub use self::lock::{LockState, auto_lock_timeout};
pub use self::password::{MIN_SCORE, PasswordStrength, WeakPassword, check_strength, estimate};
pub use self::unlock::{BackoffState, backoff_delay};

/// The OS keyring service name (SPEC §5.3).
pub const KEYRING_SERVICE: &str = "sverb";

/// The OS keyring account for the database with id `db_id` (`meta.db_id`), so several
/// `SVERB_HOME`s never share an entry.
pub fn keyring_account(db_id: &str) -> String {
    format!("lmk-kek:{db_id}")
}

/// Argon2id cost (memory in KiB, passes, lanes), without the salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Cost {
    /// The production defaults (SPEC §5.3): m = 256 MiB, t = 3, p = 1.
    pub const PRODUCTION: Self = Self {
        m_kib: Argon2Params::DEFAULT_M_KIB,
        t: Argon2Params::DEFAULT_T,
        p: Argon2Params::DEFAULT_P,
    };

    /// The cheapest accepted cost (m = 19 MiB, t = 1), **for tests only**.
    pub const TEST: Self = Self {
        m_kib: Argon2Params::MIN_M_KIB,
        t: 1,
        p: 1,
    };

    /// The cost new vaults (and password changes) use in this build: [`Self::TEST`]
    /// in this crate's unit tests, [`Self::PRODUCTION`] everywhere else. Other crates'
    /// tests pass [`Self::TEST`] explicitly.
    pub const fn current_default() -> Self {
        if cfg!(test) {
            Self::TEST
        } else {
            Self::PRODUCTION
        }
    }

    /// Full parameters with `salt`.
    pub const fn with_salt(self, salt: [u8; 16]) -> KdfParams {
        KdfParams {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
            salt,
        }
    }
}

impl Default for Argon2Cost {
    fn default() -> Self {
        Self::current_default()
    }
}

/// `meta.kdf`: `{alg: "argon2id", m_kib, t, p, salt}` as a CBOR map (SPEC §5.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// Random 16-byte salt (local only; never the OPAQUE salt, §11.2.1).
    pub salt: [u8; 16],
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfParams")
            .field("m_kib", &self.m_kib)
            .field("t", &self.t)
            .field("p", &self.p)
            .finish_non_exhaustive()
    }
}

/// The only algorithm name `meta.kdf` may carry.
pub const KDF_ALG: &str = "argon2id";

impl KdfParams {
    /// The parameters for `sverb_crypto::kdf::argon2id`.
    pub const fn argon2(&self) -> Argon2Params {
        Argon2Params {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
            salt: self.salt,
        }
    }

    /// The cost part.
    pub const fn cost(&self) -> Argon2Cost {
        Argon2Cost {
            m_kib: self.m_kib,
            t: self.t,
            p: self.p,
        }
    }

    /// CBOR map encoding for `meta.kdf`.
    pub fn to_cbor(&self) -> Vec<u8> {
        use ciborium::Value;
        let map = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text(KDF_ALG.into())),
            (
                Value::Text("m_kib".into()),
                Value::Integer(self.m_kib.into()),
            ),
            (Value::Text("t".into()), Value::Integer(self.t.into())),
            (Value::Text("p".into()), Value::Integer(self.p.into())),
            (Value::Text("salt".into()), Value::Bytes(self.salt.to_vec())),
        ]);
        let mut out = Vec::new();
        // Writing a small in-memory value into a Vec cannot fail.
        let _ = ciborium::into_writer(&map, &mut out);
        out
    }

    /// Decodes [`KdfParams::to_cbor`] and validates the bounds.
    ///
    /// # Errors
    /// [`VaultError::Corrupt`] for anything but a well-formed argon2id map within the
    /// bounds `sverb_crypto` accepts.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, VaultError> {
        use ciborium::Value;
        let bad = |what: &str| VaultError::Corrupt(format!("meta.kdf: {what}"));
        let value: Value = ciborium::from_reader(bytes).map_err(|_| bad("not CBOR"))?;
        let Value::Map(entries) = value else {
            return Err(bad("not a map"));
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
        };
        let int = |key: &str| -> Result<u32, VaultError> {
            get(key)
                .and_then(Value::as_integer)
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(|| bad(key))
        };
        if get("alg").and_then(Value::as_text) != Some(KDF_ALG) {
            return Err(bad("unsupported alg"));
        }
        let salt: [u8; 16] = get("salt")
            .and_then(Value::as_bytes)
            .and_then(|b| b.as_slice().try_into().ok())
            .ok_or_else(|| bad("salt"))?;
        let params = Self {
            m_kib: int("m_kib")?,
            t: int("t")?,
            p: int("p")?,
            salt,
        };
        params
            .argon2()
            .validate()
            .map_err(|_| bad("parameters out of range"))?;
        Ok(params)
    }
}

/// Vault errors shared by the TUI service and the CLI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// No `meta.kdf` yet: run `sverb` once to set a master password.
    #[error("sverb is not initialized; run `sverb` once to set a master password")]
    NotInitialized,
    /// First run was requested on an initialized database.
    #[error("the vault is already initialized")]
    AlreadyInitialized,
    /// The password did not unwrap the LMK (AEAD failure; deliberately no detail).
    #[error("wrong master password")]
    WrongPassword {
        /// Consecutive failures so far (persisted).
        failures: u32,
        /// How long until the next attempt is allowed, if there is a delay.
        retry_after: Option<Duration>,
    },
    /// An attempt came before `meta.unlock_next_allowed_at`; Argon2 did not run.
    #[error("too many failed attempts; try again in {}s", retry_after.as_secs().max(1))]
    Backoff {
        /// Remaining delay.
        retry_after: Duration,
    },
    /// The new password is too weak (zxcvbn score < 3).
    #[error(transparent)]
    WeakPassword(#[from] WeakPassword),
    /// The keyring could not provide the KEK (missing entry, cancelled prompt, no
    /// keyring service).
    #[error("keyring unlock failed: {0}")]
    Keyring(String),
    /// Keyring unlock is not enabled for this database.
    #[error("keyring unlock is not enabled")]
    KeyringNotEnabled,
    /// The operation needs an unlocked vault.
    #[error("the vault is locked")]
    Locked,
    /// Stored vault metadata is damaged.
    #[error("vault data is corrupt: {0}")]
    Corrupt(String),
    /// The store failed.
    #[error("vault storage error: {0}")]
    Storage(String),
}

impl VaultError {
    /// Maps a crypto error from unwrapping a stored key: authentication failures stay
    /// opaque.
    pub fn from_crypto(err: CryptoError, what: &str) -> Self {
        match err {
            CryptoError::Auth => Self::Corrupt(format!("{what} does not decrypt")),
            other => Self::Corrupt(format!("{what}: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_params_cbor_roundtrip() {
        let p = Argon2Cost::PRODUCTION.with_salt([3; 16]);
        let back = KdfParams::from_cbor(&p.to_cbor());
        assert_eq!(back, Ok(p));
        // A real CBOR map with a byte-string salt.
        let v: ciborium::Value =
            ciborium::from_reader(p.to_cbor().as_slice()).unwrap_or(ciborium::Value::Null);
        assert!(v.as_map().is_some_and(|m| m.len() == 5));
    }

    #[test]
    fn kdf_params_rejects_bad_input() {
        assert!(KdfParams::from_cbor(b"junk").is_err());
        let low = Argon2Cost {
            m_kib: 8,
            t: 1,
            p: 1,
        }
        .with_salt([0; 16]);
        assert!(KdfParams::from_cbor(&low.to_cbor()).is_err());
    }

    #[test]
    fn keyring_accounts_differ_per_db() {
        assert_eq!(keyring_account("a"), "lmk-kek:a");
        assert_ne!(keyring_account("a"), keyring_account("b"));
    }

    #[test]
    fn unit_tests_use_cheap_params() {
        assert_eq!(Argon2Cost::current_default(), Argon2Cost::TEST);
    }
}
