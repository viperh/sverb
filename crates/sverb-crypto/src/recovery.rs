//! Recovery key and recovery bundle (§11.2).
//!
//! ```text
//! recovery_key    = 256 random bits, shown once as a 24-word BIP39 phrase (English)
//! recovery KEK    = HKDF-SHA256(salt = none, ikm = recovery_key, info = "sverb/recovery/v1")
//! recovery_bundle = 0x01 || nonce || XChaCha20-Poly1305(recovery KEK, nonce,
//!                   aad = "sverb/recovery-bundle/v1" || user_id(16),
//!                   same plaintext as the private bundle)
//! ```
//!
//! The 256-bit entropy is the key itself: BIP39 is only an encoding with an
//! 8-bit checksum (SHA-256 of the entropy). The BIP39 seed derivation
//! (PBKDF2 with a passphrase) is **not** used.
//!
//! Parsing is case-insensitive and tolerates any amount of whitespace between,
//! before and after words; it requires exactly 24 words from the English list
//! and a valid checksum.

use bip39::{Language, Mnemonic};
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::account::{AccountKeys, open_keys, seal_keys};
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_key32;
use crate::keys::{KEY_LEN, Key32};

/// Number of words in a recovery phrase (256-bit entropy).
pub const RECOVERY_WORDS: usize = 24;

/// The 256-bit recovery key. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey(Key32);

impl RecoveryKey {
    /// Wraps raw recovery-key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Key32::from_bytes(bytes))
    }

    /// Exposes the raw bytes. Keep the borrow short.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }

    /// The recovery KEK: `HKDF-SHA256(recovery_key, info = "sverb/recovery/v1")`.
    #[must_use]
    pub fn kek(&self) -> Key32 {
        hkdf_key32(self.0.expose_secret(), None, &canon::info_recovery_key())
    }

    /// The 24-word English BIP39 phrase for this key.
    #[must_use]
    pub fn mnemonic(&self) -> RecoveryMnemonic {
        RecoveryMnemonic::from_key(self)
    }
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

/// A 24-word recovery phrase, to be shown to the user **once**. Zeroized on
/// drop (bip39's `zeroize` feature); `Debug` is redacted, and there is deliberately no `Display`.
pub struct RecoveryMnemonic(Mnemonic);

impl RecoveryMnemonic {
    #[allow(clippy::expect_used)]
    fn from_key(key: &RecoveryKey) -> Self {
        // 32 bytes is always valid BIP39 entropy (256 bits → 24 words).
        let m = Mnemonic::from_entropy_in(Language::English, key.expose_secret())
            .expect("256-bit entropy is valid BIP39 entropy");
        Self(m)
    }

    /// The words, in order.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.words()
    }

    /// The phrase as space-separated lowercase words.
    #[must_use]
    pub fn phrase(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(RECOVERY_WORDS * 9));
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(w);
        }
        s
    }
}

impl core::fmt::Debug for RecoveryMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryMnemonic([REDACTED])")
    }
}

/// Generates a fresh recovery key (32 bytes from `rng`) and its phrase.
pub fn recovery_key_generate<R: CryptoRng + ?Sized>(
    rng: &mut R,
) -> (RecoveryKey, RecoveryMnemonic) {
    let mut bytes = [0u8; KEY_LEN];
    rng.fill_bytes(&mut bytes);
    let key = RecoveryKey::from_bytes(bytes);
    bytes.zeroize();
    let words = key.mnemonic();
    (key, words)
}

/// Parses a 24-word English BIP39 phrase back into the recovery key.
///
/// Case-insensitive; any whitespace (spaces, tabs, newlines, repeated or
/// leading/trailing) separates words.
///
/// # Errors
/// [`CryptoError::Malformed`] for a word count other than 24, an unknown
/// word, or a bad checksum.
pub fn recovery_key_from_mnemonic(words: &str) -> Result<RecoveryKey> {
    let lower = Zeroizing::new(words.to_lowercase());
    if lower.split_whitespace().count() != RECOVERY_WORDS {
        return Err(CryptoError::Malformed("recovery phrase must have 24 words"));
    }
    let mut m = Mnemonic::parse_in_normalized(Language::English, &lower).map_err(|e| match e {
        bip39::Error::InvalidChecksum => CryptoError::Malformed("recovery phrase checksum"),
        bip39::Error::UnknownWord(_) => CryptoError::Malformed("recovery phrase unknown word"),
        _ => CryptoError::Malformed("recovery phrase"),
    })?;
    let (mut entropy, len) = m.to_entropy_array();
    m.zeroize();
    let key = if len == KEY_LEN {
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&entropy[..KEY_LEN]);
        let key = RecoveryKey::from_bytes(bytes);
        bytes.zeroize();
        Ok(key)
    } else {
        Err(CryptoError::Malformed("recovery phrase must have 24 words"))
    };
    entropy.zeroize();
    key
}

/// Seals the account keys under the recovery KEK into a `recovery_bundle`
/// bound to `user_id`.
///
/// # Errors
/// Only if the AEAD rejects the input, which cannot happen for this size.
pub fn seal_recovery_bundle<R: CryptoRng + ?Sized>(
    recovery_key: &RecoveryKey,
    user_id: &Id16,
    keys: &AccountKeys,
    rng: &mut R,
) -> Result<Vec<u8>> {
    seal_keys(
        &recovery_key.kek(),
        &canon::aad_recovery_bundle(user_id),
        keys,
        rng,
    )
}

/// Opens a `recovery_bundle` sealed by [`seal_recovery_bundle`].
///
/// # Errors
/// [`CryptoError::Auth`] for a wrong recovery key, wrong `user_id` or
/// tampered bytes; [`CryptoError::Malformed`] /
/// [`CryptoError::UnsupportedVersion`] for bad framing.
pub fn open_recovery_bundle(
    recovery_key: &RecoveryKey,
    user_id: &Id16,
    bundle: &[u8],
) -> Result<AccountKeys> {
    open_keys(
        &recovery_key.kek(),
        &canon::aad_recovery_bundle(user_id),
        bundle,
    )
}
