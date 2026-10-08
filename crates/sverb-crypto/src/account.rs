//! Account key hierarchy (§11.2).
//!
//! ```text
//! password ──OPAQUE──▶ export_key (64 B) ──HKDF("sverb/akek/v1")──▶ AKEK
//! AKEK ──AEAD──▶ private_bundle = seal({x25519_sk, ed25519_sk})
//! ```
//!
//! # One password, two derivations (§11.2.1)
//!
//! The account password is also the local master password, and it is used
//! in two **independent** ways:
//!
//! - **Local KEK**: `Argon2id(password, local_salt)` ([`crate::kdf::argon2id`]),
//!   which wraps the LMK on this device only.
//! - **AKEK**: OPAQUE turns the password into `export_key` inside an OPRF
//!   keyed by the server (`sverb-crypto::opaque`, M4-02), then
//!   [`derive_akek`] applies HKDF-SHA256 with the `"sverb/akek/v1"` label.
//!
//! The constructions, salts and labels differ, so neither output reveals the
//! other: knowing the local KEK says nothing about AKEK, and vice versa. A
//! sanity test in `tests/account.rs` checks that the same password yields
//! unrelated outputs.
//!
//! # Formats (frozen by `tests/kat/account.json`)
//!
//! Plaintext of both the private and the recovery bundle is the
//! deterministic CBOR (RFC 8949 §4.2.1) map, keys in canonical order:
//!
//! ```text
//! { "x25519_sk": bstr(32), "ed25519_sk": bstr(32) }
//! = a2 69 "x25519_sk" 58 20 <32 B> 6a "ed25519_sk" 58 20 <32 B>   (90 bytes)
//! ```
//!
//! It is encoded and decoded by hand (strictly: any other CBOR encoding is
//! rejected), which avoids leaving copies of the secret keys in a generic
//! CBOR value tree.
//!
//! Serialized bundle: `0x01 (format version) || nonce (24 B) || XChaCha20-Poly1305(ct || tag)`.
//!
//! - `private_bundle`: key = AKEK, AAD = [`crate::canon::aad_private_bundle`]
//!   (`"sverb/bundle/v1" || user_id(16) || version(u32 BE)`).
//! - `recovery_bundle`: see [`crate::recovery`].

use ed25519_dalek::SigningKey;
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::aead;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::fingerprint::key_fingerprint;
use crate::kdf::hkdf_key32;
use crate::keys::{KEY_LEN, Key32, NONCE_LEN, Nonce24};
use crate::random::random_nonce24;

/// Length of the OPAQUE `export_key` (SHA-512 output, §11.2).
pub const EXPORT_KEY_LEN: usize = 64;
/// Format version byte of private and recovery bundles.
pub const BUNDLE_VERSION: u8 = 0x01;
/// Length of the bundle plaintext (the CBOR map above).
pub const BUNDLE_PT_LEN: usize = 90;
/// Length of a serialized bundle.
pub const BUNDLE_LEN: usize = 1 + NONCE_LEN + BUNDLE_PT_LEN + aead::TAG_LEN;

const CBOR_X_KEY: &[u8] = b"\x69x25519_sk";
const CBOR_ED_KEY: &[u8] = b"\x6aed25519_sk";
const CBOR_BSTR32: [u8; 2] = [0x58, 0x20];
const CBOR_MAP2: u8 = 0xa2;

/// Derives the Account Key-Encryption Key from the OPAQUE `export_key`:
/// `AKEK = HKDF-SHA256(salt = none, ikm = export_key, info = "sverb/akek/v1")`.
#[must_use]
pub fn derive_akek(export_key: &[u8; EXPORT_KEY_LEN]) -> Key32 {
    hkdf_key32(export_key, None, &canon::info_akek())
}

/// The account's private keys: X25519 (encryption, HPKE recipient) and
/// Ed25519 (signing grants). Zeroized on drop; `Debug` is redacted.
#[derive(Clone)]
pub struct AccountKeys {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

/// The public half of [`AccountKeys`], as published to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountPublicKeys {
    /// X25519 public key (HPKE recipient key).
    pub x25519: [u8; 32],
    /// Ed25519 public key (grant verification).
    pub ed25519: [u8; 32],
}

impl AccountPublicKeys {
    /// The key fingerprint (see [`crate::fingerprint::key_fingerprint`]).
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        key_fingerprint(&self.x25519, &self.ed25519)
    }
}

impl AccountKeys {
    /// Rebuilds the keys from their raw secret bytes. The caller should
    /// zeroize its copies.
    #[must_use]
    pub fn from_secret_bytes(x25519_sk: [u8; 32], ed25519_sk: [u8; 32]) -> Self {
        Self {
            x25519: StaticSecret::from(x25519_sk),
            ed25519: SigningKey::from_bytes(&ed25519_sk),
        }
    }

    /// The raw X25519 secret key. Keep the borrow short.
    #[must_use]
    pub fn x25519_secret_bytes(&self) -> &[u8; 32] {
        self.x25519.as_bytes()
    }

    /// The Ed25519 signing key.
    #[must_use]
    pub const fn ed25519_signing_key(&self) -> &SigningKey {
        &self.ed25519
    }

    /// The public keys.
    #[must_use]
    pub fn public(&self) -> AccountPublicKeys {
        AccountPublicKeys {
            x25519: X25519Public::from(&self.x25519).to_bytes(),
            ed25519: self.ed25519.verifying_key().to_bytes(),
        }
    }

    /// Deterministic CBOR plaintext (see the module docs).
    fn to_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(BUNDLE_PT_LEN));
        out.push(CBOR_MAP2);
        out.extend_from_slice(CBOR_X_KEY);
        out.extend_from_slice(&CBOR_BSTR32);
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(CBOR_ED_KEY);
        out.extend_from_slice(&CBOR_BSTR32);
        out.extend_from_slice(self.ed25519.as_bytes());
        debug_assert_eq!(out.len(), BUNDLE_PT_LEN);
        out
    }

    /// Strict decoder of [`AccountKeys::to_cbor`].
    fn from_cbor(pt: &[u8]) -> Result<Self> {
        const BAD: CryptoError = CryptoError::Malformed("account bundle plaintext");
        if pt.len() != BUNDLE_PT_LEN || pt[0] != CBOR_MAP2 {
            return Err(BAD);
        }
        let (x, rest) = take_entry(&pt[1..], CBOR_X_KEY).ok_or(BAD)?;
        let (ed, rest) = take_entry(rest, CBOR_ED_KEY).ok_or(BAD)?;
        if !rest.is_empty() {
            return Err(BAD);
        }
        let mut x = *x;
        let mut ed = *ed;
        let keys = Self::from_secret_bytes(x, ed);
        x.zeroize();
        ed.zeroize();
        Ok(keys)
    }
}

/// Reads `key || 58 20 || 32 bytes`.
fn take_entry<'a>(buf: &'a [u8], key: &[u8]) -> Option<(&'a [u8; 32], &'a [u8])> {
    let rest = buf.strip_prefix(key)?.strip_prefix(&CBOR_BSTR32[..])?;
    let (value, rest) = rest.split_first_chunk::<32>()?;
    Some((value, rest))
}

impl core::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKeys")
            .field("public", &self.public())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Generates a fresh X25519 + Ed25519 account keypair on this device.
///
/// Draws 64 bytes from `rng`: the X25519 secret (first 32, clamped per
/// RFC 7748) then the Ed25519 seed (next 32).
pub fn generate_account_keys<R: CryptoRng + ?Sized>(rng: &mut R) -> AccountKeys {
    let mut x = [0u8; KEY_LEN];
    let mut ed = [0u8; KEY_LEN];
    rng.fill_bytes(&mut x);
    rng.fill_bytes(&mut ed);
    // RFC 7748 clamping, so the stored bytes equal the scalar actually used.
    x[0] &= 248;
    x[31] &= 127;
    x[31] |= 64;
    let keys = AccountKeys::from_secret_bytes(x, ed);
    x.zeroize();
    ed.zeroize();
    keys
}

/// Seals the account keys under AKEK into a `private_bundle`
/// (`0x01 || nonce || ct`), bound to `user_id` and the account key `version`.
///
/// # Errors
/// Only if the AEAD rejects the input, which cannot happen for this size.
pub fn seal_private_bundle<R: CryptoRng + ?Sized>(
    akek: &Key32,
    user_id: &Id16,
    version: u32,
    keys: &AccountKeys,
    rng: &mut R,
) -> Result<Vec<u8>> {
    seal_keys(
        akek,
        &canon::aad_private_bundle(user_id, version),
        keys,
        rng,
    )
}

/// Opens a `private_bundle` sealed by [`seal_private_bundle`].
///
/// # Errors
/// [`CryptoError::UnsupportedVersion`] for an unknown format byte,
/// [`CryptoError::Malformed`] for a wrong length, and [`CryptoError::Auth`]
/// for a wrong AKEK, `user_id` or `version`, or tampered bytes.
pub fn open_private_bundle(
    akek: &Key32,
    user_id: &Id16,
    version: u32,
    bundle: &[u8],
) -> Result<AccountKeys> {
    open_keys(akek, &canon::aad_private_bundle(user_id, version), bundle)
}

/// Shared by the private and the recovery bundle.
pub(crate) fn seal_keys<R: CryptoRng + ?Sized>(
    kek: &Key32,
    aad: &[u8],
    keys: &AccountKeys,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let nonce = random_nonce24(rng);
    let ct = aead::seal(kek, &nonce, aad, &keys.to_cbor())?;
    let mut out = Vec::with_capacity(BUNDLE_LEN);
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Shared by the private and the recovery bundle.
pub(crate) fn open_keys(kek: &Key32, aad: &[u8], bundle: &[u8]) -> Result<AccountKeys> {
    let (&version, rest) = bundle
        .split_first()
        .ok_or(CryptoError::Malformed("empty bundle"))?;
    if version != BUNDLE_VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    if bundle.len() != BUNDLE_LEN {
        return Err(CryptoError::Malformed("bundle length"));
    }
    let (nonce, ct) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptoError::Malformed("bundle length"))?;
    let pt = aead::open(kek, &Nonce24::from_bytes(*nonce), aad, ct)?;
    AccountKeys::from_cbor(&pt)
}

/// Fuzz entry point (T-09): feeds arbitrary bytes to the bundle decoders
/// with fixed keys. Must never panic.
#[doc(hidden)]
pub fn fuzz_open_bundle(data: &[u8]) {
    let k = Key32::from_bytes([0x42; 32]);
    let _ = open_private_bundle(&k, &[1; 16], 1, data);
    let _ = crate::recovery::open_recovery_bundle(
        &crate::recovery::RecoveryKey::from_bytes([0x42; 32]),
        &[1; 16],
        data,
    );
    let _ = AccountKeys::from_cbor(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_roundtrip_and_strictness() {
        let keys = AccountKeys::from_secret_bytes([1; 32], [2; 32]);
        let pt = keys.to_cbor();
        assert_eq!(pt.len(), BUNDLE_PT_LEN);
        let back = AccountKeys::from_cbor(&pt);
        assert_eq!(back.map(|k| k.public()).ok(), Some(keys.public()));
        // Any single-byte change in the framing is rejected.
        for i in [0usize, 1, 5, 11, 12, 45, 56, 57] {
            let mut bad = pt.to_vec();
            bad[i] ^= 0x01;
            assert!(AccountKeys::from_cbor(&bad).is_err(), "byte {i}");
        }
        assert!(AccountKeys::from_cbor(&pt[..89]).is_err());
    }

    #[test]
    fn generated_x25519_is_clamped() {
        let mut rng = crate::random::os_rng();
        let k = generate_account_keys(&mut rng);
        let x = k.x25519_secret_bytes();
        assert_eq!(x[0] & 7, 0);
        assert_eq!(x[31] & 0xc0, 0x40);
    }
}
