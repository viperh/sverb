//! HPKE (RFC 9180) in base mode, single-shot (§11.1, §11.3).
//!
//! The suite is fixed: **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//! ChaCha20-Poly1305** (RFC 9180 ids `kem = 0x0020`, `kdf = 0x0001`,
//! `aead = 0x0003`), via the `hpke` 0.14 crate.
//!
//! **RNG.** `hpke` 0.14, `x25519-dalek` 3 and `ed25519-dalek` 3 all use
//! `rand_core` 0.10, the same generation as the rest of this crate, so the
//! caller's `CryptoRng` is passed straight through to
//! [`hpke::single_shot_seal_with_rng`]; no adapter is needed.
//!
//! **Wire format** of a sealed message (canonical, §11.1):
//!
//! ```text
//! u32 BE len(enc) || enc (32 B) || u32 BE len(ct) || ct (pt.len() + 16 B)
//! ```
//!
//! Both fields are length-prefixed so the format stays unambiguous if the
//! suite ever changes. The decoder is strict: the `enc` length must be 32, and
//! there may be no trailing bytes.
//!
//! The context (vault id, key version, ...) is bound through HPKE `info`; the
//! HPKE AAD is always empty.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::canon::Canon;
use crate::error::{CryptoError, Result};

/// The KEM of the sverb suite.
pub type Kem = X25519HkdfSha256;
/// The KDF of the sverb suite.
pub type Kdf = HkdfSha256;
/// The AEAD of the sverb suite.
pub type Aead = ChaCha20Poly1305;

/// Length of the encapsulated key (`enc`) for DHKEM(X25519).
pub const ENC_LEN: usize = 32;
/// Length of the ChaCha20-Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Length of an X25519 public or secret key.
pub const X25519_LEN: usize = 32;

/// Seals `pt` to the X25519 public key `recipient_pub` in base mode, with
/// the given HPKE `info` (from a [`crate::canon`] builder) and an empty AAD.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the public key is rejected by the KEM
/// (for example a small-order point whose shared secret is all zeros).
pub fn seal_base<R: CryptoRng + ?Sized>(
    recipient_pub: &[u8; X25519_LEN],
    info: &[u8],
    pt: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pub)
        .map_err(|_| CryptoError::InvalidParams("hpke public key"))?;
    // `single_shot_seal_with_rng` takes a sized `&mut impl CryptoRng`;
    // `&mut R` is one (rand_core implements the RNG traits for `DerefMut`).
    let mut rng = rng;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        pt,
        &[],
        &mut rng,
    )
    .map_err(|_| CryptoError::InvalidParams("hpke seal"))?;
    Ok(Canon::default()
        .bytes(enc.to_bytes().as_slice())
        .bytes(&ct)
        .finish())
}

/// Opens a message produced by [`seal_base`] with the X25519 secret key
/// `recipient_sk` and the same `info`.
///
/// # Errors
/// [`CryptoError::Malformed`] if the framing is wrong;
/// [`CryptoError::Auth`] on any decapsulation or decryption failure (wrong
/// key, wrong `info`, tampered bytes), indistinguishably.
pub fn open_base(
    recipient_sk: &[u8; X25519_LEN],
    info: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (enc, ct) = decode_sealed(sealed)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
        .map_err(|_| CryptoError::Malformed("hpke enc"))?;
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_sk)
        .map_err(|_| CryptoError::InvalidParams("hpke secret key"))?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, info, ct, &[])
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Auth)
}

/// Splits the wire format into `(enc, ct)` without any crypto.
///
/// # Errors
/// [`CryptoError::Malformed`] on a bad length prefix, a wrong `enc` length, a
/// ciphertext shorter than the tag, or trailing bytes.
pub fn decode_sealed(sealed: &[u8]) -> Result<(&[u8], &[u8])> {
    let (enc, rest) = take_len_prefixed(sealed)?;
    if enc.len() != ENC_LEN {
        return Err(CryptoError::Malformed("hpke enc length"));
    }
    let (ct, rest) = take_len_prefixed(rest)?;
    if ct.len() < TAG_LEN {
        return Err(CryptoError::Malformed("hpke ciphertext too short"));
    }
    if !rest.is_empty() {
        return Err(CryptoError::Malformed("hpke trailing bytes"));
    }
    Ok((enc, ct))
}

/// Reads one `u32 BE len || bytes` field.
pub(crate) fn take_len_prefixed(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, rest) = buf
        .split_first_chunk::<4>()
        .ok_or(CryptoError::Malformed("truncated length prefix"))?;
    let len = usize::try_from(u32::from_be_bytes(*len))
        .map_err(|_| CryptoError::Malformed("length prefix"))?;
    if rest.len() < len {
        return Err(CryptoError::Malformed("truncated field"));
    }
    Ok(rest.split_at(len))
}
