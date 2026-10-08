//! Key derivation: HKDF-SHA256 and Argon2id (§11.1, §5.3).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::keys::{KEY_LEN, Key32};

/// Maximum HKDF-SHA256 output length (255 * 32 bytes, RFC 5869).
pub const HKDF_MAX_OUT: usize = 255 * 32;

/// HKDF-SHA256 extract-and-expand (RFC 5869).
///
/// `info` must come from a builder in [`crate::canon`].
///
/// # Errors
/// [`CryptoError::InvalidParams`] if `out_len` is 0 or exceeds [`HKDF_MAX_OUT`].
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if out_len == 0 || out_len > HKDF_MAX_OUT {
        return Err(CryptoError::InvalidParams("hkdf output length"));
    }
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut okm)
        .map_err(|_| CryptoError::InvalidParams("hkdf output length"))?;
    Ok(okm)
}

/// HKDF-SHA256 producing a 32-byte key (cannot fail: 32 bytes is always
/// within the output limit).
#[must_use]
pub fn hkdf_key32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Key32 {
    let mut okm = [0u8; KEY_LEN];
    let expanded = Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm);
    debug_assert!(expanded.is_ok(), "32-byte HKDF output is always valid");
    let key = Key32::from_bytes(okm);
    okm.zeroize();
    key
}

/// Argon2id cost parameters plus salt, as stored in `meta` (§5.3).
///
/// Serialize with [`Argon2Params::to_bytes`] / [`Argon2Params::from_bytes`]
/// (canonical: `m_kib || t || p` as `u32` BE, then the 16-byte salt), or
/// mirror the public fields in a serde type in `sverb-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
    /// Random per-device salt.
    pub salt: [u8; 16],
}

impl Argon2Params {
    /// Default memory cost: 256 MiB.
    pub const DEFAULT_M_KIB: u32 = 262_144;
    /// Default pass count.
    pub const DEFAULT_T: u32 = 3;
    /// Default parallelism.
    pub const DEFAULT_P: u32 = 1;
    /// Minimum accepted memory cost (19 MiB).
    pub const MIN_M_KIB: u32 = 19_456;
    /// Maximum accepted memory cost (4 GiB), so a corrupted `meta` row can't
    /// make unlock allocate unbounded memory.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// Maximum accepted pass count.
    pub const MAX_T: u32 = 64;
    /// Maximum accepted parallelism.
    pub const MAX_P: u32 = 16;
    /// Length of [`Argon2Params::to_bytes`].
    pub const ENCODED_LEN: usize = 12 + 16;

    /// The spec defaults (m = 256 MiB, t = 3, p = 1) with the given salt.
    #[must_use]
    pub const fn with_salt(salt: [u8; 16]) -> Self {
        Self {
            m_kib: Self::DEFAULT_M_KIB,
            t: Self::DEFAULT_T,
            p: Self::DEFAULT_P,
            salt,
        }
    }

    /// Checks the bounds (`m_kib ≥ 19456`, `t ≥ 1`, `p ≥ 1`, plus sanity maxima).
    ///
    /// # Errors
    /// [`CryptoError::InvalidParams`] when a parameter is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.m_kib < Self::MIN_M_KIB {
            return Err(CryptoError::InvalidParams("argon2 m_kib below 19456"));
        }
        if self.m_kib > Self::MAX_M_KIB {
            return Err(CryptoError::InvalidParams("argon2 m_kib too large"));
        }
        if self.t < 1 || self.t > Self::MAX_T {
            return Err(CryptoError::InvalidParams("argon2 t out of range"));
        }
        if self.p < 1 || self.p > Self::MAX_P {
            return Err(CryptoError::InvalidParams("argon2 p out of range"));
        }
        Ok(())
    }

    /// Canonical encoding: `m_kib || t || p` (`u32` BE each) `|| salt(16)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..4].copy_from_slice(&self.m_kib.to_be_bytes());
        out[4..8].copy_from_slice(&self.t.to_be_bytes());
        out[8..12].copy_from_slice(&self.p.to_be_bytes());
        out[12..].copy_from_slice(&self.salt);
        out
    }

    /// Decodes [`Argon2Params::to_bytes`] and validates the result.
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] on a wrong length, or
    /// [`CryptoError::InvalidParams`] if the values are out of bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let b: &[u8; Self::ENCODED_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::Malformed("argon2 params length"))?;
        let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[12..]);
        let params = Self {
            m_kib: u(0),
            t: u(4),
            p: u(8),
            salt,
        };
        params.validate()?;
        Ok(params)
    }
}

/// Derives a 32-byte key-encryption key from a password with Argon2id
/// (version 0x13, no secret, no associated data).
///
/// **CPU- and memory-heavy** (about 256 MiB and on the order of a second with
/// the defaults). Async callers must run it inside
/// `tokio::task::spawn_blocking`, never on a runtime worker thread.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the parameters fail
/// [`Argon2Params::validate`].
pub fn argon2id(password: &[u8], params: &Argon2Params) -> Result<Key32> {
    params.validate()?;
    argon2id_raw(password, &params.salt, params.m_kib, params.t, params.p)
}

fn argon2id_raw(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Key32> {
    let a2_params = argon2::Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidParams("argon2 params rejected"))?;
    let ctx = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        a2_params,
    );
    let mut out = [0u8; KEY_LEN];
    ctx.hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::InvalidParams("argon2 failed"))?;
    let key = Key32::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
            .collect()
    }

    /// RFC 5869 test case 1 through our wrapper.
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap_or_default();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn hkdf_bounds() {
        assert!(hkdf_sha256(b"k", None, b"", 0).is_err());
        assert!(hkdf_sha256(b"k", None, b"", HKDF_MAX_OUT + 1).is_err());
        assert!(hkdf_sha256(b"k", None, b"", HKDF_MAX_OUT).is_ok());
    }

    /// Reference vector from phc-winner-argon2 `test.c` (also among the
    /// `argon2` crate's KATs): Argon2id v0x13, t=2, m=2^16, p=1,
    /// "password" / "somesalt". Cross-checks our wrapper's parameter mapping.
    #[test]
    fn argon2id_reference_vector() {
        let key = argon2id_raw(b"password", b"somesalt", 1 << 16, 2, 1);
        let expected = unhex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
        assert_eq!(key.map(|k| k.expose_secret().to_vec()).ok(), Some(expected));
    }

    // T-11
    #[test]
    fn params_roundtrip_and_bounds() {
        let p = Argon2Params::with_salt([9; 16]);
        assert_eq!(Argon2Params::from_bytes(&p.to_bytes()), Ok(p));
        let low = Argon2Params { m_kib: 1024, ..p };
        assert!(matches!(low.validate(), Err(CryptoError::InvalidParams(_))));
        assert!(matches!(
            argon2id(b"pw", &low),
            Err(CryptoError::InvalidParams(_))
        ));
        assert!(Argon2Params { t: 0, ..p }.validate().is_err());
        assert!(Argon2Params { p: 0, ..p }.validate().is_err());
        assert!(Argon2Params::from_bytes(&[0; 5]).is_err());
    }
}
