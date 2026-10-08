//! Minimal zeroizing key types.
//!
//! `sverb-crypto` cannot depend on `sverb-core` (core depends on crypto), so it
//! defines its own small secret types. `sverb-core::secret` re-exports or
//! wraps them.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a symmetric key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of an XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// A 256-bit secret key. Zeroized on drop; `Debug` never prints the bytes;
/// equality is constant-time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; KEY_LEN]);

impl Key32 {
    /// Wraps raw key bytes. The caller should zeroize its own copy.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies a key from a slice; the slice must be exactly 32 bytes.
    ///
    /// # Errors
    /// [`crate::CryptoError::Malformed`] if the length is not 32.
    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| crate::CryptoError::Malformed("key must be 32 bytes"))?;
        Ok(Self(arr))
    }

    /// Exposes the raw key bytes. Keep the borrow as short as possible.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key32([REDACTED])")
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Key32 {}

/// A 192-bit XChaCha20-Poly1305 nonce. Nonces are public, but the type keeps
/// them from being confused with other 24-byte values.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Nonce24([u8; NONCE_LEN]);

impl Nonce24 {
    /// Wraps raw nonce bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Nonce24 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Nonce24(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}
