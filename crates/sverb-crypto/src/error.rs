//! The single error type of `sverb-crypto`.

/// Errors returned by `sverb-crypto`.
///
/// Every authentication failure (wrong key, tampered ciphertext, wrong AAD
/// context, wrong wrap purpose) maps to the **same** opaque [`CryptoError::Auth`]
/// value. Callers must never try to tell those cases apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// AEAD authentication failed. Deliberately carries no detail.
    #[error("decryption failed")]
    Auth,
    /// The input is structurally invalid (too short, bad padding, unknown key
    /// version, ...).
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// The envelope's format version byte is not supported by this build.
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    /// Caller-supplied parameters are out of bounds.
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),
    /// Decompression failed or exceeded the output cap.
    #[error("decompression failed")]
    Decompress,
    // Ed25519 verification failure (grants, §11.3 / §13.3). Kept apart
    // from `Auth` so callers can tell "untrusted grant" from "cannot decrypt".
    /// An Ed25519 signature did not verify (wrong key, tampered message or
    /// malformed signature). Deliberately carries no detail.
    #[error("signature verification failed")]
    BadSignature,
}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
