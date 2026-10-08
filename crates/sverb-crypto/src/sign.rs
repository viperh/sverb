//! Ed25519 signatures (§11.1, §11.3, §13.3).
//!
//! Thin wrappers over `ed25519-dalek` 3 so callers deal in raw byte arrays.
//! Verification uses `verify_strict`, which rejects non-canonical signatures
//! and small-order public keys, so a signature can't be malleated into a
//! second valid encoding of the same grant.
//!
//! Signed messages must come from a builder in [`crate::canon`] (for example
//! [`crate::canon::sig_grant`]).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CryptoError, Result};

/// Length of an Ed25519 public key.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 secret key (seed).
pub const ED25519_SECRET_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Signs `msg` with `sk`. Ed25519 is deterministic, so no RNG is needed.
#[must_use]
pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    sk.sign(msg).to_bytes()
}

/// Verifies `sig` over `msg` against the raw public key `pk` (strict mode).
///
/// # Errors
/// [`CryptoError::BadSignature`] for an invalid public key, a non-canonical
/// or wrong signature, or a modified message. The causes are not
/// distinguished.
pub fn verify(pk: &[u8; ED25519_PUBLIC_LEN], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| CryptoError::BadSignature)?;
    let sig = Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// The raw public key of `sk`.
#[must_use]
pub fn public_key(sk: &SigningKey) -> [u8; ED25519_PUBLIC_LEN] {
    sk.verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 test 1 (empty message), through our wrappers.
    #[test]
    fn rfc8032_test1() {
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
                .collect()
        };
        let seed: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap_or([0; 32]);
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(
            public_key(&sk).to_vec(),
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = sign(&sk, b"");
        assert_eq!(
            sig.to_vec(),
            unhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        assert_eq!(verify(&public_key(&sk), b"", &sig), Ok(()));
        assert_eq!(
            verify(&public_key(&sk), b"x", &sig),
            Err(CryptoError::BadSignature)
        );
    }
}
