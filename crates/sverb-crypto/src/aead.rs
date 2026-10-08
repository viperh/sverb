//! XChaCha20-Poly1305 with 24-byte random nonces (§11.1).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{Key32, Nonce24};

/// Length of the Poly1305 authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    let key: &Key = key.expose_secret().into();
    XChaCha20Poly1305::new(key)
}

/// Encrypts `pt` under `key`/`nonce`, authenticating `aad`. Returns
/// `ciphertext || tag` (`pt.len() + 16` bytes).
///
/// The nonce must never repeat under the same key; draw it from
/// [`crate::random::random_nonce24`].
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the plaintext exceeds the XChaCha20
/// block-counter limit (~256 GiB).
pub fn seal(key: &Key32, nonce: &Nonce24, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let nonce: &XNonce = nonce.as_bytes().into();
    cipher(key)
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| CryptoError::InvalidParams("plaintext too long"))
}

/// Decrypts and authenticates `ct` (`ciphertext || tag`).
///
/// # Errors
/// [`CryptoError::Auth`] on any failure: wrong key, wrong nonce, wrong AAD,
/// tampered or truncated ciphertext. The causes are indistinguishable by design.
pub fn open(key: &Key32, nonce: &Nonce24, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: &XNonce = nonce.as_bytes().into();
    cipher(key)
        .decrypt(nonce, Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Auth)
}
