//!
//! `recording_key = HKDF(LMK, info = "sverb/recording/v1")`,
//! `aad = conn_id (16) || chunk_index (u64 BE) || is_last (u8)`,
//! chunk = `nonce (24) || ct || tag`.

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_key32;
use crate::keys::{Key32, NONCE_LEN, Nonce24};
use crate::random::random_nonce24;

/// Derives the recording key from the LMK (HKDF-SHA256, no salt).
#[must_use]
pub fn recording_key(lmk: &Key32) -> Key32 {
    hkdf_key32(lmk.expose_secret(), None, &canon::info_recording_key())
}

/// Seals one chunk of asciicast lines.
///
/// # Errors
/// [`CryptoError::InvalidParams`] only for absurdly large inputs.
pub fn seal_chunk<R: CryptoRng + ?Sized>(
    key: &Key32,
    conn_id: &Id16,
    chunk_index: u64,
    is_last: bool,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let nonce = random_nonce24(rng);
    seal_chunk_with_nonce(key, conn_id, chunk_index, is_last, plaintext, &nonce)
}

/// [`seal_chunk`] with an explicit nonce, for known-answer tests only.
///
/// # Errors
/// As [`seal_chunk`].
#[doc(hidden)]
pub fn seal_chunk_with_nonce(
    key: &Key32,
    conn_id: &Id16,
    chunk_index: u64,
    is_last: bool,
    plaintext: &[u8],
    nonce: &Nonce24,
) -> Result<Vec<u8>> {
    let aad = canon::aad_recording_chunk(conn_id, chunk_index, is_last);
    let ct = aead::seal(key, nonce, &aad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens one chunk. The caller supplies the expected `chunk_index` and
/// `is_last`; a reordered, replayed or re-flagged chunk fails with `Auth`.
/// A file whose last readable chunk does not open with `is_last = true` was
/// truncated.
///
/// # Errors
/// [`CryptoError::Auth`] on any authentication failure,
/// [`CryptoError::Malformed`] if shorter than nonce + tag.
pub fn open_chunk(
    key: &Key32,
    conn_id: &Id16,
    chunk_index: u64,
    is_last: bool,
    chunk: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if chunk.len() < NONCE_LEN + aead::TAG_LEN {
        return Err(CryptoError::Malformed("recording chunk too short"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&chunk[..NONCE_LEN]);
    let aad = canon::aad_recording_chunk(conn_id, chunk_index, is_last);
    aead::open(key, &Nonce24::from_bytes(nonce), &aad, &chunk[NONCE_LEN..])
}
