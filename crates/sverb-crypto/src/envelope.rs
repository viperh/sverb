//! Item envelopes (§11.4).
//!
//! ```text
//! item_key  = HKDF-SHA256(ikm = VK, salt = item_id, info = "sverb/item/v1")
//! aad       = "sverb-item-v1" || vault_id || item_id || key_version (u32 BE)
//! plaintext = pad256(zstd(body))          // body = CBOR bytes from sverb-core
//! envelope  = 0x01 || key_version (u32 BE) || nonce (24) || ciphertext || tag
//! ```

use std::io::Read;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead::{self, TAG_LEN};
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_key32;
use crate::keys::{Key32, NONCE_LEN, Nonce24};
use crate::pad::{pad256, unpad256};
use crate::random::random_nonce24;

/// Envelope format version written by this build.
pub const FORMAT_V1: u8 = 0x01;
/// Header length: version (1) + key_version (4) + nonce (24).
pub const HEADER_LEN: usize = 1 + 4 + NONCE_LEN;
/// Smallest structurally valid envelope (header + tag; real envelopes also
/// carry at least one 256-byte padded block).
pub const MIN_LEN: usize = HEADER_LEN + TAG_LEN;
/// zstd compression level for item bodies.
pub const ZSTD_LEVEL: i32 = 3;
/// Decompressed size cap (zip-bomb guard; items are ≤ 1 MiB, §10.5).
pub const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

/// Derives the per-item subkey from the vault key.
#[must_use]
pub fn item_key(vk: &Key32, item_id: &Id16) -> Key32 {
    hkdf_key32(vk.expose_secret(), Some(item_id), &canon::info_item_key())
}

/// Compresses (zstd level 3) and pads a body into the plaintext that gets
/// encrypted.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if zstd fails to compress.
pub fn encode_plaintext(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let compressed = Zeroizing::new(
        zstd::bulk::compress(body, ZSTD_LEVEL)
            .map_err(|_| CryptoError::InvalidParams("zstd compression failed"))?,
    );
    Ok(Zeroizing::new(pad256(&compressed)))
}

/// Inverse of [`encode_plaintext`]: unpads and decompresses with a
/// [`MAX_DECOMPRESSED`] output cap. Memory use is bounded by the cap no
/// matter what the frame header claims.
///
/// # Errors
/// [`CryptoError::Malformed`] on bad padding, [`CryptoError::Decompress`] on
/// invalid zstd data or output above the cap.
pub fn decode_plaintext(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let compressed = unpad256(padded)?;
    // Our frames declare their size, so they decompress in one pass with a
    // reused per-thread context (a fresh streaming decoder per item allocated its
    // window every time: most of the 10k-item unlock was spent there). One-pass
    // decompression writes straight into `out`; the context keeps no plaintext window.
    match zstd::zstd_safe::get_frame_content_size(compressed) {
        Ok(Some(n)) if n > MAX_DECOMPRESSED as u64 => return Err(CryptoError::Decompress),
        Ok(Some(n)) => {
            if let Some(out) = decompress_known_size(compressed, n as usize) {
                return Ok(out);
            }
        }
        // Unknown size (or not a valid header): the bounded streaming path decides.
        _ => {}
    }
    decode_streaming(compressed)
}

/// One-pass decompression of a frame that declares `size` bytes; `None` when it
/// does not decode to exactly that (the streaming path then reports the error).
fn decompress_known_size(compressed: &[u8], size: usize) -> Option<Zeroizing<Vec<u8>>> {
    thread_local! {
        static DCTX: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> =
            const { std::cell::RefCell::new(None) };
    }
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    let n = DCTX.with(|cell| {
        let mut slot = cell.try_borrow_mut().ok()?;
        if slot.is_none() {
            *slot = zstd::bulk::Decompressor::new().ok();
        }
        slot.as_mut()?
            .decompress_to_buffer(compressed, &mut *out)
            .ok()
    })?;
    (n == size).then_some(out)
}

/// The streaming decoder with the output cap (frames without a declared size).
fn decode_streaming(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let decoder = zstd::stream::read::Decoder::with_buffer(compressed)
        .map_err(|_| CryptoError::Decompress)?;
    let mut out = Zeroizing::new(Vec::new());
    // Read at most cap + 1 bytes: one byte past the cap proves the bomb.
    decoder
        .take(MAX_DECOMPRESSED as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| CryptoError::Decompress)?;
    if out.len() > MAX_DECOMPRESSED {
        return Err(CryptoError::Decompress);
    }
    Ok(out)
}

/// Seals an item body (already CBOR-encoded by `sverb-core`) into a v1
/// envelope under vault key `vk`, with a fresh random nonce from `rng`.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if compression or encryption fails (only
/// possible for absurdly large inputs).
pub fn seal_item<R: CryptoRng + ?Sized>(
    vk: &Key32,
    vault_id: &Id16,
    item_id: &Id16,
    key_version: u32,
    body: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let nonce = random_nonce24(rng);
    seal_item_with_nonce(vk, vault_id, item_id, key_version, body, &nonce)
}

/// [`seal_item`] with an explicit nonce. Only for known-answer tests and
/// fixtures; production code must use [`seal_item`] so every write gets a
/// fresh random nonce.
///
/// # Errors
/// As [`seal_item`].
#[doc(hidden)]
pub fn seal_item_with_nonce(
    vk: &Key32,
    vault_id: &Id16,
    item_id: &Id16,
    key_version: u32,
    body: &[u8],
    nonce: &Nonce24,
) -> Result<Vec<u8>> {
    let key = item_key(vk, item_id);
    let aad = canon::aad_item(vault_id, item_id, key_version);
    let plaintext = encode_plaintext(body)?;
    let ct = aead::seal(&key, nonce, &aad, &plaintext)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(FORMAT_V1);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parsed, **unauthenticated** envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// Format version byte (always [`FORMAT_V1`] after a successful parse).
    pub version: u8,
    /// Vault key version the envelope claims to be sealed under.
    pub key_version: u32,
    /// The AEAD nonce.
    pub nonce: Nonce24,
}

/// Parses the envelope header without decrypting, e.g. to find which VK
/// version an envelope needs. The values are not authenticated.
///
/// # Errors
/// [`CryptoError::Malformed`] if too short,
/// [`CryptoError::UnsupportedVersion`] for an unknown version byte.
pub fn parse_header(envelope: &[u8]) -> Result<EnvelopeHeader> {
    let Some(&version) = envelope.first() else {
        return Err(CryptoError::Malformed("empty envelope"));
    };
    if version != FORMAT_V1 {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    if envelope.len() < MIN_LEN {
        return Err(CryptoError::Malformed("envelope too short"));
    }
    let key_version = u32::from_be_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[5..HEADER_LEN]);
    Ok(EnvelopeHeader {
        version,
        key_version,
        nonce: Nonce24::from_bytes(nonce),
    })
}

/// Opens a v1 envelope: reads `key_version` from the header, picks the VK via
/// `vk_lookup`, verifies the AAD (so an envelope moved to another item or
/// vault fails), decrypts, unpads and decompresses.
///
/// # Errors
/// - [`CryptoError::Auth`] for a wrong key or any tampering (one opaque error),
/// - [`CryptoError::UnsupportedVersion`] for an unknown format byte,
/// - [`CryptoError::Malformed`] for a truncated header or a `key_version`
///   with no VK available,
/// - [`CryptoError::Decompress`] if the authenticated payload is not valid
///   zstd or expands beyond [`MAX_DECOMPRESSED`].
pub fn open_item<'k, F>(
    vk_lookup: F,
    vault_id: &Id16,
    item_id: &Id16,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>>
where
    F: Fn(u32) -> Option<&'k Key32>,
{
    let header = parse_header(envelope)?;
    let vk = vk_lookup(header.key_version).ok_or(CryptoError::Malformed("unknown key version"))?;
    let key = item_key(vk, item_id);
    let aad = canon::aad_item(vault_id, item_id, header.key_version);
    let padded = aead::open(&key, &header.nonce, &aad, &envelope[HEADER_LEN..])?;
    decode_plaintext(&padded)
}

/// Fuzz entry point: feeds arbitrary bytes to [`open_item`] with a
/// fixed key for every version. Must never panic.
#[doc(hidden)]
pub fn fuzz_open_item(data: &[u8]) {
    let vk = Key32::from_bytes([0x42; 32]);
    let _ = open_item(|_| Some(&vk), &[1; 16], &[2; 16], data);
    let _ = decode_plaintext(data);
}
