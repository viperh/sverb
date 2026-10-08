//! `SHA256:` fingerprints, as `ssh-keygen -l` prints them: the SHA-256 of the key blob
//! (the decoded base64 field of a `known_hosts` / `.pub` line), base64 without padding.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use sha2::{Digest, Sha256};

/// The key blob of a base64 public-key field (`None`: not base64).
pub fn key_blob(base64: &str) -> Option<Vec<u8>> {
    STANDARD.decode(base64.trim()).ok()
}

/// The raw SHA-256 digest of a key blob (the randomart input).
pub fn sha256_digest(blob: &[u8]) -> [u8; 32] {
    Sha256::digest(blob).into()
}

/// `SHA256:<base64, no padding>` of a key blob.
pub fn fingerprint_sha256(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(sha256_digest(blob)))
}
