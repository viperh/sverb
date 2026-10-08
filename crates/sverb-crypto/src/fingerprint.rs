//! Account key fingerprints and safety numbers (§13.3, used by M5-03).
//!
//! **Fingerprint:**
//! `fpr = SHA-256("sverb/fpr/v1" || x25519_pub(32) || ed25519_pub(32))`, 32 bytes.
//!
//! **Safety number** of two accounts A and B (Signal-style, 60 digits in 12
//! groups of 5):
//!
//! 1. Sort the two fingerprints by byte-wise lexicographic order: `lo ≤ hi`.
//! 2. For each fingerprint `f` in `[lo, hi]`, for `i` in `0..6`, take the 5
//!    bytes `f[5i..5i+5]` as a 40-bit big-endian integer and reduce it
//!    modulo 100000, printed as 5 zero-padded digits. That gives 30 digits
//!    (6 groups) per fingerprint; the first 30 bytes of each fingerprint are
//!    used.
//! 3. Join the 12 groups with single spaces: `lo`'s six groups, then `hi`'s.
//!
//! Sorting makes the result symmetric (`safety_number(a, b) ==
//! safety_number(b, a)`), and each half depends only on one account's keys,
//! so either key changing changes the number. Each half carries ~99.7 bits
//! (6 × log2(100000)); the modulo bias (2^40 mod 10^5) is below 2^-23 per
//! group. Unlike Signal there is no iterated hashing: the fingerprint is
//! already a SHA-256 over a domain-separated encoding, and a second-preimage
//! on ~100 bits is out of reach.

use sha2::{Digest, Sha256};

use crate::canon;

/// Length of a fingerprint.
pub const FINGERPRINT_LEN: usize = 32;
/// Number of digits in a safety number.
pub const SAFETY_NUMBER_DIGITS: usize = 60;

/// `SHA-256("sverb/fpr/v1" || x25519_pub || ed25519_pub)`.
#[must_use]
pub fn key_fingerprint(x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    Sha256::digest(canon::fpr_input(x25519_pub, ed25519_pub)).into()
}

/// The 60-digit safety number of two fingerprints, as 12 space-separated
/// groups of 5 digits. Symmetric in its arguments.
#[must_use]
pub fn safety_number(a: &[u8; FINGERPRINT_LEN], b: &[u8; FINGERPRINT_LEN]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut groups: Vec<String> = Vec::with_capacity(12);
    for f in [lo, hi] {
        let (chunks, _) = f.as_chunks::<5>();
        for chunk in chunks.iter().take(6) {
            let v = chunk.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
            groups.push(format!("{:05}", v % 100_000));
        }
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape() {
        let n = safety_number(&[0; 32], &[0xff; 32]);
        assert_eq!(n.len(), SAFETY_NUMBER_DIGITS + 11);
        // 0x0000000000 → 00000; 0xffffffffff = 1099511627775 → 27775.
        assert_eq!(
            n,
            "00000 00000 00000 00000 00000 00000 27775 27775 27775 27775 27775 27775"
        );
    }
}
