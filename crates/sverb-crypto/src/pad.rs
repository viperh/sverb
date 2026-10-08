//! ISO/IEC 7816-4 padding to a multiple of 256 bytes (§11.4).

use crate::error::{CryptoError, Result};

/// Padding block size.
pub const BLOCK: usize = 256;

/// Appends `0x80` and then zero bytes up to the next multiple of 256. A full
/// block of padding is added when `data.len()` is already a multiple of 256,
/// so the output is always strictly longer than the input.
#[must_use]
pub fn pad256(data: &[u8]) -> Vec<u8> {
    let padded_len = (data.len() / BLOCK + 1) * BLOCK;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(padded_len, 0);
    out
}

/// Removes [`pad256`] padding.
///
/// # Errors
/// [`CryptoError::Malformed`] if the length is not a non-zero multiple of 256,
/// or if the last non-zero byte is not a `0x80` marker inside the last block.
pub fn unpad256(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
        return Err(CryptoError::Malformed(
            "padded length not a multiple of 256",
        ));
    }
    let last_block_start = data.len() - BLOCK;
    let marker = data
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(CryptoError::Malformed("missing padding marker"))?;
    if marker < last_block_start || data[marker] != 0x80 {
        return Err(CryptoError::Malformed("bad padding"));
    }
    Ok(&data[..marker])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_block_gets_full_padding() {
        let p = pad256(&[1u8; 256]);
        assert_eq!(p.len(), 512);
        assert_eq!(p[256], 0x80);
        assert_eq!(unpad256(&p).ok(), Some(&[1u8; 256][..]));
    }

    #[test]
    fn empty_input() {
        let p = pad256(&[]);
        assert_eq!(p.len(), 256);
        assert_eq!(p[0], 0x80);
        assert_eq!(unpad256(&p).ok(), Some(&[][..]));
    }

    #[test]
    fn malformed() {
        assert!(unpad256(&[]).is_err());
        assert!(unpad256(&[0u8; 255]).is_err());
        assert!(unpad256(&[0u8; 256]).is_err());
        let mut bad = vec![0u8; 256];
        bad[10] = 0x81;
        assert!(unpad256(&bad).is_err());
        // A marker more than one block from the end is rejected.
        let mut early = vec![0u8; 512];
        early[100] = 0x80;
        assert!(unpad256(&early).is_err());
    }
}
