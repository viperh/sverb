//! PEM PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`) and SEC1 EC (`BEGIN EC PRIVATE KEY`)
//! private keys, plain or legacy-encrypted (OpenSSL "traditional" format:
//! `Proc-Type: 4,ENCRYPTED` + `DEK-Info: AES-{128,192,256}-CBC,<iv>`, key derived with
//! `EVP_BytesToKey(MD5, 1 round)`). DES / 3DES-encrypted PEMs are refused with a
//! "convert with ssh-keygen -p" message.

use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};
use rsa::pkcs1::DecodeRsaPrivateKey;
use ssh_key::{
    PrivateKey,
    private::{EcdsaKeypair, KeypairData, RsaKeypair},
};
use zeroize::Zeroizing;

use super::{KeyFormat, PemBlock, pem_block};
use crate::keychain::KeychainError;

/// OID of NIST P-256.
pub const OID_P256: &str = "1.2.840.10045.3.1.7";
/// OID of NIST P-384.
pub const OID_P384: &str = "1.3.132.0.34";
/// OID of NIST P-521.
pub const OID_P521: &str = "1.3.132.0.35";

fn label(format: KeyFormat) -> Result<&'static str, KeychainError> {
    match format {
        KeyFormat::Pkcs1 => Ok("RSA PRIVATE KEY"),
        KeyFormat::Sec1 => Ok("EC PRIVATE KEY"),
        _ => Err(KeychainError::Format),
    }
}

/// Whether a PKCS#1 / SEC1 PEM is legacy-encrypted.
pub fn is_encrypted(text: &str, format: KeyFormat) -> bool {
    label(format)
        .and_then(|l| pem_block(text, l))
        .is_ok_and(|b| {
            b.header("Proc-Type")
                .is_some_and(|v| v.contains("ENCRYPTED"))
        })
}

/// Decode a PKCS#1 or SEC1 PEM (`format`), decrypting it with `passphrase` if needed.
///
/// # Errors
/// [`KeychainError::NeedsPassphrase`], [`KeychainError::WrongPassphrase`],
/// [`KeychainError::UnsupportedEncryptedPem`], [`KeychainError::Format`].
pub fn decode(
    text: &str,
    format: KeyFormat,
    passphrase: Option<&str>,
) -> Result<PrivateKey, KeychainError> {
    let block = pem_block(text, label(format)?)?;
    let encrypted = block
        .header("Proc-Type")
        .is_some_and(|v| v.contains("ENCRYPTED"));
    if !encrypted {
        return decode_der(&block.der, format).map_err(|_| KeychainError::Format);
    }
    let pass = passphrase.ok_or(KeychainError::NeedsPassphrase)?;
    let der = decrypt_legacy(&block, pass)?;
    // A wrong passphrase usually fails the padding check; if it passes by chance the
    // DER does not parse.
    decode_der(&der, format).map_err(|_| KeychainError::WrongPassphrase)
}

/// Parse decrypted DER (PKCS#1 `RSAPrivateKey` or SEC1 `ECPrivateKey`).
pub(crate) fn decode_der(der: &[u8], format: KeyFormat) -> Result<PrivateKey, KeychainError> {
    match format {
        KeyFormat::Pkcs1 => {
            let rsa = rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(|_| KeychainError::Format)?;
            rsa_key(&rsa)
        }
        KeyFormat::Sec1 => sec1_key(der),
        _ => Err(KeychainError::Format),
    }
}

/// An `ssh_key` RSA private key from an `rsa` one.
pub(crate) fn rsa_key(rsa: &rsa::RsaPrivateKey) -> Result<PrivateKey, KeychainError> {
    let kp = RsaKeypair::try_from(rsa).map_err(|e| KeychainError::Invalid(e.to_string()))?;
    PrivateKey::new(KeypairData::from(kp), "").map_err(|e| KeychainError::Invalid(e.to_string()))
}

/// An `ssh_key` ECDSA private key from SEC1 DER (named curve P-256/384/521).
pub(crate) fn sec1_key(der: &[u8]) -> Result<PrivateKey, KeychainError> {
    let ec = sec1::EcPrivateKey::try_from(der).map_err(|_| KeychainError::Format)?;
    let curve = ec
        .parameters
        .and_then(|p| p.named_curve())
        .map(|o| o.to_string())
        .ok_or_else(|| KeychainError::Unsupported("EC key without a named curve".to_owned()))?;
    ec_key(&curve, der)
}

/// An `ssh_key` ECDSA private key for the curve `oid` from SEC1 DER.
pub(crate) fn ec_key(oid: &str, sec1_der: &[u8]) -> Result<PrivateKey, KeychainError> {
    let bad = |_| KeychainError::Format;
    let kp = match oid {
        OID_P256 => {
            let sk = p256::SecretKey::from_sec1_der(sec1_der).map_err(bad)?;
            EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        OID_P384 => {
            let sk = p384::SecretKey::from_sec1_der(sec1_der).map_err(bad)?;
            EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        OID_P521 => {
            let sk = p521::SecretKey::from_sec1_der(sec1_der).map_err(bad)?;
            EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        other => return Err(KeychainError::Unsupported(format!("EC curve {other}"))),
    };
    PrivateKey::new(KeypairData::from(kp), "").map_err(|e| KeychainError::Invalid(e.to_string()))
}

/// OpenSSL's `EVP_BytesToKey` with MD5, one iteration, `salt` = the IV's first 8 bytes.
fn bytes_to_key(pass: &[u8], salt: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut prev: Option<[u8; 16]> = None;
    while out.len() < len {
        let mut h = Md5::new();
        if let Some(p) = prev {
            h.update(p);
        }
        h.update(pass);
        h.update(salt);
        let d: [u8; 16] = h.finalize().into();
        out.extend_from_slice(&d);
        prev = Some(d);
    }
    out.truncate(len);
    out
}

fn decrypt_legacy(block: &PemBlock, pass: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
    let dek = block
        .header("DEK-Info")
        .ok_or_else(|| KeychainError::UnsupportedEncryptedPem("no DEK-Info".to_owned()))?;
    let (cipher, iv_hex) = dek
        .split_once(',')
        .ok_or_else(|| KeychainError::UnsupportedEncryptedPem(dek.to_owned()))?;
    let cipher = cipher.trim().to_ascii_uppercase();
    let key_len = match cipher.as_str() {
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        other => return Err(KeychainError::UnsupportedEncryptedPem(other.to_owned())),
    };
    let iv = hex_decode(iv_hex.trim())
        .filter(|v| v.len() == 16)
        .ok_or_else(|| KeychainError::UnsupportedEncryptedPem("bad IV".to_owned()))?;
    let key = bytes_to_key(pass.as_bytes(), &iv[..8], key_len);
    let mut buf = Zeroizing::new(block.der.to_vec());
    let bad_len = |_| KeychainError::WrongPassphrase;
    let plain_len = match key_len {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .map_err(|_| KeychainError::Format)?
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(bad_len)?
            .len(),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(&key, &iv)
            .map_err(|_| KeychainError::Format)?
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(bad_len)?
            .len(),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .map_err(|_| KeychainError::Format)?
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(bad_len)?
            .len(),
    };
    buf.truncate(plain_len);
    Ok(buf)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
