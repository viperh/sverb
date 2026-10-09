//! PKCS#8 private keys: `BEGIN PRIVATE KEY` and `BEGIN ENCRYPTED PRIVATE KEY`
//! (PBES2: PBKDF2 / scrypt with AES-CBC / AES-GCM, through the `pkcs8` crate). RSA,
//! ECDSA P-256/384/521 and Ed25519.

use der::Decode as _;
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use rsa::pkcs8::DecodePrivateKey as _;
use ssh_key::{
    PrivateKey,
    private::{Ed25519Keypair, KeypairData},
};

use super::{pem::ec_key, pem_block};
use crate::keychain::KeychainError;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";

/// Decode a plain PKCS#8 PEM.
///
/// # Errors
/// [`KeychainError::Format`], [`KeychainError::Unsupported`].
pub fn decode(text: &str) -> Result<PrivateKey, KeychainError> {
    let block = pem_block(text, "PRIVATE KEY")?;
    decode_der(&block.der)
}

/// Decode an encrypted PKCS#8 PEM with `passphrase`.
///
/// # Errors
/// [`KeychainError::NeedsPassphrase`], [`KeychainError::WrongPassphrase`],
/// [`KeychainError::Format`], [`KeychainError::Unsupported`].
pub fn decode_encrypted(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
    let block = pem_block(text, "ENCRYPTED PRIVATE KEY")?;
    let info =
        EncryptedPrivateKeyInfoRef::from_der(&block.der).map_err(|_| KeychainError::Format)?;
    let pass = passphrase.ok_or(KeychainError::NeedsPassphrase)?;
    let doc = info
        .decrypt(pass.as_bytes())
        .map_err(|_| KeychainError::WrongPassphrase)?;
    decode_der(doc.as_bytes()).map_err(|e| match e {
        KeychainError::Format => KeychainError::WrongPassphrase,
        other => other,
    })
}

/// Decode PKCS#8 `PrivateKeyInfo` DER.
///
/// # Errors
/// [`KeychainError::Format`], [`KeychainError::Unsupported`].
pub(crate) fn decode_der(der: &[u8]) -> Result<PrivateKey, KeychainError> {
    let info = PrivateKeyInfoRef::from_der(der).map_err(|_| KeychainError::Format)?;
    let oid = info.algorithm.oid.to_string();
    match oid.as_str() {
        OID_RSA => {
            let rsa = rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| KeychainError::Format)?;
            super::pem::rsa_key(&rsa)
        }
        OID_EC => {
            let curve = info
                .algorithm
                .parameters_oid()
                .map_err(|_| KeychainError::Format)?
                .to_string();
            // The private key field is a SEC1 `ECPrivateKey`.
            ec_key(&curve, info.private_key.as_bytes())
        }
        OID_ED25519 => {
            // `CurvePrivateKey ::= OCTET STRING` inside the private key field.
            let seed: [u8; 32] = match info.private_key.as_bytes() {
                [0x04, 0x20, rest @ ..] => rest.try_into().map_err(|_| KeychainError::Format)?,
                _ => return Err(KeychainError::Format),
            };
            let kp = Ed25519Keypair::from_seed(&seed);
            PrivateKey::new(KeypairData::from(kp), "")
                .map_err(|e| KeychainError::Invalid(e.to_string()))
        }
        other => Err(KeychainError::Unsupported(format!(
            "PKCS#8 algorithm {other}"
        ))),
    }
}
