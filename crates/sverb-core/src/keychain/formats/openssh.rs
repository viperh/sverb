//! M2-03: OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`), plain or
//! encrypted (bcrypt-pbkdf). The public key is readable without the passphrase.

use ssh_key::PrivateKey;

use crate::keychain::KeychainError;

/// Parse without decrypting.
///
/// # Errors
/// [`KeychainError::Format`].
pub fn parse(text: &str) -> Result<PrivateKey, KeychainError> {
    PrivateKey::from_openssh(text.trim()).map_err(|_| KeychainError::Format)
}

/// Whether the key is passphrase-encrypted.
pub fn is_encrypted(text: &str) -> bool {
    parse(text).is_ok_and(|k| k.is_encrypted())
}

/// Parse and decrypt (with `passphrase` when encrypted).
///
/// # Errors
/// [`KeychainError::Format`], [`KeychainError::NeedsPassphrase`],
/// [`KeychainError::WrongPassphrase`].
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
    let key = parse(text)?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pass = passphrase.ok_or(KeychainError::NeedsPassphrase)?;
    key.decrypt(pass.as_bytes())
        .map_err(|_| KeychainError::WrongPassphrase)
}
