//! M1-14 §2.6 → M2-03: the host form's key-file import now goes through the keychain
//! (`sverb_core::keychain::import`): every format it reads (OpenSSH, PEM PKCS#1 / SEC1,
//! PKCS#8, a `.pub` agent reference, plugins) is accepted. This module stays as a thin
//! compatibility layer for callers of the M1 API; new code uses the keychain directly.
//!
//! An encrypted OpenSSH key is stored as given (the auth chain asks for its
//! passphrase); other encrypted formats need the passphrase, which this path doesn't
//! ask for (import them from the Keychain view).

use russh::keys::Algorithm;
use sverb_core::{
    keychain::{
        self, KeychainError,
        import::{ImportOptions, import_file, import_text},
    },
    model::KeyAlgorithm,
    secret::SecretString,
};

/// Files larger than this are not private keys.
pub const MAX_KEY_FILE_BYTES: u64 = keychain::MAX_KEY_FILE_BYTES;

/// A parsed key, ready to become a `Key` item.
#[derive(Debug)]
pub struct ImportedKey {
    /// The algorithm as the Key item stores it.
    pub algorithm: KeyAlgorithm,
    /// The public key, OpenSSH format (`ssh-ed25519 AAAA… comment`).
    pub public_key: String,
    /// The key's comment (a label suggestion).
    pub comment: String,
    /// The private key is passphrase-protected.
    pub encrypted: bool,
    /// The private key in OpenSSH format (empty for an agent reference key).
    pub private_key: SecretString,
}

/// Why a key could not be imported.
pub type KeyImportError = KeychainError;

/// The Key item algorithm for `algorithm` (`bits`: the RSA modulus size).
pub fn key_algorithm(algorithm: &Algorithm, bits: u32) -> Option<KeyAlgorithm> {
    keychain::key_algorithm(algorithm, bits)
}

fn convert(k: keychain::import::ImportedKey) -> ImportedKey {
    ImportedKey {
        algorithm: k.algorithm,
        public_key: k.public_key,
        comment: k.comment,
        encrypted: k.encrypted,
        private_key: k.private_key.unwrap_or_else(|| SecretString::from("")),
    }
}

/// Parse a key in any keychain format (no passphrase).
///
/// # Errors
/// See [`KeychainError`].
pub fn import_openssh(text: &str) -> Result<ImportedKey, KeyImportError> {
    import_text(text, None, ImportOptions::default()).map(convert)
}

/// Read and parse the key file at `path` (`~/` is expanded).
///
/// # Errors
/// As [`import_openssh`], or [`KeychainError::Read`].
pub fn import_openssh_file(path: &str) -> Result<ImportedKey, KeyImportError> {
    import_file(path, None, ImportOptions::default()).map(convert)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::ssh::test_keys as fixtures;

    #[test]
    fn imports_openssh_keys_plain_and_encrypted() {
        let k = import_openssh(fixtures::ED25519).unwrap();
        assert_eq!(k.algorithm, KeyAlgorithm::Ed25519);
        assert!(k.public_key.starts_with("ssh-ed25519 AAAA"));
        assert!(!k.encrypted);
        let k = import_openssh(fixtures::ED25519_ENCRYPTED).unwrap();
        assert!(k.encrypted);
        assert!(k.public_key.starts_with("ssh-ed25519 "));
        let k = import_openssh(fixtures::RSA_2048).unwrap();
        assert_eq!(k.algorithm, KeyAlgorithm::Rsa2048);
    }

    #[test]
    fn rejects_unreadable_input() {
        assert_eq!(
            import_openssh("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----")
                .unwrap_err(),
            KeychainError::Format
        );
        assert!(matches!(
            import_openssh_file("/nonexistent/id_ed25519").unwrap_err(),
            KeychainError::Read(_)
        ));
    }
}
