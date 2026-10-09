//! The keychain (SPEC §4.5, §4.6, §9.4): SSH key generation, import, export,
//! passphrase changes and certificates. UI-agnostic; the TUI (`views/keychain`) and the
//! CLI (`sverb keys …`) drive it.
//!
//! - [`generate`]: Ed25519 (default), ECDSA P-256/384/521, RSA 2048/3072/4096 with
//!   `OsRng`, optionally passphrase-encrypted in OpenSSH format (bcrypt-pbkdf, as
//!   `ssh-keygen` does).
//! - [`import`]: OpenSSH, PEM PKCS#1 RSA and SEC1 EC (plain or legacy
//!   `Proc-Type: 4,ENCRYPTED` AES-CBC), PKCS#8 (plain or PBES2-encrypted), and a lone
//!   `.pub` public key (an agent / hardware reference key, SPEC §9.4). PuTTY `.ppk`
//!   plugs in through the [`import::KeyImporter`] registry. Everything is stored
//!   re-serialized in OpenSSH format.
//! - [`export`]: public line, private key file (mode `0600`, optional re-encryption),
//!   passphrase changes.
//! - [`cert`]: OpenSSH certificate fields, derived on read (never stored, §4.6), the
//!   key match check and expiry badges.
//!
//! Private material only ever lives in [`SecretString`]s (redacted `Debug`, zeroized on
//! drop) or `Zeroizing` buffers.

pub mod cert;
pub mod export;
pub mod formats;
pub mod generate;
pub mod import;

#[cfg(test)]
mod tests;

use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding};
pub use ssh_key::{PrivateKey, PublicKey};

use crate::{model::KeyAlgorithm, secret::SecretString};

/// Files larger than this are not keys or certificates.
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Passphrase attempts before an import is aborted (task §2.3).
pub const PASSPHRASE_TRIES: u8 = 3;

/// Why a keychain operation failed. Messages are user-facing and never contain key
/// material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainError {
    /// The key is encrypted and no passphrase was given.
    #[error("this key is encrypted: a passphrase is needed")]
    NeedsPassphrase,
    /// The passphrase does not decrypt the key.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// [`PASSPHRASE_TRIES`] wrong passphrases: nothing was imported.
    #[error("wrong passphrase ({PASSPHRASE_TRIES} tries): import aborted, nothing was saved")]
    TooManyTries,
    /// The user cancelled a passphrase prompt.
    #[error("cancelled")]
    Cancelled,
    /// Not a key format sverb reads.
    #[error(
        "not a key sverb can read (OpenSSH, PEM PKCS#1 / SEC1, PKCS#8, PuTTY, or a .pub public key)"
    )]
    Format,
    /// A key type sverb doesn't store (DSA, …).
    #[error("unsupported key type {0}")]
    Unsupported(String),
    /// A legacy encrypted PEM with a cipher we can't decrypt.
    #[error("unsupported encrypted PEM ({0}); convert it with `ssh-keygen -p -f <file>`")]
    UnsupportedEncryptedPem(String),
    #[error("{0}")]
    Importer(String),
    /// A file could not be read.
    #[error("could not read {0}")]
    Read(String),
    /// A file could not be written.
    #[error("could not write {0}")]
    Write(String),
    /// The destination exists and overwriting was not confirmed.
    #[error("{0} already exists")]
    Exists(String),
    /// An agent / hardware reference key has no private part.
    #[error("this key has no private part (it is an agent / hardware key reference)")]
    NoPrivateKey,
    /// The stored key is damaged.
    #[error("invalid key: {0}")]
    Invalid(String),
    /// A certificate could not be parsed.
    #[error("not an OpenSSH certificate: {0}")]
    Cert(String),
    /// The certificate certifies another public key.
    #[error("the certificate is for a different key")]
    CertMismatch,
}

/// The Key item algorithm for `algorithm` (`rsa_bits`: the RSA modulus size).
pub fn key_algorithm(algorithm: &Algorithm, rsa_bits: u32) -> Option<KeyAlgorithm> {
    Some(match algorithm {
        Algorithm::Ed25519 => KeyAlgorithm::Ed25519,
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => KeyAlgorithm::EcdsaP256,
            EcdsaCurve::NistP384 => KeyAlgorithm::EcdsaP384,
            EcdsaCurve::NistP521 => KeyAlgorithm::EcdsaP521,
        },
        Algorithm::Rsa { .. } => match rsa_bits {
            0..=2048 => KeyAlgorithm::Rsa2048,
            2049..=3072 => KeyAlgorithm::Rsa3072,
            _ => KeyAlgorithm::Rsa4096,
        },
        Algorithm::SkEd25519 => KeyAlgorithm::SkEd25519,
        Algorithm::SkEcdsaSha2NistP256 => KeyAlgorithm::SkEcdsa,
        _ => return None,
    })
}

/// The Key item algorithm of a public key.
pub fn public_key_algorithm(key: &PublicKey) -> Option<KeyAlgorithm> {
    let bits = key.key_data().rsa().map_or(0, |r| r.key_size());
    key_algorithm(&key.algorithm(), bits)
}

/// A human name for an algorithm (`"Ed25519"`, `"ECDSA P-256"`, `"RSA 4096"`, …).
pub fn algorithm_name(alg: KeyAlgorithm) -> &'static str {
    match alg {
        KeyAlgorithm::Ed25519 => "Ed25519",
        KeyAlgorithm::EcdsaP256 => "ECDSA P-256",
        KeyAlgorithm::EcdsaP384 => "ECDSA P-384",
        KeyAlgorithm::EcdsaP521 => "ECDSA P-521",
        KeyAlgorithm::Rsa2048 => "RSA 2048",
        KeyAlgorithm::Rsa3072 => "RSA 3072",
        KeyAlgorithm::Rsa4096 => "RSA 4096",
        KeyAlgorithm::SkEd25519 => "Ed25519-SK",
        KeyAlgorithm::SkEcdsa => "ECDSA-SK",
    }
}

/// Parse an OpenSSH public key line (`ssh-ed25519 AAAA… comment`).
///
/// # Errors
/// [`KeychainError::Format`].
pub fn parse_public(line: &str) -> Result<PublicKey, KeychainError> {
    PublicKey::from_openssh(line.trim()).map_err(|_| KeychainError::Format)
}

/// The SHA256 fingerprint of a public key line (`SHA256:…`), `None` if unparseable.
pub fn fingerprint(public_line: &str) -> Option<String> {
    parse_public(public_line)
        .ok()
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
}

/// Whether two public key lines hold the same key (comments ignored).
pub fn same_public_key(a: &str, b: &str) -> bool {
    match (parse_public(a), parse_public(b)) {
        (Ok(a), Ok(b)) => a.key_data() == b.key_data(),
        _ => false,
    }
}

/// The OpenSSH public line of `key` (with its comment).
///
/// # Errors
/// [`KeychainError::Invalid`] if it can't be encoded.
pub fn public_line(key: &PublicKey) -> Result<String, KeychainError> {
    key.to_openssh()
        .map_err(|e| KeychainError::Invalid(e.to_string()))
}

/// Serialize a private key in OpenSSH format.
///
/// # Errors
/// [`KeychainError::Invalid`] if it can't be encoded.
pub fn private_openssh(key: &PrivateKey) -> Result<SecretString, KeychainError> {
    let text = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| KeychainError::Invalid(e.to_string()))?;
    Ok(SecretString::from(text.trim_end()))
}

/// Encrypt `key` (decrypted) with `passphrase` in OpenSSH format (AES-256-CTR,
/// bcrypt-pbkdf: what `ssh-keygen` writes).
///
/// # Errors
/// [`KeychainError::Invalid`] on an encoding failure.
pub fn encrypt_openssh(key: &PrivateKey, passphrase: &str) -> Result<SecretString, KeychainError> {
    let mut rng = sverb_crypto::random::os_rng();
    let enc = key
        .encrypt(&mut rng, passphrase.as_bytes())
        .map_err(|e| KeychainError::Invalid(e.to_string()))?;
    private_openssh(&enc)
}

/// Serialize `key` in OpenSSH format, encrypted when `passphrase` is non-empty.
///
/// # Errors
/// As [`encrypt_openssh`] / [`private_openssh`].
pub fn store_openssh(
    key: &PrivateKey,
    passphrase: Option<&str>,
) -> Result<SecretString, KeychainError> {
    match passphrase.filter(|p| !p.is_empty()) {
        Some(p) => encrypt_openssh(key, p),
        None => private_openssh(key),
    }
}

/// Parse an OpenSSH private key and decrypt it (`passphrase`, when encrypted).
///
/// # Errors
/// [`KeychainError::Invalid`], [`KeychainError::NeedsPassphrase`],
/// [`KeychainError::WrongPassphrase`].
pub fn decrypt_openssh(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
    let key =
        PrivateKey::from_openssh(text.trim()).map_err(|e| KeychainError::Invalid(e.to_string()))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pass = passphrase.ok_or(KeychainError::NeedsPassphrase)?;
    key.decrypt(pass.as_bytes())
        .map_err(|_| KeychainError::WrongPassphrase)
}

/// Expand a leading `~/` (or a lone `~`) to the home directory.
pub fn expand_home(path: &str) -> std::path::PathBuf {
    let home = || std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if path == "~"
        && let Some(h) = home()
    {
        return std::path::PathBuf::from(h);
    }
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(h) = home()
    {
        return std::path::PathBuf::from(h).join(rest);
    }
    std::path::PathBuf::from(path)
}
