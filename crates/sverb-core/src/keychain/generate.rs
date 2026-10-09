//!
//! Ed25519 (default), ECDSA P-256/384/521 and RSA 2048/3072/4096 from the OS CSPRNG.
//! With a passphrase the private key is stored **encrypted in OpenSSH format**
//! (bcrypt-pbkdf + AES-256-CTR, as `ssh-keygen` writes it). RSA generation takes
//! seconds (RSA-4096): callers run it off the UI thread ([`is_slow`]).

use rand_core::CryptoRng;
use ssh_key::{
    Algorithm, EcdsaCurve, PrivateKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair},
};

use super::{KeychainError, fingerprint, public_line, store_openssh};
use crate::{
    model::{Key, KeyAlgorithm, WireEnum as _},
    secret::SecretString,
};

/// The algorithms sverb generates, in menu order (Ed25519 first: the default).
pub const GENERATABLE: [KeyAlgorithm; 7] = [
    KeyAlgorithm::Ed25519,
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::EcdsaP521,
    KeyAlgorithm::Rsa2048,
    KeyAlgorithm::Rsa3072,
    KeyAlgorithm::Rsa4096,
];

/// What to generate.
#[derive(Debug)]
pub struct GenerateRequest {
    /// One of [`GENERATABLE`].
    pub algorithm: KeyAlgorithm,
    /// The key comment (default [`default_comment`]).
    pub comment: String,
    /// Encrypt the stored private key with this passphrase (`None` / empty: plain).
    pub passphrase: Option<SecretString>,
}

/// A generated key pair.
#[derive(Debug)]
pub struct GeneratedKey {
    /// The algorithm.
    pub algorithm: KeyAlgorithm,
    /// OpenSSH private key, encrypted when a passphrase was given.
    pub private_key: SecretString,
    /// OpenSSH public key line, with the comment.
    pub public_key: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// The private key is passphrase-encrypted.
    pub encrypted: bool,
}

impl GeneratedKey {
    /// The Key item for this key pair; `remember` stores the passphrase in the vault.
    pub fn into_key(self, label: String, passphrase: Option<SecretString>, remember: bool) -> Key {
        Key {
            label,
            algorithm: self.algorithm,
            private_key: self.private_key,
            public_key: self.public_key,
            passphrase: passphrase.filter(|p| remember && !p.expose().is_empty()),
            certificate_ids: Vec::new(),
            agent_forwardable: false,
            confirm_on_use: false,
            read_only: false,
        }
    }
}

/// Whether generating `alg` may take seconds (RSA): show a progress dialog and run it
/// in `spawn_blocking`.
pub fn is_slow(alg: KeyAlgorithm) -> bool {
    matches!(
        alg,
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096
    )
}

/// The default key comment: `user@hostname-sverb`.
pub fn default_comment() -> String {
    let user = ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "user".to_owned());
    format!("{user}@{}-sverb", hostname())
}

fn hostname() -> String {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(h) = std::env::var(var)
            && !h.trim().is_empty()
        {
            return h.trim().to_owned();
        }
    }
    for file in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(h) = std::fs::read_to_string(file)
            && !h.trim().is_empty()
        {
            return h.trim().to_owned();
        }
    }
    "localhost".to_owned()
}

/// The default label: `"<type> <date>"` (e.g. `"Ed25519 2026-10-08"`).
pub fn default_label(alg: KeyAlgorithm, date: &str) -> String {
    format!("{} {date}", super::algorithm_name(alg))
}

/// Generate a key pair from the OS CSPRNG.
///
/// # Errors
/// [`KeychainError::Unsupported`] for a non-generatable algorithm (FIDO keys);
/// [`KeychainError::Invalid`] on an encoding failure.
pub fn generate(req: &GenerateRequest) -> Result<GeneratedKey, KeychainError> {
    let mut rng = sverb_crypto::random::os_rng();
    generate_with(&mut rng, req)
}

/// [`generate`] with an injected RNG.
///
/// # Errors
/// As [`generate`].
pub fn generate_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    req: &GenerateRequest,
) -> Result<GeneratedKey, KeychainError> {
    let invalid = |e: ssh_key::Error| KeychainError::Invalid(e.to_string());
    let data = match req.algorithm {
        KeyAlgorithm::Ed25519 => KeypairData::from(Ed25519Keypair::random(rng)),
        KeyAlgorithm::EcdsaP256 => {
            KeypairData::from(EcdsaKeypair::random(rng, EcdsaCurve::NistP256).map_err(invalid)?)
        }
        KeyAlgorithm::EcdsaP384 => {
            KeypairData::from(EcdsaKeypair::random(rng, EcdsaCurve::NistP384).map_err(invalid)?)
        }
        KeyAlgorithm::EcdsaP521 => {
            KeypairData::from(EcdsaKeypair::random(rng, EcdsaCurve::NistP521).map_err(invalid)?)
        }
        KeyAlgorithm::Rsa2048 => KeypairData::from(RsaKeypair::random(rng, 2048).map_err(invalid)?),
        KeyAlgorithm::Rsa3072 => KeypairData::from(RsaKeypair::random(rng, 3072).map_err(invalid)?),
        KeyAlgorithm::Rsa4096 => KeypairData::from(RsaKeypair::random(rng, 4096).map_err(invalid)?),
        other => return Err(KeychainError::Unsupported(other.as_wire().to_owned())),
    };
    let key = PrivateKey::new(data, req.comment.clone()).map_err(invalid)?;
    debug_assert!(!matches!(key.algorithm(), Algorithm::Dsa));
    let public_key = public_line(key.public_key())?;
    let pass = req
        .passphrase
        .as_ref()
        .map(|p| p.expose())
        .filter(|p| !p.is_empty());
    let private_key = store_openssh(&key, pass)?;
    Ok(GeneratedKey {
        algorithm: req.algorithm,
        fingerprint: fingerprint(&public_key).unwrap_or_default(),
        public_key,
        private_key,
        encrypted: pass.is_some(),
    })
}
