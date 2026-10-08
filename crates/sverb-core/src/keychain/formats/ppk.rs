//! M7-03: PuTTY `.ppk` private keys (SPEC §9.4), versions 2 and 3, parsed in-house.
//!
//! ```text
//! PuTTY-User-Key-File-3: ssh-ed25519
//! Encryption: aes256-cbc            (or none)
//! Comment: my key
//! Public-Lines: 2                   (base64 of the SSH wire public key)
//! Key-Derivation: Argon2id          (v3, encrypted only: Argon2id / Argon2i / Argon2d,
//! Argon2-Memory: 8192                Argon2-Memory in KiB, -Passes, -Parallelism,
//! Argon2-Passes: 13                  -Salt in hex)
//! Argon2-Parallelism: 1
//! Argon2-Salt: 0123…
//! Private-Lines: 1                  (base64 of the private blob, AES-256-CBC if encrypted)
//! Private-MAC: 1a2b…                (hex)
//! ```
//!
//! - **v2**: AES key = `SHA1(00000000 ‖ pass) ‖ SHA1(00000001 ‖ pass)` (first 32 bytes),
//!   IV zero; MAC = HMAC-SHA1 keyed with `SHA1("putty-private-key-file-mac-key" ‖ pass)`
//!   (an empty passphrase when unencrypted).
//! - **v3**: Argon2 over the passphrase and salt, 80 bytes = AES key (32) ‖ IV (16) ‖ MAC
//!   key (32); MAC = HMAC-SHA256 (an empty MAC key when unencrypted).
//! - The MAC covers `string(alg) string(encryption) string(comment) string(public blob)
//!   string(private blob)` (the decrypted private blob, padding included) and is
//!   **checked before the private blob is used**: a mismatch is a wrong passphrase
//!   (encrypted) or a damaged file (unencrypted).
//! - Private blobs: Ed25519 `string(seed, little-endian)`; ECDSA `mpint(d)`; RSA
//!   `mpint(d) mpint(p) mpint(q) mpint(iqmp)`. DSA (and v1 files) are refused.
//! - Hostile input is bounded: [`MAX_PPK_BYTES`], [`MAX_LINES`], [`MAX_BLOB_LINES`] and
//!   the Argon2 parameters ([`MAX_ARGON2_MEMORY_KIB`] …), so a crafted file can't make the
//!   key derivation allocate gigabytes or run for minutes.
//!
//! [`PpkImporter`] is the `.ppk` [`KeyImporter`] (registered by default in
//! [`import`](crate::keychain::import)); the result is re-serialized to OpenSSH like
//! every other import (M2-03).

use base64::Engine as _;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use ssh_key::{
    Mpint, PrivateKey, PublicKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey},
    public::KeyData,
};
use zeroize::Zeroizing;

use crate::keychain::{KeychainError, import::KeyImporter, import::PPK_IMPORTER};

/// Larger files are not `.ppk` keys (an RSA 16384 key is about 20 KiB).
pub const MAX_PPK_BYTES: usize = 64 * 1024;
/// Lines in a `.ppk` file.
pub const MAX_LINES: usize = 1024;
/// `Public-Lines` / `Private-Lines` (64 base64 characters each: 24 KiB blobs).
pub const MAX_BLOB_LINES: usize = 512;
/// Argon2 memory (KiB): 1 GiB.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1024 * 1024;
/// Argon2 passes.
pub const MAX_ARGON2_PASSES: u32 = 1000;
/// Argon2 lanes.
pub const MAX_ARGON2_PARALLELISM: u32 = 64;
/// Argon2 work budget: memory (KiB) × passes (16 passes over 1 GiB).
pub const MAX_ARGON2_WORK: u64 = 16 * 1024 * 1024;
/// Argon2 salt length (bytes).
const ARGON2_SALT_LEN: std::ops::RangeInclusive<usize> = 8..=64;

const HEADER: &str = "PuTTY-User-Key-File-";
const V2_MAC_KEY_PREFIX: &[u8] = b"putty-private-key-file-mac-key";

/// The file version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpkVersion {
    /// `PuTTY-User-Key-File-2` (SHA-1 key derivation, HMAC-SHA1).
    V2,
    /// `PuTTY-User-Key-File-3` (Argon2, HMAC-SHA256).
    V3,
}

/// The v3 key derivation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Kdf {
    /// `Key-Derivation`.
    pub algorithm: argon2::Algorithm,
    /// `Argon2-Memory` (KiB).
    pub memory_kib: u32,
    /// `Argon2-Passes`.
    pub passes: u32,
    /// `Argon2-Parallelism`.
    pub parallelism: u32,
    /// `Argon2-Salt`.
    pub salt: Vec<u8>,
}

/// A parsed (not yet decrypted or verified) `.ppk` file.
pub struct PpkFile {
    /// v2 or v3.
    pub version: PpkVersion,
    /// The key algorithm (`ssh-ed25519`, …).
    pub algorithm: String,
    /// `Encryption: aes256-cbc`.
    pub encrypted: bool,
    /// `Comment`.
    pub comment: String,
    /// The SSH wire public key.
    pub public_blob: Vec<u8>,
    /// The private blob as stored (encrypted when [`PpkFile::encrypted`]).
    private_blob: Zeroizing<Vec<u8>>,
    /// `Private-MAC`.
    mac: Vec<u8>,
    /// v3, encrypted: the Argon2 parameters.
    pub kdf: Option<Argon2Kdf>,
}

impl std::fmt::Debug for PpkFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PpkFile")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("encrypted", &self.encrypted)
            .field("comment", &self.comment)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

/// Whether `text` looks like a `.ppk` file (by its first line).
pub fn is_ppk(text: &str) -> bool {
    text.trim_start().starts_with(HEADER)
}

fn invalid(msg: impl Into<String>) -> KeychainError {
    KeychainError::Invalid(msg.into())
}

/// The line iterator with the bounds and `Name: value` headers.
struct Lines<'a> {
    inner: std::iter::Take<std::str::Lines<'a>>,
}

impl<'a> Lines<'a> {
    fn next_line(&mut self) -> Result<&'a str, KeychainError> {
        self.inner
            .next()
            .map(|l| l.trim_end_matches('\r'))
            .ok_or(KeychainError::Format)
    }

    /// The next line, which must be the header `name`; its value.
    fn header(&mut self, name: &str) -> Result<&'a str, KeychainError> {
        let line = self.next_line()?;
        let (key, value) = line.split_once(':').ok_or(KeychainError::Format)?;
        if key != name {
            return Err(KeychainError::Format);
        }
        Ok(value.strip_prefix(' ').unwrap_or(value))
    }

    fn number(&mut self, name: &str) -> Result<u32, KeychainError> {
        self.header(name)?
            .trim()
            .parse::<u32>()
            .map_err(|_| KeychainError::Format)
    }

    /// `<name>-Lines: n` and `n` base64 lines.
    fn blob(&mut self, name: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        let n = self.number(name)? as usize;
        if n > MAX_BLOB_LINES {
            return Err(invalid(format!("PuTTY key: {name} {n} is too large")));
        }
        let mut b64 = Zeroizing::new(String::new());
        for _ in 0..n {
            b64.push_str(self.next_line()?.trim());
        }
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| KeychainError::Format)
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn check_algorithm(alg: &str) -> Result<(), KeychainError> {
    match alg {
        "ssh-ed25519"
        | "ecdsa-sha2-nistp256"
        | "ecdsa-sha2-nistp384"
        | "ecdsa-sha2-nistp521"
        | "ssh-rsa" => Ok(()),
        "ssh-dss" => Err(KeychainError::Unsupported("ssh-dss (DSA)".to_owned())),
        other => Err(KeychainError::Unsupported(other.chars().take(64).collect())),
    }
}

/// Parse the structure of a `.ppk` file (no decryption, no MAC check).
///
/// # Errors
/// [`KeychainError::Format`] (not a `.ppk` or truncated), [`KeychainError::Unsupported`]
/// (v1, DSA, an unknown cipher or key derivation), [`KeychainError::Invalid`] (over a
/// bound).
pub fn parse(text: &str) -> Result<PpkFile, KeychainError> {
    if text.len() > MAX_PPK_BYTES {
        return Err(invalid("PuTTY key file is too large"));
    }
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.lines().nth(MAX_LINES).is_some() {
        return Err(invalid("PuTTY key file has too many lines"));
    }
    let mut lines = Lines {
        inner: text.lines().take(MAX_LINES),
    };
    let first = lines.next_line()?;
    let rest = first.strip_prefix(HEADER).ok_or(KeychainError::Format)?;
    let (ver, alg) = rest.split_once(':').ok_or(KeychainError::Format)?;
    let version = match ver {
        "2" => PpkVersion::V2,
        "3" => PpkVersion::V3,
        "1" => {
            return Err(KeychainError::Unsupported(
                "PuTTY key file version 1 (re-save it with a current PuTTYgen)".to_owned(),
            ));
        }
        _ => return Err(KeychainError::Format),
    };
    let algorithm = alg.trim().to_owned();
    check_algorithm(&algorithm)?;
    let encrypted = match lines.header("Encryption")?.trim() {
        "none" => false,
        "aes256-cbc" => true,
        other => {
            return Err(KeychainError::Unsupported(format!(
                "PuTTY key encryption {}",
                other.chars().take(32).collect::<String>()
            )));
        }
    };
    let comment = lines.header("Comment")?.to_owned();
    let public_blob = lines.blob("Public-Lines")?.to_vec();
    let kdf = if version == PpkVersion::V3 && encrypted {
        Some(parse_kdf(&mut lines)?)
    } else {
        None
    };
    let private_blob = lines.blob("Private-Lines")?;
    let mac = hex_decode(lines.header("Private-MAC")?).ok_or(KeychainError::Format)?;
    let mac_len = match version {
        PpkVersion::V2 => 20,
        PpkVersion::V3 => 32,
    };
    if mac.len() != mac_len {
        return Err(KeychainError::Format);
    }
    if encrypted && (private_blob.is_empty() || !private_blob.len().is_multiple_of(16)) {
        return Err(KeychainError::Format);
    }
    Ok(PpkFile {
        version,
        algorithm,
        encrypted,
        comment,
        public_blob,
        private_blob,
        mac,
        kdf,
    })
}

fn parse_kdf(lines: &mut Lines<'_>) -> Result<Argon2Kdf, KeychainError> {
    let algorithm = match lines.header("Key-Derivation")?.trim() {
        "Argon2id" => argon2::Algorithm::Argon2id,
        "Argon2i" => argon2::Algorithm::Argon2i,
        "Argon2d" => argon2::Algorithm::Argon2d,
        other => {
            return Err(KeychainError::Unsupported(format!(
                "PuTTY key derivation {}",
                other.chars().take(32).collect::<String>()
            )));
        }
    };
    let memory_kib = lines.number("Argon2-Memory")?;
    let passes = lines.number("Argon2-Passes")?;
    let parallelism = lines.number("Argon2-Parallelism")?;
    let salt = hex_decode(lines.header("Argon2-Salt")?).ok_or(KeychainError::Format)?;
    let kdf = Argon2Kdf {
        algorithm,
        memory_kib,
        passes,
        parallelism,
        salt,
    };
    check_kdf(&kdf)?;
    Ok(kdf)
}

/// The DoS guard on v3 parameters.
fn check_kdf(k: &Argon2Kdf) -> Result<(), KeychainError> {
    if k.memory_kib > MAX_ARGON2_MEMORY_KIB {
        return Err(invalid(format!(
            "PuTTY key: Argon2 memory {} KiB is over the 1 GiB limit",
            k.memory_kib
        )));
    }
    if k.passes == 0 || k.passes > MAX_ARGON2_PASSES {
        return Err(invalid(format!(
            "PuTTY key: Argon2 passes {} out of range (1..={MAX_ARGON2_PASSES})",
            k.passes
        )));
    }
    if k.parallelism == 0 || k.parallelism > MAX_ARGON2_PARALLELISM {
        return Err(invalid(format!(
            "PuTTY key: Argon2 parallelism {} out of range (1..={MAX_ARGON2_PARALLELISM})",
            k.parallelism
        )));
    }
    if u64::from(k.memory_kib) * u64::from(k.passes) > MAX_ARGON2_WORK {
        return Err(invalid(
            "PuTTY key: Argon2 memory × passes is over the work limit",
        ));
    }
    if !ARGON2_SALT_LEN.contains(&k.salt.len()) {
        return Err(KeychainError::Format);
    }
    Ok(())
}

/// The public key of a `.ppk` file (readable without the passphrase; not verified by
/// the MAC).
///
/// # Errors
/// As [`parse`]; [`KeychainError::Format`] for a bad public blob.
pub fn public_key(text: &str) -> Result<PublicKey, KeychainError> {
    let file = parse(text)?;
    public_of(&file)
}

fn public_of(file: &PpkFile) -> Result<PublicKey, KeychainError> {
    let mut key = PublicKey::from_bytes(&file.public_blob).map_err(|_| KeychainError::Format)?;
    if key.algorithm().as_str() != file.algorithm {
        return Err(invalid(
            "PuTTY key: the public key does not match the header",
        ));
    }
    key.set_comment(file.comment.clone());
    Ok(key)
}

fn string_into(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(b);
}

/// Keys derived from the passphrase: AES key, IV, MAC key.
struct Derived {
    aes: Zeroizing<[u8; 32]>,
    iv: [u8; 16],
    mac: Zeroizing<Vec<u8>>,
}

fn derive(file: &PpkFile, pass: &[u8]) -> Result<Derived, KeychainError> {
    match file.version {
        PpkVersion::V2 => {
            let mut aes = Zeroizing::new([0u8; 32]);
            if file.encrypted {
                let mut h0 = Sha1::new();
                h0.update(0u32.to_be_bytes());
                h0.update(pass);
                let mut h1 = Sha1::new();
                h1.update(1u32.to_be_bytes());
                h1.update(pass);
                let mut both = Zeroizing::new(Vec::with_capacity(40));
                both.extend_from_slice(&h0.finalize());
                both.extend_from_slice(&h1.finalize());
                aes.copy_from_slice(&both[..32]);
            }
            let mut m = Sha1::new();
            m.update(V2_MAC_KEY_PREFIX);
            m.update(if file.encrypted { pass } else { b"" });
            Ok(Derived {
                aes,
                iv: [0; 16],
                mac: Zeroizing::new(m.finalize().to_vec()),
            })
        }
        PpkVersion::V3 => {
            let Some(k) = &file.kdf else {
                return Ok(Derived {
                    aes: Zeroizing::new([0; 32]),
                    iv: [0; 16],
                    mac: Zeroizing::new(Vec::new()),
                });
            };
            check_kdf(k)?;
            let params = argon2::Params::new(k.memory_kib, k.passes, k.parallelism, Some(80))
                .map_err(|e| invalid(format!("PuTTY key: Argon2 parameters: {e}")))?;
            let argon = argon2::Argon2::new(k.algorithm, argon2::Version::V0x13, params);
            let mut out = Zeroizing::new([0u8; 80]);
            argon
                .hash_password_into(pass, &k.salt, out.as_mut_slice())
                .map_err(|e| invalid(format!("PuTTY key: Argon2: {e}")))?;
            let mut aes = Zeroizing::new([0u8; 32]);
            aes.copy_from_slice(&out[..32]);
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&out[32..48]);
            Ok(Derived {
                aes,
                iv,
                mac: Zeroizing::new(out[48..80].to_vec()),
            })
        }
    }
}

fn mac_ok(file: &PpkFile, mac_key: &[u8], private: &[u8]) -> bool {
    let mut data = Zeroizing::new(Vec::with_capacity(
        64 + file.comment.len() + file.public_blob.len() + private.len(),
    ));
    string_into(&mut data, file.algorithm.as_bytes());
    string_into(
        &mut data,
        if file.encrypted {
            b"aes256-cbc"
        } else {
            b"none"
        },
    );
    string_into(&mut data, file.comment.as_bytes());
    string_into(&mut data, &file.public_blob);
    string_into(&mut data, private);
    match file.version {
        PpkVersion::V2 => <Hmac<Sha1> as KeyInit>::new_from_slice(mac_key)
            .map(|mut m| {
                m.update(&data);
                m.verify_slice(&file.mac).is_ok()
            })
            .unwrap_or(false),
        PpkVersion::V3 => <Hmac<Sha256> as KeyInit>::new_from_slice(mac_key)
            .map(|mut m| {
                m.update(&data);
                m.verify_slice(&file.mac).is_ok()
            })
            .unwrap_or(false),
    }
}

/// Parse, decrypt (with `passphrase` when encrypted), verify the MAC and build the key.
///
/// # Errors
/// As [`parse`]; [`KeychainError::NeedsPassphrase`]; [`KeychainError::WrongPassphrase`]
/// (encrypted, MAC mismatch); [`KeychainError::Invalid`] (unencrypted MAC mismatch, a
/// private part that doesn't match the public key).
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
    let file = parse(text)?;
    let public = public_of(&file)?;
    let pass: &[u8] = if file.encrypted {
        passphrase
            .filter(|p| !p.is_empty())
            .ok_or(KeychainError::NeedsPassphrase)?
            .as_bytes()
    } else {
        b""
    };
    let keys = derive(&file, pass)?;
    let mut private = Zeroizing::new(file.private_blob.to_vec());
    if file.encrypted {
        let len = cbc::Decryptor::<aes::Aes256>::new_from_slices(keys.aes.as_slice(), &keys.iv)
            .map_err(|_| KeychainError::Format)?
            .decrypt_padded::<NoPadding>(&mut private)
            .map_err(|_| KeychainError::Format)?
            .len();
        private.truncate(len);
    }
    if !mac_ok(&file, &keys.mac, &private) {
        return Err(if file.encrypted {
            KeychainError::WrongPassphrase
        } else {
            invalid("PuTTY key: MAC check failed (the file is damaged or was modified)")
        });
    }
    build(&public, &private, &file.comment)
}

/// An SSH wire-format reader over the private blob.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn string(&mut self) -> Result<&'a [u8], KeychainError> {
        let bad = || invalid("PuTTY key: malformed private part");
        let len_bytes: [u8; 4] = self
            .0
            .get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let body = self.0.get(4..4 + len).ok_or_else(bad)?;
        self.0 = &self.0[4 + len..];
        Ok(body)
    }

    fn mpint(&mut self) -> Result<Mpint, KeychainError> {
        let b = self.string()?;
        Mpint::from_bytes(b).map_err(|_| invalid("PuTTY key: malformed integer"))
    }
}

/// A big-endian unsigned integer (mpint body) left-padded to `size` bytes.
fn scalar(b: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
    let trimmed = {
        let mut s = b;
        while let [0, rest @ ..] = s {
            s = rest;
        }
        s
    };
    if trimmed.len() > size {
        return Err(invalid("PuTTY key: private scalar too large"));
    }
    let mut out = Zeroizing::new(vec![0u8; size]);
    out[size - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

fn build(public: &PublicKey, private: &[u8], comment: &str) -> Result<PrivateKey, KeychainError> {
    let mismatch = || invalid("PuTTY key: the private part does not match the public key");
    let mut w = Wire(private);
    let keypair = match public.key_data() {
        KeyData::Ed25519(_) => {
            let le = w.string()?;
            if le.len() > 32 {
                return Err(invalid("PuTTY key: malformed Ed25519 private key"));
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            seed[..le.len()].copy_from_slice(le);
            KeypairData::from(Ed25519Keypair::from_seed(&seed))
        }
        KeyData::Ecdsa(pk) => {
            let d = w.mpint()?;
            let bytes = d.as_positive_bytes().ok_or_else(mismatch)?;
            let bad = |_| mismatch();
            let kp = match pk.curve() {
                ssh_key::EcdsaCurve::NistP256 => {
                    let sk = p256::SecretKey::from_slice(&scalar(bytes, 32)?).map_err(bad)?;
                    EcdsaKeypair::NistP256 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
                ssh_key::EcdsaCurve::NistP384 => {
                    let sk = p384::SecretKey::from_slice(&scalar(bytes, 48)?).map_err(bad)?;
                    EcdsaKeypair::NistP384 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
                ssh_key::EcdsaCurve::NistP521 => {
                    let sk = p521::SecretKey::from_slice(&scalar(bytes, 66)?).map_err(bad)?;
                    EcdsaKeypair::NistP521 {
                        public: sk.public_key().into(),
                        private: sk.into(),
                    }
                }
            };
            KeypairData::from(kp)
        }
        KeyData::Rsa(pk) => {
            let d = w.mpint()?;
            let p = w.mpint()?;
            let q = w.mpint()?;
            let iqmp = w.mpint()?;
            let priv_key = RsaPrivateKey::new(d, iqmp, p, q).map_err(|_| mismatch())?;
            let kp = RsaKeypair::new(pk.clone(), priv_key).map_err(|_| mismatch())?;
            // Reconstruct and check it (n = p·q, d·e ≡ 1, …).
            let rsa_key = rsa::RsaPrivateKey::try_from(&kp).map_err(|_| mismatch())?;
            rsa_key.validate().map_err(|_| mismatch())?;
            KeypairData::from(kp)
        }
        _ => {
            return Err(KeychainError::Unsupported(
                public.algorithm().as_str().to_owned(),
            ));
        }
    };
    let key = PrivateKey::new(keypair, comment).map_err(|e| invalid(e.to_string()))?;
    if key.public_key().key_data() != public.key_data() {
        return Err(mismatch());
    }
    Ok(key)
}

/// The PuTTY `.ppk` [`KeyImporter`].
#[derive(Debug, Clone, Copy, Default)]
pub struct PpkImporter;

impl KeyImporter for PpkImporter {
    fn name(&self) -> &'static str {
        PPK_IMPORTER
    }

    fn detects(&self, text: &str) -> bool {
        is_ppk(text)
    }

    fn is_encrypted(&self, text: &str) -> bool {
        parse(text).is_ok_and(|f| f.encrypted)
    }

    fn decode(&self, text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
        decode(text, passphrase)
    }
}

#[cfg(test)]
#[path = "ppk_tests.rs"]
mod tests;
