//! M2-03 §2.3: private key formats, detected by content.
//!
//! - [`openssh`]: `-----BEGIN OPENSSH PRIVATE KEY-----` (plain or bcrypt-encrypted).
//! - [`pem`]: `BEGIN RSA PRIVATE KEY` (PKCS#1) and `BEGIN EC PRIVATE KEY` (SEC1), plain
//!   or legacy-encrypted (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: AES-128-CBC` /
//!   `AES-192-CBC` / `AES-256-CBC`; other ciphers get a "convert with ssh-keygen -p"
//!   message).
//! - [`pkcs8`]: `BEGIN PRIVATE KEY` and `BEGIN ENCRYPTED PRIVATE KEY` (PBES2).
//!
//! Each decoder returns a decrypted `ssh_key::PrivateKey`; the importer re-serializes
//! it to OpenSSH.

pub mod openssh;
pub mod pem;
pub mod pkcs8;
// M7-03: PuTTY `.ppk` v2 / v3 (registered as the `.ppk` KeyImporter).
pub mod ppk;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::KeychainError;

/// The format of a key text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// OpenSSH private key.
    OpenSsh,
    /// PEM PKCS#1 RSA private key.
    Pkcs1,
    /// PEM SEC1 EC private key.
    Sec1,
    /// PKCS#8 private key (plain).
    Pkcs8,
    /// PKCS#8 encrypted private key (PBES2).
    Pkcs8Encrypted,
    /// An OpenSSH public key line (`.pub`): an agent / hardware reference.
    PublicKey,
    /// Claimed by a registered [`KeyImporter`](super::import::KeyImporter) (its name).
    Plugin(&'static str),
    /// Not recognized.
    Unknown,
}

impl KeyFormat {
    /// A short name for messages and the CLI.
    pub fn name(self) -> &'static str {
        match self {
            Self::OpenSsh => "OpenSSH",
            Self::Pkcs1 => "PEM PKCS#1",
            Self::Sec1 => "PEM SEC1",
            Self::Pkcs8 => "PKCS#8",
            Self::Pkcs8Encrypted => "PKCS#8 (encrypted)",
            Self::PublicKey => "public key",
            Self::Plugin(name) => name,
            Self::Unknown => "unknown",
        }
    }
}

/// The format of `text` by its armor line (built-in formats only; plugins are asked by
/// [`detect`](super::import::detect)).
pub fn detect_builtin(text: &str) -> KeyFormat {
    let t = text.trim_start();
    for line in t.lines().map(str::trim) {
        match line {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => return KeyFormat::OpenSsh,
            "-----BEGIN RSA PRIVATE KEY-----" => return KeyFormat::Pkcs1,
            "-----BEGIN EC PRIVATE KEY-----" => return KeyFormat::Sec1,
            "-----BEGIN PRIVATE KEY-----" => return KeyFormat::Pkcs8,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----" => return KeyFormat::Pkcs8Encrypted,
            l if l.starts_with("-----BEGIN ") => return KeyFormat::Unknown,
            _ => {}
        }
    }
    if super::parse_public(first_line(t)).is_ok() {
        return KeyFormat::PublicKey;
    }
    KeyFormat::Unknown
}

fn first_line(t: &str) -> &str {
    t.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// A decoded PEM block: its RFC 1421 headers and DER body.
pub(crate) struct PemBlock {
    /// `Name: value` headers (legacy encryption).
    pub headers: Vec<(String, String)>,
    /// The DER bytes (zeroized on drop).
    pub der: Zeroizing<Vec<u8>>,
}

impl PemBlock {
    /// A header's value.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Decode the first PEM block labelled `label` (`RSA PRIVATE KEY`, …).
pub(crate) fn pem_block(text: &str, label: &str) -> Result<PemBlock, KeychainError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut lines = text.lines().map(str::trim);
    lines
        .by_ref()
        .find(|l| *l == begin)
        .ok_or(KeychainError::Format)?;
    let mut headers = Vec::new();
    let mut body = Zeroizing::new(String::new());
    let mut ended = false;
    let mut in_headers = true;
    for line in lines {
        if line == end {
            ended = true;
            break;
        }
        if in_headers {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_owned(), v.trim().to_owned()));
                continue;
            }
            in_headers = false;
            if line.is_empty() {
                continue;
            }
        }
        body.push_str(line);
    }
    if !ended {
        return Err(KeychainError::Format);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| KeychainError::Format)?;
    Ok(PemBlock {
        headers,
        der: Zeroizing::new(der),
    })
}
