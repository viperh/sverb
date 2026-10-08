//! M2-03 §2.6: OpenSSH certificates (SPEC §4.6, §9.4).
//!
//! A Certificate item stores only the certificate line; everything shown (principals,
//! validity window, CA fingerprint, key id, serial, type) is **derived on read** by
//! [`parse_cert`] and never stored. [`validate_for_key`] rejects a certificate whose
//! public key differs from the key it is attached to. [`expiry_badge`] takes the
//! clock as a parameter (tests inject it).

use ssh_key::{Certificate, HashAlg, certificate::CertType};

use super::{KeychainError, parse_public};

/// Warn when a certificate expires within this many seconds (7 days).
pub const EXPIRY_WARN_SECS: u64 = 7 * 24 * 60 * 60;

/// `valid_before` of a certificate that never expires.
pub const FOREVER: u64 = u64::MAX;

/// The derived fields of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// `user` or `host`.
    pub cert_type: &'static str,
    /// The certified key's algorithm (`ssh-ed25519`, …).
    pub algorithm: String,
    /// The certificate's key id.
    pub key_id: String,
    /// The serial number.
    pub serial: u64,
    /// Valid principals (empty: any).
    pub principals: Vec<String>,
    /// Valid from (UNIX seconds).
    pub valid_after: u64,
    /// Valid until (UNIX seconds; [`FOREVER`]: no expiry).
    pub valid_before: u64,
    /// The signing CA's `SHA256:…` fingerprint.
    pub ca_fingerprint: String,
    /// The certified public key's `SHA256:…` fingerprint.
    pub key_fingerprint: String,
}

/// A certificate's validity relative to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryBadge {
    /// Valid for more than 7 days (or forever).
    None,
    /// Expires within 7 days (yellow).
    Expiring,
    /// Expired (red).
    Expired,
    /// Not valid yet.
    NotYetValid,
}

impl ExpiryBadge {
    /// The badge text (empty for [`ExpiryBadge::None`]).
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Expiring => "expiring",
            Self::Expired => "expired",
            Self::NotYetValid => "not yet valid",
        }
    }

    /// The more urgent of two badges (a key with several certificates).
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        let rank = |b: Self| match b {
            Self::None => 0,
            Self::NotYetValid => 1,
            Self::Expiring => 2,
            Self::Expired => 3,
        };
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }
}

fn parse(text: &str) -> Result<Certificate, KeychainError> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    Certificate::from_openssh(line).map_err(|e| KeychainError::Cert(e.to_string()))
}

/// The derived fields of an OpenSSH certificate line.
///
/// # Errors
/// [`KeychainError::Cert`].
pub fn parse_cert(text: &str) -> Result<CertInfo, KeychainError> {
    let c = parse(text)?;
    Ok(CertInfo {
        cert_type: match c.cert_type() {
            CertType::User => "user",
            CertType::Host => "host",
        },
        algorithm: c.algorithm().as_str().to_owned(),
        key_id: c.key_id().to_owned(),
        serial: c.serial(),
        principals: c.valid_principals().to_vec(),
        valid_after: c.valid_after(),
        valid_before: c.valid_before(),
        ca_fingerprint: c.signature_key().fingerprint(HashAlg::Sha256).to_string(),
        key_fingerprint: c.public_key().fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// Parse `cert_text` and check it certifies `public_line`'s key.
///
/// # Errors
/// [`KeychainError::Cert`], [`KeychainError::CertMismatch`].
pub fn validate_for_key(cert_text: &str, public_line: &str) -> Result<CertInfo, KeychainError> {
    let c = parse(cert_text)?;
    let key = parse_public(public_line).map_err(|_| KeychainError::CertMismatch)?;
    if c.public_key() != key.key_data() {
        return Err(KeychainError::CertMismatch);
    }
    parse_cert(cert_text)
}

/// The badge of `info` at `now` (UNIX seconds).
pub fn expiry_badge(info: &CertInfo, now: u64) -> ExpiryBadge {
    if now >= info.valid_before {
        ExpiryBadge::Expired
    } else if now < info.valid_after {
        ExpiryBadge::NotYetValid
    } else if info.valid_before != FOREVER && info.valid_before - now <= EXPIRY_WARN_SECS {
        ExpiryBadge::Expiring
    } else {
        ExpiryBadge::None
    }
}

/// The current UNIX time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A short label suggestion for a certificate: its key id, else the comment.
pub fn suggested_label(text: &str) -> String {
    match parse(text) {
        Ok(c) if !c.key_id().is_empty() => c.key_id().to_owned(),
        Ok(c) if !c.comment().is_empty() => c.comment().to_owned(),
        _ => "certificate".to_owned(),
    }
}
