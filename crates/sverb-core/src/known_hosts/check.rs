//! Verifying a presented host key against the entries (SPEC §9.5).
//!
//! [`check`] decides what the key *is*, in this order:
//! 1. **Revoked:** the key, or the CA that signed the certificate, is listed `@revoked`
//!    for the host → always rejected, even if a CA would accept it.
//! 2. **Certificate:** a host certificate signed by an `@cert-authority` key whose
//!    pattern matches the host, valid now, of type *host*, listing the host name (without
//!    the port) among its principals, without critical options, of an allowed key type →
//!    accepted. Otherwise the certified key is checked like a plain one (3–5), with
//!    the reason noted.
//! 3. **Known:** an entry with the same type and the same key → accepted.
//! 4. **Changed:** entries of the same type but another key → a changed key.
//! 5. **Unknown:** no entry of this type.
//!
//! [`decide`] applies the policy (`strict`, `ask`, `accept-new`).

use ssh_key::{Algorithm, Certificate, HashAlg, PublicKey, certificate::CertType, public::KeyData};

use crate::{
    config::HostKeyPolicy,
    model::{KnownHost, KnownHostMarker, UnixMillis},
};

use super::{
    fingerprint::{fingerprint_sha256, key_blob, sha256_digest},
    hashed,
    lookup::{lookup, lookup_key},
    randomart::randomart,
};

/// The key a server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentedKey {
    /// A plain public key.
    Plain(PublicKey),
    /// A certificate (its certified key is what signed the key exchange).
    Cert(Box<Certificate>),
}

impl PresentedKey {
    /// Parse OpenSSH text (`ssh-ed25519 AAAA… [comment]` or a `*-cert-v01@openssh.com`
    /// line).
    ///
    /// # Errors
    /// Not a public key or certificate.
    pub fn from_openssh(text: &str) -> Result<Self, ssh_key::Error> {
        let algo = text.split_whitespace().next().unwrap_or_default();
        if algo.ends_with("-cert-v01@openssh.com") {
            Ok(Self::Cert(Box::new(Certificate::from_openssh(text)?)))
        } else {
            Ok(Self::Plain(PublicKey::from_openssh(text)?))
        }
    }

    /// The (certified) key's data.
    pub fn key_data(&self) -> &KeyData {
        match self {
            Self::Plain(k) => k.key_data(),
            Self::Cert(c) => c.public_key(),
        }
    }

    /// Details of the (certified) key for prompts and saving.
    pub fn info(&self) -> KeyInfo {
        KeyInfo::of(self.key_data())
    }
}

/// A plain key's type, blob, fingerprint and randomart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, …
    pub key_type: String,
    /// The base64 key blob (the `known_hosts` key field).
    pub base64: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// The randomart picture (`\n`-separated lines).
    pub randomart: String,
    /// Key size in bits (`ED25519` → 256, RSA → modulus size).
    pub bits: u32,
}

/// The name and size OpenSSH shows in the randomart header (`sshkey_type`,
/// `sshkey_size`).
fn display_type(key: &KeyData) -> (&'static str, u32) {
    match key {
        KeyData::Ed25519(_) => ("ED25519", 256),
        KeyData::Ecdsa(k) => (
            "ECDSA",
            match k.curve() {
                ssh_key::EcdsaCurve::NistP256 => 256,
                ssh_key::EcdsaCurve::NistP384 => 384,
                ssh_key::EcdsaCurve::NistP521 => 521,
            },
        ),
        KeyData::Rsa(k) => ("RSA", k.key_size()),
        KeyData::Dsa(_) => ("DSA", 1024),
        KeyData::SkEd25519(_) => ("ED25519-SK", 256),
        KeyData::SkEcdsaSha2NistP256(_) => ("ECDSA-SK", 256),
        _ => ("UNKNOWN", 0),
    }
}

/// The blob of a key (the decoded `known_hosts` key field).
fn blob_of(key: &KeyData) -> Vec<u8> {
    PublicKey::new(key.clone(), "")
        .to_bytes()
        .unwrap_or_default()
}

impl KeyInfo {
    /// The details of `key`.
    pub fn of(key: &KeyData) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let blob = blob_of(key);
        let (name, bits) = display_type(key);
        Self {
            key_type: key.algorithm().as_str().to_owned(),
            base64: STANDARD.encode(&blob),
            fingerprint: fingerprint_sha256(&blob),
            randomart: randomart(&sha256_digest(&blob), name, bits),
            bits,
        }
    }

    /// The details of a `known_hosts` entry's key (`None`: the key does not decode).
    pub fn of_entry(entry: &KnownHost) -> Option<Self> {
        let blob = key_blob(&entry.public_key)?;
        match PublicKey::from_bytes(&blob) {
            Ok(k) => Some(Self::of(k.key_data())),
            Err(_) => Some(Self {
                key_type: entry.key_type.clone(),
                base64: entry.public_key.clone(),
                fingerprint: fingerprint_sha256(&blob),
                randomart: randomart(&sha256_digest(&blob), "UNKNOWN", 0),
                bits: 0,
            }),
        }
    }
}

/// What a presented key is for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Listed `@revoked` (the key or its CA).
    Revoked {
        /// Which key was revoked (`SHA256:…`).
        fingerprint: String,
    },
    /// A host certificate signed by a trusted CA, valid for this host now.
    CertValid {
        /// The CA key's fingerprint.
        ca_fingerprint: String,
    },
    /// The same key is trusted for this host.
    Known,
    /// Another key of the same type is trusted for this host.
    Changed {
        /// The entries the new key would replace.
        old: Vec<KnownHost>,
        /// Why a presented certificate was not accepted, if it was one.
        cert_note: Option<String>,
    },
    /// No key of this type is trusted for this host.
    Unknown {
        /// Why a presented certificate was not accepted, if it was one.
        cert_note: Option<String>,
    },
}

/// What the policy makes of a [`CheckResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Trusted.
    Accept,
    /// Ask about an unknown key (the modal).
    AskUnknown,
    /// Warn about a changed key (the red screen).
    AskChanged,
    /// Refuse, with the reason.
    Reject(String),
    /// `accept-new`: save the unknown key and connect.
    AutoSave,
}

/// Whether two key-type names are the same type for "one key per type" (all RSA
/// signature names share the `ssh-rsa` key).
pub fn same_key_type(a: &str, b: &str) -> bool {
    let rsa = |n: &str| n == "ssh-rsa" || n.starts_with("rsa-sha2-");
    a == b || (rsa(a) && rsa(b))
}

fn entry_blob_eq(entry: &KnownHost, blob: &[u8]) -> bool {
    key_blob(&entry.public_key).is_some_and(|b| b == blob)
}

/// Why the certificate is not acceptable for `hostname` at `now` under one of the
/// `cas` (`Ok`: it is).
fn check_cert(
    cert: &Certificate,
    cas: &[KnownHost],
    hostname: &str,
    now: u64,
) -> Result<String, String> {
    let ca_blob = blob_of(cert.signature_key());
    if !cas.iter().any(|ca| entry_blob_eq(ca, &ca_blob)) {
        return Err("the certificate's CA is not trusted for this host".to_owned());
    }
    if cert.cert_type() != CertType::Host {
        return Err("a user certificate was presented as a host key".to_owned());
    }
    let allowed = |a: &Algorithm| {
        matches!(
            a,
            Algorithm::Ed25519
                | Algorithm::Ecdsa { .. }
                | Algorithm::Rsa { .. }
                | Algorithm::SkEd25519
                | Algorithm::SkEcdsaSha2NistP256
        )
    };
    if !allowed(&cert.public_key().algorithm()) || !allowed(&cert.signature_key().algorithm()) {
        return Err(format!(
            "certificate key type {} is not allowed",
            cert.public_key().algorithm()
        ));
    }
    let ca_fp = cert.signature_key().fingerprint(HashAlg::Sha256);
    if cert.verify_signature().is_err() {
        return Err("the certificate's signature does not verify".to_owned());
    }
    if cert.validate_at(now, [&ca_fp]).is_err() {
        return Err("the certificate is not valid now (expired or not yet valid)".to_owned());
    }
    let principals = cert.valid_principals();
    if !principals.iter().any(|p| p.eq_ignore_ascii_case(hostname)) {
        return Err(format!("the certificate is not valid for {hostname}"));
    }
    if !cert.critical_options().is_empty() {
        return Err("the certificate has critical options".to_owned());
    }
    Ok(ca_fp.to_string())
}

/// What `key` is for `host:port` given `entries`, at `now` (seconds since the epoch;
/// only certificates use it).
pub fn check<'a>(
    entries: impl IntoIterator<Item = &'a KnownHost>,
    host: &str,
    port: u16,
    key: &PresentedKey,
    now: u64,
) -> CheckResult {
    let known = lookup(entries, host, port);
    let blob = blob_of(key.key_data());

    // 1. Revoked: the key itself, or the CA that signed the certificate.
    let mut revoked_blobs = vec![blob.clone()];
    if let PresentedKey::Cert(cert) = key {
        revoked_blobs.push(blob_of(cert.signature_key()));
    }
    for revoked in &known.revoked {
        if let Some(b) = revoked_blobs.iter().find(|b| entry_blob_eq(revoked, b)) {
            return CheckResult::Revoked {
                fingerprint: fingerprint_sha256(b),
            };
        }
    }

    // 2. A host certificate from a trusted CA.
    let mut cert_note = None;
    if let PresentedKey::Cert(cert) = key {
        match check_cert(cert, &known.cas, host, now) {
            Ok(ca_fingerprint) => return CheckResult::CertValid { ca_fingerprint },
            Err(why) => cert_note = Some(why),
        }
    }

    // 3–5. The (certified) plain key against the host's entries of its type.
    let key_type = key.key_data().algorithm();
    let same_type: Vec<&KnownHost> = known
        .matching
        .iter()
        .filter(|e| same_key_type(&e.key_type, key_type.as_str()))
        .collect();
    if same_type.iter().any(|e| entry_blob_eq(e, &blob)) {
        return CheckResult::Known;
    }
    if same_type.is_empty() {
        CheckResult::Unknown { cert_note }
    } else {
        CheckResult::Changed {
            old: same_type.into_iter().cloned().collect(),
            cert_note,
        }
    }
}

/// Apply `policy` to `result` (the 3 × 5 table of SPEC §9.5).
pub fn decide(policy: HostKeyPolicy, result: &CheckResult) -> PolicyDecision {
    match (result, policy) {
        (CheckResult::Revoked { fingerprint }, _) => {
            PolicyDecision::Reject(format!("the host key {fingerprint} is marked @revoked"))
        }
        (CheckResult::CertValid { .. } | CheckResult::Known, _) => PolicyDecision::Accept,
        (CheckResult::Changed { .. }, HostKeyPolicy::Ask) => PolicyDecision::AskChanged,
        (CheckResult::Changed { .. }, HostKeyPolicy::Strict | HostKeyPolicy::AcceptNew) => {
            PolicyDecision::Reject(
                "REMOTE HOST IDENTIFICATION HAS CHANGED: the host key differs from the trusted one"
                    .to_owned(),
            )
        }
        (CheckResult::Unknown { .. }, HostKeyPolicy::Strict) => PolicyDecision::Reject(
            "the host key is unknown and host_key_policy is strict".to_owned(),
        ),
        (CheckResult::Unknown { .. }, HostKeyPolicy::Ask) => PolicyDecision::AskUnknown,
        (CheckResult::Unknown { .. }, HostKeyPolicy::AcceptNew) => PolicyDecision::AutoSave,
    }
}

/// A new entry trusting `key` for `host:port`, hashed with a fresh salt when `hash`
/// (`ssh.hash_known_hosts`). A hashing failure (no OS randomness) stores it unhashed.
pub fn new_entry(host: &str, port: u16, key: &KeyInfo, hash: bool, now: UnixMillis) -> KnownHost {
    let plain = lookup_key(host, port);
    let host_pattern = if hash {
        hashed::hash_host(&plain).unwrap_or(plain)
    } else {
        plain
    };
    KnownHost {
        host_pattern,
        key_type: key.key_type.clone(),
        public_key: key.base64.clone(),
        added_at: now,
        comment: None,
        marker: KnownHostMarker::None,
        read_only: false,
    }
}

/// The fingerprint of an entry's key, or `?` when it does not decode.
pub fn entry_fingerprint(entry: &KnownHost) -> String {
    key_blob(&entry.public_key).map_or_else(|| "?".to_owned(), |b| fingerprint_sha256(&b))
}
