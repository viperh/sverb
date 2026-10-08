//! The OpenSSH `known_hosts` format (sshd(8) "SSH_KNOWN_HOSTS FILE FORMAT"):
//!
//! ```text
//! [@cert-authority|@revoked] host-patterns key-type base64-key [comment]
//! ```
//!
//! Blank lines and `#` comments are skipped. Host fields are pattern lists or hashed
//! (`|1|salt|hash`). Every key type is accepted, certificates and `sk-*` keys included;
//! a key type sverb doesn't know is kept as is (so exporting writes it back) with a
//! warning. Lines that cannot be an entry (missing fields, bad base64, a blob of another
//! type, an unknown marker, a malformed hashed field) are skipped with a warning.
//!
//! Shared with the `~/.ssh/known_hosts` importer (M2-11).

use crate::model::{KnownHost, KnownHostMarker};

use super::{fingerprint::key_blob, hashed};

/// A line that was skipped or kept with a caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    /// 1-based line number.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

/// Key types sverb knows (plain, `sk-*` and their certificates).
pub const KNOWN_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
];

/// The type name at the start of a key blob (an SSH `string`).
fn blob_type(blob: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    let end = 4_usize.checked_add(usize::try_from(len).ok()?)?;
    std::str::from_utf8(blob.get(4..end)?).ok()
}

/// Split off the first whitespace-separated field.
fn field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    Some(match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    })
}

/// Parse one non-comment line: the entry and an optional caveat, or why it was skipped.
fn parse_line(line: &str) -> Result<(KnownHost, Option<String>), String> {
    let (first, rest) = field(line).ok_or("empty line")?;
    let (marker, hosts, rest) = match first.strip_prefix('@') {
        Some("cert-authority") => {
            let (h, r) = field(rest).ok_or("missing host patterns")?;
            (KnownHostMarker::CertAuthority, h, r)
        }
        Some("revoked") => {
            let (h, r) = field(rest).ok_or("missing host patterns")?;
            (KnownHostMarker::Revoked, h, r)
        }
        Some(other) => return Err(format!("unknown marker @{other}")),
        None => (KnownHostMarker::None, first, rest),
    };
    let (key_type, rest) = field(rest).ok_or("missing key type")?;
    let (key, rest) = field(rest).ok_or("missing key")?;
    let comment = rest.trim();
    if hashed::is_hashed(hosts) && hashed::decode(hosts).is_none() {
        return Err("malformed hashed host name".to_owned());
    }
    let blob = key_blob(key).ok_or("the key is not valid base64")?;
    match blob_type(&blob) {
        Some(t) if t == key_type => {}
        Some(t) => return Err(format!("key type {key_type} does not match the key ({t})")),
        None => return Err("the key is not an SSH public key".to_owned()),
    }
    let caveat = (!KNOWN_KEY_TYPES.contains(&key_type))
        .then(|| format!("unknown key type {key_type} (kept as is)"));
    Ok((
        KnownHost {
            host_pattern: hosts.to_owned(),
            key_type: key_type.to_owned(),
            public_key: key.to_owned(),
            comment: (!comment.is_empty()).then(|| comment.to_owned()),
            marker,
            ..KnownHost::default()
        },
        caveat,
    ))
}

/// Parse a `known_hosts` file: the entries (`added_at` left at 0 for the caller) and a
/// warning per skipped or caveated line.
pub fn parse_known_hosts(text: &str) -> (Vec<KnownHost>, Vec<ParseWarning>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok((entry, caveat)) => {
                if let Some(reason) = caveat {
                    warnings.push(ParseWarning {
                        line: i + 1,
                        reason,
                    });
                }
                entries.push(entry);
            }
            Err(reason) => warnings.push(ParseWarning {
                line: i + 1,
                reason,
            }),
        }
    }
    (entries, warnings)
}

/// One `known_hosts` line for `entry` (no trailing newline).
pub fn to_line(entry: &KnownHost) -> String {
    let marker = match entry.marker {
        KnownHostMarker::None => "",
        KnownHostMarker::CertAuthority => "@cert-authority ",
        KnownHostMarker::Revoked => "@revoked ",
    };
    let mut line = format!(
        "{marker}{} {} {}",
        entry.host_pattern, entry.key_type, entry.public_key
    );
    if let Some(comment) = entry.comment.as_deref().map(str::trim)
        && !comment.is_empty()
    {
        line.push(' ');
        // One line per entry: line breaks in a comment become spaces.
        line.push_str(&comment.replace(['\n', '\r'], " "));
    }
    line
}

/// A `known_hosts` file with one line per entry.
pub fn export<'a>(entries: impl IntoIterator<Item = &'a KnownHost>) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&to_line(entry));
        out.push('\n');
    }
    out
}
