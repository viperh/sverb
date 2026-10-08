//! Algorithm preferences (SPEC §6.1.8).
//!
//! sverb's preference table, filtered against what the pinned russh implements, with
//! the per-host legacy opt-in (`Host.algorithms`) appended **after** the secure
//! preferences, and host-key types already known for the host moved to the front
//! (§9.5). The table works on names (`String`s); [`to_russh`] converts it to
//! `russh::Preferred`, dropping anything russh can't do.
//!
//! [`supported`] lists the result for `sverb doctor --algos` (M7-04).

use std::borrow::Cow;

use russh::{Preferred, cipher, compression, kex, keys::Algorithm, mac};
use sverb_core::model::AlgoOverrides;
use tracing::debug;

/// Key exchange, most preferred first (§6.1.8).
pub const SECURE_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
];

/// Host-key algorithms, most preferred first. Their `-cert-v01@openssh.com` variants are
/// offered too (ahead of the plain keys, as OpenSSH does).
pub const SECURE_HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Ciphers, most preferred first.
pub const SECURE_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes128-ctr",
];

/// MACs (used with the non-AEAD ciphers only).
pub const SECURE_MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
];

/// Compression.
pub const SECURE_COMPRESSION: &[&str] = &["none"];

/// Key exchange that a host may opt into (disabled by default).
pub const LEGACY_KEX: &[&str] = &["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"];

/// Host-key algorithms that a host may opt into.
pub const LEGACY_HOST_KEYS: &[&str] = &["ssh-rsa", "ssh-dss"];

/// Ciphers that a host may opt into.
pub const LEGACY_CIPHERS: &[&str] = &["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"];

/// MACs that a host may opt into.
pub const LEGACY_MACS: &[&str] = &["hmac-sha1"];

/// Compression that a host may opt into.
pub const LEGACY_COMPRESSION: &[&str] = &["zlib@openssh.com"];

/// An algorithm category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgoKind {
    /// Key exchange.
    Kex,
    /// Host key.
    HostKey,
    /// Cipher.
    Cipher,
    /// MAC.
    Mac,
    /// Compression.
    Compression,
}

impl AlgoKind {
    /// The words used in messages ("No common key exchange: …").
    pub fn noun(self) -> &'static str {
        match self {
            Self::Kex => "key exchange",
            Self::HostKey => "host key algorithm",
            Self::Cipher => "cipher",
            Self::Mac => "MAC",
            Self::Compression => "compression",
        }
    }

    /// The secure list.
    pub fn secure(self) -> &'static [&'static str] {
        match self {
            Self::Kex => SECURE_KEX,
            Self::HostKey => SECURE_HOST_KEYS,
            Self::Cipher => SECURE_CIPHERS,
            Self::Mac => SECURE_MACS,
            Self::Compression => SECURE_COMPRESSION,
        }
    }

    /// The disabled-by-default list.
    pub fn legacy(self) -> &'static [&'static str] {
        match self {
            Self::Kex => LEGACY_KEX,
            Self::HostKey => LEGACY_HOST_KEYS,
            Self::Cipher => LEGACY_CIPHERS,
            Self::Mac => LEGACY_MACS,
            Self::Compression => LEGACY_COMPRESSION,
        }
    }

    /// Whether the pinned russh implements `name` in this category.
    pub fn is_supported(self, name: &str) -> bool {
        match self {
            Self::Kex => kex::Name::try_from(name).is_ok() && name != "none",
            Self::HostKey => host_key_algorithm(name).is_some(),
            Self::Cipher => {
                cipher::Name::try_from(name).is_ok() && !matches!(name, "none" | "clear")
            }
            Self::Mac => mac::Name::try_from(name).is_ok() && name != "none",
            Self::Compression => compression::Name::try_from(name).is_ok(),
        }
    }

    const ALL: [Self; 5] = [
        Self::Kex,
        Self::HostKey,
        Self::Cipher,
        Self::Mac,
        Self::Compression,
    ];
}

/// The host-key algorithms russh can verify (no DSA: the pinned russh is built without
/// its `dsa` feature; no FIDO `sk-*` host keys).
fn host_key_algorithm(name: &str) -> Option<Algorithm> {
    match Algorithm::new(name).ok()? {
        a @ (Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }) => Some(a),
        _ => None,
    }
}

/// The preference lists for one connection, by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlgoTable {
    /// Key exchange.
    pub kex: Vec<String>,
    /// Host key algorithms (plain names; certificate variants are derived).
    pub host_key: Vec<String>,
    /// Ciphers.
    pub cipher: Vec<String>,
    /// MACs.
    pub mac: Vec<String>,
    /// Compression.
    pub compression: Vec<String>,
}

impl AlgoTable {
    /// The list for `kind`.
    pub fn list(&self, kind: AlgoKind) -> &[String] {
        match kind {
            AlgoKind::Kex => &self.kex,
            AlgoKind::HostKey => &self.host_key,
            AlgoKind::Cipher => &self.cipher,
            AlgoKind::Mac => &self.mac,
            AlgoKind::Compression => &self.compression,
        }
    }

    fn list_mut(&mut self, kind: AlgoKind) -> &mut Vec<String> {
        match kind {
            AlgoKind::Kex => &mut self.kex,
            AlgoKind::HostKey => &mut self.host_key,
            AlgoKind::Cipher => &mut self.cipher,
            AlgoKind::Mac => &mut self.mac,
            AlgoKind::Compression => &mut self.compression,
        }
    }
}

fn extras(overrides: &AlgoOverrides, kind: AlgoKind) -> &[String] {
    let list = match kind {
        AlgoKind::Kex => &overrides.kex,
        AlgoKind::HostKey => &overrides.host_key,
        AlgoKind::Cipher => &overrides.cipher,
        AlgoKind::Mac => &overrides.mac,
        AlgoKind::Compression => &overrides.compression,
    };
    list.as_deref().unwrap_or(&[])
}

/// The secure table, filtered against russh (what [`supported`] reports).
pub fn secure_table() -> AlgoTable {
    preferences(&AlgoOverrides::default(), &[])
}

/// The preferences for a host: the secure list (only what russh implements), then the
/// host's legacy opt-ins (only names from the disabled-by-default list that russh
/// implements; anything else is ignored and logged at `debug`), with the host-key types
/// in `known_key_types` (from known_hosts, §9.5) moved to the front.
pub fn preferences(overrides: &AlgoOverrides, known_key_types: &[String]) -> AlgoTable {
    let mut table = AlgoTable::default();
    for kind in AlgoKind::ALL {
        let list = table.list_mut(kind);
        list.extend(
            kind.secure()
                .iter()
                .filter(|n| kind.is_supported(n))
                .map(|n| (*n).to_owned()),
        );
        for name in extras(overrides, kind) {
            let name = name.trim();
            if list.iter().any(|n| n == name) {
                continue;
            }
            if !kind.legacy().contains(&name) {
                debug!(
                    kind = kind.noun(),
                    algorithm = name,
                    "algorithm override ignored: not a legacy algorithm"
                );
            } else if !kind.is_supported(name) {
                debug!(
                    kind = kind.noun(),
                    algorithm = name,
                    "algorithm override ignored: not implemented by russh"
                );
            } else {
                list.push(name.to_owned());
            }
        }
    }
    table.host_key = reorder_host_keys(&table.host_key, known_key_types);
    table
}

/// Whether two host-key names are the same key type (all RSA signature variants share
/// one `ssh-rsa` key).
fn same_key_type(known: &str, algorithm: &str) -> bool {
    let rsa = |n: &str| n == "ssh-rsa" || n.starts_with("rsa-sha2-");
    known == algorithm || (rsa(known) && rsa(algorithm))
}

/// Move the algorithms whose key type is in `known` to the front, keeping the
/// preference order within both groups (§9.5: so a known host presents the key we
/// already trust instead of prompting for another type).
pub fn reorder_host_keys(list: &[String], known: &[String]) -> Vec<String> {
    let is_known = |a: &String| known.iter().any(|k| same_key_type(k, a));
    let (mut front, back): (Vec<String>, Vec<String>) = list.iter().cloned().partition(is_known);
    front.extend(back);
    front
}

/// Extension pseudo-algorithms appended to the key exchange list: RFC 8308 ext-info
/// (`server-sig-algs`) and OpenSSH strict KEX (the Terrapin mitigation).
const KEX_EXTENSIONS: [kex::Name; 2] = [
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Whether `name` is an extension pseudo-algorithm rather than a key exchange.
pub fn is_kex_extension(name: &str) -> bool {
    name.starts_with("ext-info-") || name.starts_with("kex-strict-")
}

/// Convert `table` to russh's preferences. Names russh doesn't know are dropped.
pub fn to_russh(table: &AlgoTable) -> Preferred {
    let mut kex: Vec<kex::Name> = table
        .kex
        .iter()
        .filter_map(|n| kex::Name::try_from(n.as_str()).ok())
        .collect();
    kex.extend(KEX_EXTENSIONS);
    let key: Vec<Algorithm> = table
        .host_key
        .iter()
        .filter_map(|n| host_key_algorithm(n))
        .collect();
    // Certificates for the secure algorithms only (never `ssh-rsa` certificates).
    let certs: Vec<Algorithm> = key
        .iter()
        .filter(|a| SECURE_HOST_KEYS.contains(&a.as_str()))
        .cloned()
        .collect();
    Preferred {
        kex: Cow::Owned(kex),
        key: Cow::Owned(key),
        host_key_certificates: Cow::Owned(certs),
        cipher: Cow::Owned(
            table
                .cipher
                .iter()
                .filter_map(|n| cipher::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
        mac: Cow::Owned(
            table
                .mac
                .iter()
                .filter_map(|n| mac::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
        compression: Cow::Owned(
            table
                .compression
                .iter()
                .filter_map(|n| compression::Name::try_from(n.as_str()).ok())
                .collect(),
        ),
    }
}

/// One category of [`supported`]: what sverb offers by default and what a host can opt
/// into, both filtered against the pinned russh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedAlgos {
    /// The category.
    pub kind: AlgoKind,
    /// Offered by default, in order.
    pub default: Vec<String>,
    /// Available as a per-host legacy opt-in.
    pub legacy: Vec<String>,
}

/// Everything sverb can negotiate with this build (`sverb doctor --algos`, M7-04).
pub fn supported() -> Vec<SupportedAlgos> {
    let table = secure_table();
    AlgoKind::ALL
        .iter()
        .map(|&kind| SupportedAlgos {
            kind,
            default: table.list(kind).to_vec(),
            legacy: kind
                .legacy()
                .iter()
                .filter(|n| kind.is_supported(n))
                .map(|n| (*n).to_owned())
                .collect(),
        })
        .collect()
}

/// The certificate name of a host-key algorithm (`ssh-ed25519-cert-v01@openssh.com`).
pub fn certificate_name(name: &str) -> Option<String> {
    host_key_algorithm(name).map(|a| a.to_certificate_type())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn s(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// T-05: the secure list is filtered against russh, and legacy algorithms appear
    /// only with an override, at the end.
    #[test]
    fn t05_algorithm_preferences() {
        let table = secure_table();
        for kind in AlgoKind::ALL {
            let list = table.list(kind);
            assert!(!list.is_empty(), "{kind:?} has algorithms");
            for name in list {
                assert!(kind.secure().contains(&name.as_str()), "{name} is secure");
                assert!(kind.is_supported(name), "{name} is implemented");
            }
            for legacy in kind.legacy() {
                assert!(
                    !list.iter().any(|n| n == legacy),
                    "{legacy} is off by default"
                );
            }
        }
        // The pinned russh has ML-KEM and the curve25519 pair, in this order.
        assert_eq!(
            &table.kex[..3],
            &s(&[
                "mlkem768x25519-sha256",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org"
            ])
        );
        assert_eq!(table.compression, s(&["none"]));

        let overrides = AlgoOverrides {
            kex: Some(s(&["diffie-hellman-group14-sha1"])),
            ..AlgoOverrides::default()
        };
        let table = preferences(&overrides, &[]);
        assert_eq!(
            table.kex.last().map(String::as_str),
            Some("diffie-hellman-group14-sha1")
        );
        assert_eq!(table.kex.len(), secure_table().kex.len() + 1);
        assert!(!table.host_key.iter().any(|n| n == "ssh-rsa"));
    }

    /// Overrides outside the legacy list, unimplemented ones and duplicates are ignored.
    #[test]
    fn overrides_are_restricted_to_the_legacy_list() {
        let overrides = AlgoOverrides {
            kex: Some(s(&[
                "curve25519-sha256",
                "made-up-kex",
                "diffie-hellman-group1-sha1",
            ])),
            host_key: Some(s(&["ssh-rsa", "ssh-dss"])),
            cipher: Some(s(&["aes128-cbc", "3des-cbc"])),
            mac: Some(s(&["hmac-sha1", "hmac-md5"])),
            compression: Some(s(&["zlib@openssh.com"])),
        };
        let table = preferences(&overrides, &[]);
        let secure = secure_table();
        assert_eq!(
            table.kex[secure.kex.len()..],
            s(&["diffie-hellman-group1-sha1"])
        );
        // ssh-dss: russh is built without DSA.
        assert_eq!(table.host_key[secure.host_key.len()..], s(&["ssh-rsa"]));
        // 3des-cbc: russh is built without `des`.
        assert_eq!(table.cipher[secure.cipher.len()..], s(&["aes128-cbc"]));
        assert_eq!(table.mac[secure.mac.len()..], s(&["hmac-sha1"]));
        assert_eq!(table.compression, s(&["none", "zlib@openssh.com"]));
        let preferred = to_russh(&table);
        assert_eq!(
            preferred.kex.len(),
            table.kex.len() + 2,
            "plus ext-info-c and strict kex"
        );
        assert_eq!(preferred.key.len(), table.host_key.len());
        assert!(
            !preferred
                .host_key_certificates
                .iter()
                .any(|a| a.as_str() == "ssh-rsa")
        );
    }

    /// T-06: host-key types known for the host move to the front.
    #[test]
    fn t06_host_key_reordering() {
        let table = preferences(&AlgoOverrides::default(), &s(&["rsa-sha2-512"]));
        assert_eq!(table.host_key[0], "rsa-sha2-512");
        assert_eq!(table.host_key[1], "rsa-sha2-256", "same key type");
        assert_eq!(table.host_key[2], "ssh-ed25519");
        // known_hosts stores RSA keys as `ssh-rsa`: the SHA-2 variants move up, but
        // `ssh-rsa` itself is still not offered.
        let table = preferences(
            &AlgoOverrides::default(),
            &s(&["ssh-rsa", "ecdsa-sha2-nistp384"]),
        );
        assert_eq!(
            &table.host_key[..3],
            &s(&["ecdsa-sha2-nistp384", "rsa-sha2-512", "rsa-sha2-256"])
        );
        assert!(!table.host_key.iter().any(|n| n == "ssh-rsa"));
    }

    #[test]
    fn supported_lists_every_category() {
        let all = supported();
        assert_eq!(all.len(), 5);
        let kex = all.iter().find(|a| a.kind == AlgoKind::Kex).unwrap();
        assert_eq!(
            kex.legacy,
            s(&["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"])
        );
        assert_eq!(
            certificate_name("ssh-ed25519").as_deref(),
            Some("ssh-ed25519-cert-v01@openssh.com")
        );
    }
}
