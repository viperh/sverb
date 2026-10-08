//! Which entries apply to a host (SPEC §9.5).
//!
//! The **lookup key** is `host` for port 22 and `[host]:port` otherwise (IPv6 literals
//! too: `[::1]:2222`). Jump hops are looked up under their own `address:port` as seen
//! from the previous hop (§6.1.4), so the caller passes the hop's address and port.
//!
//! Host fields follow OpenSSH: a hashed field (`|1|…`) matches when the HMAC of the
//! lookup key with its salt is equal (constant time); otherwise the field is a
//! comma-separated pattern list where `*` matches any run of characters, `?` one
//! character, and a `!pattern` that matches vetoes the whole list. Matching ignores
//! ASCII case, as host names do.

use crate::model::{DEFAULT_SSH_PORT, KnownHost, KnownHostMarker};

use super::hashed;

/// The entries that apply to a host, by marker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownKeys {
    /// Plain host keys for this host (possibly several, one per key type).
    pub matching: Vec<KnownHost>,
    /// `@cert-authority` entries whose pattern matches this host.
    pub cas: Vec<KnownHost>,
    /// `@revoked` entries whose pattern matches this host.
    pub revoked: Vec<KnownHost>,
}

impl KnownKeys {
    /// Nothing applies.
    pub fn is_empty(&self) -> bool {
        self.matching.is_empty() && self.cas.is_empty() && self.revoked.is_empty()
    }
}

/// `host` for port 22, `[host]:port` otherwise.
pub fn lookup_key(host: &str, port: u16) -> String {
    if port == DEFAULT_SSH_PORT {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// OpenSSH glob: `*` any run (also empty), `?` exactly one character. ASCII case is
/// ignored.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    // Iterative matcher with backtracking to the last `*`.
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some('?') => {
                pi += 1;
                ti += 1;
            }
            Some(c) if *c == t[ti] => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether the comma-separated pattern list matches `text`: at least one positive
/// pattern matches and no `!negated` one does.
pub fn pattern_list_matches(list: &str, text: &str) -> bool {
    let mut positive = false;
    for pattern in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match pattern.strip_prefix('!') {
            Some(negated) => {
                if glob(negated, text) {
                    return false;
                }
            }
            None => positive |= glob(pattern, text),
        }
    }
    positive
}

/// Whether an entry's host field matches `lookup_key` (hashed or pattern list).
pub fn host_field_matches(field: &str, lookup_key: &str) -> bool {
    if hashed::is_hashed(field) {
        hashed::matches(field, lookup_key)
    } else {
        pattern_list_matches(field, lookup_key)
    }
}

/// The entries that apply to `host:port`.
pub fn lookup<'a>(
    entries: impl IntoIterator<Item = &'a KnownHost>,
    host: &str,
    port: u16,
) -> KnownKeys {
    let key = lookup_key(host, port);
    let mut out = KnownKeys::default();
    for entry in entries {
        if !host_field_matches(&entry.host_pattern, &key) {
            continue;
        }
        match entry.marker {
            KnownHostMarker::None => out.matching.push(entry.clone()),
            KnownHostMarker::CertAuthority => out.cas.push(entry.clone()),
            KnownHostMarker::Revoked => out.revoked.push(entry.clone()),
        }
    }
    out
}

/// Key types (`ssh-ed25519`, `ssh-rsa`, …) already trusted for `host:port`, in entry
/// order without duplicates. Feeds the host-key algorithm reordering (§6.1.8).
pub fn key_types_for<'a>(
    entries: impl IntoIterator<Item = &'a KnownHost>,
    host: &str,
    port: u16,
) -> Vec<String> {
    let mut types: Vec<String> = Vec::new();
    for entry in lookup(entries, host, port).matching {
        if !types.contains(&entry.key_type) {
            types.push(entry.key_type);
        }
    }
    types
}
