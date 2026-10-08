//! Field validation (SPEC §4.2, §4.3, §6.1.4, §9.7) as pure functions.
//!
//! Errors carry the field name so forms (M1-06) can show them inline.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Range;

use super::host::Host;
use super::ids::ItemId;

/// Jump hosts' own chains are expanded recursively up to this many hops (§6.1.4).
pub const MAX_JUMP_DEPTH: usize = 8;

/// A field-level validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// The (dotted) field name, e.g. `address` or `env`.
    pub field: String,
    /// A short user-facing message.
    pub message: String,
}

impl ValidationError {
    /// Builds an error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Validates a host address and returns its normalized form: an IP literal as given,
/// or a DNS name converted to ASCII (IDNA / UTS-46, lowercase, punycode).
///
/// Rejects brackets, `user@host`, `host:port`, whitespace, labels over 63 bytes and
/// names over 253 bytes (one trailing dot is allowed and dropped).
pub fn validate_address(address: &str) -> Result<String, ValidationError> {
    let err = |m: &str| Err(ValidationError::new("address", m));
    if address.is_empty() {
        return err("enter a hostname or IP address");
    }
    if address.chars().any(char::is_whitespace) {
        return err("must not contain spaces");
    }
    if address.contains('[') || address.contains(']') {
        return err("write IPv6 addresses without brackets");
    }
    if address.contains('@') {
        return err("put the user name in the username field, not the address");
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if address.contains(':') {
        return err("put the port in the port field, not the address");
    }
    let Ok(ascii) = idna::domain_to_ascii(address) else {
        return err("not a valid hostname");
    };
    let name = ascii.strip_suffix('.').unwrap_or(&ascii);
    if name.is_empty() {
        return err("not a valid hostname");
    }
    if name.len() > 253 {
        return err("hostname is longer than 253 characters");
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return err("hostname has an empty label");
        }
        if label.len() > 63 {
            return err("a hostname label is longer than 63 characters");
        }
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok_chars || label.starts_with('-') || label.ends_with('-') {
            return err("not a valid hostname");
        }
    }
    // An all-numeric last label would be a malformed IPv4 address, not a name.
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return err("not a valid IP address");
    }
    Ok(name.to_owned())
}

/// Validates a port (1..=65535).
pub fn validate_port(field: &str, port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::new(
            field,
            "port must be between 1 and 65535",
        ));
    }
    Ok(())
}

/// Validates an environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn validate_env_name(name: &str) -> Result<(), ValidationError> {
    let mut bytes = name.bytes();
    let ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(ValidationError::new(
            "env",
            format!(
                "invalid variable name {name:?}: use letters, digits and _, not starting with a digit"
            ),
        ))
    }
}

/// Validates the self-contained fields of a host (address, port, env names).
/// Jump chains need the store; see [`validate_jump_chain`].
pub fn validate_host(host: &Host) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    if let Err(e) = validate_address(&host.address) {
        errors.push(e);
    }
    if let Some(port) = host.port
        && let Err(e) = validate_port("port", port)
    {
        errors.push(e);
    }
    for (name, _) in &host.env {
        if let Err(e) = validate_env_name(name) {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validates `host`'s `jump_chain` and returns the fully resolved hop list (jump hosts'
/// own chains expanded recursively, §6.1.4).
///
/// `lookup` returns a host's `jump_chain`; a missing host counts as an empty chain
/// (dangling references are treated as `None`, §12.4). Rejects the host itself in its
/// chain, cycles, and resolved chains longer than [`MAX_JUMP_DEPTH`].
pub fn validate_jump_chain(
    host: ItemId,
    chain: &[ItemId],
    lookup: impl Fn(ItemId) -> Option<Vec<ItemId>>,
) -> Result<Vec<ItemId>, ValidationError> {
    if chain.contains(&host) {
        return Err(ValidationError::new(
            "jump_chain",
            "a host can't jump through itself",
        ));
    }
    let mut stack = vec![host];
    let mut out = Vec::new();
    expand_chain(chain, &lookup, &mut stack, &mut out)?;
    Ok(out)
}

fn expand_chain(
    chain: &[ItemId],
    lookup: &impl Fn(ItemId) -> Option<Vec<ItemId>>,
    stack: &mut Vec<ItemId>,
    out: &mut Vec<ItemId>,
) -> Result<(), ValidationError> {
    let too_deep = || {
        ValidationError::new(
            "jump_chain",
            format!("jump chain is deeper than {MAX_JUMP_DEPTH} hops"),
        )
    };
    for &hop in chain {
        if stack.contains(&hop) {
            return Err(ValidationError::new("jump_chain", "jump chain has a cycle"));
        }
        if stack.len() > MAX_JUMP_DEPTH {
            return Err(too_deep());
        }
        stack.push(hop);
        let sub = lookup(hop).unwrap_or_default();
        expand_chain(&sub, lookup, stack, out)?;
        stack.pop();
        out.push(hop);
        if out.len() > MAX_JUMP_DEPTH {
            return Err(too_deep());
        }
    }
    Ok(())
}

/// Rejects a `parent_id` that would make `group` its own ancestor (§4.3).
/// `parent_of` returns a group's current parent.
pub fn validate_group_parent(
    group: ItemId,
    parent: Option<ItemId>,
    parent_of: impl Fn(ItemId) -> Option<ItemId>,
) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    let mut cur = parent;
    while let Some(p) = cur {
        if p == group {
            return Err(ValidationError::new(
                "parent_id",
                "a group can't be inside itself",
            ));
        }
        if !seen.insert(p) {
            break; // an existing cycle elsewhere; not created by this write
        }
        cur = parent_of(p);
    }
    Ok(())
}

/// A `{{…}}` reference in a snippet script (§9.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetVarRef {
    /// Variable name (`host.label` style dots allowed).
    pub name: String,
    /// `{{name:default}}`
    pub default: Option<String>,
    /// `{{name|q}}`: shell-quote the value.
    pub quote: bool,
    /// Byte range of the whole `{{…}}` in the script.
    pub span: Range<usize>,
}

/// Validates a snippet variable name: `[A-Za-z_][A-Za-z0-9_.]*`.
pub fn validate_var_name(name: &str) -> Result<(), ValidationError> {
    let mut bytes = name.bytes();
    let ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(ValidationError::new(
            "script",
            format!("invalid variable name {name:?}"),
        ))
    }
}

/// Parses the `{{name}}`, `{{name:default}}` and `{{name|q}}` (also
/// `{{name:default|q}}`) references in a snippet script.
pub fn parse_snippet_vars(script: &str) -> Result<Vec<SnippetVarRef>, ValidationError> {
    let mut refs = Vec::new();
    let mut pos = 0;
    while let Some(off) = script[pos..].find("{{") {
        let start = pos + off;
        let inner_start = start + 2;
        let Some(len) = script[inner_start..].find("}}") else {
            return Err(ValidationError::new("script", "unterminated {{ in script"));
        };
        let inner = &script[inner_start..inner_start + len];
        let end = inner_start + len + 2;
        let (body, quote) = match inner.rsplit_once('|') {
            Some((b, "q")) => (b, true),
            Some((_, f)) => {
                return Err(ValidationError::new(
                    "script",
                    format!("unknown filter |{f} (only |q is supported)"),
                ));
            }
            None => (inner, false),
        };
        let (name, default) = match body.split_once(':') {
            Some((n, d)) => (n, Some(d.to_owned())),
            None => (body, None),
        };
        validate_var_name(name)?;
        refs.push(SnippetVarRef {
            name: name.to_owned(),
            default,
            quote,
            span: start..end,
        });
        pos = end;
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // T-11
    #[test]
    fn address_table() {
        for (input, normalized) in [
            ("example.com", "example.com"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("10.0.0.1", "10.0.0.1"),
            ("::1", "::1"),
            ("fe80::1", "fe80::1"),
            ("Example.COM.", "example.com"),
            ("my_host", "my_host"),
        ] {
            assert_eq!(
                validate_address(input).as_deref(),
                Ok(normalized),
                "{input}"
            );
        }
        let long_label = "a".repeat(64);
        let name_254 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(name_254.len(), 254);
        let name_253 = &name_254[..253];
        assert!(validate_address(name_253).is_ok());
        for input in [
            "[::1]",
            "a b",
            "root@x",
            "x:22",
            "",
            name_254.as_str(),
            long_label.as_str(),
            "-bad.example",
            "999.1.1.1",
        ] {
            let e = validate_address(input);
            assert!(e.is_err(), "{input:?} accepted");
            assert_eq!(e.err().map(|e| e.field), Some("address".to_owned()));
        }
    }

    // T-12
    #[test]
    fn port_range() {
        assert!(validate_port("port", 0).is_err());
        assert!(validate_port("port", 1).is_ok());
        assert!(validate_port("port", 65535).is_ok());
    }

    // T-13
    #[test]
    fn env_names() {
        assert!(validate_env_name("PATH").is_ok());
        assert!(validate_env_name("_X1").is_ok());
        for bad in ["1X", "A-B", ""] {
            assert!(validate_env_name(bad).is_err(), "{bad:?}");
        }
    }

    fn ids(n: u8) -> Vec<ItemId> {
        (1..=n).map(|i| ItemId::from_bytes([i; 16])).collect()
    }

    // T-14
    #[test]
    fn jump_chain_rules() {
        let h = ids(20);
        let none = |_: ItemId| None;
        // Self-reference.
        assert!(validate_jump_chain(h[0], &[h[1], h[0]], none).is_err());
        // A -> B -> A.
        let mut chains = HashMap::new();
        chains.insert(h[1], vec![h[0]]);
        assert!(validate_jump_chain(h[0], &[h[1]], |id| chains.get(&id).cloned()).is_err());
        // B -> C -> B (cycle not involving the host).
        let mut chains = HashMap::new();
        chains.insert(h[1], vec![h[2]]);
        chains.insert(h[2], vec![h[1]]);
        assert!(validate_jump_chain(h[0], &[h[1]], |id| chains.get(&id).cloned()).is_err());

        // Nested chain: hop i jumps through hop i+1. Depth n = n hops.
        let nested = |n: usize| {
            let mut chains = HashMap::new();
            for i in 1..n {
                chains.insert(h[i], vec![h[i + 1]]);
            }
            validate_jump_chain(h[0], &[h[1]], move |id| chains.get(&id).cloned())
        };
        let ok = nested(8);
        assert_eq!(ok.as_ref().map(Vec::len), Ok(8));
        // Resolved order: the outermost hop first.
        assert_eq!(ok.ok().and_then(|v| v.first().copied()), Some(h[8]));
        assert!(nested(9).is_err());

        // Flat chains count too.
        assert!(validate_jump_chain(h[0], &h[1..9], none).is_ok());
        assert!(validate_jump_chain(h[0], &h[1..10], none).is_err());

        // Missing hosts are treated as having no chain.
        assert!(validate_jump_chain(h[0], &[h[5]], none).is_ok());
    }

    // T-15
    #[test]
    fn group_parent_cycles() {
        let g = ids(4);
        // g1 <- g2 <- g3 (g3's parent is g2, g2's parent is g1)
        let parents: HashMap<ItemId, ItemId> = [(g[2], g[1]), (g[1], g[0])].into_iter().collect();
        let parent_of = |id: ItemId| parents.get(&id).copied();
        // Making g1's parent g3 closes the loop.
        assert!(validate_group_parent(g[0], Some(g[2]), parent_of).is_err());
        assert!(validate_group_parent(g[0], Some(g[0]), parent_of).is_err());
        assert!(validate_group_parent(g[3], Some(g[2]), parent_of).is_ok());
        assert!(validate_group_parent(g[0], None, parent_of).is_ok());
    }

    #[test]
    fn snippet_variables() {
        let refs = parse_snippet_vars("ssh {{host.label}} {{user:root}} {{path|q}} {{x:a b|q}}");
        let refs = refs.unwrap_or_default();
        assert_eq!(refs.len(), 4);
        assert_eq!(refs[0].name, "host.label");
        assert_eq!(refs[1].default.as_deref(), Some("root"));
        assert!(refs[2].quote);
        assert_eq!(refs[3].default.as_deref(), Some("a b"));
        assert!(refs[3].quote);
        assert!(parse_snippet_vars("{{1bad}}").is_err());
        assert!(parse_snippet_vars("{{a-b}}").is_err());
        assert!(parse_snippet_vars("{{open").is_err());
        assert!(parse_snippet_vars("{{a|z}}").is_err());
        assert!(parse_snippet_vars("plain text").is_ok_and(|v| v.is_empty()));
    }
}
