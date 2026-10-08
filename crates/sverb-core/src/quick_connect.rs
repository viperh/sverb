//! M1-07: the quick-connect target parser (SPEC §9.1, `leader o`, `sverb connect`).
//!
//! Accepted forms:
//! - `host`, `user@host`, `host:port`, `user@host:port`,
//! - `[v6addr]:port`, `user@[v6addr]:port`, `[v6addr]`,
//! - a bare IPv6 address without a port (`::1`, `fe80::1%eth0` with a zone id),
//! - `ssh://[user@]host[:port]` with an optional trailing `/`; the user is
//!   percent-decoded (`ssh://u%40corp@h` is user `u@corp`).
//!
//! Hostnames are checked with the host model's address rules
//! ([`validate_address`](crate::model::validate::validate_address)); IPv6 literals
//! (optionally with a zone id) are checked here. Ports must be 1–65535.

use std::fmt;
use std::net::Ipv6Addr;

use crate::model::validate::validate_address;

/// A parsed quick-connect target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickTarget {
    /// Hostname or IP literal, without brackets (an IPv6 zone id is kept: `fe80::1%eth0`).
    pub host: String,
    /// Login user, if given.
    pub user: Option<String>,
    /// Port, if given.
    pub port: Option<u16>,
}

impl QuickTarget {
    /// `user@host:port` as typed back to the user (IPv6 bracketed when a port follows).
    pub fn display(&self) -> String {
        let mut out = String::new();
        if let Some(user) = &self.user {
            out.push_str(user);
            out.push('@');
        }
        match self.port {
            Some(port) if self.host.contains(':') => {
                out.push_str(&format!("[{}]:{port}", self.host));
            }
            Some(port) => out.push_str(&format!("{}:{port}", self.host)),
            None => out.push_str(&self.host),
        }
        out
    }
}

impl fmt::Display for QuickTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Why a quick-connect target did not parse. The message is shown inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickConnectError(pub String);

impl fmt::Display for QuickConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QuickConnectError {}

fn err<T>(msg: impl Into<String>) -> Result<T, QuickConnectError> {
    Err(QuickConnectError(msg.into()))
}

/// Parse a quick-connect target. See the [module docs](self).
///
/// # Errors
/// [`QuickConnectError`] with a short user-facing message.
pub fn parse(input: &str) -> Result<QuickTarget, QuickConnectError> {
    let input = input.trim();
    if input.is_empty() {
        return err("enter a host, user@host or user@host:port");
    }
    if let Some(rest) = strip_prefix_ci(input, "ssh://") {
        return parse_url(rest);
    }
    if input.contains("://") {
        return err("only ssh:// URLs are supported");
    }
    let (user, hostport) = split_user(input)?;
    let (host, port) = split_host_port(hostport)?;
    Ok(QuickTarget {
        host,
        user: user.map(str::to_owned),
        port,
    })
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

fn parse_url(rest: &str) -> Result<QuickTarget, QuickConnectError> {
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        return err("an ssh:// URL takes no path");
    }
    let (user, hostport) = split_user(authority)?;
    let user = user.map(percent_decode).transpose()?;
    if let Some(u) = &user {
        check_user(u)?;
    }
    let (host, port) = split_host_port(hostport)?;
    Ok(QuickTarget { host, user, port })
}

/// `user@rest` → (`Some(user)`, rest); more than one `@` is an error.
fn split_user(s: &str) -> Result<(Option<&str>, &str), QuickConnectError> {
    match s.matches('@').count() {
        0 => Ok((None, s)),
        1 => {
            let (user, rest) = s.split_once('@').unwrap_or((s, ""));
            if user.is_empty() {
                return err("the user name before @ is empty");
            }
            if rest.is_empty() {
                return err("the host after @ is empty");
            }
            check_user(user)?;
            Ok((Some(user), rest))
        }
        _ => err("more than one @ (write a literal @ in a user name as %40 in an ssh:// URL)"),
    }
}

fn check_user(user: &str) -> Result<(), QuickConnectError> {
    if user.is_empty() {
        return err("the user name is empty");
    }
    if user.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return err("the user name must not contain spaces");
    }
    Ok(())
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>), QuickConnectError> {
    if s.is_empty() {
        return err("the host is empty");
    }
    if let Some(inner) = s.strip_prefix('[') {
        let Some((addr, after)) = inner.split_once(']') else {
            return err("missing ] after the IPv6 address");
        };
        check_v6(addr)?;
        let port = match after {
            "" => None,
            p => match p.strip_prefix(':') {
                Some(p) => Some(parse_port(p)?),
                None => return err("unexpected text after ]"),
            },
        };
        return Ok((addr.to_owned(), port));
    }
    if s.contains(']') {
        return err("unexpected ]");
    }
    match s.matches(':').count() {
        0 => Ok((check_name(s)?, None)),
        1 => {
            let (host, port) = s.split_once(':').unwrap_or((s, ""));
            if host.is_empty() {
                return err("the host is empty");
            }
            Ok((check_name(host)?, Some(parse_port(port)?)))
        }
        // A bare IPv6 literal (no port: use brackets for one).
        _ => {
            check_v6(s)?;
            Ok((s.to_owned(), None))
        }
    }
}

fn check_name(host: &str) -> Result<String, QuickConnectError> {
    validate_address(host).map_err(|e| QuickConnectError(e.message))
}

/// An IPv6 literal, optionally with a `%zone` (interface name or index).
fn check_v6(s: &str) -> Result<(), QuickConnectError> {
    let (addr, zone) = match s.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (s, None),
    };
    if addr.parse::<Ipv6Addr>().is_err() {
        return err(format!("{s:?} is not a valid IPv6 address"));
    }
    if let Some(zone) = zone {
        let ok = !zone.is_empty()
            && zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return err("invalid IPv6 zone id");
        }
    }
    Ok(())
}

fn parse_port(p: &str) -> Result<u16, QuickConnectError> {
    if p.is_empty() {
        return err("the port after : is empty");
    }
    if !p.bytes().all(|b| b.is_ascii_digit()) {
        return err(format!("{p:?} is not a port number"));
    }
    match p.parse::<u32>() {
        Ok(n @ 1..=65_535) => Ok(u16::try_from(n).unwrap_or(u16::MAX)),
        _ => err("the port must be between 1 and 65535"),
    }
}

/// Decode `%XX` escapes (UTF-8). A bad escape or invalid UTF-8 is an error.
fn percent_decode(s: &str) -> Result<String, QuickConnectError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(b) => out.push(b),
                None => return err("invalid %-escape in the user name"),
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).or_else(|_| err("the user name is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, user: Option<&str>, port: Option<u16>) -> QuickTarget {
        QuickTarget {
            host: host.to_owned(),
            user: user.map(str::to_owned),
            port,
        }
    }

    // T-01
    #[test]
    fn t01_quick_connect_table() {
        let ok: &[(&str, QuickTarget)] = &[
            ("h", t("h", None, None)),
            ("u@h", t("h", Some("u"), None)),
            ("h:2222", t("h", None, Some(2222))),
            ("u@h:2222", t("h", Some("u"), Some(2222))),
            ("[::1]:22", t("::1", None, Some(22))),
            ("u@[fe80::1]:2200", t("fe80::1", Some("u"), Some(2200))),
            ("::1", t("::1", None, None)),
            ("fe80::1%eth0", t("fe80::1%eth0", None, None)),
            ("[fe80::1%eth0]:22", t("fe80::1%eth0", None, Some(22))),
            ("[2001:db8::5]", t("2001:db8::5", None, None)),
            ("ssh://u@h:2222", t("h", Some("u"), Some(2222))),
            ("ssh://u%40corp@h", t("h", Some("u@corp"), None)),
            ("ssh://h/", t("h", None, None)),
            ("ssh://h", t("h", None, None)),
            ("SSH://root@[::1]:2022/", t("::1", Some("root"), Some(2022))),
            (
                "  deploy@10.0.0.5:2222  ",
                t("10.0.0.5", Some("deploy"), Some(2222)),
            ),
            ("db.example.com", t("db.example.com", None, None)),
            ("h:65535", t("h", None, Some(65535))),
            ("h:1", t("h", None, Some(1))),
        ];
        for (input, want) in ok {
            assert_eq!(parse(input).as_ref(), Ok(want), "input {input:?}");
        }
        let bad = [
            "u@",
            "@h",
            "h:0",
            "h:99999",
            "h:",
            "h:22x",
            "[::1",
            "[::1]x",
            "",
            "   ",
            "user@host@x",
            "bad host",
            "ssh://h/path",
            "http://h",
            "fe80::1%",
            "[nothex::zz]:22",
            "ssh://u%4@h",
        ];
        for input in bad {
            assert!(
                parse(input).is_err(),
                "input {input:?} parsed: {:?}",
                parse(input)
            );
        }
        assert!(ok.len() + bad.len() >= 25);
    }

    #[test]
    fn display_round_trips() {
        for input in ["u@h:2222", "u@[fe80::1]:2200", "::1", "h"] {
            let target = parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(parse(&target.display()), Ok(target));
        }
    }
}
