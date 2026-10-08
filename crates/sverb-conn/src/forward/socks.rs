//! The SOCKS wire format (RFC 1928 for SOCKS5, plus SOCKS4/4a), **pure**: no I/O, no
//! allocation beyond the parsed values, and no panics on any input. This is the fuzz
//! target (`fuzz/fuzz_targets/socks5_request.rs` calls [`fuzz_socks_request`]).
//!
//! The server side that drives these parsers over a stream is
//! `forward::socks_server`.
//!
//! Parsers take the bytes received so far and return:
//! - `Ok(Some((value, consumed)))`: a complete message of `consumed` bytes,
//! - `Ok(None)`: incomplete, read more,
//! - `Err(_)`: malformed; the server replies (when the error says how) and closes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SOCKS version 5.
pub const VER5: u8 = 0x05;
/// SOCKS version 4 (and 4a).
pub const VER4: u8 = 0x04;
/// Auth method "no authentication required".
pub const METHOD_NO_AUTH: u8 = 0x00;
/// "No acceptable methods".
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
/// The longest domain name accepted (the SOCKS5 length byte's limit; also applied to
/// SOCKS4a and to the SOCKS4 user id).
pub const MAX_NAME: usize = 255;

/// SOCKS5 reply codes (RFC 1928 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    /// `0x00` succeeded.
    Succeeded = 0x00,
    /// `0x01` general SOCKS server failure (also: the rule is at its channel cap).
    GeneralFailure = 0x01,
    /// `0x02` connection not allowed by ruleset (`administratively prohibited`).
    NotAllowed = 0x02,
    /// `0x03` network unreachable.
    NetworkUnreachable = 0x03,
    /// `0x04` host unreachable.
    HostUnreachable = 0x04,
    /// `0x05` connection refused (`connect failed`).
    ConnectionRefused = 0x05,
    /// `0x06` TTL expired.
    TtlExpired = 0x06,
    /// `0x07` command not supported (BIND, UDP ASSOCIATE).
    CommandNotSupported = 0x07,
    /// `0x08` address type not supported.
    AddressTypeNotSupported = 0x08,
}

/// SOCKS4 "request granted".
pub const REPLY4_GRANTED: u8 = 0x5A;
/// SOCKS4 "request rejected or failed".
pub const REPLY4_REJECTED: u8 = 0x5B;

/// A request command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0x01` CONNECT, the only supported one.
    Connect,
    /// `0x02` BIND.
    Bind,
    /// `0x03` UDP ASSOCIATE (SOCKS5 only).
    UdpAssociate,
    /// Anything else.
    Other(u8),
}

impl Command {
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Connect,
            0x02 => Self::Bind,
            0x03 => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

/// Where the client wants to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An IPv4 or IPv6 literal.
    Ip(IpAddr),
    /// A domain name, passed **unresolved** to the remote side (no local DNS).
    Domain(String),
}

impl Target {
    /// The host string for `direct-tcpip` (IPs in their canonical text form).
    pub fn host(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Domain(name) => name.clone(),
        }
    }
}

/// A parsed CONNECT/BIND/… request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The command.
    pub command: Command,
    /// Destination host.
    pub target: Target,
    /// Destination port.
    pub port: u16,
}

/// The first message from a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// SOCKS5 method negotiation, with the offered methods.
    V5 {
        /// Offered auth methods.
        methods: Vec<u8>,
    },
    /// A complete SOCKS4/4a request (SOCKS4 has no negotiation).
    V4(Request),
}

/// A malformed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Not SOCKS4 or SOCKS5 (or the version changed mid-handshake).
    #[error("unsupported SOCKS version {0:#04x}")]
    Version(u8),
    /// SOCKS5 method negotiation listed no methods.
    #[error("no authentication methods offered")]
    NoMethods,
    /// Reserved byte not zero.
    #[error("reserved byte not zero")]
    Reserved,
    /// Unknown SOCKS5 address type: reply [`Reply::AddressTypeNotSupported`].
    #[error("address type {0:#04x} not supported")]
    AddressType(u8),
    /// Empty, too long or non-UTF-8 domain name, or user id too long.
    #[error("invalid domain name")]
    BadName,
}

impl ParseError {
    /// The SOCKS5 reply owed for this error, if one is sent before closing.
    pub fn reply5(self) -> Option<Reply> {
        match self {
            Self::AddressType(_) => Some(Reply::AddressTypeNotSupported),
            Self::Reserved | Self::BadName => Some(Reply::GeneralFailure),
            Self::Version(_) | Self::NoMethods => None,
        }
    }
}

/// A parse step's result (see the module docs).
pub type Parsed<T> = Result<Option<(T, usize)>, ParseError>;

/// Parse the first message: SOCKS5 method negotiation or a SOCKS4/4a request.
///
/// # Errors
/// Unknown version or a malformed SOCKS4 request.
pub fn parse_hello(buf: &[u8]) -> Parsed<Hello> {
    let Some(&ver) = buf.first() else {
        return Ok(None);
    };
    match ver {
        VER5 => {
            let Some(&n) = buf.get(1) else {
                return Ok(None);
            };
            if n == 0 {
                return Err(ParseError::NoMethods);
            }
            let end = 2 + usize::from(n);
            match buf.get(2..end) {
                Some(methods) => Ok(Some((
                    Hello::V5 {
                        methods: methods.to_vec(),
                    },
                    end,
                ))),
                None => Ok(None),
            }
        }
        VER4 => Ok(parse_v4(buf)?.map(|(r, n)| (Hello::V4(r), n))),
        other => Err(ParseError::Version(other)),
    }
}

/// Position of the NUL terminating a string starting at `from`, at most
/// [`MAX_NAME`] bytes long. `Ok(None)`: incomplete.
fn nul_terminated(buf: &[u8], from: usize) -> Result<Option<usize>, ParseError> {
    let rest = buf.get(from..).unwrap_or_default();
    match rest.iter().position(|&b| b == 0) {
        Some(len) if len > MAX_NAME => Err(ParseError::BadName),
        Some(len) => Ok(Some(from + len)),
        None if rest.len() > MAX_NAME => Err(ParseError::BadName),
        None => Ok(None),
    }
}

fn domain(bytes: &[u8]) -> Result<String, ParseError> {
    if bytes.is_empty() || bytes.len() > MAX_NAME {
        return Err(ParseError::BadName);
    }
    let name = std::str::from_utf8(bytes).map_err(|_| ParseError::BadName)?;
    if name.chars().any(char::is_control) {
        return Err(ParseError::BadName);
    }
    Ok(name.to_owned())
}

/// SOCKS4: `VN=4 CD DSTPORT(2) DSTIP(4) USERID… NUL`, and for 4a with
/// `DSTIP = 0.0.0.x (x ≠ 0)`: `… DOMAIN… NUL` (resolved remotely).
fn parse_v4(buf: &[u8]) -> Parsed<Request> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let command = Command::from_byte(buf[1]);
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    let Some(user_end) = nul_terminated(buf, 8)? else {
        return Ok(None);
    };
    let o = ip.octets();
    let socks4a = o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] != 0;
    if !socks4a {
        let req = Request {
            command,
            target: Target::Ip(IpAddr::V4(ip)),
            port,
        };
        return Ok(Some((req, user_end + 1)));
    }
    let Some(name_end) = nul_terminated(buf, user_end + 1)? else {
        return Ok(None);
    };
    let name = domain(&buf[user_end + 1..name_end])?;
    let req = Request {
        command,
        target: Target::Domain(name),
        port,
    };
    Ok(Some((req, name_end + 1)))
}

/// Parse a SOCKS5 request: `VER=5 CMD RSV=0 ATYP DST.ADDR DST.PORT`.
///
/// # Errors
/// Wrong version, non-zero reserved byte, unknown address type (reply `0x08`) or a
/// bad domain name.
pub fn parse_request5(buf: &[u8]) -> Parsed<Request> {
    if buf.len() < 4 {
        return Ok(None);
    }
    if buf[0] != VER5 {
        return Err(ParseError::Version(buf[0]));
    }
    let command = Command::from_byte(buf[1]);
    if buf[2] != 0 {
        return Err(ParseError::Reserved);
    }
    let (target, addr_end) = match buf[3] {
        0x01 => {
            let Some(b) = buf.get(4..8) else {
                return Ok(None);
            };
            (
                Target::Ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
                8,
            )
        }
        0x03 => {
            let Some(&len) = buf.get(4) else {
                return Ok(None);
            };
            let end = 5 + usize::from(len);
            let Some(name) = buf.get(5..end) else {
                return Ok(None);
            };
            (Target::Domain(domain(name)?), end)
        }
        0x04 => {
            let Some(b) = buf.get(4..20) else {
                return Ok(None);
            };
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(b);
            (Target::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 20)
        }
        other => return Err(ParseError::AddressType(other)),
    };
    let Some(p) = buf.get(addr_end..addr_end + 2) else {
        return Ok(None);
    };
    let port = u16::from_be_bytes([p[0], p[1]]);
    Ok(Some((
        Request {
            command,
            target,
            port,
        },
        addr_end + 2,
    )))
}

/// The method-selection reply: no-auth if offered, else `05 FF`.
pub fn select_method(methods: &[u8]) -> [u8; 2] {
    if methods.contains(&METHOD_NO_AUTH) {
        [VER5, METHOD_NO_AUTH]
    } else {
        [VER5, METHOD_NONE_ACCEPTABLE]
    }
}

/// A SOCKS5 reply with `BND.ADDR = 0.0.0.0:0` (as OpenSSH sends).
pub fn reply5(code: Reply) -> [u8; 10] {
    [VER5, code as u8, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// A SOCKS4 reply (`0x5A` granted / `0x5B` rejected), `DSTPORT`/`DSTIP` zero.
pub fn reply4(granted: bool) -> [u8; 8] {
    let code = if granted {
        REPLY4_GRANTED
    } else {
        REPLY4_REJECTED
    };
    [0x00, code, 0, 0, 0, 0, 0, 0]
}

/// Fuzz entry point (T-20): run every parser over `data` at every split point. Must
/// never panic.
pub fn fuzz_socks_request(data: &[u8]) {
    let _ = parse_hello(data);
    let _ = parse_request5(data);
    if let Ok(Some((Hello::V5 { methods }, n))) = parse_hello(data) {
        let _ = select_method(&methods);
        if let Ok(Some((req, _))) = parse_request5(data.get(n..).unwrap_or_default()) {
            let _ = req.target.host();
        }
    }
    for cut in 0..data.len().min(64) {
        let _ = parse_hello(&data[..cut]);
        let _ = parse_request5(&data[..cut]);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn hello_v5_incomplete_then_complete() {
        assert_eq!(parse_hello(&[]), Ok(None));
        assert_eq!(parse_hello(&[5]), Ok(None));
        assert_eq!(parse_hello(&[5, 2, 0]), Ok(None));
        assert_eq!(
            parse_hello(&[5, 2, 0, 2, 9]),
            Ok(Some((
                Hello::V5 {
                    methods: vec![0, 2]
                },
                4
            )))
        );
        assert_eq!(parse_hello(&[5, 0]), Err(ParseError::NoMethods));
        assert_eq!(parse_hello(&[0x47, 0x45]), Err(ParseError::Version(0x47)));
    }

    #[test]
    fn method_selection() {
        assert_eq!(select_method(&[2, 0]), [5, 0]);
        assert_eq!(select_method(&[2]), [5, 0xFF]);
    }

    #[test]
    fn request5_address_types() {
        let v4 = [5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        let (r, n) = parse_request5(&v4).unwrap().unwrap();
        assert_eq!(n, 10);
        assert_eq!(r.target.host(), "1.2.3.4");
        assert_eq!(r.port, 80);
        let mut dom = vec![5, 1, 0, 3, 11];
        dom.extend_from_slice(b"example.com");
        dom.extend_from_slice(&443_u16.to_be_bytes());
        let (r, _) = parse_request5(&dom).unwrap().unwrap();
        assert_eq!(r.target, Target::Domain("example.com".into()));
        assert_eq!(parse_request5(&dom[..dom.len() - 1]), Ok(None));
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 22]);
        let (r, _) = parse_request5(&v6).unwrap().unwrap();
        assert_eq!(r.target.host(), "::1");
        assert_eq!(
            parse_request5(&[5, 1, 0, 9, 0]),
            Err(ParseError::AddressType(9))
        );
        assert_eq!(
            parse_request5(&[5, 1, 0, 3, 0, 0, 80]),
            Err(ParseError::BadName)
        );
    }

    #[test]
    fn socks4_and_4a() {
        let mut v4 = vec![4, 1, 0, 80, 10, 0, 0, 1];
        v4.extend_from_slice(b"me\0");
        let (h, n) = parse_hello(&v4).unwrap().unwrap();
        assert_eq!(n, v4.len());
        assert_eq!(
            h,
            Hello::V4(Request {
                command: Command::Connect,
                target: Target::Ip("10.0.0.1".parse().unwrap()),
                port: 80
            })
        );
        let mut v4a = vec![4, 1, 1, 187, 0, 0, 0, 7, 0];
        assert_eq!(parse_hello(&v4a), Ok(None));
        v4a.extend_from_slice(b"db.internal\0");
        let (h, _) = parse_hello(&v4a).unwrap().unwrap();
        let Hello::V4(r) = h else { panic!() };
        assert_eq!(r.target, Target::Domain("db.internal".into()));
        assert_eq!(r.port, 443);
        // An endless user id is cut off.
        let mut long = vec![4, 1, 0, 80, 1, 1, 1, 1];
        long.extend(std::iter::repeat_n(b'a', 300));
        assert_eq!(parse_hello(&long), Err(ParseError::BadName));
    }

    #[test]
    fn replies() {
        assert_eq!(reply5(Reply::Succeeded), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply4(true)[1], 0x5A);
        assert_eq!(reply4(false)[1], 0x5B);
    }

    /// T-20 (body): arbitrary input never panics.
    #[test]
    fn fuzz_body_never_panics() {
        let mut seed: u32 = 0x1234_5678;
        for len in 0..300 {
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                data.push(seed.to_le_bytes()[0]);
            }
            for first in [4_u8, 5] {
                if let Some(b) = data.first_mut() {
                    *b = first;
                }
                fuzz_socks_request(&data);
            }
        }
    }
}
