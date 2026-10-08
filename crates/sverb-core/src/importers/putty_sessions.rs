//! M7-03: PuTTY saved sessions (SPEC §9.13).
//!
//! Sources:
//! - **Linux / macOS**: `~/.putty/sessions/*`, one file per session (the file name is
//!   the URL-encoded session name), `Key=Value` lines ([`read_dir`]);
//! - **Windows**: the registry, `HKCU\Software\SimonTatham\PuTTY\Sessions\<encoded name>`
//!   (values are `REG_SZ` or `REG_DWORD`; `registry::read_sessions`, `cfg(windows)`).
//!
//! Both yield [`Session`]s that [`plan`] maps onto the M2-11 [`ImportPlan`] (the same
//! preview, classification and confirmation as every import):
//!
//! | PuTTY | sverb |
//! |---|---|
//! | session name (URL-decoded) | `label` |
//! | `HostName` (`user@host` allowed) | `address` (+ `username`) |
//! | `PortNumber` | `port` (22 is left unset) |
//! | `UserName` | `username` (a `user@` in `HostName` wins, as in PuTTY) |
//! | `Protocol` | only `ssh`; other protocols are skipped |
//! | `PublicKeyFile` | an identity file (the `.ppk` is imported after confirmation) |
//! | `ProxyMethod` 2 / 3 + `ProxyHost`, `ProxyPort`, `ProxyUsername` | `proxy` socks5 / http |
//! | `ProxyMethod` 1 (SOCKS4), 4 (telnet), 5 (local command), 6+ (SSH) | session skipped |
//! | `ProxyPassword` | never imported (PuTTY keeps it in plain text): set it in sverb |
//! | `AgentFwd=1` | `agent_forwarding = true` |
//! | `PortForwardings` (`L8080=host:80,R…,D1080`) | port forward rules |
//! | `TerminalType` | a warning when it is not `xterm` (sverb sets `TERM` itself) |
//!
//! `Default Settings` is PuTTY's template for new sessions, not a server: it is skipped.
//! Every input is bounded ([`MAX_SESSIONS`], [`MAX_SESSION_BYTES`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
    Draft, ForwardDraft, HostDraft, ImportError, ImportPlan, ImportSource, PlanRef, PlannedItem,
    ProxyDraft, ProxyDraftKind, Skipped, preview::fill_fields,
};
use crate::model::{DEFAULT_BIND_ADDR, ForwardKind, ItemKind, validate::validate_address};

/// Sessions read at most.
pub const MAX_SESSIONS: usize = 4096;
/// Bytes of one session file read at most.
pub const MAX_SESSION_BYTES: u64 = 256 * 1024;
/// Port forwarding entries of one session read at most.
pub const MAX_FORWARDS: usize = 256;

/// The name of PuTTY's template session.
pub const DEFAULT_SETTINGS: &str = "Default Settings";

/// One saved PuTTY session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// The decoded session name.
    pub name: String,
    /// Where it was read (`sessions/<file>` or the registry key), for the preview.
    pub source: String,
    /// The settings (`HostName`, `PortNumber`, …), as strings.
    pub values: BTreeMap<String, String>,
}

impl Session {
    fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    }
}

/// `~/.putty/sessions` (`None` without a home directory).
pub fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".putty").join("sessions"))
}

/// Decodes PuTTY's session name escaping (`%20` → space, any `%XX`); invalid escapes
/// are kept as they are.
pub fn decode_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = name.get(i + 1..i + 3)
            && let Ok(b) = u8::from_str_radix(hex, 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses a session file: `Key=Value` lines (the value is everything after the first
/// `=`, kept as written).
pub fn parse_session_file(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.trim_end_matches('\r').split_once('=')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (k.to_owned(), v.to_owned()))
        })
        .collect()
}

/// Reads every session file of `dir` (sorted by name). Unreadable or oversized files
/// become warnings in the plan made from them (see [`parse_dir`]).
///
/// # Errors
/// [`ImportError::Read`] when the directory can't be listed.
pub fn read_dir(dir: &Path) -> Result<(Vec<Session>, Vec<String>), ImportError> {
    let read_err = |e: std::io::Error| ImportError::Read {
        path: dir.display().to_string(),
        message: e.to_string(),
    };
    let mut names: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(read_err)? {
        let entry = entry.map_err(read_err)?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        names.push((name, entry.path()));
        if names.len() > MAX_SESSIONS {
            return Err(ImportError::Format(format!(
                "more than {MAX_SESSIONS} PuTTY sessions in {}",
                dir.display()
            )));
        }
    }
    names.sort();
    let mut sessions = Vec::new();
    let mut warnings = Vec::new();
    for (name, path) in names {
        let source = format!("sessions/{name}");
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => continue,
            Err(e) => {
                warnings.push(format!("{source}: cannot read: {e}"));
                continue;
            }
        };
        if meta.len() > MAX_SESSION_BYTES {
            warnings.push(format!("{source}: too large, ignored"));
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => sessions.push(Session {
                name: decode_name(&name),
                source,
                values: parse_session_file(&String::from_utf8_lossy(&bytes)),
            }),
            Err(e) => warnings.push(format!("{source}: cannot read: {e}")),
        }
    }
    Ok((sessions, warnings))
}

/// [`read_dir`] then [`plan`].
///
/// # Errors
/// As [`read_dir`].
pub fn parse_dir(dir: &Path) -> Result<ImportPlan, ImportError> {
    let (sessions, warnings) = read_dir(dir)?;
    let mut p = plan(&sessions);
    p.warnings.splice(0..0, warnings);
    Ok(p)
}

/// The sessions of the current user: the registry on Windows, else
/// `~/.putty/sessions`.
///
/// # Errors
/// As [`read_dir`] / `registry::read_sessions`; no home directory.
pub fn parse_user() -> Result<ImportPlan, ImportError> {
    #[cfg(windows)]
    {
        let sessions = registry::read_sessions(registry::SESSIONS_KEY)?;
        Ok(plan(&sessions))
    }
    #[cfg(not(windows))]
    {
        let dir = default_dir()
            .ok_or_else(|| ImportError::Format("no home directory to find ~/.putty".to_owned()))?;
        parse_dir(&dir)
    }
}

/// `host:port`, bracketing IPv6 literals.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn port_of(s: Option<&str>) -> Option<u16> {
    s.and_then(|p| p.parse::<u16>().ok()).filter(|p| *p > 0)
}

/// Splits `[v6]:port`, `host:port` or a bare `port` (`host` `None`).
fn split_endpoint(s: &str) -> Option<(Option<String>, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((Some(h.to_owned()), port_of(Some(p))?));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Some((Some(h.to_owned()), port_of(Some(p))?)),
        Some(_) => None,
        None => Some((None, port_of(Some(s))?)),
    }
}

/// A parsed `PortForwardings` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// L / R / D.
    pub kind: ForwardKind,
    /// The bind address, when given.
    pub bind_addr: Option<String>,
    /// The bind port.
    pub bind_port: u16,
    /// `host:port` (L / R).
    pub dest: Option<(String, u16)>,
}

/// Parses one `PortForwardings` entry: an optional address family (`4` / `6`), `L` /
/// `R` / `D`, `[bind:]port`, then `=host:port` (L / R; a `D` may carry `=` and nothing).
///
/// # Errors
/// A reason for the skipped entry.
pub fn parse_forward(entry: &str) -> Result<ForwardSpec, String> {
    let e = entry.trim();
    let e = e.strip_prefix(['4', '6']).unwrap_or(e);
    let mut chars = e.chars();
    let kind = match chars.next() {
        Some('L') => ForwardKind::Local,
        Some('R') => ForwardKind::Remote,
        Some('D') => ForwardKind::Dynamic,
        _ => return Err(format!("unknown forward {entry:?}")),
    };
    let rest = chars.as_str();
    let (bind, dest) = match rest.split_once('=') {
        Some((b, d)) => (b, Some(d.trim()).filter(|d| !d.is_empty())),
        None => (rest, None),
    };
    let (bind_addr, bind_port) =
        split_endpoint(bind).ok_or_else(|| format!("bad listen port in {entry:?}"))?;
    let dest = match (kind, dest) {
        (ForwardKind::Dynamic, _) => None,
        (_, None) => return Err(format!("no destination in {entry:?}")),
        (_, Some(d)) => match split_endpoint(d) {
            Some((Some(h), p)) => Some((h, p)),
            _ => return Err(format!("bad destination in {entry:?}")),
        },
    };
    Ok(ForwardSpec {
        kind,
        bind_addr,
        bind_port,
        dest,
    })
}

/// Why a session is not imported (`None`: it is).
fn skip_reason(s: &Session) -> Option<String> {
    if s.name == DEFAULT_SETTINGS {
        return Some(
            "PuTTY's Default Settings are a template for new sessions, not a host".to_owned(),
        );
    }
    let protocol = s.get("Protocol").unwrap_or("ssh");
    if !protocol.eq_ignore_ascii_case("ssh") {
        return Some(format!("non-SSH protocol not supported ({protocol})"));
    }
    match s.get("ProxyMethod").unwrap_or("0") {
        "0" | "2" | "3" => None,
        "1" => Some("SOCKS4 proxy not supported (use SOCKS5)".to_owned()),
        "4" => Some("telnet proxy (ProxyTelnetCommand) not supported".to_owned()),
        "5" => Some("local proxy command not supported (add it as a ProxyCommand)".to_owned()),
        "6" | "7" | "8" => {
            Some("SSH proxy not imported (add the proxy host as a jump host)".to_owned())
        }
        other => Some(format!("unknown ProxyMethod {other}")),
    }
}

/// Maps sessions onto a plan (all items `New`): hosts first, then their forwards.
pub fn plan(sessions: &[Session]) -> ImportPlan {
    let mut plan = ImportPlan::new(ImportSource::Putty);
    let mut hosts: Vec<(PlannedItem, Vec<(ForwardSpec, String)>)> = Vec::new();
    let mut proxy_passwords = Vec::new();
    for s in sessions.iter().take(MAX_SESSIONS) {
        let at = Some(s.source.clone());
        if let Some(reason) = skip_reason(s) {
            plan.skipped
                .push(Skipped::new(at, format!("{}: {reason}", s.name)));
            continue;
        }
        let Some(raw_host) = s.get("HostName") else {
            plan.skipped
                .push(Skipped::new(at, format!("{}: no HostName", s.name)));
            continue;
        };
        let (host_user, host) = match raw_host.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_owned()).filter(|u| !u.is_empty()), h),
            None => (None, raw_host),
        };
        let address = match validate_address(host) {
            Ok(a) => a,
            Err(e) => {
                plan.skipped.push(Skipped::new(
                    at,
                    format!("{}: invalid HostName {raw_host:?}: {}", s.name, e.message),
                ));
                continue;
            }
        };
        let port = match s.get("PortNumber") {
            None => None,
            Some(p) => match port_of(Some(p)) {
                Some(22) => None,
                Some(p) => Some(p),
                None => {
                    plan.skipped.push(Skipped::new(
                        at,
                        format!("{}: invalid PortNumber {p:?}", s.name),
                    ));
                    continue;
                }
            },
        };
        let username = host_user.or_else(|| s.get("UserName").map(str::to_owned));
        let proxy = match s.get("ProxyMethod") {
            Some(m @ ("2" | "3")) => {
                let kind = if m == "2" {
                    ProxyDraftKind::Socks5
                } else {
                    ProxyDraftKind::Http
                };
                let Some(phost) = s.get("ProxyHost") else {
                    plan.skipped.push(Skipped::new(
                        at,
                        format!("{}: proxy without a ProxyHost", s.name),
                    ));
                    continue;
                };
                let default_port = if kind == ProxyDraftKind::Socks5 {
                    1080
                } else {
                    80
                };
                let Some(pport) = s
                    .get("ProxyPort")
                    .map_or(Some(default_port), |p| port_of(Some(p)))
                else {
                    plan.skipped
                        .push(Skipped::new(at, format!("{}: invalid ProxyPort", s.name)));
                    continue;
                };
                if s.get("ProxyPassword").is_some() {
                    proxy_passwords.push(s.name.clone());
                }
                Some(ProxyDraft {
                    kind,
                    addr: host_port(phost, pport),
                    user: s.get("ProxyUsername").map(str::to_owned),
                })
            }
            _ => None,
        };
        if let Some(term) = s.get("TerminalType")
            && term != "xterm"
        {
            plan.warnings.push(format!(
                "{}: TerminalType {term:?} is not imported (sverb sets TERM itself)",
                s.name
            ));
        }
        let mut forwards = Vec::new();
        if let Some(list) = s.get("PortForwardings") {
            for entry in list
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .take(MAX_FORWARDS)
            {
                match parse_forward(entry) {
                    Ok(spec) => forwards.push((spec, s.source.clone())),
                    Err(why) => plan
                        .skipped
                        .push(Skipped::new(at.clone(), format!("{}: {why}", s.name))),
                }
            }
        }
        let draft = HostDraft {
            label: s.name.clone(),
            address,
            port,
            username,
            identity_files: s
                .get("PublicKeyFile")
                .map(|k| vec![k.to_owned()])
                .unwrap_or_default(),
            proxy,
            agent_forwarding: (s.get("AgentFwd") == Some("1")).then_some(true),
            ..HostDraft::default()
        };
        let mut item =
            PlannedItem::new(ItemKind::Host, s.name.clone(), Draft::Host(Box::new(draft)));
        item.source_line = at;
        hosts.push((item, forwards));
    }
    if !proxy_passwords.is_empty() {
        plan.notes.push(format!(
            "proxy passwords are not imported (PuTTY stores them in plain text); set them in sverb after the import: {}",
            proxy_passwords.join(", ")
        ));
    }

    let mut all_forwards = Vec::new();
    for (item, forwards) in hosts {
        all_forwards.push((item.label.clone(), forwards));
        plan.push(item);
    }
    for (host_ref, (alias, forwards)) in all_forwards.into_iter().enumerate() {
        let mut refs: Vec<PlanRef> = Vec::new();
        for (spec, at) in forwards {
            let letter = match spec.kind {
                ForwardKind::Local => 'L',
                ForwardKind::Remote => 'R',
                ForwardKind::Dynamic => 'D',
            };
            let label = format!("{alias} {letter}{}", spec.bind_port);
            let (dest_host, dest_port) = match spec.dest {
                Some((h, p)) => (Some(h), Some(p)),
                None => (None, None),
            };
            let draft = ForwardDraft {
                label: label.clone(),
                kind: spec.kind,
                host: host_ref,
                bind_addr: spec
                    .bind_addr
                    .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_owned()),
                bind_port: spec.bind_port,
                dest_host,
                dest_port,
            };
            let mut item = PlannedItem::new(ItemKind::PortForward, label, Draft::Forward(draft));
            item.source_line = Some(at);
            refs.push(plan.push(item));
        }
        if let Some(Draft::Host(h)) = plan.items.get_mut(host_ref).map(|i| &mut i.draft) {
            h.forwards = refs;
        }
    }
    fill_fields(&mut plan);
    plan
}

/// PuTTY sessions in the Windows registry.
#[cfg(windows)]
pub mod registry {
    use winreg::{
        RegKey,
        enums::{HKEY_CURRENT_USER, REG_DWORD, REG_EXPAND_SZ, REG_SZ},
        types::FromRegValue as _,
    };

    use super::{MAX_SESSIONS, Session, decode_name};
    use crate::importers::ImportError;

    /// Where PuTTY keeps its sessions under `HKEY_CURRENT_USER`.
    pub const SESSIONS_KEY: &str = r"Software\SimonTatham\PuTTY\Sessions";

    /// Reads every session under `HKCU\<root>` (tests inject their own root).
    ///
    /// # Errors
    /// [`ImportError::Read`] when the key can't be opened.
    pub fn read_sessions(root: &str) -> Result<Vec<Session>, ImportError> {
        let read_err = |e: std::io::Error| ImportError::Read {
            path: format!(r"HKCU\{root}"),
            message: e.to_string(),
        };
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let sessions_key = hkcu.open_subkey(root).map_err(read_err)?;
        let mut names: Vec<String> = sessions_key
            .enum_keys()
            .filter_map(Result::ok)
            .take(MAX_SESSIONS + 1)
            .collect();
        if names.len() > MAX_SESSIONS {
            return Err(ImportError::Format(format!(
                "more than {MAX_SESSIONS} PuTTY sessions in the registry"
            )));
        }
        names.sort();
        let mut out = Vec::new();
        for raw in names {
            let Ok(key) = sessions_key.open_subkey(&raw) else {
                continue;
            };
            let mut values = std::collections::BTreeMap::new();
            for (name, value) in key.enum_values().filter_map(Result::ok).take(4096) {
                let text = match value.vtype {
                    REG_DWORD => u32::from_reg_value(&value).ok().map(|n| n.to_string()),
                    REG_SZ | REG_EXPAND_SZ => String::from_reg_value(&value).ok(),
                    _ => None,
                };
                if let Some(t) = text {
                    values.insert(name, t);
                }
            }
            out.push(Session {
                name: decode_name(&raw),
                source: format!(r"HKCU\{root}\{raw}"),
                values,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "putty_tests.rs"]
mod tests;
