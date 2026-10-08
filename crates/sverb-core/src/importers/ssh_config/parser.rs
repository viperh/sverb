//! Lines → `Host` / `Match` blocks with typed settings.
//!
//! - Lines before the first `Host` / `Match` form the global block (they apply to every
//!   host, like `Host *`).
//! - `Match` blocks are skipped with a reason (their settings are ignored).
//! - The supported keywords (§9.13) are parsed into [`Setting`]s; a value that cannot
//!   be read is skipped with its line and a reason. Every other keyword is counted in
//!   [`Parsed::unsupported`] (reported once per keyword, not per line).

use std::collections::BTreeMap;

use super::include::SourcedLine;
use crate::importers::Skipped;
use crate::model::ForwardKind;

/// A `Host` pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// `!pattern`
    pub negated: bool,
    /// The glob (`*`, `?`), lowercased.
    pub glob: String,
}

impl Pattern {
    fn parse(s: &str) -> Self {
        match s.strip_prefix('!') {
            Some(rest) => Self {
                negated: true,
                glob: rest.to_ascii_lowercase(),
            },
            None => Self {
                negated: false,
                glob: s.to_ascii_lowercase(),
            },
        }
    }

    /// Contains `*` or `?`.
    pub fn is_wildcard(&self) -> bool {
        self.glob.contains(['*', '?'])
    }

    /// A concrete alias: not negated, no wildcard.
    pub fn is_concrete(&self) -> bool {
        !self.negated && !self.is_wildcard()
    }
}

/// ssh's `match_pattern`: `*` and `?` globbing, case-insensitive.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// ssh's `match_pattern_list`: a negated match wins, then any positive match.
pub fn patterns_match(patterns: &[Pattern], host: &str) -> bool {
    let mut matched = false;
    for p in patterns {
        if glob_match(&p.glob, host) {
            if p.negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// A forward as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Local, remote or dynamic.
    pub kind: ForwardKind,
    /// The listen address (`None`: the default).
    pub bind_addr: Option<String>,
    /// The listen port.
    pub bind_port: u16,
    /// The destination (`None` for dynamic).
    pub dest: Option<(String, u16)>,
}

/// One parsed setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// `HostName` (tokens not expanded).
    HostName(String),
    /// `User`
    User(String),
    /// `Port`
    Port(u16),
    /// `IdentityFile` (`none` is kept and means no file).
    IdentityFile(String),
    /// `ProxyJump` hops (`none`: empty).
    ProxyJump(Vec<String>),
    /// `ProxyCommand` (`none`: empty).
    ProxyCommand(String),
    /// `LocalForward` / `RemoteForward` / `DynamicForward`
    Forward(ForwardSpec),
    /// `ForwardAgent`
    ForwardAgent(bool),
    /// `SetEnv NAME=value` (one per variable)
    SetEnv(String, String),
    /// `ServerAliveInterval`
    ServerAliveInterval(u32),
}

/// A setting and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `file:line`
    pub at: String,
    /// The value.
    pub setting: Setting,
}

/// What a block applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockKind {
    /// Lines before the first `Host` / `Match`.
    Global,
    /// `Host pattern…`
    Host(Vec<Pattern>),
    /// `Match …` (skipped).
    Match,
}

/// A block of settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Global, Host or Match.
    pub kind: BlockKind,
    /// `file:line` of the `Host` line (empty for the global block).
    pub at: String,
    /// The `Host` patterns as written.
    pub raw: String,
    /// Settings in order.
    pub entries: Vec<Entry>,
}

impl Block {
    /// Whether this block applies to `alias`.
    pub fn applies_to(&self, alias: &str) -> bool {
        match &self.kind {
            BlockKind::Global => true,
            BlockKind::Host(p) => patterns_match(p, alias),
            BlockKind::Match => false,
        }
    }
}

/// The parsed configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Blocks in file order (the global block first, when it has entries).
    pub blocks: Vec<Block>,
    /// Unsupported keyword (as first written) → occurrences.
    pub unsupported: BTreeMap<String, (String, usize)>,
    /// Entries that could not be read, and skipped `Match` blocks.
    pub skipped: Vec<Skipped>,
}

/// Parses flattened lines into blocks.
pub fn parse(lines: &[SourcedLine]) -> Parsed {
    let mut out = Parsed::default();
    let mut current = Block {
        kind: BlockKind::Global,
        at: String::new(),
        raw: String::new(),
        entries: Vec::new(),
    };
    let push = |out: &mut Parsed, b: Block| {
        if !(b.kind == BlockKind::Global && b.entries.is_empty()) {
            out.blocks.push(b);
        }
    };
    for SourcedLine { at, line } in lines {
        match line.keyword.as_str() {
            "host" => {
                let prev = std::mem::replace(
                    &mut current,
                    Block {
                        kind: BlockKind::Host(
                            line.args.iter().map(|a| Pattern::parse(a)).collect(),
                        ),
                        at: at.clone(),
                        raw: line.args.join(" "),
                        entries: Vec::new(),
                    },
                );
                push(&mut out, prev);
                if line.args.is_empty() {
                    out.skipped
                        .push(Skipped::new(Some(at.clone()), "Host without a pattern"));
                }
            }
            "match" => {
                let prev = std::mem::replace(
                    &mut current,
                    Block {
                        kind: BlockKind::Match,
                        at: at.clone(),
                        raw: line.args.join(" "),
                        entries: Vec::new(),
                    },
                );
                push(&mut out, prev);
                out.skipped.push(Skipped::new(
                    Some(at.clone()),
                    format!(
                        "Match {} is not supported; its settings are skipped",
                        line.args.join(" ")
                    ),
                ));
            }
            kw => {
                if current.kind == BlockKind::Match {
                    continue;
                }
                match parse_setting(kw, &line.args) {
                    Some(Ok(settings)) => {
                        for setting in settings {
                            current.entries.push(Entry {
                                at: at.clone(),
                                setting,
                            });
                        }
                    }
                    Some(Err(reason)) => out.skipped.push(Skipped::new(
                        Some(at.clone()),
                        format!("{}: {reason}", line.raw_keyword),
                    )),
                    None => {
                        out.unsupported
                            .entry(kw.to_owned())
                            .or_insert_with(|| (line.raw_keyword.clone(), 0))
                            .1 += 1;
                    }
                }
            }
        }
    }
    push(&mut out, current);
    out
}

fn one_arg(args: &[String]) -> Result<&str, String> {
    match args {
        [a] => Ok(a),
        [] => Err("missing value".to_owned()),
        _ => Err("expected one value".to_owned()),
    }
}

fn yes_no(s: &str) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        other => Err(format!("{other:?} is not yes or no")),
    }
}

/// Parses a supported keyword (`None`: unsupported).
fn parse_setting(kw: &str, args: &[String]) -> Option<Result<Vec<Setting>, String>> {
    let r = match kw {
        "hostname" => one_arg(args).map(|a| vec![Setting::HostName(a.to_owned())]),
        "user" => one_arg(args).map(|a| vec![Setting::User(a.to_owned())]),
        "port" => one_arg(args).and_then(|a| match a.parse::<u16>() {
            Ok(p) if p > 0 => Ok(vec![Setting::Port(p)]),
            _ => Err(format!("invalid port {a:?}")),
        }),
        "identityfile" => one_arg(args).map(|a| vec![Setting::IdentityFile(a.to_owned())]),
        "proxyjump" => one_arg(args).map(|a| {
            let hops = if a.eq_ignore_ascii_case("none") {
                Vec::new()
            } else {
                a.split(',').map(|h| h.trim().to_owned()).collect()
            };
            vec![Setting::ProxyJump(hops)]
        }),
        "proxycommand" => {
            if args.is_empty() {
                Err("missing value".to_owned())
            } else if args.len() == 1 && args[0].eq_ignore_ascii_case("none") {
                Ok(vec![Setting::ProxyCommand(String::new())])
            } else {
                Ok(vec![Setting::ProxyCommand(args.join(" "))])
            }
        }
        "localforward" => forward(ForwardKind::Local, args).map(|f| vec![Setting::Forward(f)]),
        "remoteforward" => forward(ForwardKind::Remote, args).map(|f| vec![Setting::Forward(f)]),
        "dynamicforward" => forward(ForwardKind::Dynamic, args).map(|f| vec![Setting::Forward(f)]),
        "forwardagent" => one_arg(args).and_then(|a| {
            // A socket path or $ENV means "forward that agent": yes.
            if a.starts_with('/') || a.starts_with('$') || a.starts_with('~') {
                Ok(vec![Setting::ForwardAgent(true)])
            } else {
                yes_no(a).map(|b| vec![Setting::ForwardAgent(b)])
            }
        }),
        "setenv" => {
            if args.is_empty() {
                Err("missing value".to_owned())
            } else {
                args.iter()
                    .map(|a| match a.split_once('=') {
                        Some((k, v)) if !k.is_empty() => {
                            Ok(Setting::SetEnv(k.to_owned(), v.to_owned()))
                        }
                        _ => Err(format!("{a:?} is not NAME=value")),
                    })
                    .collect()
            }
        }
        "serveraliveinterval" => one_arg(args).and_then(|a| {
            a.parse::<u32>()
                .map(|s| vec![Setting::ServerAliveInterval(s)])
                .map_err(|_| format!("invalid interval {a:?}"))
        }),
        _ => return None,
    };
    Some(r)
}

/// `[bind:]port` → (bind, port). IPv6 binds are written `[::1]:port` or `::1/port`.
fn listen(spec: &str) -> Result<(Option<String>, u16), String> {
    let (bind, port) = split_host_port(spec).ok_or_else(|| format!("invalid listen {spec:?}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid port in {spec:?}"))?;
    let bind = bind.map(|b| {
        if b == "*" || b.is_empty() {
            "0.0.0.0".to_owned()
        } else {
            b
        }
    });
    Ok((bind, port))
}

/// Splits `host:port`, `[v6]:port`, `host/port` or a bare `port`.
fn split_host_port(spec: &str) -> Option<(Option<String>, &str)> {
    if let Some(rest) = spec.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .or_else(|| after.strip_prefix('/'))?;
        return Some((Some(host.to_owned()), port));
    }
    if let Some((h, p)) = spec.rsplit_once('/') {
        return Some((Some(h.to_owned()), p));
    }
    match spec.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((Some(h.to_owned()), p)),
        Some(_) => None,
        None => Some((None, spec)),
    }
}

fn forward(kind: ForwardKind, args: &[String]) -> Result<ForwardSpec, String> {
    match (kind, args) {
        (ForwardKind::Dynamic, [l]) => {
            let (bind_addr, bind_port) = listen(l)?;
            Ok(ForwardSpec {
                kind,
                bind_addr,
                bind_port,
                dest: None,
            })
        }
        (ForwardKind::Local | ForwardKind::Remote, [l, d]) => {
            if l.starts_with('/') || d.starts_with('/') {
                return Err("Unix-socket forwards are not supported".to_owned());
            }
            let (bind_addr, bind_port) = listen(l)?;
            let (host, port) = match split_host_port(d) {
                Some((Some(h), p)) if !h.is_empty() => (h, p),
                _ => return Err(format!("invalid destination {d:?}")),
            };
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid destination port in {d:?}"))?;
            Ok(ForwardSpec {
                kind,
                bind_addr,
                bind_port,
                dest: Some((host, port)),
            })
        }
        (ForwardKind::Remote, [_]) => {
            Err("remote dynamic (reverse SOCKS) forwards are not supported".to_owned())
        }
        _ => Err("wrong number of values".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.prod", "web.prod"));
        assert!(!glob_match("*.prod", "web.prod.x"));
        assert!(glob_match("web?", "WEB1"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        let p = vec![Pattern::parse("!x"), Pattern::parse("*")];
        assert!(patterns_match(&p, "y"));
        assert!(!patterns_match(&p, "x"));
    }

    #[test]
    fn forwards() {
        let f = forward(
            ForwardKind::Local,
            &["5432".to_owned(), "db:5432".to_owned()],
        );
        assert_eq!(
            f,
            Ok(ForwardSpec {
                kind: ForwardKind::Local,
                bind_addr: None,
                bind_port: 5432,
                dest: Some(("db".to_owned(), 5432)),
            })
        );
        let f = forward(
            ForwardKind::Local,
            &["[::1]:8080".to_owned(), "[fe80::1]:80".to_owned()],
        );
        assert_eq!(
            f.map(|f| (f.bind_addr, f.dest)),
            Ok((Some("::1".to_owned()), Some(("fe80::1".to_owned(), 80))))
        );
        let f = forward(ForwardKind::Dynamic, &["*:1080".to_owned()]);
        assert_eq!(f.map(|f| f.bind_addr), Ok(Some("0.0.0.0".to_owned())));
        assert!(forward(ForwardKind::Remote, &["8080".to_owned()]).is_err());
    }
}
