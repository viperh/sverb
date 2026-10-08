//! Lossy `ssh_config` export (§9.13): one `Host <label>` block per host with HostName,
//! User, Port, ProxyJump (the hop hosts' labels), ProxyCommand, the forwards,
//! ForwardAgent, SetEnv and ServerAliveInterval. Settings a host inherits from its
//! groups are written on the host (groups have no ssh_config equivalent). IdentityFile
//! is written only for keys with a known source path. Secrets are never written; the
//! file starts with [`super::SECRETS_WARNING`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::model::{ForwardKind, Group, Host, ItemId, PortForward, Proxy};

/// What the export reads.
#[derive(Debug, Default)]
pub struct SshConfigExport {
    /// Hosts, in output order.
    pub hosts: Vec<(ItemId, Host)>,
    /// Groups (for inherited settings).
    pub groups: BTreeMap<ItemId, Group>,
    /// Forwarding rules.
    pub forwards: Vec<PortForward>,
    /// Key item → the file it was imported from (when known).
    pub key_paths: BTreeMap<ItemId, String>,
}

/// A `Host` alias for `label`: whitespace and pattern characters become `-`.
pub fn sanitize_label(label: &str) -> String {
    let s: String = label
        .trim()
        .chars()
        .map(|c| {
            if c.is_whitespace() || matches!(c, '*' | '?' | '!' | ',' | '#' | '"' | '\'' | '=') {
                '-'
            } else {
                c
            }
        })
        .collect();
    if s.is_empty() { "host".to_owned() } else { s }
}

fn quote(v: &str) -> String {
    if v.is_empty() || v.contains(|c: char| c.is_whitespace() || c == '#' || c == '"') {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        v.to_owned()
    }
}

/// The settings of `host` with its group chain's defaults filled in.
struct Effective {
    user: Option<String>,
    port: Option<u16>,
    key_id: Option<ItemId>,
    jump: Vec<ItemId>,
    proxy_command: Option<String>,
    agent_forwarding: Option<bool>,
    env: Vec<(String, String)>,
    keepalive: Option<u32>,
}

fn effective(host: &Host, groups: &BTreeMap<ItemId, Group>) -> Effective {
    let mut e = Effective {
        user: host.username.clone(),
        port: host.port,
        key_id: host.key_id,
        jump: host.jump_chain.clone(),
        proxy_command: match &host.proxy {
            Some(Proxy::Command(c)) => Some(c.clone()),
            _ => None,
        },
        agent_forwarding: host.agent_forwarding,
        env: host.env.clone(),
        keepalive: host.keepalive_secs,
    };
    let (mut jump_set, mut env_set) = (
        !host.jump_chain.is_empty() || host.explicit_empty.jump_chain,
        !host.env.is_empty() || host.explicit_empty.env,
    );
    let mut cur = host.group_id;
    let mut seen = BTreeSet::new();
    while let Some(gid) = cur {
        if !seen.insert(gid) {
            break;
        }
        let Some(g) = groups.get(&gid) else { break };
        let d = &g.defaults;
        e.user = e.user.take().or_else(|| d.username.clone());
        e.port = e.port.or(d.port);
        e.key_id = e.key_id.or(d.key_id);
        if !jump_set && let Some(j) = &d.jump_chain {
            e.jump = j.clone();
            jump_set = true;
        }
        if e.proxy_command.is_none()
            && let Some(Proxy::Command(c)) = &d.proxy
        {
            e.proxy_command = Some(c.clone());
        }
        e.agent_forwarding = e.agent_forwarding.or(d.agent_forwarding);
        if !env_set && let Some(env) = &d.env {
            e.env = env.clone();
            env_set = true;
        }
        e.keepalive = e.keepalive.or(d.keepalive_secs);
        cur = g.parent_id;
    }
    e
}

fn bind(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

/// The `ssh_config` text.
pub fn export(data: &SshConfigExport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Exported from sverb.");
    let _ = writeln!(out, "# {}", super::SECRETS_WARNING);
    // Unique aliases.
    let mut aliases: BTreeMap<ItemId, String> = BTreeMap::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (id, host) in &data.hosts {
        let base = sanitize_label(host.display_label());
        let mut alias = base.clone();
        let mut n = 2;
        while !used.insert(alias.to_ascii_lowercase()) {
            alias = format!("{base}-{n}");
            n += 1;
        }
        aliases.insert(*id, alias);
    }
    for (id, host) in &data.hosts {
        let e = effective(host, &data.groups);
        let alias = &aliases[id];
        let _ = writeln!(out, "\nHost {alias}");
        let _ = writeln!(out, "    HostName {}", host.address);
        if let Some(u) = &e.user {
            let _ = writeln!(out, "    User {}", quote(u));
        }
        if let Some(p) = e.port {
            let _ = writeln!(out, "    Port {p}");
        }
        if let Some(path) = e.key_id.and_then(|k| data.key_paths.get(&k)) {
            let _ = writeln!(out, "    IdentityFile {}", quote(path));
        }
        if !e.jump.is_empty() {
            let hops: Vec<&str> = e
                .jump
                .iter()
                .filter_map(|j| aliases.get(j).map(String::as_str))
                .collect();
            if hops.len() == e.jump.len() {
                let _ = writeln!(out, "    ProxyJump {}", hops.join(","));
            } else {
                let _ = writeln!(out, "    # ProxyJump omitted: a hop host is not exported");
            }
        }
        if let Some(c) = &e.proxy_command {
            let _ = writeln!(out, "    ProxyCommand {c}");
        }
        for f in data.forwards.iter().filter(|f| f.host_id == *id) {
            let dest = || {
                format!(
                    "{}:{}",
                    f.dest_host.as_deref().unwrap_or("localhost"),
                    f.dest_port.unwrap_or(0)
                )
            };
            match f.kind {
                ForwardKind::Local => {
                    let _ = writeln!(
                        out,
                        "    LocalForward {} {}",
                        bind(&f.bind_addr, f.bind_port),
                        dest()
                    );
                }
                ForwardKind::Remote => {
                    let _ = writeln!(
                        out,
                        "    RemoteForward {} {}",
                        bind(&f.bind_addr, f.bind_port),
                        dest()
                    );
                }
                ForwardKind::Dynamic => {
                    let _ = writeln!(
                        out,
                        "    DynamicForward {}",
                        bind(&f.bind_addr, f.bind_port)
                    );
                }
            }
        }
        if let Some(a) = e.agent_forwarding {
            let _ = writeln!(out, "    ForwardAgent {}", if a { "yes" } else { "no" });
        }
        for (k, v) in &e.env {
            let _ = writeln!(out, "    SetEnv {}", quote(&format!("{k}={v}")));
        }
        if let Some(k) = e.keepalive {
            let _ = writeln!(out, "    ServerAliveInterval {k}");
        }
    }
    out
}
