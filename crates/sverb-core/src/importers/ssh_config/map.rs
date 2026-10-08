//! Blocks → planned items (§9.13).
//!
//! **Semantics.** For every concrete alias, the settings are what OpenSSH would use:
//! the blocks that match the alias are read in order and the first value obtained for
//! a keyword wins (`IdentityFile` and the forwards accumulate; `SetEnv` keeps the
//! first value per variable).
//!
//! **Wildcard blocks → groups.** `Host *` (and the global lines before the first
//! `Host`) become the group "Imported defaults"; any other wildcard pattern line
//! (`Host *.prod`) becomes a group named after it, nested under "Imported defaults",
//! with the block's own settings as defaults. A host joins the first wildcard group
//! that matches it (else "Imported defaults", else the target group). The host then
//! stores only the values that differ from what its group chain provides, so the
//! resolved settings equal OpenSSH's first-match result. Blocks with negated patterns
//! (`Host !x *`) cannot be a group: they are skipped as groups with a reason and their
//! values are stored on the matching hosts. Values a group cannot hold (HostName,
//! forwards) are applied per host and noted.

use std::collections::BTreeMap;

use super::parser::{Block, BlockKind, ForwardSpec, Parsed, Setting};
use crate::importers::{
    DefaultsDraft, Draft, ForwardDraft, GroupDraft, HostDraft, ImportPlan, ImportSource, PlanRef,
    PlannedItem, Skipped,
};
use crate::model::{DEFAULT_BIND_ADDR, ForwardKind, ItemKind, validate::validate_address};

/// The group that receives `Host *` settings.
pub const DEFAULTS_GROUP: &str = "Imported defaults";

/// The first-match result of a list of blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Eff {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_files: Vec<String>,
    proxy_jump: Option<Vec<String>>,
    proxy_command: Option<String>,
    forwards: Vec<(ForwardSpec, String)>,
    forward_agent: Option<bool>,
    env: Vec<(String, String)>,
    keepalive: Option<u32>,
}

fn effective<'a>(blocks: impl IntoIterator<Item = &'a Block>) -> Eff {
    let mut e = Eff::default();
    for block in blocks {
        for entry in &block.entries {
            match &entry.setting {
                Setting::HostName(h) => {
                    e.hostname.get_or_insert_with(|| h.clone());
                }
                Setting::User(u) => {
                    e.user.get_or_insert_with(|| u.clone());
                }
                Setting::Port(p) => {
                    e.port.get_or_insert(*p);
                }
                Setting::IdentityFile(f) => {
                    if !f.eq_ignore_ascii_case("none") && !e.identity_files.contains(f) {
                        e.identity_files.push(f.clone());
                    }
                }
                Setting::ProxyJump(h) => {
                    e.proxy_jump.get_or_insert_with(|| h.clone());
                }
                Setting::ProxyCommand(c) => {
                    e.proxy_command.get_or_insert_with(|| c.clone());
                }
                Setting::Forward(f) => e.forwards.push((f.clone(), entry.at.clone())),
                Setting::ForwardAgent(b) => {
                    e.forward_agent.get_or_insert(*b);
                }
                Setting::SetEnv(k, v) => {
                    if !e.env.iter().any(|(ek, _)| ek == k) {
                        e.env.push((k.clone(), v.clone()));
                    }
                }
                Setting::ServerAliveInterval(s) => {
                    e.keepalive.get_or_insert(*s);
                }
            }
        }
    }
    e
}

/// `%h` → the alias, `%%` → `%` (other tokens are left as written).
fn expand_hostname(value: &str, alias: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(alias),
            Some('%') => out.push('%'),
            Some(o) => {
                out.push('%');
                out.push(o);
            }
            None => out.push('%'),
        }
    }
    out
}

/// A ProxyJump hop: `[ssh://][user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hop {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

fn parse_hop(spec: &str) -> Option<Hop> {
    let s = spec.strip_prefix("ssh://").unwrap_or(spec);
    let s = s.trim_end_matches('/');
    let (user, hostport) = match s.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_owned()), h),
        None => (None, s),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        (h.to_owned(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_owned(), Some(p.parse().ok()?)),
            Some(_) => (hostport.to_owned(), None),
            None => (hostport.to_owned(), None),
        }
    };
    if host.is_empty() || port == Some(0) {
        return None;
    }
    Some(Hop { user, host, port })
}

struct Ctx<'a> {
    parsed: &'a Parsed,
    plan: ImportPlan,
    /// alias → its host ref.
    alias_refs: BTreeMap<String, PlanRef>,
    /// alias → its address (for hops written `user@alias`).
    alias_addr: BTreeMap<String, String>,
    /// Hop spec → created host.
    hop_refs: BTreeMap<String, PlanRef>,
    /// Hosts created for hops (pushed after the aliases).
    hop_drafts: Vec<(PlannedItem, PlanRef)>,
    next_ref: PlanRef,
}

impl Ctx<'_> {
    /// Resolves hops to planned hosts (aliases are linked, other specs create hosts).
    fn hops(&mut self, specs: &[String], at: &str, own: Option<PlanRef>) -> Vec<PlanRef> {
        let mut out = Vec::new();
        for spec in specs {
            let Some(hop) = parse_hop(spec) else {
                self.plan.skipped.push(Skipped::new(
                    Some(at.to_owned()),
                    format!("ProxyJump hop {spec:?} is not [user@]host[:port]; hop skipped"),
                ));
                continue;
            };
            let lower = hop.host.to_ascii_lowercase();
            let r = if hop.user.is_none()
                && hop.port.is_none()
                && let Some(r) = self.alias_refs.get(&lower)
            {
                *r
            } else if let Some(r) = self.hop_refs.get(spec) {
                *r
            } else {
                let address = self
                    .alias_addr
                    .get(&lower)
                    .cloned()
                    .unwrap_or_else(|| hop.host.clone());
                let address = match validate_address(&address) {
                    Ok(a) => a,
                    Err(e) => {
                        self.plan.skipped.push(Skipped::new(
                            Some(at.to_owned()),
                            format!("ProxyJump hop {spec:?}: {}; hop skipped", e.message),
                        ));
                        continue;
                    }
                };
                let draft = HostDraft {
                    label: spec.clone(),
                    address,
                    port: hop.port,
                    username: hop.user.clone(),
                    ..HostDraft::default()
                };
                let r = self.next_ref;
                self.next_ref += 1;
                let mut item =
                    PlannedItem::new(ItemKind::Host, spec.clone(), Draft::Host(Box::new(draft)));
                item.source_line = Some(at.to_owned());
                self.hop_drafts.push((item, r));
                self.hop_refs.insert(spec.clone(), r);
                r
            };
            if Some(r) == own {
                continue; // a host never jumps through itself
            }
            out.push(r);
        }
        out
    }
}

/// A wildcard group in the making.
struct WildGroup {
    name: String,
    at: String,
    blocks: Vec<usize>,
    is_defaults: bool,
}

/// Maps parsed blocks to a plan.
pub fn map(parsed: &Parsed) -> ImportPlan {
    let mut plan = ImportPlan::new(ImportSource::SshConfig);
    plan.skipped.extend(parsed.skipped.iter().cloned());

    // ---- wildcard groups
    let mut defaults_blocks: Vec<usize> = Vec::new();
    let mut groups: Vec<WildGroup> = Vec::new();
    for (i, block) in parsed.blocks.iter().enumerate() {
        match &block.kind {
            BlockKind::Global => defaults_blocks.push(i),
            BlockKind::Match => {}
            BlockKind::Host(patterns) => {
                if patterns.iter().all(|p| p.is_concrete()) {
                    continue;
                }
                if patterns.iter().any(|p| p.negated) {
                    plan.skipped.push(Skipped::new(
                        Some(block.at.clone()),
                        format!(
                            "Host {}: negated patterns cannot become a group; its settings are applied to the matching hosts directly",
                            block.raw
                        ),
                    ));
                    continue;
                }
                let wild: Vec<&str> = patterns
                    .iter()
                    .filter(|p| p.is_wildcard())
                    .map(|p| p.glob.as_str())
                    .collect();
                if wild == ["*"] {
                    defaults_blocks.push(i);
                    continue;
                }
                let name = wild.join(" ");
                if let Some(g) = groups.iter_mut().find(|g| g.name == name) {
                    g.blocks.push(i);
                } else {
                    groups.push(WildGroup {
                        name,
                        at: block.at.clone(),
                        blocks: vec![i],
                        is_defaults: false,
                    });
                }
            }
        }
    }
    let has_defaults = !defaults_blocks.is_empty();
    if has_defaults {
        let at = defaults_blocks
            .iter()
            .map(|&i| parsed.blocks[i].at.clone())
            .find(|a| !a.is_empty())
            .unwrap_or_default();
        groups.insert(
            0,
            WildGroup {
                name: DEFAULTS_GROUP.to_owned(),
                at,
                blocks: defaults_blocks,
                is_defaults: true,
            },
        );
    }
    for g in &groups {
        for &bi in &g.blocks {
            let b = &parsed.blocks[bi];
            for e in &b.entries {
                let what = match e.setting {
                    Setting::HostName(_) => "HostName",
                    Setting::Forward(_) => "the forward",
                    _ => continue,
                };
                let shown = if b.raw.is_empty() {
                    "(global)"
                } else {
                    b.raw.as_str()
                };
                plan.notes.push(format!(
                    "{}: {what} of Host {shown} is applied to each matching host (a group cannot hold it)",
                    e.at
                ));
            }
        }
    }

    // ---- concrete aliases, in order of first appearance
    let mut aliases: Vec<(String, String)> = Vec::new(); // (alias as written, at)
    for block in &parsed.blocks {
        if let BlockKind::Host(patterns) = &block.kind {
            for p in patterns.iter().filter(|p| p.is_concrete()) {
                if !aliases.iter().any(|(a, _)| a.eq_ignore_ascii_case(&p.glob)) {
                    aliases.push((p.glob.clone(), block.at.clone()));
                }
            }
        }
    }

    // Effective settings and addresses; hosts with a bad address are skipped.
    let mut hosts: Vec<(String, String, Eff, String)> = Vec::new(); // alias, at, eff, address
    for (alias, at) in aliases {
        let eff = effective(parsed.blocks.iter().filter(|b| b.applies_to(&alias)));
        let address = eff
            .hostname
            .as_deref()
            .map_or_else(|| alias.clone(), |h| expand_hostname(h, &alias));
        match validate_address(&address) {
            Ok(a) => hosts.push((alias, at, eff, a)),
            Err(e) => plan.skipped.push(Skipped::new(
                Some(at),
                format!("Host {alias}: address {address:?}: {}", e.message),
            )),
        }
    }

    let n_groups = groups.len();
    let mut cx = Ctx {
        parsed,
        plan,
        alias_refs: BTreeMap::new(),
        alias_addr: BTreeMap::new(),
        hop_refs: BTreeMap::new(),
        hop_drafts: Vec::new(),
        next_ref: n_groups + hosts.len(),
    };
    for (i, (alias, _, _, addr)) in hosts.iter().enumerate() {
        cx.alias_refs.insert(alias.clone(), n_groups + i);
        cx.alias_addr.insert(alias.clone(), addr.clone());
    }

    // ---- groups
    let defaults_ref = groups.iter().position(|g| g.is_defaults);
    let group_effs: Vec<Eff> = groups
        .iter()
        .map(|g| effective(g.blocks.iter().map(|&i| &cx.parsed.blocks[i])))
        .collect();
    let mut group_items = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        let eff = &group_effs[gi];
        let jump = eff
            .proxy_jump
            .clone()
            .map(|specs| cx.hops(&specs, &g.at, None))
            .unwrap_or_default();
        let defaults = DefaultsDraft {
            port: eff.port,
            username: eff.user.clone(),
            identity_files: eff.identity_files.clone(),
            jump_chain: jump,
            proxy_command: eff.proxy_command.clone().filter(|c| !c.is_empty()),
            agent_forwarding: eff.forward_agent,
            env: eff.env.clone(),
            keepalive_secs: eff.keepalive,
        };
        let draft = GroupDraft {
            name: g.name.clone(),
            parent: if g.is_defaults { None } else { defaults_ref },
            defaults,
        };
        let mut item = PlannedItem::new(ItemKind::Group, g.name.clone(), Draft::Group(draft));
        item.source_line = (!g.at.is_empty()).then(|| g.at.clone());
        group_items.push(item);
    }

    // ---- hosts
    let mut host_items = Vec::new();
    let mut host_forwards: Vec<Vec<(ForwardSpec, String)>> = Vec::new();
    for (i, (alias, at, eff, address)) in hosts.iter().enumerate() {
        let own = n_groups + i;
        // The host's group: the first wildcard group matching it, else the defaults.
        let group = groups
            .iter()
            .position(|g| {
                !g.is_defaults
                    && g.blocks
                        .iter()
                        .any(|&bi| cx.parsed.blocks[bi].applies_to(alias))
            })
            .or(defaults_ref);
        // What the group chain provides.
        let mut chain_blocks: Vec<usize> = Vec::new();
        if let Some(g) = group {
            chain_blocks.extend(&groups[g].blocks);
            if Some(g) != defaults_ref
                && let Some(d) = defaults_ref
            {
                chain_blocks.extend(&groups[d].blocks);
            }
        }
        let inh = effective(chain_blocks.iter().map(|&bi| &cx.parsed.blocks[bi]));
        let mut draft = HostDraft {
            label: alias.clone(),
            address: address.clone(),
            group,
            ..HostDraft::default()
        };
        if eff.user != inh.user {
            draft.username = eff.user.clone();
        }
        if eff.port != inh.port {
            draft.port = eff.port;
        }
        if eff.identity_files != inh.identity_files {
            draft.identity_files = eff.identity_files.clone();
        }
        if eff.proxy_jump != inh.proxy_jump {
            match &eff.proxy_jump {
                Some(specs) if specs.is_empty() => draft.no_jump = true,
                Some(specs) => {
                    draft.jump_chain = cx.hops(specs, at, Some(own));
                    if draft.jump_chain.is_empty() {
                        draft.no_jump = true;
                    }
                }
                None => {}
            }
        }
        if eff.proxy_command != inh.proxy_command {
            match eff.proxy_command.as_deref() {
                Some("") => cx.plan.warnings.push(format!(
                    "Host {alias}: ProxyCommand none cannot override the group's ProxyCommand; the host inherits it"
                )),
                Some(c) => draft.proxy_command = Some(c.to_owned()),
                None => {}
            }
        }
        if eff.forward_agent != inh.forward_agent {
            draft.agent_forwarding = eff.forward_agent;
        }
        if eff.env != inh.env {
            draft.env = eff.env.clone();
        }
        if eff.keepalive != inh.keepalive {
            draft.keepalive_secs = eff.keepalive;
        }
        let mut item =
            PlannedItem::new(ItemKind::Host, alias.clone(), Draft::Host(Box::new(draft)));
        item.source_line = Some(at.clone());
        host_items.push(item);
        host_forwards.push(eff.forwards.clone());
    }

    // ---- push in reference order: groups, hosts, hop hosts, then forwards
    let mut plan = std::mem::replace(&mut cx.plan, ImportPlan::new(ImportSource::SshConfig));
    for item in group_items {
        plan.push(item);
    }
    for item in host_items {
        plan.push(item);
    }
    for (item, r) in std::mem::take(&mut cx.hop_drafts) {
        let got = plan.push(item);
        debug_assert_eq!(got, r);
    }
    for (i, forwards) in host_forwards.into_iter().enumerate() {
        let host_ref = n_groups + i;
        let alias = plan.label_of(host_ref).to_owned();
        let mut refs = Vec::new();
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

    if !parsed.unsupported.is_empty() {
        let list: Vec<String> = parsed
            .unsupported
            .values()
            .map(|(name, n)| format!("{name} ({n})"))
            .collect();
        plan.warnings
            .push(format!("Unsupported keywords skipped: {}", list.join(", ")));
    }
    plan
}
