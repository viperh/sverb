//! Settings resolution with provenance (SPEC §4.3, §4.13, §12.4).
//!
//! Every inheritable setting resolves **Host → Group → parent Group → … → vault
//! defaults → global config** (then sverb's built-in default), and the
//! [`Provenance`] records which level won, so the UI can show
//! `port: 2222 (from group "prod")`.
//!
//! - **Layers.** Each level is a [`Settings`]: the inheritable fields with `None`
//!   meaning "inherit". The host's own layer comes from [`Settings::from_host`], a
//!   group's and the vault defaults' from [`Settings::from_defaults`]. Lists
//!   (`jump_chain`, `env`, `port_forwards`) inherit only when absent on the host, not
//!   when explicitly empty (`Host::explicit_empty`).
//! - **Credentials.** Each field resolves on its own, but an identity is expanded at
//!   the level where it is set (`host.identity_id` or `group.defaults.identity_id`):
//!   its username, password and key count as values of that level, below the
//!   level's inline fields (§4.2).
//! - **Missing references** (a deleted group, identity, key, snippet, jump host or
//!   forward) resolve as `None` at read time (§12.4), are logged at `debug` and
//!   reported in [`ResolvedHost::warnings`] (the detail pane shows "missing group").
//! - **Cycles.** The group walk stops on a revisited id and after
//!   [`MAX_GROUP_DEPTH`] groups, even though writes reject cycles.
//! - **No secrets.** Resolution never reads secret values: a [`Settings`] layer only
//!   says *that* a password is stored, and [`ResolvedHost::password`] says *where*
//!   ([`SecretOrigin`]); the connector reads it from the vault. That keeps
//!   [`ResolvedHost`] `Clone`/`Eq` and safe to hand around.
//!
//! Pure and deterministic: the only inputs are the host, an [`ItemLookup`], the vault
//! defaults and [`GlobalDefaults`].

pub mod provenance;
// Jump-chain expansion (recursive, cycle-checked, depth-limited).
pub mod chain;
// Approval of values that act locally (§17.1).
pub mod approval;
// The per-user credential override layer of shared hosts (§13.4).
pub mod overrides;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use tracing::debug;

use crate::config::Config;
use crate::model::group::MAX_GROUP_DEPTH;
use crate::model::{
    AgentSource, AlgoOverrides, Backspace, DEFAULT_SSH_PORT, Group, Host, HostDefaults, Identity,
    ItemId, Proxy, VaultId, WireEnum,
};

pub use chain::{
    ChainError, ChainHop, HopInfo, MAX_JUMP_HOPS, effective_route, expand_by, expand_chain,
};
pub use provenance::{Provenance, SettingKey, Source};

/// The charset used when nothing sets one.
pub const DEFAULT_CHARSET: &str = "UTF-8";

// ---------------------------------------------------------------------- layers

/// A proxy setting without its password (only whether one is stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxySettings {
    /// SOCKS5 via `addr`.
    Socks5 {
        /// `host:port`.
        addr: String,
        /// Proxy user, if any.
        user: Option<String>,
        /// A proxy password is stored.
        has_password: bool,
    },
    /// HTTP CONNECT via `addr`.
    Http {
        /// `host:port`.
        addr: String,
        /// Proxy user, if any.
        user: Option<String>,
        /// A proxy password is stored.
        has_password: bool,
    },
    /// A ProxyCommand.
    Command(String),
}

impl ProxySettings {
    /// The secret-free form of `proxy`.
    pub fn from_proxy(proxy: &Proxy) -> Self {
        match proxy {
            Proxy::Socks5 { addr, auth } => Self::Socks5 {
                addr: addr.clone(),
                user: auth.as_ref().map(|a| a.user.clone()),
                has_password: auth.as_ref().is_some_and(|a| a.password.is_some()),
            },
            Proxy::Http { addr, auth } => Self::Http {
                addr: addr.clone(),
                user: auth.as_ref().map(|a| a.user.clone()),
                has_password: auth.as_ref().is_some_and(|a| a.password.is_some()),
            },
            Proxy::Command(c) => Self::Command(c.clone()),
        }
    }

    /// One line for the UI (`SOCKS5 user@proxy:1080`, `command: …`).
    pub fn describe(&self) -> String {
        match self {
            Self::Socks5 { addr, user, .. } | Self::Http { addr, user, .. } => {
                let kind = if matches!(self, Self::Socks5 { .. }) {
                    "SOCKS5"
                } else {
                    "HTTP"
                };
                match user {
                    Some(u) => format!("{kind} {u}@{addr}"),
                    None => format!("{kind} {addr}"),
                }
            }
            Self::Command(c) => format!("command: {c}"),
        }
    }
}

/// One level of the resolution chain: every inheritable setting, `None` meaning
/// "inherit from the next level". Holds no secret values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `port`
    pub port: Option<u16>,
    /// `identity_id`
    pub identity_id: Option<ItemId>,
    /// `username` (inline; overrides the identity of the same level)
    pub username: Option<String>,
    /// An inline password is stored at this level.
    pub password: bool,
    /// `key_id` (inline)
    pub key_id: Option<ItemId>,
    /// `jump_chain` (`Some(vec![])`: explicitly none)
    pub jump_chain: Option<Vec<ItemId>>,
    /// `proxy.*`
    pub proxy: Option<ProxySettings>,
    /// `agent_forwarding`
    pub agent_forwarding: Option<bool>,
    /// `agent_source`
    pub agent_source: Option<AgentSource>,
    /// `env` (`Some(vec![])`: explicitly none)
    pub env: Option<Vec<(String, String)>>,
    /// `startup_snippet_id`
    pub startup_snippet_id: Option<ItemId>,
    /// `keepalive_secs`
    pub keepalive_secs: Option<u32>,
    /// `charset`
    pub charset: Option<String>,
    /// `backspace`
    pub backspace: Option<Backspace>,
    /// `color_scheme`
    pub color_scheme: Option<String>,
    /// `port_forwards` (`Some(vec![])`: explicitly none)
    pub port_forwards: Option<Vec<ItemId>>,
    /// `algorithms.*`
    pub algorithms: Option<AlgoOverrides>,
    /// `request_pty_for_exec`
    pub request_pty_for_exec: Option<bool>,
    /// `record_sessions`
    pub record_sessions: Option<bool>,
    /// `auto_reconnect`
    pub auto_reconnect: Option<bool>,
}

fn non_empty(s: Option<&String>) -> Option<String> {
    s.filter(|s| !s.is_empty()).cloned()
}

fn list<T: Clone>(v: &[T], explicit_empty: bool) -> Option<Vec<T>> {
    (!v.is_empty() || explicit_empty).then(|| v.to_vec())
}

impl Settings {
    /// The host's own level. Empty lists inherit unless flagged explicitly empty.
    pub fn from_host(host: &Host) -> Self {
        let ex = host.explicit_empty;
        Self {
            port: host.port,
            identity_id: host.identity_id,
            username: non_empty(host.username.as_ref()),
            password: host.password.is_some(),
            key_id: host.key_id,
            jump_chain: list(&host.jump_chain, ex.jump_chain),
            proxy: host.proxy.as_ref().map(ProxySettings::from_proxy),
            agent_forwarding: host.agent_forwarding,
            agent_source: host.agent_source,
            env: list(&host.env, ex.env),
            startup_snippet_id: host.startup_snippet_id,
            keepalive_secs: host.keepalive_secs,
            charset: non_empty(host.charset.as_ref()),
            backspace: host.backspace,
            color_scheme: non_empty(host.color_scheme.as_ref()),
            port_forwards: list(&host.port_forwards, ex.port_forwards),
            algorithms: host.algorithms.clone(),
            request_pty_for_exec: host.request_pty_for_exec,
            record_sessions: host.record_sessions,
            auto_reconnect: host.auto_reconnect,
        }
    }

    /// A group's or the vault's defaults.
    pub fn from_defaults(d: &HostDefaults) -> Self {
        Self {
            port: d.port,
            identity_id: d.identity_id,
            username: non_empty(d.username.as_ref()),
            password: d.password.is_some(),
            key_id: d.key_id,
            jump_chain: d.jump_chain.clone(),
            proxy: d.proxy.as_ref().map(ProxySettings::from_proxy),
            agent_forwarding: d.agent_forwarding,
            agent_source: d.agent_source,
            env: d.env.clone(),
            startup_snippet_id: d.startup_snippet_id,
            keepalive_secs: d.keepalive_secs,
            charset: non_empty(d.charset.as_ref()),
            backspace: d.backspace,
            color_scheme: non_empty(d.color_scheme.as_ref()),
            port_forwards: d.port_forwards.clone(),
            algorithms: d.algorithms.clone(),
            request_pty_for_exec: d.request_pty_for_exec,
            record_sessions: d.record_sessions,
            auto_reconnect: d.auto_reconnect,
        }
    }

    /// Whether `key` is set at this level.
    pub fn is_set(&self, key: SettingKey) -> bool {
        match key {
            SettingKey::Port => self.port.is_some(),
            SettingKey::IdentityId => self.identity_id.is_some(),
            SettingKey::Username => self.username.is_some(),
            SettingKey::Password => self.password,
            SettingKey::KeyId => self.key_id.is_some(),
            SettingKey::JumpChain => self.jump_chain.is_some(),
            SettingKey::Proxy => self.proxy.is_some(),
            SettingKey::AgentForwarding => self.agent_forwarding.is_some(),
            SettingKey::AgentSource => self.agent_source.is_some(),
            SettingKey::Env => self.env.is_some(),
            SettingKey::StartupSnippetId => self.startup_snippet_id.is_some(),
            SettingKey::KeepaliveSecs => self.keepalive_secs.is_some(),
            SettingKey::Charset => self.charset.is_some(),
            SettingKey::Backspace => self.backspace.is_some(),
            SettingKey::ColorScheme => self.color_scheme.is_some(),
            SettingKey::PortForwards => self.port_forwards.is_some(),
            SettingKey::Algorithms => self.algorithms.is_some(),
            SettingKey::RequestPtyForExec => self.request_pty_for_exec.is_some(),
            SettingKey::RecordSessions => self.record_sessions.is_some(),
            SettingKey::AutoReconnect => self.auto_reconnect.is_some(),
        }
    }

    /// How many settings this level sets.
    pub fn count(&self) -> usize {
        SettingKey::ALL.iter().filter(|k| self.is_set(**k)).count()
    }
}

// ---------------------------------------------------------------------- lookup

/// A group as resolution sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupNode {
    /// `name`
    pub name: String,
    /// `parent_id`
    pub parent_id: Option<ItemId>,
    /// `icon`
    pub icon: Option<String>,
    /// `defaults.*`
    pub defaults: Settings,
}

impl GroupNode {
    /// From the typed view.
    pub fn from_group(g: &Group) -> Self {
        Self {
            name: g.name.clone(),
            parent_id: g.parent_id,
            icon: g.icon.clone(),
            defaults: Settings::from_defaults(&g.defaults),
        }
    }
}

/// An identity as resolution sees it (no password value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityNode {
    /// `label`
    pub label: String,
    /// `username`
    pub username: String,
    /// A password is stored.
    pub has_password: bool,
    /// `key_id`
    pub key_id: Option<ItemId>,
}

impl IdentityNode {
    /// From the typed view.
    pub fn from_identity(i: &Identity) -> Self {
        Self {
            label: i.label.clone(),
            username: i.username.clone(),
            has_password: i.password.is_some(),
            key_id: i.key_id,
        }
    }
}

/// What resolution reads besides the host.
pub trait ItemLookup {
    /// A live group (not the vault-defaults item).
    fn group(&self, id: ItemId) -> Option<&GroupNode>;
    /// A live identity.
    fn identity(&self, id: ItemId) -> Option<&IdentityNode>;
    /// Whether a referenced key, snippet, host or forward exists (default: assume so).
    fn exists(&self, _id: ItemId) -> bool {
        true
    }
}

/// An in-memory [`ItemLookup`]: groups, identities, vault defaults and (optionally)
/// the set of live item ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupTable {
    /// Groups by id.
    pub groups: BTreeMap<ItemId, GroupNode>,
    /// Identities by id.
    pub identities: BTreeMap<ItemId, IdentityNode>,
    /// Vault defaults (§4.13) by vault.
    pub vault_defaults: BTreeMap<VaultId, Settings>,
    /// The item holding each vault's defaults.
    pub vault_defaults_items: BTreeMap<VaultId, ItemId>,
    /// Live item ids; `None`: every reference is assumed to exist.
    pub live: Option<BTreeSet<ItemId>>,
}

impl LookupTable {
    /// Add a group item of `vault`. A vault-defaults item becomes that vault's
    /// defaults (the smallest id wins if a sync race made two).
    pub fn insert_group(&mut self, id: ItemId, vault: VaultId, g: &Group) {
        if g.is_vault_defaults {
            if self
                .vault_defaults_items
                .get(&vault)
                .is_none_or(|cur| id < *cur)
            {
                self.vault_defaults_items.insert(vault, id);
                self.vault_defaults
                    .insert(vault, Settings::from_defaults(&g.defaults));
            }
        } else {
            self.groups.insert(id, GroupNode::from_group(g));
        }
    }

    /// Add an identity.
    pub fn insert_identity(&mut self, id: ItemId, i: &Identity) {
        self.identities.insert(id, IdentityNode::from_identity(i));
    }

    /// Record a live item id (enables missing-reference checks).
    pub fn mark_live(&mut self, id: ItemId) {
        self.live.get_or_insert_with(BTreeSet::new).insert(id);
    }

    /// The defaults of `vault`.
    pub fn defaults_of(&self, vault: VaultId) -> Option<&Settings> {
        self.vault_defaults.get(&vault)
    }
}

impl ItemLookup for LookupTable {
    fn group(&self, id: ItemId) -> Option<&GroupNode> {
        self.groups.get(&id)
    }

    fn identity(&self, id: ItemId) -> Option<&IdentityNode> {
        self.identities.get(&id)
    }

    fn exists(&self, id: ItemId) -> bool {
        self.live.as_ref().is_none_or(|l| l.contains(&id))
    }
}

// ---------------------------------------------------------------------- output

/// The global level: `config.toml` values that act as defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalDefaults {
    /// `ssh.keepalive_secs`
    pub keepalive_secs: u32,
    /// `terminal.color_scheme`
    pub color_scheme: String,
    /// `recording.enabled`
    pub record_sessions: bool,
    /// `ssh.auto_reconnect`
    pub auto_reconnect: bool,
}

impl GlobalDefaults {
    /// From the loaded config.
    pub fn from_config(config: &Config) -> Self {
        Self {
            keepalive_secs: config.ssh.keepalive_secs,
            color_scheme: config.terminal.color_scheme.clone(),
            record_sessions: config.recording.enabled,
            auto_reconnect: config.ssh.auto_reconnect,
        }
    }
}

impl Default for GlobalDefaults {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

/// Where the resolved password is stored (its value is never copied by resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretOrigin {
    /// The level that supplied it.
    pub source: Source,
    /// The identity it belongs to (`None`: the level's inline `password`).
    pub identity: Option<ItemId>,
}

/// A problem found while resolving (the value resolved as if unset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolveWarning {
    /// A group in the chain no longer exists.
    MissingGroup(ItemId),
    /// The group chain loops back to this group (corrupt data).
    GroupCycle(ItemId),
    /// The group chain is deeper than [`MAX_GROUP_DEPTH`].
    DepthLimit,
    /// A referenced identity no longer exists.
    MissingIdentity(ItemId),
    /// A referenced key, snippet, jump host or forward no longer exists.
    MissingItem(ItemId),
}

impl ResolveWarning {
    /// The chip shown in the detail pane.
    pub fn chip(&self) -> &'static str {
        match self {
            Self::MissingGroup(_) => "missing group",
            Self::GroupCycle(_) | Self::DepthLimit => "group cycle",
            Self::MissingIdentity(_) => "missing identity",
            Self::MissingItem(_) => "missing reference",
        }
    }
}

/// What a host connects with: every setting resolved, plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    /// `label` (may be empty).
    pub label: String,
    /// Hostname or IP literal.
    pub address: String,
    /// Port (22 when nothing sets one).
    pub port: u16,
    /// The host's group, if it exists.
    pub group_id: Option<ItemId>,
    /// The groups walked, nearest first.
    pub group_chain: Vec<ItemId>,
    /// The identity in effect.
    pub identity_id: Option<ItemId>,
    /// Login user (`None`: the connector falls back to the local user).
    pub username: Option<String>,
    /// Where the password is stored, if any.
    pub password: Option<SecretOrigin>,
    /// The key in effect.
    pub key_id: Option<ItemId>,
    /// Hosts to hop through, in order (missing ones dropped).
    pub jump_chain: Vec<ItemId>,
    /// `proxy.*`
    pub proxy: Option<ProxySettings>,
    /// Agent forwarding.
    pub agent_forwarding: bool,
    /// Which agent answers.
    pub agent_source: AgentSource,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Snippet run after the shell opens.
    pub startup_snippet_id: Option<ItemId>,
    /// Keepalive interval (`0` disables).
    pub keepalive_secs: u32,
    /// Remote charset ([`DEFAULT_CHARSET`] by default).
    pub charset: String,
    /// What Backspace sends.
    pub backspace: Backspace,
    /// Color scheme name.
    pub color_scheme: String,
    /// Forwarding rules auto-started with this host (missing ones dropped).
    pub port_forwards: Vec<ItemId>,
    /// Legacy algorithm opt-ins.
    pub algorithms: Option<AlgoOverrides>,
    /// Request a PTY for exec runs.
    pub request_pty_for_exec: bool,
    /// Record sessions.
    pub record_sessions: bool,
    /// Reconnect automatically after a drop.
    pub auto_reconnect: bool,
    /// Where each setting came from.
    pub provenance: Provenance,
    /// Missing references and chain problems (sorted, deduplicated).
    pub warnings: Vec<ResolveWarning>,
}

impl ResolvedHost {
    /// Where `key` came from.
    pub fn source(&self, key: SettingKey) -> &Source {
        self.provenance.get(key)
    }

    /// Whether at least one setting comes from `group`.
    pub fn inherits_from(&self, group: ItemId) -> bool {
        self.provenance.uses_group(group)
    }

    /// The host's group reference points nowhere.
    pub fn missing_group(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| matches!(w, ResolveWarning::MissingGroup(_)))
    }

    /// The resolved value of `key` as short text for the UI (`None`: nothing set).
    /// References are shown by short id; callers swap in names.
    pub fn display(&self, key: SettingKey) -> Option<String> {
        let yn = |b: bool| if b { "yes" } else { "no" }.to_owned();
        let count = |n: usize, what: &str| format!("{n} {what}");
        Some(match key {
            SettingKey::Port => self.port.to_string(),
            SettingKey::IdentityId => self.identity_id?.short(),
            SettingKey::Username => self.username.clone()?,
            SettingKey::Password => {
                self.password.as_ref()?;
                "••••••".to_owned()
            }
            SettingKey::KeyId => self.key_id?.short(),
            SettingKey::JumpChain if self.jump_chain.is_empty() => return None,
            SettingKey::JumpChain => count(self.jump_chain.len(), "hop(s)"),
            SettingKey::Proxy => self.proxy.as_ref()?.describe(),
            SettingKey::AgentForwarding => yn(self.agent_forwarding),
            SettingKey::AgentSource => self.agent_source.as_wire().to_owned(),
            SettingKey::Env if self.env.is_empty() => return None,
            SettingKey::Env => count(self.env.len(), "variable(s)"),
            SettingKey::StartupSnippetId => self.startup_snippet_id?.short(),
            SettingKey::KeepaliveSecs => self.keepalive_secs.to_string(),
            SettingKey::Charset => self.charset.clone(),
            SettingKey::Backspace => self.backspace.as_wire().to_owned(),
            SettingKey::ColorScheme => self.color_scheme.clone(),
            SettingKey::PortForwards if self.port_forwards.is_empty() => return None,
            SettingKey::PortForwards => count(self.port_forwards.len(), "rule(s)"),
            SettingKey::Algorithms => {
                self.algorithms.as_ref()?;
                "custom".to_owned()
            }
            SettingKey::RequestPtyForExec => yn(self.request_pty_for_exec),
            SettingKey::RecordSessions => yn(self.record_sessions),
            SettingKey::AutoReconnect => yn(self.auto_reconnect),
        })
    }
}

// ---------------------------------------------------------------------- resolution

/// What is being resolved besides its settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    /// `label`
    pub label: String,
    /// `address`
    pub address: String,
    /// `group_id` (for a group's own editor: its parent).
    pub group_id: Option<ItemId>,
}

impl Target {
    /// The target of `host`.
    pub fn of(host: &Host) -> Self {
        Self {
            label: host.label.clone(),
            address: host.address.clone(),
            group_id: host.group_id,
        }
    }
}

/// The group chain from `start` up (nearest first): cycle-safe, depth-limited,
/// stopping at a missing group.
pub fn group_chain<'a, L: ItemLookup + ?Sized>(
    start: Option<ItemId>,
    lookup: &'a L,
    warnings: &mut Vec<ResolveWarning>,
) -> Vec<(ItemId, &'a GroupNode)> {
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cur = start;
    while let Some(id) = cur {
        if chain.len() >= MAX_GROUP_DEPTH {
            debug!(group = %id.short(), "group chain too deep");
            warnings.push(ResolveWarning::DepthLimit);
            break;
        }
        if !seen.insert(id) {
            debug!(group = %id.short(), "group cycle");
            warnings.push(ResolveWarning::GroupCycle(id));
            break;
        }
        match lookup.group(id) {
            Some(node) => {
                chain.push((id, node));
                cur = node.parent_id;
            }
            None => {
                debug!(group = %id.short(), "missing group reference");
                warnings.push(ResolveWarning::MissingGroup(id));
                break;
            }
        }
    }
    chain
}

/// Resolve a host (§4.3).
pub fn resolve<L: ItemLookup + ?Sized>(
    host: &Host,
    lookup: &L,
    vault_defaults: Option<&Settings>,
    config: &Config,
) -> ResolvedHost {
    resolve_settings(
        &Target::of(host),
        &Settings::from_host(host),
        lookup,
        vault_defaults,
        &GlobalDefaults::from_config(config),
    )
}

type Layer<'a> = (Source, &'a Settings);

fn first<T>(
    layers: &[Layer<'_>],
    mut f: impl FnMut(&Settings) -> Option<T>,
) -> Option<(T, Source)> {
    layers
        .iter()
        .find_map(|(src, s)| f(s).map(|v| (v, src.clone())))
}

/// Resolve `own` (a host's level, or an empty level for a group's editor) under
/// `target.group_id`, the vault defaults and the globals.
pub fn resolve_settings<L: ItemLookup + ?Sized>(
    target: &Target,
    own: &Settings,
    lookup: &L,
    vault_defaults: Option<&Settings>,
    globals: &GlobalDefaults,
) -> ResolvedHost {
    let mut warnings = Vec::new();
    let chain = group_chain(target.group_id, lookup, &mut warnings);
    let mut layers: Vec<Layer<'_>> = vec![(Source::Host, own)];
    for (id, node) in &chain {
        layers.push((
            Source::Group {
                id: *id,
                name: node.name.clone(),
            },
            &node.defaults,
        ));
    }
    if let Some(v) = vault_defaults {
        layers.push((Source::VaultDefaults, v));
    }

    let mut prov = Provenance::default();
    let mut missing: Vec<ResolveWarning> = Vec::new();
    let mut take = |key: SettingKey, found: Option<Source>, fallback: Source| {
        prov.set(key, found.unwrap_or(fallback));
    };

    // An identity set at a level, if it exists.
    let identity_at = |s: &Settings, missing: &mut Vec<ResolveWarning>| {
        let id = s.identity_id?;
        match lookup.identity(id) {
            Some(node) => Some((id, node)),
            None => {
                debug!(identity = %id.short(), "missing identity reference");
                missing.push(ResolveWarning::MissingIdentity(id));
                None
            }
        }
    };
    let exists = |id: ItemId, missing: &mut Vec<ResolveWarning>| {
        let ok = lookup.exists(id);
        if !ok {
            debug!(item = %id.short(), "missing reference");
            missing.push(ResolveWarning::MissingItem(id));
        }
        ok
    };

    let port = first(&layers, |s| s.port);
    take(
        SettingKey::Port,
        port.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let identity = first(&layers, |s| identity_at(s, &mut missing).map(|(id, _)| id));
    take(
        SettingKey::IdentityId,
        identity.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let username = first(&layers, |s| {
        s.username.clone().or_else(|| {
            identity_at(s, &mut missing)
                .map(|(_, i)| i.username.clone())
                .filter(|u| !u.is_empty())
        })
    });
    take(
        SettingKey::Username,
        username.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let password = first(&layers, |s| {
        if s.password {
            Some(None)
        } else {
            identity_at(s, &mut missing)
                .filter(|(_, i)| i.has_password)
                .map(|(id, _)| Some(id))
        }
    });
    take(
        SettingKey::Password,
        password.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let key_id = first(&layers, |s| {
        s.key_id.filter(|k| exists(*k, &mut missing)).or_else(|| {
            identity_at(s, &mut missing)
                .and_then(|(_, i)| i.key_id)
                .filter(|k| exists(*k, &mut missing))
        })
    });
    take(
        SettingKey::KeyId,
        key_id.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let live_list = |ids: Vec<ItemId>, missing: &mut Vec<ResolveWarning>| -> Vec<ItemId> {
        ids.into_iter().filter(|id| exists(*id, missing)).collect()
    };
    let jump_chain = first(&layers, |s| s.jump_chain.clone());
    take(
        SettingKey::JumpChain,
        jump_chain.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let port_forwards = first(&layers, |s| s.port_forwards.clone());
    take(
        SettingKey::PortForwards,
        port_forwards.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );

    let proxy = first(&layers, |s| s.proxy.clone());
    take(
        SettingKey::Proxy,
        proxy.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let agent_forwarding = first(&layers, |s| s.agent_forwarding);
    take(
        SettingKey::AgentForwarding,
        agent_forwarding.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let agent_source = first(&layers, |s| s.agent_source);
    take(
        SettingKey::AgentSource,
        agent_source.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let env = first(&layers, |s| s.env.clone());
    take(
        SettingKey::Env,
        env.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let snippet = first(&layers, |s| {
        s.startup_snippet_id.filter(|id| exists(*id, &mut missing))
    });
    take(
        SettingKey::StartupSnippetId,
        snippet.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let keepalive = first(&layers, |s| s.keepalive_secs);
    take(
        SettingKey::KeepaliveSecs,
        keepalive.as_ref().map(|p| p.1.clone()),
        Source::GlobalConfig,
    );
    let charset = first(&layers, |s| s.charset.clone());
    take(
        SettingKey::Charset,
        charset.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let backspace = first(&layers, |s| s.backspace);
    take(
        SettingKey::Backspace,
        backspace.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let scheme = first(&layers, |s| s.color_scheme.clone());
    take(
        SettingKey::ColorScheme,
        scheme.as_ref().map(|p| p.1.clone()),
        Source::GlobalConfig,
    );
    let algorithms = first(&layers, |s| s.algorithms.clone());
    take(
        SettingKey::Algorithms,
        algorithms.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let pty = first(&layers, |s| s.request_pty_for_exec);
    take(
        SettingKey::RequestPtyForExec,
        pty.as_ref().map(|p| p.1.clone()),
        Source::BuiltinDefault,
    );
    let record = first(&layers, |s| s.record_sessions);
    take(
        SettingKey::RecordSessions,
        record.as_ref().map(|p| p.1.clone()),
        Source::GlobalConfig,
    );
    let auto_reconnect = first(&layers, |s| s.auto_reconnect);
    take(
        SettingKey::AutoReconnect,
        auto_reconnect.as_ref().map(|p| p.1.clone()),
        Source::GlobalConfig,
    );

    let jump_chain = live_list(jump_chain.map(|p| p.0).unwrap_or_default(), &mut missing);
    let port_forwards = live_list(port_forwards.map(|p| p.0).unwrap_or_default(), &mut missing);

    warnings.extend(missing);
    warnings.sort();
    warnings.dedup();

    ResolvedHost {
        label: target.label.clone(),
        address: target.address.clone(),
        port: port.map_or(DEFAULT_SSH_PORT, |p| p.0),
        group_id: chain.first().map(|(id, _)| *id),
        group_chain: chain.iter().map(|(id, _)| *id).collect(),
        identity_id: identity.map(|p| p.0),
        username: username.map(|p| p.0),
        password: password.map(|(identity, source)| SecretOrigin { source, identity }),
        key_id: key_id.map(|p| p.0),
        jump_chain,
        proxy: proxy.map(|p| p.0),
        agent_forwarding: agent_forwarding.is_some_and(|p| p.0),
        agent_source: agent_source.map_or(AgentSource::Builtin, |p| p.0),
        env: env.map(|p| p.0).unwrap_or_default(),
        startup_snippet_id: snippet.map(|p| p.0),
        keepalive_secs: keepalive.map_or(globals.keepalive_secs, |p| p.0),
        charset: charset.map_or_else(|| DEFAULT_CHARSET.to_owned(), |p| p.0),
        backspace: backspace.map_or(Backspace::Del, |p| p.0),
        color_scheme: scheme.map_or_else(|| globals.color_scheme.clone(), |p| p.0),
        port_forwards,
        algorithms: algorithms.map(|p| p.0),
        request_pty_for_exec: pty.is_some_and(|p| p.0),
        record_sessions: record.map_or(globals.record_sessions, |p| p.0),
        auto_reconnect: auto_reconnect.map_or(globals.auto_reconnect, |p| p.0),
        provenance: prov,
        warnings,
    }
}

/// The password a [`SecretOrigin`] points at (the connector's read): the
/// identity's when the origin names one, else the inline password of that level.
/// `group` and `identity` look up live items; `vault_defaults` is the vault-defaults
/// item's `defaults`.
pub fn password_for<'a>(
    origin: &SecretOrigin,
    host: &'a Host,
    group: impl Fn(ItemId) -> Option<&'a Group>,
    identity: impl Fn(ItemId) -> Option<&'a Identity>,
    vault_defaults: Option<&'a HostDefaults>,
) -> Option<&'a crate::secret::SecretString> {
    if let Some(id) = origin.identity {
        return identity(id)?.password.as_ref();
    }
    match &origin.source {
        Source::Host => host.password.as_ref(),
        Source::Group { id, .. } => group(*id)?.defaults.password.as_ref(),
        Source::VaultDefaults => vault_defaults?.password.as_ref(),
        // An override's inline password is read from the override item by
        // the caller (it is not one of these levels).
        Source::GlobalConfig | Source::BuiltinDefault | Source::Override { .. } => None,
    }
}

/// How many of `hosts` take at least one setting from `group` (the group detail's
/// "N hosts inherit these settings").
pub fn count_inheriting<'a>(
    group: ItemId,
    resolved: impl IntoIterator<Item = &'a ResolvedHost>,
) -> usize {
    resolved
        .into_iter()
        .filter(|r| r.inherits_from(group))
        .count()
}
