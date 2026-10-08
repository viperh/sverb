//! M1-07: what the Hosts view knows about hosts beyond the search index.
//!
//! The index (M1-05) orders and filters hosts but only holds searchable text. The
//! [`HostCatalog`] adds the remaining **non-secret** fields (port, credentials
//! references, connection settings, notes), tag colors, group / identity / key names
//! and the device-local `last_connected_at`. The vault service builds it
//! (`services::vault::items`) after every index change and the reducer keeps the
//! latest one; it is dropped on lock.
//!
//! Secrets never enter the catalog: a host's password is only `has_password`. The
//! one exception is [`HostRecord`], loaded on demand to prefill the edit form, whose
//! password is a redacted, zeroizing [`SecretValue`].

use std::collections::BTreeMap;
use std::fmt;

use sverb_core::model::{
    AgentSource, AlgoOverrides, Backspace, DEFAULT_SSH_PORT, ExplicitEmpty, Host, ItemId, Proxy,
    VaultId, WireEnum,
};
// M2-01
use sverb_core::resolve::{
    GlobalDefaults, LookupTable, ProxySettings, ResolvedHost, Settings, Target, resolve_settings,
};
use sverb_core::ssh_command::{Hop, KeySource, SshTarget};

use crate::widgets::form::SecretValue;

/// How a host reaches its target (`proxy.*`), without the proxy password.
#[derive(Clone, PartialEq, Eq)]
pub enum ProxySummary {
    /// SOCKS5 via `addr`.
    Socks5 {
        /// `host:port`.
        addr: String,
        /// Proxy user, if any.
        user: Option<String>,
    },
    /// HTTP CONNECT via `addr`.
    Http {
        /// `host:port`.
        addr: String,
        /// Proxy user, if any.
        user: Option<String>,
    },
    /// A ProxyCommand.
    Command(String),
}

impl fmt::Debug for ProxySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Socks5 { .. } => "Socks5",
            Self::Http { .. } => "Http",
            Self::Command(_) => "Command",
        };
        write!(f, "ProxySummary::{kind}(..)")
    }
}

impl ProxySummary {
    fn from_proxy(proxy: &Proxy) -> Self {
        match proxy {
            Proxy::Socks5 { addr, auth } => Self::Socks5 {
                addr: addr.clone(),
                user: auth.as_ref().map(|a| a.user.clone()),
            },
            Proxy::Http { addr, auth } => Self::Http {
                addr: addr.clone(),
                user: auth.as_ref().map(|a| a.user.clone()),
            },
            Proxy::Command(c) => Self::Command(c.clone()),
        }
    }

    // M2-01
    fn to_settings(&self) -> ProxySettings {
        match self {
            Self::Socks5 { addr, user } => ProxySettings::Socks5 {
                addr: addr.clone(),
                user: user.clone(),
                has_password: false,
            },
            Self::Http { addr, user } => ProxySettings::Http {
                addr: addr.clone(),
                user: user.clone(),
                has_password: false,
            },
            Self::Command(c) => ProxySettings::Command(c.clone()),
        }
    }

    /// One line for the detail pane.
    pub fn describe(&self) -> String {
        match self {
            Self::Socks5 { addr, user } => match user {
                Some(u) => format!("SOCKS5 {u}@{addr}"),
                None => format!("SOCKS5 {addr}"),
            },
            Self::Http { addr, user } => match user {
                Some(u) => format!("HTTP {u}@{addr}"),
                None => format!("HTTP {addr}"),
            },
            Self::Command(c) => format!("command: {c}"),
        }
    }
}

/// The non-secret fields of one host.
#[derive(Clone, PartialEq, Eq)]
pub struct HostSummary {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// `label` (may be empty: [`HostSummary::display_label`]).
    pub label: String,
    /// `address`.
    pub address: String,
    /// `port`.
    pub port: Option<u16>,
    /// `group_id`.
    pub group_id: Option<ItemId>,
    /// `tags`.
    pub tags: Vec<ItemId>,
    /// `identity_id`.
    pub identity_id: Option<ItemId>,
    /// `username`.
    pub username: Option<String>,
    /// An inline password is stored.
    pub has_password: bool,
    /// `key_id`.
    pub key_id: Option<ItemId>,
    /// `jump_chain`.
    pub jump_chain: Vec<ItemId>,
    /// `proxy.*` (no password).
    pub proxy: Option<ProxySummary>,
    /// `agent_forwarding`.
    pub agent_forwarding: Option<bool>,
    /// `agent_source` (wire string).
    pub agent_source: Option<String>,
    /// `env`.
    pub env: Vec<(String, String)>,
    /// `startup_snippet_id`.
    pub startup_snippet_id: Option<ItemId>,
    /// `keepalive_secs`.
    pub keepalive_secs: Option<u32>,
    /// `charset`.
    pub charset: Option<String>,
    /// `backspace` (wire string).
    pub backspace: Option<String>,
    /// `color_scheme`.
    pub color_scheme: Option<String>,
    /// `port_forwards`.
    pub port_forwards: Vec<ItemId>,
    /// `notes` (Markdown).
    pub notes: Option<String>,
    /// `pinned`.
    pub pinned: bool,
    /// `request_pty_for_exec`.
    pub request_pty_for_exec: Option<bool>,
    /// `record_sessions` (M3-05).
    pub record_sessions: Option<bool>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
    /// Device-local: last successful connect, UNIX ms.
    pub last_connected_at: Option<i64>,
    // M2-01
    /// Lists stored as explicitly empty (they don't inherit).
    pub explicit_empty: ExplicitEmpty,
    /// `algorithms.*`.
    pub algorithms: Option<AlgoOverrides>,
    // M1-16
    /// `auto_reconnect`.
    pub auto_reconnect: Option<bool>,
}

impl Default for HostSummary {
    /// An empty (unsaved) host with nil ids.
    fn default() -> Self {
        Self::from_host(
            ItemId::from_bytes([0; 16]),
            VaultId::from_bytes([0; 16]),
            &Host::default(),
            None,
        )
    }
}

impl HostSummary {
    /// The non-secret fields of `host`.
    pub fn from_host(
        id: ItemId,
        vault: VaultId,
        host: &Host,
        last_connected_at: Option<i64>,
    ) -> Self {
        Self {
            id,
            vault,
            label: host.label.clone(),
            address: host.address.clone(),
            port: host.port,
            group_id: host.group_id,
            tags: host.tags.clone(),
            identity_id: host.identity_id,
            username: host.username.clone(),
            has_password: host
                .password
                .as_ref()
                .is_some_and(|p| !p.expose().is_empty()),
            key_id: host.key_id,
            jump_chain: host.jump_chain.clone(),
            proxy: host.proxy.as_ref().map(ProxySummary::from_proxy),
            agent_forwarding: host.agent_forwarding,
            agent_source: host
                .agent_source
                .map(|a: AgentSource| a.as_wire().to_owned()),
            env: host.env.clone(),
            startup_snippet_id: host.startup_snippet_id,
            keepalive_secs: host.keepalive_secs,
            charset: host.charset.clone(),
            backspace: host.backspace.map(|b: Backspace| b.as_wire().to_owned()),
            color_scheme: host.color_scheme.clone(),
            port_forwards: host.port_forwards.clone(),
            notes: host.notes.clone(),
            pinned: host.pinned,
            request_pty_for_exec: host.request_pty_for_exec,
            record_sessions: host.record_sessions,
            read_only: host.read_only,
            last_connected_at,
            // M2-01
            explicit_empty: host.explicit_empty,
            algorithms: host.algorithms.clone(),
            // M1-16
            auto_reconnect: host.auto_reconnect,
        }
    }

    // M2-01
    /// The host's own level for settings resolution (no secret values).
    pub fn settings(&self) -> Settings {
        let list = |empty: bool, explicit: bool| !empty || explicit;
        Settings {
            port: self.port,
            identity_id: self.identity_id,
            username: self.username.clone().filter(|u| !u.is_empty()),
            password: self.has_password,
            key_id: self.key_id,
            jump_chain: list(self.jump_chain.is_empty(), self.explicit_empty.jump_chain)
                .then(|| self.jump_chain.clone()),
            proxy: self.proxy.as_ref().map(ProxySummary::to_settings),
            agent_forwarding: self.agent_forwarding,
            agent_source: self
                .agent_source
                .as_deref()
                .and_then(AgentSource::from_wire),
            env: list(self.env.is_empty(), self.explicit_empty.env).then(|| self.env.clone()),
            startup_snippet_id: self.startup_snippet_id,
            keepalive_secs: self.keepalive_secs,
            charset: self.charset.clone().filter(|c| !c.is_empty()),
            backspace: self.backspace.as_deref().and_then(Backspace::from_wire),
            color_scheme: self.color_scheme.clone().filter(|c| !c.is_empty()),
            port_forwards: list(
                self.port_forwards.is_empty(),
                self.explicit_empty.port_forwards,
            )
            .then(|| self.port_forwards.clone()),
            algorithms: self.algorithms.clone(),
            request_pty_for_exec: self.request_pty_for_exec,
            record_sessions: self.record_sessions,
            // M1-16
            auto_reconnect: self.auto_reconnect,
        }
    }

    // M2-01
    /// What resolution needs besides the settings.
    pub fn resolve_target(&self) -> Target {
        Target {
            label: self.label.clone(),
            address: self.address.clone(),
            group_id: self.group_id,
        }
    }

    /// `label`, or the address when the label is empty.
    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.address
        } else {
            &self.label
        }
    }

    /// `user@address:port` (port only when not 22; IPv6 bracketed before a port).
    pub fn target(&self, user: Option<&str>) -> String {
        format_target(user, &self.address, self.port)
    }
}

// M2-01
/// `user@address:port` (port only when not 22; IPv6 bracketed before a port).
pub fn format_target(user: Option<&str>, address: &str, port: Option<u16>) -> String {
    let mut out = String::new();
    if let Some(u) = user {
        out.push_str(u);
        out.push('@');
    }
    match port.filter(|p| *p != DEFAULT_SSH_PORT) {
        Some(p) if address.contains(':') => out.push_str(&format!("[{address}]:{p}")),
        Some(p) => out.push_str(&format!("{address}:{p}")),
        None => out.push_str(address),
    }
    out
}

impl fmt::Debug for HostSummary {
    // Decrypted user data stays out of logs (SPEC §17).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostSummary")
            .field("id", &self.id)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// A tag: name and color.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TagInfo {
    /// `name`.
    pub name: String,
    /// `color` (a color name or `#rrggbb`).
    pub color: Option<String>,
}

/// An identity: label, user name and key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityInfo {
    /// `label`.
    pub label: String,
    /// `username`.
    pub username: String,
    /// `key_id`.
    pub key_id: Option<ItemId>,
}

/// Everything the Hosts view shows, built by the vault service.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HostCatalog {
    /// Live (not deleted) hosts.
    pub hosts: BTreeMap<ItemId, HostSummary>,
    /// Tags by id.
    pub tags: BTreeMap<ItemId, TagInfo>,
    /// Group names by id.
    pub groups: BTreeMap<ItemId, String>,
    /// Identities by id.
    pub identities: BTreeMap<ItemId, IdentityInfo>,
    /// Key labels by id.
    pub keys: BTreeMap<ItemId, String>,
    /// Snippet names by id.
    pub snippets: BTreeMap<ItemId, String>,
    /// Vault display names.
    pub vault_names: BTreeMap<VaultId, String>,
    /// When it was built (UNIX ms): "last connected" is relative to it.
    pub loaded_at: i64,
    // M2-01
    /// Groups (with their defaults), identities and vault defaults for settings
    /// resolution, and every live item id (missing references, §12.4).
    pub lookup: LookupTable,
    /// The vault of each group.
    pub group_vaults: BTreeMap<ItemId, VaultId>,
    /// The vault of each tag (names are unique per vault, §4.11).
    pub tag_vaults: BTreeMap<ItemId, VaultId>,
    /// The Personal vault (new groups, tags and vault defaults go there).
    pub personal_vault: Option<VaultId>,
    // M2-03
    /// Keys for the Keychain (public data only: no private key, no passphrase).
    pub key_details: BTreeMap<ItemId, crate::views::keychain::keys::KeyInfo>,
    /// Certificates for the Keychain, with their derived fields.
    pub certs: BTreeMap<ItemId, crate::views::keychain::keys::CertSummary>,
}

impl fmt::Debug for HostCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostCatalog")
            .field("hosts", &self.hosts.len())
            .field("tags", &self.tags.len())
            .field("loaded_at", &self.loaded_at)
            .finish_non_exhaustive()
    }
}

impl HostCatalog {
    /// The effective user of `host` (M2-01: resolved through its groups and the
    /// vault defaults: inline `username`, its identity's, then inherited).
    pub fn user_of(&self, host: &HostSummary) -> Option<String> {
        self.resolve(host, &GlobalDefaults::default()).username
    }

    // M2-01
    /// Resolve `host` through its group chain, its vault's defaults and `globals`.
    pub fn resolve(&self, host: &HostSummary, globals: &GlobalDefaults) -> ResolvedHost {
        resolve_settings(
            &host.resolve_target(),
            &host.settings(),
            self,
            self.lookup.defaults_of(host.vault),
            globals,
        )
    }

    // M2-01
    /// What a host in `group` (of `vault`) would inherit: the group editor's and the
    /// host form's placeholders.
    pub fn inherited(
        &self,
        group: Option<ItemId>,
        vault: Option<VaultId>,
        globals: &GlobalDefaults,
    ) -> ResolvedHost {
        let vault = vault.or(self.personal_vault);
        resolve_settings(
            &Target {
                group_id: group,
                ..Target::default()
            },
            &Settings::default(),
            self,
            vault.and_then(|v| self.lookup.defaults_of(v)),
            globals,
        )
    }

    // M2-01
    /// The name of a group (`None` if it no longer exists).
    pub fn group_name(&self, id: ItemId) -> Option<&str> {
        self.lookup.groups.get(&id).map(|g| g.name.as_str())
    }

    // M2-01
    /// Groups in tree order (parents before children, siblings by name) with their
    /// depth. Cycle-safe.
    pub fn group_tree(&self) -> Vec<(ItemId, usize)> {
        let groups = &self.lookup.groups;
        let mut children: BTreeMap<Option<ItemId>, Vec<ItemId>> = BTreeMap::new();
        for (id, g) in groups {
            let parent = g.parent_id.filter(|p| groups.contains_key(p) && p != id);
            children.entry(parent).or_default().push(*id);
        }
        for kids in children.values_mut() {
            kids.sort_by_key(|id| (groups[id].name.to_lowercase(), *id));
        }
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut stack: Vec<(ItemId, usize)> = children
            .get(&None)
            .map(|k| k.iter().rev().map(|id| (*id, 0)).collect())
            .unwrap_or_default();
        while let Some((id, depth)) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            out.push((id, depth));
            if let Some(kids) = children.get(&Some(id)) {
                stack.extend(kids.iter().rev().map(|k| (*k, depth + 1)));
            }
        }
        // Groups only reachable through a cycle: list them at the top level.
        for id in groups.keys() {
            if !seen.contains(id) {
                out.push((*id, 0));
            }
        }
        out
    }

    // M2-01
    /// How many hosts take at least one setting from `group` ("N hosts inherit").
    pub fn inheriting_hosts(&self, group: ItemId) -> usize {
        let globals = GlobalDefaults::default();
        self.hosts
            .values()
            .filter(|h| self.resolve(h, &globals).inherits_from(group))
            .count()
    }

    // M2-01
    /// Hosts directly in `group`, and its direct subgroups.
    pub fn group_contents(&self, group: ItemId) -> (usize, usize) {
        let hosts = self
            .hosts
            .values()
            .filter(|h| h.group_id == Some(group))
            .count();
        let groups = self
            .lookup
            .groups
            .values()
            .filter(|g| g.parent_id == Some(group))
            .count();
        (hosts, groups)
    }

    /// The tags of `host` that exist, in the host's order.
    pub fn tags_of(&self, host: &HostSummary) -> Vec<TagInfo> {
        host.tags
            .iter()
            .filter_map(|t| self.tags.get(t).cloned())
            .collect()
    }

    /// The `ssh` command-line target for `host` (copy as command), from its resolved
    /// settings (M2-01: group defaults and vault defaults included).
    pub fn ssh_target(&self, host: &HostSummary) -> SshTarget {
        let globals = GlobalDefaults::default();
        let r = self.resolve(host, &globals);
        let port = |p: u16| (p != DEFAULT_SSH_PORT).then_some(p);
        // M2-05: `-J` lists the effective chain (hops' own chains expanded). A chain
        // that can't be expanded (cycle, too deep) is emitted as configured.
        let hops = self.effective_chain(host, &globals).unwrap_or_else(|_| {
            r.jump_chain
                .iter()
                .filter_map(|j| self.hosts.get(j))
                .map(|j| self.resolve(j, &globals))
                .collect()
        });
        let jump = hops
            .into_iter()
            .map(|hop| Hop {
                user: hop.username,
                address: hop.address,
                port: port(hop.port),
            })
            .collect();
        SshTarget {
            user: r.username.clone(),
            address: r.address.clone(),
            port: port(r.port),
            jump,
            // Keys have no recorded source path yet (M2-03 import may add one).
            key: r.key_id.map(|_| KeySource::Vault),
            proxy_command: match &r.proxy {
                Some(ProxySettings::Command(c)) => Some(c.clone()),
                _ => None,
            },
            agent_forwarding: r.agent_forwarding,
            env: r.env.clone(),
        }
    }

    // M2-05
    /// The effective jump chain of `host` (§6.1.4): its resolved chain with every hop's
    /// own chain expanded before it, in connection order (the host not included).
    ///
    /// # Errors
    /// A cycle or more than 8 hops.
    pub fn effective_chain(
        &self,
        host: &HostSummary,
        globals: &GlobalDefaults,
    ) -> Result<Vec<ResolvedHost>, sverb_core::resolve::ChainError> {
        let r = self.resolve(host, globals);
        let hops = sverb_core::resolve::expand_chain(Some(host.id), &r, |id| {
            self.hosts.get(&id).map(|h| self.resolve(h, globals))
        })?;
        Ok(hops.into_iter().map(|h| h.host).collect())
    }

    /// The `count` hosts connected most recently, newest first.
    pub fn recent(&self, count: usize) -> Vec<ItemId> {
        let mut hosts: Vec<&HostSummary> = self
            .hosts
            .values()
            .filter(|h| h.last_connected_at.is_some())
            .collect();
        hosts.sort_by(|a, b| {
            b.last_connected_at
                .cmp(&a.last_connected_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        hosts.into_iter().take(count).map(|h| h.id).collect()
    }
}

// M2-01: the catalog resolves through its lookup table; identities come from the
// table too (the `identities` map above stays for display).
impl sverb_core::resolve::ItemLookup for HostCatalog {
    fn group(&self, id: ItemId) -> Option<&sverb_core::resolve::GroupNode> {
        self.lookup.groups.get(&id)
    }

    fn identity(&self, id: ItemId) -> Option<&sverb_core::resolve::IdentityNode> {
        self.lookup.identities.get(&id)
    }

    fn exists(&self, id: ItemId) -> bool {
        sverb_core::resolve::ItemLookup::exists(&self.lookup, id)
    }
}

/// A host loaded for the edit form: the summary plus the inline password.
#[derive(Clone, PartialEq, Eq)]
pub struct HostRecord {
    /// The non-secret fields.
    pub summary: HostSummary,
    /// The inline password (redacted `Debug`, zeroized on drop).
    pub password: Option<SecretValue>,
}

impl fmt::Debug for HostRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostRecord")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}
