//! Where each resolved setting came from (SPEC §4.3).
//!
//! The UI renders it as `port: 2222 (from group "prod")`.

use std::collections::BTreeMap;
use std::fmt;

use crate::model::ItemId;

/// An inheritable setting of a host (§4.3: the optional fields of `Host` minus
/// label, address, group, tags, notes and pinned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SettingKey {
    /// `port`
    Port,
    /// `identity_id`
    IdentityId,
    /// `username`
    Username,
    /// `password`
    Password,
    /// `key_id`
    KeyId,
    /// `jump_chain`
    JumpChain,
    /// `proxy.*`
    Proxy,
    /// `agent_forwarding`
    AgentForwarding,
    /// `agent_source`
    AgentSource,
    /// `env`
    Env,
    /// `startup_snippet_id`
    StartupSnippetId,
    /// `keepalive_secs`
    KeepaliveSecs,
    /// `charset`
    Charset,
    /// `backspace`
    Backspace,
    /// `color_scheme`
    ColorScheme,
    /// `port_forwards`
    PortForwards,
    /// `algorithms.*`
    Algorithms,
    /// `request_pty_for_exec`
    RequestPtyForExec,
    /// `record_sessions`
    RecordSessions,
    /// `auto_reconnect` (spec addition)
    AutoReconnect,
}

impl SettingKey {
    /// Every key, in form order.
    pub const ALL: [SettingKey; 20] = [
        Self::Port,
        Self::IdentityId,
        Self::Username,
        Self::Password,
        Self::KeyId,
        Self::JumpChain,
        Self::Proxy,
        Self::AgentForwarding,
        Self::AgentSource,
        Self::Env,
        Self::StartupSnippetId,
        Self::KeepaliveSecs,
        Self::Charset,
        Self::Backspace,
        Self::ColorScheme,
        Self::PortForwards,
        Self::Algorithms,
        Self::RequestPtyForExec,
        Self::RecordSessions,
        Self::AutoReconnect,
    ];

    /// The model field name (also the host form's field key).
    pub const fn field(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::IdentityId => "identity_id",
            Self::Username => "username",
            Self::Password => "password",
            Self::KeyId => "key_id",
            Self::JumpChain => "jump_chain",
            Self::Proxy => "proxy",
            Self::AgentForwarding => "agent_forwarding",
            Self::AgentSource => "agent_source",
            Self::Env => "env",
            Self::StartupSnippetId => "startup_snippet_id",
            Self::KeepaliveSecs => "keepalive_secs",
            Self::Charset => "charset",
            Self::Backspace => "backspace",
            Self::ColorScheme => "color_scheme",
            Self::PortForwards => "port_forwards",
            Self::Algorithms => "algorithms",
            Self::RequestPtyForExec => "request_pty_for_exec",
            Self::RecordSessions => "record_sessions",
            Self::AutoReconnect => "auto_reconnect",
        }
    }

    /// The key whose model field is `field` (`proxy.kind` → `Proxy`).
    pub fn from_field(field: &str) -> Option<Self> {
        let head = field.split('.').next().unwrap_or(field);
        Self::ALL.into_iter().find(|k| k.field() == head)
    }
}

/// Where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The host itself.
    Host,
    /// A group in the host's chain (its own group or an ancestor).
    Group {
        /// The group.
        id: ItemId,
        /// Its name at resolution time.
        name: String,
    },
    /// The vault's defaults (§4.13).
    VaultDefaults,
    /// `config.toml`.
    GlobalConfig,
    /// sverb's built-in default (nothing set anywhere).
    BuiltinDefault,
    /// The user's own credential override for a shared host (§13.4), stored in
    /// their personal vault.
    Override {
        /// The override item.
        item: ItemId,
    },
}

impl Source {
    /// Whether the value is inherited (not set on the host itself).
    pub fn is_inherited(&self) -> bool {
        !matches!(self, Self::Host)
    }

    /// The group the value came from, if any.
    pub fn group(&self) -> Option<ItemId> {
        match self {
            Self::Group { id, .. } => Some(*id),
            _ => None,
        }
    }
}

impl fmt::Display for Source {
    /// `host`, `group "prod"`, `vault defaults`, `config`, `default`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => f.write_str("host"),
            Self::Group { name, .. } => write!(f, "group {name:?}"),
            Self::VaultDefaults => f.write_str("vault defaults"),
            Self::GlobalConfig => f.write_str("config"),
            Self::BuiltinDefault => f.write_str("default"),
            Self::Override { .. } => f.write_str("your override"),
        }
    }
}

/// The source of every resolved setting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance(BTreeMap<SettingKey, Source>);

impl Provenance {
    /// Record where `key` came from.
    pub fn set(&mut self, key: SettingKey, source: Source) {
        self.0.insert(key, source);
    }

    /// Where `key` came from (`BuiltinDefault` if never recorded).
    pub fn get(&self, key: SettingKey) -> &Source {
        self.0.get(&key).unwrap_or(&Source::BuiltinDefault)
    }

    /// Every recorded `(key, source)`.
    pub fn iter(&self) -> impl Iterator<Item = (SettingKey, &Source)> {
        self.0.iter().map(|(k, s)| (*k, s))
    }

    /// Whether any setting came from `group`.
    pub fn uses_group(&self, group: ItemId) -> bool {
        self.0.values().any(|s| s.group() == Some(group))
    }
}
