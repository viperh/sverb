//! Typed views for hosts and groups (SPEC §4.2, §4.3).

use super::body::ItemBody;
use super::fields::{Reader, ViewError, Writer, check_kind, wire_enum};
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use crate::secret::SecretString;

/// The port used when neither the host nor its groups set one.
pub const DEFAULT_SSH_PORT: u16 = 22;

wire_enum!(
    /// Which agent answers forwarded agent requests (§6.1.6).
    AgentSource {
        /// sverb's built-in agent (the default).
        Builtin => "builtin",
        /// The system agent (`SSH_AUTH_SOCK` / Pageant).
        System => "system",
        /// Both, built-in first.
        Both => "both",
    }
);

wire_enum!(
    /// What the Backspace key sends.
    Backspace {
        /// `0x7f`.
        Del => "del",
        /// `0x08`.
        CtrlH => "ctrl-h",
    }
);

/// Credentials for a SOCKS5 or HTTP proxy.
#[derive(Debug)]
pub struct ProxyAuth {
    /// `proxy.auth.user`
    pub user: String,
    /// `proxy.auth.password`
    pub password: Option<SecretString>,
}

/// How to reach the host (§6.1.5). Flattened into `proxy.*` keys.
#[derive(Debug)]
pub enum Proxy {
    /// `proxy.kind = "socks5"`, `proxy.addr`, `proxy.auth.*`
    Socks5 {
        /// `host:port` of the proxy.
        addr: String,
        /// Optional user/password.
        auth: Option<ProxyAuth>,
    },
    /// `proxy.kind = "http"` (HTTP CONNECT), `proxy.addr`, `proxy.auth.*`
    Http {
        /// `host:port` of the proxy.
        addr: String,
        /// Optional basic auth.
        auth: Option<ProxyAuth>,
    },
    /// `proxy.kind = "command"`, `proxy.command` (ProxyCommand, `%h %p %r %%`).
    Command(String),
}

/// Per-host opt-in to algorithms that are disabled by default (§6.1.8).
/// Each list is extra algorithm names to enable, in preference order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlgoOverrides {
    /// `algorithms.kex`
    pub kex: Option<Vec<String>>,
    /// `algorithms.host_key`
    pub host_key: Option<Vec<String>>,
    /// `algorithms.cipher`
    pub cipher: Option<Vec<String>>,
    /// `algorithms.mac`
    pub mac: Option<Vec<String>>,
    /// `algorithms.compression`
    pub compression: Option<Vec<String>>,
}

impl AlgoOverrides {
    fn is_empty(&self) -> bool {
        self.kex.is_none()
            && self.host_key.is_none()
            && self.cipher.is_none()
            && self.mac.is_none()
            && self.compression.is_none()
    }
}

const ALGO_KEYS: [&str; 5] = ["kex", "host_key", "cipher", "mac", "compression"];

fn read_algorithms(r: &Reader<'_>) -> Result<Option<AlgoOverrides>, ViewError> {
    let a = AlgoOverrides {
        kex: r.opt_strs("algorithms.kex")?,
        host_key: r.opt_strs("algorithms.host_key")?,
        cipher: r.opt_strs("algorithms.cipher")?,
        mac: r.opt_strs("algorithms.mac")?,
        compression: r.opt_strs("algorithms.compression")?,
    };
    Ok((!a.is_empty()).then_some(a))
}

fn write_algorithms(w: &mut Writer<'_>, a: Option<&AlgoOverrides>) {
    let empty = AlgoOverrides::default();
    let a = a.unwrap_or(&empty);
    let lists = [&a.kex, &a.host_key, &a.cipher, &a.mac, &a.compression];
    for (key, list) in ALGO_KEYS.iter().zip(lists) {
        w.opt_strs(&format!("algorithms.{key}"), list.as_deref());
    }
}

fn read_proxy(r: &Reader<'_>) -> Result<Option<Proxy>, ViewError> {
    let Some(kind) = r.opt_str("proxy.kind")? else {
        return Ok(None);
    };
    let auth = || -> Result<Option<ProxyAuth>, ViewError> {
        Ok(match r.opt_str("proxy.auth.user")? {
            Some(user) => Some(ProxyAuth {
                user,
                password: r.opt_secret("proxy.auth.password")?,
            }),
            None => None,
        })
    };
    Ok(Some(match kind.as_str() {
        "socks5" => Proxy::Socks5 {
            addr: r.str("proxy.addr")?,
            auth: auth()?,
        },
        "http" => Proxy::Http {
            addr: r.str("proxy.addr")?,
            auth: auth()?,
        },
        "command" => Proxy::Command(r.str("proxy.command")?),
        _ => return Err(r.type_err("proxy.kind")),
    }))
}

fn write_proxy(w: &mut Writer<'_>, proxy: Option<&Proxy>) {
    let (kind, addr, auth, command) = match proxy {
        None => (None, None, None, None),
        Some(Proxy::Socks5 { addr, auth }) => (Some("socks5"), Some(addr), auth.as_ref(), None),
        Some(Proxy::Http { addr, auth }) => (Some("http"), Some(addr), auth.as_ref(), None),
        Some(Proxy::Command(c)) => (Some("command"), None, None, Some(c)),
    };
    w.opt("proxy.kind", kind);
    w.opt("proxy.addr", addr.cloned());
    match auth {
        Some(a) => {
            w.always("proxy.auth.user", a.user.clone());
            w.opt_secret("proxy.auth.password", a.password.as_ref());
        }
        None => {
            w.clear("proxy.auth.user");
            w.clear("proxy.auth.password");
        }
    }
    w.opt("proxy.command", command.cloned());
}

/// A host (§4.2). `None` options fall through to the group chain, then to defaults.
#[derive(Debug, Default)]
pub struct Host {
    /// Display name. Use [`Host::display_label`], which falls back to `address`.
    pub label: String,
    /// Hostname, IPv4 or IPv6 literal (no brackets).
    pub address: String,
    /// Defaults to 22 ([`DEFAULT_SSH_PORT`]).
    pub port: Option<u16>,
    /// The group this host belongs to.
    pub group_id: Option<ItemId>,
    /// Tag items (whole-value LWW list).
    pub tags: Vec<ItemId>,
    /// Reusable credentials.
    pub identity_id: Option<ItemId>,
    /// Inline credential; overrides the identity.
    pub username: Option<String>,
    /// Inline credential.
    pub password: Option<SecretString>,
    /// Inline credential.
    pub key_id: Option<ItemId>,
    /// Ordered hosts to hop through (whole-value LWW list).
    pub jump_chain: Vec<ItemId>,
    /// `proxy.*`
    pub proxy: Option<Proxy>,
    /// Agent forwarding.
    pub agent_forwarding: Option<bool>,
    /// Which agent answers forwarded requests. Default `Builtin`.
    pub agent_source: Option<AgentSource>,
    /// Environment variables sent via `env` requests (whole-value LWW list).
    pub env: Vec<(String, String)>,
    /// Snippet run after the shell opens.
    pub startup_snippet_id: Option<ItemId>,
    /// Keepalive interval.
    pub keepalive_secs: Option<u32>,
    /// Remote charset; UTF-8 when `None`.
    pub charset: Option<String>,
    /// What Backspace sends.
    pub backspace: Option<Backspace>,
    /// Theme name.
    pub color_scheme: Option<String>,
    /// Forwarding rules auto-started with this host (whole-value LWW list).
    pub port_forwards: Vec<ItemId>,
    /// Markdown notes.
    pub notes: Option<String>,
    /// Pinned to the top as a favorite.
    pub pinned: bool,
    /// `algorithms.*`
    pub algorithms: Option<AlgoOverrides>,
    /// Request a PTY for exec runs.
    pub request_pty_for_exec: Option<bool>,
    /// Record sessions to this host; `None` inherits (group chain, then
    /// `recording.enabled`). See [`resolve_record_sessions`].
    pub record_sessions: Option<bool>,
    /// Reconnect automatically after a drop; `None` inherits (group chain, then
    /// `ssh.auto_reconnect`).
    pub auto_reconnect: Option<bool>,
    /// The body's schema is newer than this build: show it, don't edit it (§4.1).
    pub read_only: bool,
    /// Which list fields are stored as an explicit empty list. An empty list that is
    /// not flagged here is absent and inherits (§4.3, `docs/data-model.md`).
    pub explicit_empty: ExplicitEmpty,
}

/// List fields of a [`Host`] stored as an explicit empty list (`[]`): "none, don't
/// inherit". A non-empty list is always set; an empty unflagged one inherits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExplicitEmpty {
    /// `jump_chain = []`
    pub jump_chain: bool,
    /// `env = []`
    pub env: bool,
    /// `port_forwards = []`
    pub port_forwards: bool,
}

fn stored_empty(body: &ItemBody, key: &str) -> bool {
    body.get(key)
        .and_then(ciborium::Value::as_array)
        .is_some_and(Vec::is_empty)
}

impl Host {
    /// `label`, or `address` when the label is empty (computed, never stored).
    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.address
        } else {
            &self.label
        }
    }

    /// The port to connect to when nothing else sets one.
    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_SSH_PORT)
    }

    /// Writes the fields that differ from `body` (each through [`ItemBody::set`]).
    /// Keys this view doesn't know are left untouched.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.text("address", &self.address);
        w.opt("port", self.port);
        w.opt("group_id", self.group_id);
        w.ids("tags", &self.tags);
        w.opt("identity_id", self.identity_id);
        w.opt("username", self.username.clone());
        w.opt_secret("password", self.password.as_ref());
        w.opt("key_id", self.key_id);
        // An empty list is written only when explicitly empty (else it inherits).
        let set = |v: bool, explicit: bool| !v || explicit;
        w.opt_ids(
            "jump_chain",
            set(self.jump_chain.is_empty(), self.explicit_empty.jump_chain)
                .then_some(self.jump_chain.as_slice()),
        );
        write_proxy(&mut w, self.proxy.as_ref());
        w.opt("agent_forwarding", self.agent_forwarding);
        w.opt_enum("agent_source", self.agent_source);
        w.opt_pairs(
            "env",
            set(self.env.is_empty(), self.explicit_empty.env).then_some(self.env.as_slice()),
        );
        w.opt("startup_snippet_id", self.startup_snippet_id);
        w.opt("keepalive_secs", self.keepalive_secs);
        w.opt("charset", self.charset.clone());
        w.opt_enum("backspace", self.backspace);
        w.opt("color_scheme", self.color_scheme.clone());
        w.opt_ids(
            "port_forwards",
            set(
                self.port_forwards.is_empty(),
                self.explicit_empty.port_forwards,
            )
            .then_some(self.port_forwards.as_slice()),
        );
        w.opt("notes", self.notes.clone());
        w.flag("pinned", self.pinned);
        write_algorithms(&mut w, self.algorithms.as_ref());
        w.opt("request_pty_for_exec", self.request_pty_for_exec);
        w.opt("record_sessions", self.record_sessions);
        w.opt("auto_reconnect", self.auto_reconnect);
    }
}

impl TryFrom<&ItemBody> for Host {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Host)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            address: r.str("address")?,
            port: r.int("port")?,
            group_id: r.opt_id("group_id")?,
            tags: r.ids("tags")?,
            identity_id: r.opt_id("identity_id")?,
            username: r.opt_str("username")?,
            password: r.opt_secret("password")?,
            key_id: r.opt_id("key_id")?,
            jump_chain: r.ids("jump_chain")?,
            proxy: read_proxy(&r)?,
            agent_forwarding: r.opt_bool("agent_forwarding")?,
            agent_source: r.opt_enum("agent_source")?,
            env: r.opt_pairs("env")?.unwrap_or_default(),
            startup_snippet_id: r.opt_id("startup_snippet_id")?,
            keepalive_secs: r.int("keepalive_secs")?,
            charset: r.opt_str("charset")?,
            backspace: r.opt_enum("backspace")?,
            color_scheme: r.opt_str("color_scheme")?,
            port_forwards: r.ids("port_forwards")?,
            notes: r.opt_str("notes")?,
            pinned: r.bool("pinned")?,
            algorithms: read_algorithms(&r)?,
            request_pty_for_exec: r.opt_bool("request_pty_for_exec")?,
            record_sessions: r.opt_bool("record_sessions")?,
            auto_reconnect: r.opt_bool("auto_reconnect")?,
            read_only,
            explicit_empty: ExplicitEmpty {
                jump_chain: stored_empty(body, "jump_chain"),
                env: stored_empty(body, "env"),
                port_forwards: stored_empty(body, "port_forwards"),
            },
        })
    }
}

/// Inheritable host settings (§4.3): the optional settings of [`Host`] without the
/// per-host identity fields (`label`, `address`, `group_id`, `tags`, `notes`,
/// `pinned`). Every field is optional, so `None` means "inherit". Stored under a
/// prefix (`defaults.` in a [`Group`]).
#[derive(Debug, Default)]
pub struct HostDefaults {
    /// `port`
    pub port: Option<u16>,
    /// `identity_id`
    pub identity_id: Option<ItemId>,
    /// `username`
    pub username: Option<String>,
    /// `password`
    pub password: Option<SecretString>,
    /// `key_id`
    pub key_id: Option<ItemId>,
    /// `jump_chain`
    pub jump_chain: Option<Vec<ItemId>>,
    /// `proxy.*`
    pub proxy: Option<Proxy>,
    /// `agent_forwarding`
    pub agent_forwarding: Option<bool>,
    /// `agent_source`
    pub agent_source: Option<AgentSource>,
    /// `env`
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
    /// `port_forwards`
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

impl HostDefaults {
    /// Reads the defaults stored under `prefix` (e.g. `"defaults."`).
    pub fn read(body: &ItemBody, prefix: &str) -> Result<Self, ViewError> {
        let r = Reader::with_prefix(body, prefix);
        Ok(Self {
            port: r.int("port")?,
            identity_id: r.opt_id("identity_id")?,
            username: r.opt_str("username")?,
            password: r.opt_secret("password")?,
            key_id: r.opt_id("key_id")?,
            jump_chain: r.opt_ids("jump_chain")?,
            proxy: read_proxy(&r)?,
            agent_forwarding: r.opt_bool("agent_forwarding")?,
            agent_source: r.opt_enum("agent_source")?,
            env: r.opt_pairs("env")?,
            startup_snippet_id: r.opt_id("startup_snippet_id")?,
            keepalive_secs: r.int("keepalive_secs")?,
            charset: r.opt_str("charset")?,
            backspace: r.opt_enum("backspace")?,
            color_scheme: r.opt_str("color_scheme")?,
            port_forwards: r.opt_ids("port_forwards")?,
            algorithms: read_algorithms(&r)?,
            request_pty_for_exec: r.opt_bool("request_pty_for_exec")?,
            record_sessions: r.opt_bool("record_sessions")?,
            auto_reconnect: r.opt_bool("auto_reconnect")?,
        })
    }

    /// Writes the changed defaults under `prefix`.
    pub fn write(&self, body: &mut ItemBody, prefix: &str, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.with_prefix(prefix, |w| self.write_with(w));
    }

    fn write_with(&self, w: &mut Writer<'_>) {
        w.opt("port", self.port);
        w.opt("identity_id", self.identity_id);
        w.opt("username", self.username.clone());
        w.opt_secret("password", self.password.as_ref());
        w.opt("key_id", self.key_id);
        w.opt_ids("jump_chain", self.jump_chain.as_deref());
        write_proxy(w, self.proxy.as_ref());
        w.opt("agent_forwarding", self.agent_forwarding);
        w.opt_enum("agent_source", self.agent_source);
        w.opt_pairs("env", self.env.as_deref());
        w.opt("startup_snippet_id", self.startup_snippet_id);
        w.opt("keepalive_secs", self.keepalive_secs);
        w.opt("charset", self.charset.clone());
        w.opt_enum("backspace", self.backspace);
        w.opt("color_scheme", self.color_scheme.clone());
        w.opt_ids("port_forwards", self.port_forwards.as_deref());
        write_algorithms(w, self.algorithms.as_ref());
        w.opt("request_pty_for_exec", self.request_pty_for_exec);
        w.opt("record_sessions", self.record_sessions);
        w.opt("auto_reconnect", self.auto_reconnect);
    }
}

/// Whether to record sessions to `host` (SPEC §7.5): the host's own `record_sessions`,
/// else the first group in `groups` (nearest first: the host's group, then its parents)
/// whose `defaults.record_sessions` is set, else the global `recording.enabled`.
/// `leader R` toggles a live session regardless.
pub fn resolve_record_sessions<'a>(
    host: &Host,
    groups: impl IntoIterator<Item = &'a HostDefaults>,
    global: bool,
) -> bool {
    host.record_sessions
        .or_else(|| groups.into_iter().find_map(|d| d.record_sessions))
        .unwrap_or(global)
}

/// A group of hosts (§4.3). `parent_id` cycles are rejected on write
/// (`validate::validate_group_parent`).
#[derive(Debug, Default)]
pub struct Group {
    /// `name`
    pub name: String,
    /// Parent group (nesting).
    pub parent_id: Option<ItemId>,
    /// Settings inherited by member hosts, stored under `defaults.*`.
    pub defaults: HostDefaults,
    /// `icon`
    pub icon: Option<String>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
    /// `is_vault_defaults`: this item holds its vault's defaults (§4.13), not a group
    /// of hosts. It is never shown in the tree and nothing references it.
    pub is_vault_defaults: bool,
}

/// Key prefix of [`Group::defaults`].
pub const GROUP_DEFAULTS_PREFIX: &str = "defaults.";

impl Group {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("parent_id", self.parent_id);
        w.opt("icon", self.icon.clone());
        w.flag("is_vault_defaults", self.is_vault_defaults);
        w.with_prefix(GROUP_DEFAULTS_PREFIX, |w| self.defaults.write_with(w));
    }
}

impl TryFrom<&ItemBody> for Group {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Group)?;
        let r = Reader::new(body);
        Ok(Self {
            name: r.str("name")?,
            parent_id: r.opt_id("parent_id")?,
            defaults: HostDefaults::read(body, GROUP_DEFAULTS_PREFIX)?,
            icon: r.opt_str("icon")?,
            read_only,
            is_vault_defaults: r.bool("is_vault_defaults")?,
        })
    }
}
