//! Approval of values that act on this machine (SPEC §17.1).
//!
//! Some settings make sverb do something **locally** when it connects: run a
//! ProxyCommand, listen on a non-loopback address, connect from this machine to a
//! non-loopback destination (remote forwards), or expose the system SSH agent. A
//! value like that, arriving through sync (or changed remotely), must never act
//! without an explicit approval on this device.
//!
//! - **Classification** ([`local_actions`]) runs on the **resolved** host (group and
//!   vault defaults can carry these values too). Each [`LocalAction`] is keyed by the
//!   item that *defines* the value (provenance), the field and the exact value.
//! - **Approvals** are rows `(item_id, field, sha256(value))` in the device-local
//!   `local_approvals` table (sverb-store), never synced. A changed value hashes
//!   differently, so its status becomes [`ApprovalStatus::ChangedSinceApproval`] and
//!   the user is asked again.
//! - **Pre-approved** are values typed on this device: the form save path calls
//!   [`typed_actions`] (values that changed in that save) and stores the rows; the
//!   import confirmation stores the values the preview showed. The device id of a
//!   stamp alone is never trusted (the database may have moved between devices).
//! - **Deny** is remembered for the running process only ([`DeviceApprovals::deny`]),
//!   so the user is not asked in a loop; the next start asks again.
//!
//! [`DeviceApprovals`] is the runtime view shared by the connector, the forward
//! manager, the import service and the UI: an in-memory copy of the table (checks are
//! synchronous) plus the session denials, writing approvals through an
//! [`ApprovalSink`] (the store).
//!
//! Values in [`LocalAction`] are not secrets (commands, addresses), but they may be
//! hostnames: log them at `debug` only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

use super::{ProxySettings, ResolvedHost, SettingKey, Source};
use crate::model::{
    AgentSource, ForwardKind, Group, Host, ItemBody, ItemId, ItemKind, PortForward, Proxy, WireEnum,
};

/// The field of a ProxyCommand (`proxy.kind = command`).
pub const PROXY_COMMAND_FIELD: &str = "proxy.command";
/// The field of a non-loopback local/dynamic listen address (`bind_addr:bind_port`).
pub const BIND_ADDR_FIELD: &str = "bind_addr";
/// The field of a non-loopback remote-forward destination (`dest_host:dest_port`).
pub const DEST_HOST_FIELD: &str = "dest_host";
/// The field of system-agent forwarding (value: `system` / `both`).
pub const AGENT_FIELD: &str = "agent_forwarding";

/// The message when the user denied a value in this session.
pub const BLOCKED_MESSAGE: &str = "blocked by approval policy";

/// SHA-256 of an approved value.
pub type ValueHash = [u8; 32];

/// SHA-256 of the exact `value` (the approval key's third part).
pub fn value_sha256(value: &str) -> ValueHash {
    Sha256::digest(value.as_bytes()).into()
}

/// 127.0.0.0/8, `::1` (brackets allowed) or `localhost`.
pub fn is_loopback(addr: &str) -> bool {
    let addr = addr.trim();
    addr.eq_ignore_ascii_case("localhost")
        || addr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `host:port`, an IPv6 literal in brackets (`[fe80::1]:22`).
pub fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ---------------------------------------------------------------------- actions

/// What a locally-acting value does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionKind {
    /// Runs a local process (ProxyCommand).
    ProxyCommand,
    /// Listens on a non-loopback address (local or dynamic forward).
    ForwardBind,
    /// Connects from this machine to a non-loopback destination (remote forward).
    ForwardDest,
    /// Forwards the system SSH agent (`agent_source = system | both`).
    SystemAgent,
}

impl ActionKind {
    /// The approval field.
    pub fn field(self) -> &'static str {
        match self {
            Self::ProxyCommand => PROXY_COMMAND_FIELD,
            Self::ForwardBind => BIND_ADDR_FIELD,
            Self::ForwardDest => DEST_HOST_FIELD,
            Self::SystemAgent => AGENT_FIELD,
        }
    }

    /// The kind of `field` (`None`: not a locally-acting field).
    pub fn from_field(field: &str) -> Option<Self> {
        [
            Self::ProxyCommand,
            Self::ForwardBind,
            Self::ForwardDest,
            Self::SystemAgent,
        ]
        .into_iter()
        .find(|k| k.field() == field)
    }

    /// A short label for lists (`ProxyCommand`, `listen`, `remote destination`, `agent`).
    pub fn label(self) -> &'static str {
        match self {
            Self::ProxyCommand => "ProxyCommand",
            Self::ForwardBind => "forward listens on",
            Self::ForwardDest => "forward connects to",
            Self::SystemAgent => "system agent forwarding",
        }
    }
}

/// A value that acts on this machine, keyed by the item that defines it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalAction {
    /// The item defining the value (host, group, vault-defaults group or forward).
    pub item_id: ItemId,
    /// What it does.
    pub kind: ActionKind,
    /// The exact value shown to the user and hashed.
    pub value: String,
}

impl LocalAction {
    /// A new action.
    pub fn new(item_id: ItemId, kind: ActionKind, value: impl Into<String>) -> Self {
        Self {
            item_id,
            kind,
            value: value.into(),
        }
    }

    /// The approval field.
    pub fn field(&self) -> &'static str {
        self.kind.field()
    }

    /// SHA-256 of the value.
    pub fn hash(&self) -> ValueHash {
        value_sha256(&self.value)
    }

    /// The question for the approval dialog / prompt.
    pub fn question(&self) -> String {
        match self.kind {
            ActionKind::ProxyCommand => {
                format!("This host runs a local command: `{}`. Allow?", self.value)
            }
            ActionKind::ForwardBind => format!(
                "This forward listens on {} (reachable from other machines). Allow?",
                self.value
            ),
            ActionKind::ForwardDest => format!(
                "This forward connects from this machine to {}. Allow?",
                self.value
            ),
            ActionKind::SystemAgent => format!(
                "This host forwards your system SSH agent (agent_source = {}). Allow?",
                self.value
            ),
        }
    }

    /// The headless error for host `host` (exit 5, §17.1).
    pub fn headless_message(&self, host: &str) -> String {
        let what = match self.kind {
            ActionKind::ProxyCommand => "uses a local command",
            ActionKind::ForwardBind => "has a forward listening on a non-loopback address",
            ActionKind::ForwardDest => "has a forward connecting from this machine",
            ActionKind::SystemAgent => "forwards your system SSH agent",
        };
        format!(
            "host \"{host}\" {what} that has not been approved on this device. Run: sverb approve {host}"
        )
    }
}

impl fmt::Display for LocalAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.field(), self.value)
    }
}

/// The ProxyCommand of `proxy` as an action of `item` (SOCKS5 / HTTP: none).
pub fn proxy_action(item: ItemId, proxy: &ProxySettings) -> Option<LocalAction> {
    match proxy {
        ProxySettings::Command(cmd) => Some(LocalAction::new(
            item,
            ActionKind::ProxyCommand,
            cmd.clone(),
        )),
        _ => None,
    }
}

/// The locally-acting values of forward `item` (§9.6, §17.1): a non-loopback
/// `bind_addr` of a local/dynamic rule, a non-loopback `dest_host` of a remote rule.
pub fn forward_actions(item: ItemId, rule: &PortForward) -> Vec<LocalAction> {
    match rule.kind {
        ForwardKind::Local | ForwardKind::Dynamic if !is_loopback(&rule.bind_addr) => {
            vec![LocalAction::new(
                item,
                ActionKind::ForwardBind,
                host_port(&rule.bind_addr, rule.bind_port),
            )]
        }
        ForwardKind::Remote => match &rule.dest_host {
            Some(h) if !is_loopback(h) => vec![LocalAction::new(
                item,
                ActionKind::ForwardDest,
                match rule.dest_port {
                    Some(p) => host_port(h, p),
                    None => h.clone(),
                },
            )],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Whether forwarding with `source` exposes the system agent.
pub fn agent_acts_locally(forwarding: bool, source: AgentSource) -> bool {
    forwarding && matches!(source, AgentSource::System | AgentSource::Both)
}

/// The items a host's settings can come from, besides the host itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostItems<'a> {
    /// The host.
    pub host_id: Option<ItemId>,
    /// The vault-defaults group of the host's vault (`Source::VaultDefaults`).
    pub vault_defaults: Option<ItemId>,
    /// The forwarding rules carried by the host (its `port_forwards` and the rules
    /// whose `host_id` is the host), with their items.
    pub forwards: &'a [(ItemId, PortForward)],
}

impl HostItems<'_> {
    /// The item that defines a value coming from `source`. `None` for the global
    /// config and built-in defaults (local, never synced: no approval), or an
    /// unsaved host.
    pub fn defining_item(&self, source: &Source) -> Option<ItemId> {
        match source {
            Source::Host => self.host_id,
            Source::Group { id, .. } => Some(*id),
            Source::VaultDefaults => self.vault_defaults,
            Source::GlobalConfig | Source::BuiltinDefault => None,
            // The user's own override item (personal vault).
            Source::Override { item } => Some(*item),
        }
    }
}

/// Every locally-acting value of `resolved` (and its forwards in `items`), keyed by
/// the defining items. Sorted and deduplicated.
///
/// System-agent forwarding is keyed by the item defining `agent_source` **and** the
/// one enabling `agent_forwarding` when they differ: either changing remotely asks
/// again.
pub fn local_actions(resolved: &ResolvedHost, items: &HostItems<'_>) -> Vec<LocalAction> {
    let mut out = Vec::new();
    if let Some(proxy) = &resolved.proxy
        && let Some(item) = items.defining_item(resolved.source(SettingKey::Proxy))
        && let Some(action) = proxy_action(item, proxy)
    {
        out.push(action);
    }
    if agent_acts_locally(resolved.agent_forwarding, resolved.agent_source) {
        let value = resolved.agent_source.as_wire();
        for key in [SettingKey::AgentSource, SettingKey::AgentForwarding] {
            if let Some(item) = items.defining_item(resolved.source(key)) {
                out.push(LocalAction::new(item, ActionKind::SystemAgent, value));
            }
        }
    }
    for (id, rule) in items.forwards {
        out.extend(forward_actions(*id, rule));
    }
    out.sort();
    out.dedup();
    out
}

/// The locally-acting values of a saved body (host, group / vault defaults, forward)
/// as written on its own (no inheritance).
pub fn body_actions(id: ItemId, body: &ItemBody) -> Vec<LocalAction> {
    if body.is_deleted() {
        return Vec::new();
    }
    let (proxy, source) = match body.kind {
        ItemKind::Host => match Host::try_from(body) {
            Ok(h) => (h.proxy, h.agent_source),
            Err(_) => return Vec::new(),
        },
        ItemKind::Group => match Group::try_from(body) {
            Ok(g) => (g.defaults.proxy, g.defaults.agent_source),
            Err(_) => return Vec::new(),
        },
        ItemKind::PortForward => {
            return PortForward::try_from(body)
                .map(|rule| forward_actions(id, &rule))
                .unwrap_or_default();
        }
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(Proxy::Command(cmd)) = proxy {
        out.push(LocalAction::new(id, ActionKind::ProxyCommand, cmd));
    }
    // The source set here (system / both), whether or not forwarding is enabled at
    // this level: the resolved forwarding keys both items (see `local_actions`).
    if let Some(source @ (AgentSource::System | AgentSource::Both)) = source {
        out.push(LocalAction::new(
            id,
            ActionKind::SystemAgent,
            source.as_wire(),
        ));
    }
    out
}

/// The values the user typed in a save on this device: the actions of `after` that
/// were not already in `before` (`None`: a new item). Unchanged values (for example
/// a synced ProxyCommand on a host whose label was edited) are **not** included.
pub fn typed_actions(id: ItemId, before: Option<&ItemBody>, after: &ItemBody) -> Vec<LocalAction> {
    let old = before.map(|b| body_actions(id, b)).unwrap_or_default();
    body_actions(id, after)
        .into_iter()
        .filter(|a| !old.contains(a))
        .collect()
}

// ---------------------------------------------------------------------- status

/// The approval state of one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApprovalStatus {
    /// Approved on this device with this exact value.
    Approved,
    /// Never approved on this device.
    NeedsApproval,
    /// Approved before, but the value changed since.
    ChangedSinceApproval,
}

impl ApprovalStatus {
    /// `approved`, `needs approval`, `changed since approval`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NeedsApproval => "needs approval",
            Self::ChangedSinceApproval => "changed since approval",
        }
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read access to approval rows.
pub trait ApprovalLookup {
    /// The approved hash of `(item, field)`, if a row exists.
    fn approved_hash(&self, item: ItemId, field: &str) -> Option<ValueHash>;
}

impl ApprovalLookup for HashMap<(ItemId, String), ValueHash> {
    fn approved_hash(&self, item: ItemId, field: &str) -> Option<ValueHash> {
        self.get(&(item, field.to_owned())).copied()
    }
}

impl ApprovalLookup for BTreeMap<(ItemId, String), ValueHash> {
    fn approved_hash(&self, item: ItemId, field: &str) -> Option<ValueHash> {
        self.get(&(item, field.to_owned())).copied()
    }
}

/// The status of `action` against `approvals`.
pub fn status_of(
    action: &LocalAction,
    approvals: &(impl ApprovalLookup + ?Sized),
) -> ApprovalStatus {
    match approvals.approved_hash(action.item_id, action.field()) {
        Some(h) if h == action.hash() => ApprovalStatus::Approved,
        Some(_) => ApprovalStatus::ChangedSinceApproval,
        None => ApprovalStatus::NeedsApproval,
    }
}

/// A value with its approval status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// The value.
    pub action: LocalAction,
    /// Its status.
    pub status: ApprovalStatus,
}

/// Every action with its status (for `sverb approve` and the approvals list).
pub fn review(
    actions: Vec<LocalAction>,
    approvals: &(impl ApprovalLookup + ?Sized),
) -> Vec<PendingApproval> {
    actions
        .into_iter()
        .map(|action| PendingApproval {
            status: status_of(&action, approvals),
            action,
        })
        .collect()
}

/// The core decision (§17.1): the locally-acting values of `resolved` that are not
/// approved on this device. Empty: the connect may proceed.
pub fn requires_approval(
    resolved: &ResolvedHost,
    items: &HostItems<'_>,
    approvals: &(impl ApprovalLookup + ?Sized),
) -> Vec<PendingApproval> {
    review(local_actions(resolved, items), approvals)
        .into_iter()
        .filter(|p| p.status != ApprovalStatus::Approved)
        .collect()
}

// ---------------------------------------------------------------------- runtime

/// Where [`DeviceApprovals`] persists changes (the store's `local_approvals`).
pub trait ApprovalSink: Send + Sync + fmt::Debug {
    /// `(item, field)` was approved with `hash`.
    fn approved(&self, item: ItemId, field: &str, hash: ValueHash);
    /// `(item, field)` was revoked.
    fn revoked(&self, item: ItemId, field: &str);
}

/// The answer for one value at the moment it would act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Approved: act.
    Allow,
    /// Not approved: ask (TUI) or fail with exit 5 (headless).
    Ask(ApprovalStatus),
    /// Denied earlier in this session: fail with [`BLOCKED_MESSAGE`] without asking.
    Blocked,
}

/// The device's approvals at runtime: the `local_approvals` rows (in memory, so
/// checks are synchronous), the session's denials, and the sink that persists new
/// approvals. Shared (`Arc`) by everything that acts on these values.
#[derive(Default)]
pub struct DeviceApprovals {
    rows: RwLock<HashMap<(ItemId, String), ValueHash>>,
    denied: Mutex<HashSet<(ItemId, String, ValueHash)>>,
    sink: Option<Arc<dyn ApprovalSink>>,
}

impl fmt::Debug for DeviceApprovals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceApprovals")
            .field("rows", &self.rows.read().len())
            .field("denied", &self.denied.lock().len())
            .field("sink", &self.sink)
            .finish()
    }
}

impl ApprovalLookup for DeviceApprovals {
    fn approved_hash(&self, item: ItemId, field: &str) -> Option<ValueHash> {
        self.rows.read().get(&(item, field.to_owned())).copied()
    }
}

impl DeviceApprovals {
    /// Empty, not persisted (tests, unsaved targets).
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty, persisting through `sink`.
    pub fn with_sink(sink: Arc<dyn ApprovalSink>) -> Self {
        Self {
            sink: Some(sink),
            ..Self::default()
        }
    }

    /// Load `rows` (from the table) into memory, without persisting them.
    pub fn load(&self, rows: impl IntoIterator<Item = (ItemId, String, ValueHash)>) {
        let mut map = self.rows.write();
        for (item, field, hash) in rows {
            map.insert((item, field), hash);
        }
    }

    /// Replace the in-memory rows with `rows` (a reload after another process wrote).
    pub fn replace(&self, rows: impl IntoIterator<Item = (ItemId, String, ValueHash)>) {
        let fresh: HashMap<_, _> = rows.into_iter().map(|(i, f, h)| ((i, f), h)).collect();
        *self.rows.write() = fresh;
    }

    /// The status of `value` of `(item, field)`.
    pub fn status(&self, item: ItemId, field: &str, value: &str) -> ApprovalStatus {
        match self.approved_hash(item, field) {
            Some(h) if h == value_sha256(value) => ApprovalStatus::Approved,
            Some(_) => ApprovalStatus::ChangedSinceApproval,
            None => ApprovalStatus::NeedsApproval,
        }
    }

    /// Whether `value` of `(item, field)` is approved.
    pub fn is_approved(&self, item: ItemId, field: &str, value: &str) -> bool {
        self.status(item, field, value) == ApprovalStatus::Approved
    }

    /// What to do with `value` of `(item, field)` now.
    pub fn decide(&self, item: ItemId, field: &str, value: &str) -> Decision {
        match self.status(item, field, value) {
            ApprovalStatus::Approved => Decision::Allow,
            _ if self.is_denied(item, field, value) => Decision::Blocked,
            status => Decision::Ask(status),
        }
    }

    /// [`DeviceApprovals::decide`] for `action`.
    pub fn decide_action(&self, action: &LocalAction) -> Decision {
        self.decide(action.item_id, action.field(), &action.value)
    }

    /// Approve `value` (upsert; clears a session denial) and persist it.
    pub fn approve(&self, item: ItemId, field: &str, value: &str) {
        let hash = value_sha256(value);
        self.remember(item, field, hash);
        self.denied.lock().remove(&(item, field.to_owned(), hash));
        if let Some(sink) = &self.sink {
            sink.approved(item, field, hash);
        }
    }

    /// [`DeviceApprovals::approve`] for `action`.
    pub fn approve_action(&self, action: &LocalAction) {
        self.approve(action.item_id, action.field(), &action.value);
    }

    /// Record an approval already persisted by the caller (memory only).
    pub fn remember(&self, item: ItemId, field: &str, hash: ValueHash) {
        self.rows.write().insert((item, field.to_owned()), hash);
    }

    /// Forget a row already deleted by the caller (memory only).
    pub fn forget(&self, item: ItemId, field: &str) {
        self.rows.write().remove(&(item, field.to_owned()));
    }

    /// Revoke the approval of `(item, field)` and persist it.
    pub fn revoke(&self, item: ItemId, field: &str) {
        self.forget(item, field);
        if let Some(sink) = &self.sink {
            sink.revoked(item, field);
        }
    }

    /// Deny `value` for the rest of this session (not persisted, §2.2 decision).
    pub fn deny(&self, item: ItemId, field: &str, value: &str) {
        self.denied
            .lock()
            .insert((item, field.to_owned(), value_sha256(value)));
    }

    /// [`DeviceApprovals::deny`] for `action`.
    pub fn deny_action(&self, action: &LocalAction) {
        self.deny(action.item_id, action.field(), &action.value);
    }

    /// Whether `value` was denied in this session.
    pub fn is_denied(&self, item: ItemId, field: &str, value: &str) -> bool {
        self.denied
            .lock()
            .contains(&(item, field.to_owned(), value_sha256(value)))
    }

    /// Every row `(item, field, hash)`, sorted (the Settings → Security list).
    pub fn rows(&self) -> Vec<(ItemId, String, ValueHash)> {
        let mut out: Vec<_> = self
            .rows
            .read()
            .iter()
            .map(|((i, f), h)| (*i, f.clone(), *h))
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
