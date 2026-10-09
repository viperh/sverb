//! The dry-run pipeline (§9.13): displayed fields, classification against the vault
//! (new / duplicate / conflict), and materialization of the bodies to write under the
//! chosen target vault, group and conflict policy.

use std::collections::BTreeMap;

use ciborium::Value;

use super::{
    Draft, FieldDiff, ImportError, ImportPlan, PlanRef, PlanStatus, PlannedItem, ProxyDraftKind,
    show_env, show_opt,
};
use crate::model::{
    DeviceId, Group, HlcClock, Host, HostDefaults, ItemBody, ItemId, ItemKind, KnownHost,
    PortForward, Proxy, ProxyAuth, Tag, UnixMillis, VaultId, current_schema, merge, tag::tag_key,
};

// ---------------------------------------------------------------- displayed fields

fn put(fields: &mut BTreeMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        fields.insert(key.to_owned(), v);
    }
}

fn labels(plan: &ImportPlan, refs: &[PlanRef]) -> Option<String> {
    (!refs.is_empty()).then(|| {
        refs.iter()
            .map(|r| plan.label_of(*r))
            .collect::<Vec<_>>()
            .join(",")
    })
}

/// A short form of a (base64) public key for display.
fn short_key(key: &str) -> String {
    let tail: String = key
        .chars()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

fn known_host_fields(fields: &mut BTreeMap<String, String>, k: &KnownHost) {
    put(fields, "pattern", Some(k.host_pattern.clone()));
    put(fields, "type", Some(k.key_type.clone()));
    put(fields, "key", Some(short_key(&k.public_key)));
    let marker = match k.marker {
        crate::model::KnownHostMarker::None => None,
        crate::model::KnownHostMarker::CertAuthority => Some("@cert-authority".to_owned()),
        crate::model::KnownHostMarker::Revoked => Some("@revoked".to_owned()),
    };
    put(fields, "marker", marker);
}

/// The label of a stored body (label, name, pattern, …).
pub fn body_label(body: &ItemBody) -> String {
    for key in ["label", "name", "host_pattern", "command"] {
        if let Some(Value::Text(t)) = body.get(key)
            && !t.is_empty()
        {
            return t.clone();
        }
    }
    if let Some(Value::Text(t)) = body.get("address") {
        return t.clone();
    }
    String::new()
}

/// Computes [`PlannedItem::fields`] from the drafts (references shown by label).
pub fn fill_fields(plan: &mut ImportPlan) {
    let mut all = Vec::with_capacity(plan.items.len());
    for item in &plan.items {
        let mut f = BTreeMap::new();
        match &item.draft {
            Draft::Host(h) => {
                put(&mut f, "label", Some(h.label.clone()));
                put(&mut f, "address", Some(h.address.clone()));
                put(&mut f, "port", h.port.map(|p| p.to_string()));
                put(&mut f, "user", h.username.clone());
                put(
                    &mut f,
                    "group",
                    h.group.map(|g| plan.label_of(g).to_owned()),
                );
                put(&mut f, "tags", labels(plan, &h.tags));
                put(&mut f, "identity_files", Some(h.identity_files.join(",")));
                if h.no_jump {
                    put(&mut f, "jump", Some("none".to_owned()));
                } else {
                    put(&mut f, "jump", labels(plan, &h.jump_chain));
                }
                put(&mut f, "proxy_command", h.proxy_command.clone());
                put(&mut f, "proxy", h.proxy.as_ref().map(ToString::to_string));
                put(
                    &mut f,
                    "agent_forwarding",
                    h.agent_forwarding.map(|b| b.to_string()),
                );
                put(&mut f, "env", Some(show_env(&h.env)));
                put(&mut f, "keepalive", h.keepalive_secs.map(|s| s.to_string()));
                put(
                    &mut f,
                    "forwards",
                    (!h.forwards.is_empty()).then(|| h.forwards.len().to_string()),
                );
            }
            Draft::Group(g) => {
                put(&mut f, "name", Some(g.name.clone()));
                put(
                    &mut f,
                    "parent",
                    g.parent.map(|p| plan.label_of(p).to_owned()),
                );
                let d = &g.defaults;
                put(&mut f, "defaults.port", d.port.map(|p| p.to_string()));
                put(&mut f, "defaults.user", d.username.clone());
                put(
                    &mut f,
                    "defaults.identity_files",
                    Some(d.identity_files.join(",")),
                );
                put(&mut f, "defaults.jump", labels(plan, &d.jump_chain));
                put(&mut f, "defaults.proxy_command", d.proxy_command.clone());
                put(
                    &mut f,
                    "defaults.agent_forwarding",
                    d.agent_forwarding.map(|b| b.to_string()),
                );
                put(&mut f, "defaults.env", Some(show_env(&d.env)));
                put(
                    &mut f,
                    "defaults.keepalive",
                    d.keepalive_secs.map(|s| s.to_string()),
                );
            }
            Draft::Tag(name) => put(&mut f, "name", Some(name.clone())),
            Draft::Forward(fw) => {
                put(
                    &mut f,
                    "kind",
                    Some(crate::model::WireEnum::as_wire(&fw.kind).to_owned()),
                );
                put(&mut f, "host", Some(plan.label_of(fw.host).to_owned()));
                put(
                    &mut f,
                    "bind",
                    Some(format!("{}:{}", fw.bind_addr, fw.bind_port)),
                );
                put(
                    &mut f,
                    "dest",
                    fw.dest_host
                        .as_ref()
                        .map(|h| format!("{h}:{}", show_opt(fw.dest_port.as_ref()))),
                );
            }
            Draft::KnownHost(k) => known_host_fields(&mut f, k),
            Draft::Backup { id, body } => {
                put(&mut f, "id", Some(id.short()));
                if body.is_deleted() {
                    put(&mut f, "deleted", Some("true".to_owned()));
                }
            }
        }
        all.push(f);
    }
    for (item, f) in plan.items.iter_mut().zip(all) {
        item.fields = f;
    }
}

// ---------------------------------------------------------------- existing items

/// An existing live item.
#[derive(Debug, Clone)]
pub struct ExistingItem {
    /// Its id.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// Its body.
    pub body: ItemBody,
}

/// A snapshot of the vault to classify against. Hosts, groups, tags, forwards and known
/// hosts are matched within the target vault only (no cross-vault references); backup
/// items are matched by id in every vault.
#[derive(Debug, Clone)]
pub struct Existing {
    /// The target vault.
    pub vault: VaultId,
    items: Vec<ExistingItem>,
    by_id: BTreeMap<ItemId, usize>,
}

impl Existing {
    /// Builds the snapshot from every live item (all vaults) and the target vault.
    pub fn new(items: impl IntoIterator<Item = ExistingItem>, vault: VaultId) -> Self {
        let items: Vec<ExistingItem> = items.into_iter().filter(|i| !i.body.is_deleted()).collect();
        let by_id = items.iter().enumerate().map(|(i, it)| (it.id, i)).collect();
        Self {
            vault,
            items,
            by_id,
        }
    }

    /// An item by id (any vault).
    pub fn get(&self, id: ItemId) -> Option<&ExistingItem> {
        self.by_id.get(&id).map(|&i| &self.items[i])
    }

    /// Items of `kind` in the target vault.
    pub fn in_vault(&self, kind: ItemKind) -> impl Iterator<Item = &ExistingItem> {
        self.items
            .iter()
            .filter(move |i| i.vault == self.vault && i.body.kind == kind)
    }

    /// `(id, public key)` of every key in the target vault (identity-file dedup).
    pub fn key_publics(&self) -> Vec<(ItemId, String)> {
        self.in_vault(ItemKind::Key)
            .filter_map(|k| match k.body.get("public_key") {
                Some(Value::Text(t)) => Some((k.id, t.clone())),
                _ => None,
            })
            .collect()
    }

    fn label(&self, id: ItemId) -> String {
        self.get(id)
            .map(|i| body_label(&i.body))
            .unwrap_or_else(|| "?".to_owned())
    }

    fn host_fields(&self, h: &Host) -> BTreeMap<String, String> {
        let mut f = BTreeMap::new();
        put(&mut f, "label", Some(h.label.clone()));
        put(&mut f, "address", Some(h.address.clone()));
        put(&mut f, "port", h.port.map(|p| p.to_string()));
        put(&mut f, "user", h.username.clone());
        if h.jump_chain.is_empty() && h.explicit_empty.jump_chain {
            put(&mut f, "jump", Some("none".to_owned()));
        } else {
            let jump: Vec<String> = h.jump_chain.iter().map(|j| self.label(*j)).collect();
            put(&mut f, "jump", Some(jump.join(",")));
        }
        if let Some(Proxy::Command(c)) = &h.proxy {
            put(&mut f, "proxy_command", Some(c.clone()));
        }
        put(
            &mut f,
            "agent_forwarding",
            h.agent_forwarding.map(|b| b.to_string()),
        );
        put(&mut f, "env", Some(show_env(&h.env)));
        put(&mut f, "keepalive", h.keepalive_secs.map(|s| s.to_string()));
        f
    }

    fn defaults_fields(&self, d: &HostDefaults) -> BTreeMap<String, String> {
        let mut f = BTreeMap::new();
        put(&mut f, "defaults.port", d.port.map(|p| p.to_string()));
        put(&mut f, "defaults.user", d.username.clone());
        let jump: Vec<String> = d
            .jump_chain
            .iter()
            .flatten()
            .map(|j| self.label(*j))
            .collect();
        put(&mut f, "defaults.jump", Some(jump.join(",")));
        if let Some(Proxy::Command(c)) = &d.proxy {
            put(&mut f, "defaults.proxy_command", Some(c.clone()));
        }
        put(
            &mut f,
            "defaults.agent_forwarding",
            d.agent_forwarding.map(|b| b.to_string()),
        );
        put(&mut f, "defaults.env", d.env.as_deref().map(show_env));
        put(
            &mut f,
            "defaults.keepalive",
            d.keepalive_secs.map(|s| s.to_string()),
        );
        f
    }
}

const HOST_DIFF_KEYS: [&str; 9] = [
    "label",
    "address",
    "port",
    "user",
    "jump",
    "proxy_command",
    "agent_forwarding",
    "env",
    "keepalive",
];
const GROUP_DIFF_KEYS: [&str; 7] = [
    "defaults.port",
    "defaults.user",
    "defaults.jump",
    "defaults.proxy_command",
    "defaults.agent_forwarding",
    "defaults.env",
    "defaults.keepalive",
];

fn diff(
    keys: &[&str],
    existing: &BTreeMap<String, String>,
    imported: &BTreeMap<String, String>,
) -> Vec<FieldDiff> {
    let dash = "-".to_owned();
    keys.iter()
        .filter_map(|k| {
            let e = existing.get(*k).unwrap_or(&dash);
            let i = imported.get(*k).unwrap_or(&dash);
            (e != i).then(|| FieldDiff {
                field: (*k).to_owned(),
                existing: e.clone(),
                imported: i.clone(),
            })
        })
        .collect()
}

fn status(id: ItemId, diffs: Vec<FieldDiff>) -> PlanStatus {
    if diffs.is_empty() {
        PlanStatus::Duplicate(id)
    } else {
        PlanStatus::Conflict(id, diffs)
    }
}

/// A displayable value of a stamped field (secrets redacted).
fn show_value(key: &str, v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".to_owned(),
        Some(_) if crate::model::is_secret_field(key) => "[secret]".to_owned(),
        Some(Value::Text(t)) => t.clone(),
        Some(Value::Integer(i)) => i128::from(*i).to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Bytes(b)) if b.len() == 16 => ItemId::from_value(&Value::Bytes(b.clone()))
            .map_or_else(|| "<bytes>".to_owned(), |i| i.short()),
        Some(Value::Array(a)) => format!("[{} entries]", a.len()),
        Some(_) => "<value>".to_owned(),
    }
}

/// Classifies every item against `existing` (`target_group`: the group new top-level
/// groups and hosts go into, used to match groups by name and parent). Also adds the
/// "will be created" notes for new groups and tags.
pub fn classify(plan: &mut ImportPlan, existing: &Existing, target_group: Option<ItemId>) {
    let mut resolved: Vec<Option<ItemId>> = vec![None; plan.items.len()];
    for i in 0..plan.items.len() {
        let st = classify_one(plan, i, existing, target_group, &resolved);
        resolved[i] = match &st {
            PlanStatus::New => None,
            PlanStatus::Duplicate(id) | PlanStatus::Conflict(id, _) => Some(*id),
        };
        plan.items[i].status = st;
    }
    plan.notes.retain(|n| !n.ends_with("will be created"));
    let mut notes = Vec::new();
    for item in &plan.items {
        if item.status != PlanStatus::New {
            continue;
        }
        match &item.draft {
            Draft::Group(_) => {
                notes.push(format!(
                    "Group \"{}\" will be created",
                    group_path(plan, item)
                ));
            }
            Draft::Tag(name) => notes.push(format!("Tag \"{name}\" will be created")),
            _ => {}
        }
    }
    plan.notes.extend(notes);
}

fn group_path(plan: &ImportPlan, item: &PlannedItem) -> String {
    let mut parts = vec![item.label.clone()];
    let mut cur = match &item.draft {
        Draft::Group(g) => g.parent,
        _ => None,
    };
    let mut guard = 0;
    while let Some(p) = cur {
        guard += 1;
        if guard > 64 {
            break;
        }
        parts.push(plan.label_of(p).to_owned());
        cur = match plan.items.get(p).map(|i| &i.draft) {
            Some(Draft::Group(g)) => g.parent,
            _ => None,
        };
    }
    parts.reverse();
    parts.join("/")
}

fn classify_one(
    plan: &ImportPlan,
    i: usize,
    existing: &Existing,
    target_group: Option<ItemId>,
    resolved: &[Option<ItemId>],
) -> PlanStatus {
    let item = &plan.items[i];
    match &item.draft {
        Draft::Host(h) => {
            let user = h.username.as_deref();
            let port = h.port.unwrap_or(crate::model::DEFAULT_SSH_PORT);
            let found = existing.in_vault(ItemKind::Host).find_map(|e| {
                let host = Host::try_from(&e.body).ok()?;
                (host.address.eq_ignore_ascii_case(&h.address)
                    && host.port_or_default() == port
                    && host.username.as_deref() == user)
                    .then_some((e.id, host))
            });
            match found {
                None => PlanStatus::New,
                Some((id, host)) => {
                    let mut ex = existing.host_fields(&host);
                    let mut im = item.fields.clone();
                    // The port is compared with its default.
                    for f in [&mut ex, &mut im] {
                        f.entry("port".to_owned())
                            .or_insert_with(|| "22".to_owned());
                    }
                    status(id, diff(&HOST_DIFF_KEYS, &ex, &im))
                }
            }
        }
        Draft::Group(g) => {
            let parent = match g.parent {
                Some(p) => match resolved.get(p).copied().flatten() {
                    Some(id) => Some(id),
                    None => return PlanStatus::New, // the parent is new
                },
                None => target_group,
            };
            let found = existing.in_vault(ItemKind::Group).find_map(|e| {
                let group = Group::try_from(&e.body).ok()?;
                (!group.is_vault_defaults
                    && group.name.eq_ignore_ascii_case(&g.name)
                    && group.parent_id == parent)
                    .then_some((e.id, group))
            });
            match found {
                None => PlanStatus::New,
                Some((id, group)) => {
                    let ex = existing.defaults_fields(&group.defaults);
                    status(id, diff(&GROUP_DIFF_KEYS, &ex, &item.fields))
                }
            }
        }
        Draft::Tag(name) => {
            let key = tag_key(name);
            existing
                .in_vault(ItemKind::Tag)
                .find(|e| Tag::try_from(&e.body).is_ok_and(|t| tag_key(&t.name) == key))
                .map_or(PlanStatus::New, |e| PlanStatus::Duplicate(e.id))
        }
        Draft::KnownHost(k) => existing
            .in_vault(ItemKind::KnownHost)
            .find(|e| {
                KnownHost::try_from(&e.body).is_ok_and(|x| {
                    x.host_pattern == k.host_pattern
                        && x.key_type == k.key_type
                        && x.public_key == k.public_key
                })
            })
            .map_or(PlanStatus::New, |e| PlanStatus::Duplicate(e.id)),
        Draft::Forward(fw) => {
            let Some(host_id) = resolved.get(fw.host).copied().flatten() else {
                return PlanStatus::New;
            };
            let found = existing.in_vault(ItemKind::PortForward).find_map(|e| {
                let x = PortForward::try_from(&e.body).ok()?;
                (x.host_id == host_id && x.kind == fw.kind && x.bind_port == fw.bind_port)
                    .then_some((e.id, x))
            });
            match found {
                None => PlanStatus::New,
                Some((id, x)) => {
                    let mut ex = BTreeMap::new();
                    put(
                        &mut ex,
                        "bind",
                        Some(format!("{}:{}", x.bind_addr, x.bind_port)),
                    );
                    put(
                        &mut ex,
                        "dest",
                        x.dest_host
                            .as_ref()
                            .map(|h| format!("{h}:{}", show_opt(x.dest_port.as_ref()))),
                    );
                    status(id, diff(&["bind", "dest"], &ex, &item.fields))
                }
            }
        }
        Draft::Backup { id, body } => match existing.get(*id) {
            None => PlanStatus::New,
            Some(e) => {
                let m = merge::merge(&e.body, body);
                if !m.changed() {
                    return PlanStatus::Duplicate(*id);
                }
                let diffs = m
                    .changed_fields
                    .iter()
                    .map(|k| FieldDiff {
                        field: k.clone(),
                        existing: show_value(k, e.body.fields.get(k).map(|s| &s.value)),
                        imported: show_value(k, body.fields.get(k).map(|s| &s.value)),
                    })
                    .collect::<Vec<_>>();
                if diffs.is_empty() {
                    PlanStatus::Conflict(
                        *id,
                        vec![FieldDiff {
                            field: "deleted".to_owned(),
                            existing: e.body.is_deleted().to_string(),
                            imported: body.is_deleted().to_string(),
                        }],
                    )
                } else {
                    PlanStatus::Conflict(*id, diffs)
                }
            }
        },
    }
}

// ---------------------------------------------------------------- materialize

/// What happens to conflicting items.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ConflictPolicy {
    /// Keep the existing item (default).
    #[default]
    Skip,
    /// Write the imported values over the existing item (backups: merge by HLC).
    Overwrite,
    /// Create the imported item next to the existing one.
    KeepBoth,
}

impl ConflictPolicy {
    /// `skip`, `overwrite` or `keep-both`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Overwrite => "overwrite",
            Self::KeepBoth => "keep-both",
        }
    }

    /// Parses [`ConflictPolicy::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skip" => Some(Self::Skip),
            "overwrite" => Some(Self::Overwrite),
            "keep-both" => Some(Self::KeepBoth),
            _ => None,
        }
    }

    /// The next policy (a UI toggle).
    pub const fn next(self) -> Self {
        match self {
            Self::Skip => Self::Overwrite,
            Self::Overwrite => Self::KeepBoth,
            Self::KeepBoth => Self::Skip,
        }
    }
}

/// The confirmed choices.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// New items go into this vault.
    pub vault: Option<VaultId>,
    /// New hosts and top-level groups go into this group.
    pub group: Option<ItemId>,
    /// Conflicts.
    pub policy: ConflictPolicy,
    /// IdentityFile path (as written) → the Key item (imported or existing). Files not
    /// listed are not linked.
    pub identity_keys: BTreeMap<String, ItemId>,
}

/// Create or update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    /// A new item.
    Create,
    /// An existing item changed (overwrite).
    Update,
}

/// One body to store.
#[derive(Debug, Clone)]
pub struct ItemWrite {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The stamped body.
    pub body: ItemBody,
    /// Create or update.
    pub action: WriteAction,
}

/// A locally-acting value the user saw in the preview: approved at confirmation
/// .
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalNote {
    /// The item defining the value.
    pub item_id: ItemId,
    /// The field (`proxy.command`, `bind_addr`, `dest_host`).
    pub field: String,
    /// The exact value.
    pub value: String,
}

/// The result of [`materialize`].
#[derive(Debug, Clone, Default)]
pub struct WriteSet {
    /// Bodies to store, in one transaction.
    pub writes: Vec<ItemWrite>,
    /// Values approved at confirmation.
    pub approvals: Vec<ApprovalNote>,
    /// Duplicates (nothing written).
    pub duplicates: usize,
    /// Conflicts kept as they were (`skip`).
    pub conflicts_skipped: usize,
}

impl WriteSet {
    /// Items created.
    pub fn created(&self) -> usize {
        self.writes
            .iter()
            .filter(|w| w.action == WriteAction::Create)
            .count()
    }

    /// Items updated.
    pub fn updated(&self) -> usize {
        self.writes
            .iter()
            .filter(|w| w.action == WriteAction::Update)
            .count()
    }
}

/// Whether `host` is a loopback address (127.0.0.0/8, `::1`, `localhost`).
pub fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    h.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Builds the bodies to write for `plan` (classified with [`classify`]).
///
/// `new_id` makes ids for new items (backup items keep theirs when absent locally).
///
/// # Errors
/// [`ImportError::Inconsistent`] when an overwritten item vanished or a reference is
/// dangling; [`ImportError::Format`] when there is no target vault.
pub fn materialize(
    plan: &ImportPlan,
    existing: &Existing,
    opts: &ApplyOptions,
    clock: &mut HlcClock,
    device: DeviceId,
    new_id: &mut dyn FnMut() -> ItemId,
) -> Result<WriteSet, ImportError> {
    let vault = opts
        .vault
        .ok_or_else(|| ImportError::Format("no target vault".to_owned()))?;
    let mut out = WriteSet::default();

    // Pass 1: ids and actions.
    let mut ids: Vec<ItemId> = Vec::with_capacity(plan.items.len());
    let mut actions: Vec<Option<WriteAction>> = Vec::with_capacity(plan.items.len());
    for item in &plan.items {
        let (id, action) = match (&item.status, &item.draft) {
            (PlanStatus::New, Draft::Backup { id, .. }) => (*id, Some(WriteAction::Create)),
            (PlanStatus::New, _) => (new_id(), Some(WriteAction::Create)),
            (PlanStatus::Duplicate(id), _) => {
                out.duplicates += 1;
                (*id, None)
            }
            (PlanStatus::Conflict(id, _), _) => match opts.policy {
                ConflictPolicy::Skip => {
                    out.conflicts_skipped += 1;
                    (*id, None)
                }
                ConflictPolicy::Overwrite => (*id, Some(WriteAction::Update)),
                ConflictPolicy::KeepBoth => (new_id(), Some(WriteAction::Create)),
            },
        };
        ids.push(id);
        actions.push(action);
    }
    let id_of = |r: PlanRef| -> Result<ItemId, ImportError> {
        ids.get(r)
            .copied()
            .ok_or_else(|| ImportError::Inconsistent(format!("dangling reference {r}")))
    };
    let refs = |rs: &[PlanRef]| -> Result<Vec<ItemId>, ImportError> {
        rs.iter().map(|r| id_of(*r)).collect()
    };
    let key_of = |files: &[String]| -> Option<ItemId> {
        files
            .iter()
            .find_map(|f| opts.identity_keys.get(f).copied())
    };

    // Pass 2: bodies.
    for (i, item) in plan.items.iter().enumerate() {
        let Some(action) = actions[i] else {
            continue;
        };
        let id = ids[i];
        let (mut body, item_vault) = match action {
            WriteAction::Create => (ItemBody::new(item.kind, current_schema(item.kind)), vault),
            WriteAction::Update => {
                let e = existing
                    .get(id)
                    .ok_or_else(|| ImportError::Inconsistent(format!("{} vanished", item.label)))?;
                (e.body.clone(), e.vault)
            }
        };
        let view_err = |e: crate::model::ViewError| ImportError::Inconsistent(e.to_string());
        match &item.draft {
            Draft::Host(h) => {
                let mut host = Host::try_from(&body).map_err(view_err)?;
                host.label = h.label.clone();
                host.address = h.address.clone();
                if h.port.is_some() {
                    host.port = h.port;
                }
                if h.username.is_some() {
                    host.username = h.username.clone();
                }
                match h.group {
                    Some(g) => host.group_id = Some(id_of(g)?),
                    None if action == WriteAction::Create => host.group_id = opts.group,
                    None => {}
                }
                for t in refs(&h.tags)? {
                    if !host.tags.contains(&t) {
                        host.tags.push(t);
                    }
                }
                if let Some(k) = key_of(&h.identity_files) {
                    host.key_id = Some(k);
                }
                if h.no_jump {
                    host.jump_chain.clear();
                    host.explicit_empty.jump_chain = true;
                } else if !h.jump_chain.is_empty() {
                    host.jump_chain = refs(&h.jump_chain)?;
                }
                if let Some(c) = &h.proxy_command {
                    host.proxy = Some(Proxy::Command(c.clone()));
                    out.approvals.push(ApprovalNote {
                        item_id: id,
                        field: "proxy.command".to_owned(),
                        value: c.clone(),
                    });
                }
                // SOCKS5 / HTTP proxies (PuTTY); no password.
                if let Some(p) = &h.proxy {
                    let auth = p.user.clone().map(|user| ProxyAuth {
                        user,
                        password: None,
                    });
                    host.proxy = Some(match p.kind {
                        ProxyDraftKind::Socks5 => Proxy::Socks5 {
                            addr: p.addr.clone(),
                            auth,
                        },
                        ProxyDraftKind::Http => Proxy::Http {
                            addr: p.addr.clone(),
                            auth,
                        },
                    });
                }
                if h.agent_forwarding.is_some() {
                    host.agent_forwarding = h.agent_forwarding;
                }
                if !h.env.is_empty() {
                    host.env = h.env.clone();
                }
                if h.keepalive_secs.is_some() {
                    host.keepalive_secs = h.keepalive_secs;
                }
                for f in refs(&h.forwards)? {
                    if !host.port_forwards.contains(&f) {
                        host.port_forwards.push(f);
                    }
                }
                host.apply_to(&mut body, clock, device);
            }
            Draft::Group(g) => {
                let mut group = Group::try_from(&body).map_err(view_err)?;
                group.name = g.name.clone();
                match g.parent {
                    Some(p) => group.parent_id = Some(id_of(p)?),
                    None if action == WriteAction::Create => group.parent_id = opts.group,
                    None => {}
                }
                let d = &g.defaults;
                let gd = &mut group.defaults;
                if d.port.is_some() {
                    gd.port = d.port;
                }
                if d.username.is_some() {
                    gd.username = d.username.clone();
                }
                if let Some(k) = key_of(&d.identity_files) {
                    gd.key_id = Some(k);
                }
                if !d.jump_chain.is_empty() {
                    gd.jump_chain = Some(refs(&d.jump_chain)?);
                }
                if let Some(c) = &d.proxy_command {
                    gd.proxy = Some(Proxy::Command(c.clone()));
                    out.approvals.push(ApprovalNote {
                        item_id: id,
                        field: "proxy.command".to_owned(),
                        value: c.clone(),
                    });
                }
                if d.agent_forwarding.is_some() {
                    gd.agent_forwarding = d.agent_forwarding;
                }
                if !d.env.is_empty() {
                    gd.env = Some(d.env.clone());
                }
                if d.keepalive_secs.is_some() {
                    gd.keepalive_secs = d.keepalive_secs;
                }
                group.apply_to(&mut body, clock, device);
            }
            Draft::Tag(name) => {
                let mut tag = Tag::try_from(&body).map_err(view_err)?;
                tag.name = name.trim().to_owned();
                tag.apply_to(&mut body, clock, device);
            }
            Draft::Forward(fw) => {
                let rule = PortForward {
                    label: fw.label.clone(),
                    kind: fw.kind,
                    host_id: id_of(fw.host)?,
                    bind_addr: fw.bind_addr.clone(),
                    bind_port: fw.bind_port,
                    dest_host: fw.dest_host.clone(),
                    dest_port: fw.dest_port,
                    auto_start: true,
                    read_only: false,
                };
                approvals_for_forward(id, &rule, &mut out.approvals);
                rule.apply_to(&mut body, clock, device);
            }
            Draft::KnownHost(k) => {
                let mut entry = k.clone();
                if entry.added_at == UnixMillis::default() {
                    entry.added_at = UnixMillis::now();
                }
                entry.apply_to(&mut body, clock, device);
            }
            Draft::Backup { body: b, .. } => {
                body = match action {
                    WriteAction::Update => {
                        let e = existing.get(id).ok_or_else(|| {
                            ImportError::Inconsistent(format!("{} vanished", item.label))
                        })?;
                        merge::merge(&e.body, b).body
                    }
                    WriteAction::Create => (**b).clone(),
                };
                backup_approvals(id, &body, &mut out.approvals);
            }
        }
        out.writes.push(ItemWrite {
            id,
            vault: item_vault,
            body,
            action,
        });
    }
    Ok(out)
}

fn approvals_for_forward(id: ItemId, rule: &PortForward, out: &mut Vec<ApprovalNote>) {
    use crate::model::ForwardKind;
    match rule.kind {
        ForwardKind::Local | ForwardKind::Dynamic => {
            if !is_loopback(&rule.bind_addr) {
                out.push(ApprovalNote {
                    item_id: id,
                    field: "bind_addr".to_owned(),
                    value: format!("{}:{}", rule.bind_addr, rule.bind_port),
                });
            }
        }
        ForwardKind::Remote => {
            if let Some(h) = &rule.dest_host
                && !is_loopback(h)
            {
                out.push(ApprovalNote {
                    item_id: id,
                    field: "dest_host".to_owned(),
                    value: format!("{h}:{}", show_opt(rule.dest_port.as_ref())),
                });
            }
        }
    }
}

fn backup_approvals(id: ItemId, body: &ItemBody, out: &mut Vec<ApprovalNote>) {
    if body.is_deleted() {
        return;
    }
    match body.kind {
        ItemKind::Host => {
            if let Ok(Host {
                proxy: Some(Proxy::Command(c)),
                ..
            }) = Host::try_from(body)
            {
                out.push(ApprovalNote {
                    item_id: id,
                    field: "proxy.command".to_owned(),
                    value: c,
                });
            }
        }
        ItemKind::Group => {
            if let Ok(Group {
                defaults:
                    HostDefaults {
                        proxy: Some(Proxy::Command(c)),
                        ..
                    },
                ..
            }) = Group::try_from(body)
            {
                out.push(ApprovalNote {
                    item_id: id,
                    field: "proxy.command".to_owned(),
                    value: c,
                });
            }
        }
        ItemKind::PortForward => {
            if let Ok(rule) = PortForward::try_from(body) {
                approvals_for_forward(id, &rule, out);
            }
        }
        _ => {}
    }
}
