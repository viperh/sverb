//! M1-05: the in-memory decrypted item index and its read-only snapshots (SPEC §5.2).
//!
//! [`ItemIndex`] is the mutable index owned by the vault service: built from every
//! decrypted item on unlock, updated per item write or remote apply, dropped on lock.
//! Every decrypted string it holds is a `Zeroizing<String>`, so dropping the index
//! (and the last [`IndexSnapshot`] sharing its entries) wipes the plaintext.
//!
//! [`IndexSnapshot`] is what the UI gets (`Arc<IndexSnapshot>`): immutable, cheap to
//! share (entries are `Arc`ed), queried without locks.
//!
//! **Secrets are never indexed.** Entries are built from an explicit whitelist of
//! non-secret fields per kind (labels, addresses, user names, tag and group names,
//! descriptions); `password`, `private_key`, `passphrase`, `proxy.auth.*`, snippet
//! variable defaults, … are never read.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use ciborium::Value;
use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use zeroize::Zeroizing;

use super::query::Query;
use crate::model::{ItemBody, ItemId, ItemKind, VaultId};

/// A decrypted string held by the index, wiped on drop.
pub type Text = Zeroizing<String>;

/// Separator between the segments of [`IndexEntry::group_path`].
pub const GROUP_PATH_SEPARATOR: &str = " / ";

/// Deepest group nesting followed when building group paths (cycle guard).
const MAX_GROUP_DEPTH: usize = 64;

/// One indexed item. Never contains secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// The item.
    pub item_id: ItemId,
    /// Its vault.
    pub vault_id: VaultId,
    /// Its kind.
    pub kind: ItemKind,
    /// `label` (hosts, identities, keys, …) or `name` (groups, snippets, tags, …);
    /// `host_pattern` for known hosts. May be empty for hosts: see
    /// [`IndexEntry::display_label`].
    pub label: Text,
    /// Host address (hosts only).
    pub address: Text,
    /// User name (hosts and identities).
    pub user: Text,
    /// Resolved tag names (unknown tag ids are skipped).
    pub tags: Vec<Text>,
    /// Group path from the root, `"prod / eu / web"` (for a group: its parent's path).
    pub group_path: Text,
    /// What free text is matched against: label, address, user, tags, group path
    /// and kind-specific non-secret fields, space-joined. Case is kept so smart-case
    /// queries work (the matcher folds case itself).
    pub search_text: Text,
    /// Snippet script, searched only in [`Scope::Snippets`] and [`Scope::Palette`].
    pub body_text: Text,
    /// Host `pinned` flag.
    pub pinned: bool,
}

impl IndexEntry {
    /// `label`, or the address when the label is empty (hosts).
    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.address
        } else {
            &self.label
        }
    }
}

impl fmt::Debug for IndexEntry {
    // Decrypted user data stays out of logs (SPEC §17).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexEntry")
            .field("item_id", &self.item_id)
            .field("vault_id", &self.vault_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Which items a query looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// Every indexed kind; snippet bodies are not searched.
    All,
    /// The Hosts view: hosts only.
    Hosts,
    /// The Snippets view: snippets, bodies included.
    Snippets,
    /// One kind (bodies searched only for snippets).
    Kind(ItemKind),
    /// The command palette: every kind, snippet bodies included.
    Palette,
}

impl Scope {
    fn admits(self, kind: ItemKind) -> bool {
        match self {
            Scope::All | Scope::Palette => true,
            Scope::Hosts => kind == ItemKind::Host,
            Scope::Snippets => kind == ItemKind::Snippet,
            Scope::Kind(k) => kind == k,
        }
    }

    fn searches_bodies(self) -> bool {
        matches!(
            self,
            Scope::Snippets | Scope::Palette | Scope::Kind(ItemKind::Snippet)
        )
    }
}

/// One query result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The item.
    pub item_id: ItemId,
    /// Match score (sum over the query's text atoms; 0 without text).
    pub score: u32,
    /// Matched **char** indices into [`IndexEntry::display_label`], sorted, for
    /// highlighting. Empty when the match was elsewhere (address, tags, …).
    pub highlights: Vec<u32>,
}

/// Device-local ordering data (§9.1: pinned → frecency → alphabetical).
pub trait DeviceLocalLookup {
    /// The item's frecency decayed to now (`DeviceLocal::score_at`); 0 if unknown.
    fn frecency(&self, item: ItemId) -> f64;
    /// Overrides the entry's synced `pinned` flag (`None`: use the entry's).
    fn pinned(&self, _item: ItemId) -> Option<bool> {
        None
    }
}

/// No device-local data: everything has frecency 0.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDeviceLocal;

impl DeviceLocalLookup for NoDeviceLocal {
    fn frecency(&self, _item: ItemId) -> f64 {
        0.0
    }
}

impl<S: std::hash::BuildHasher> DeviceLocalLookup for HashMap<ItemId, f64, S> {
    fn frecency(&self, item: ItemId) -> f64 {
        self.get(&item).copied().unwrap_or(0.0)
    }
}

/// The view ordering for equal scores: pinned first, then higher frecency, then
/// case-insensitive alphabetical by display label, then item id (total order).
pub fn compare_entries(a: &IndexEntry, b: &IndexEntry, lookup: &dyn DeviceLocalLookup) -> Ordering {
    let pinned = |e: &IndexEntry| lookup.pinned(e.item_id).unwrap_or(e.pinned);
    pinned(b)
        .cmp(&pinned(a))
        .then_with(|| {
            lookup
                .frecency(b.item_id)
                .total_cmp(&lookup.frecency(a.item_id))
        })
        .then_with(|| cmp_alpha(a.display_label(), b.display_label()))
        .then_with(|| a.item_id.cmp(&b.item_id))
}

fn cmp_alpha(a: &str, b: &str) -> Ordering {
    fn fold(s: &str) -> impl Iterator<Item = char> + '_ {
        s.chars().flat_map(char::to_lowercase)
    }
    fold(a).cmp(fold(b)).then_with(|| a.cmp(b))
}

// ------------------------------------------------------------------ snapshot

/// An immutable view of the index for the UI (`UiEvent::IndexUpdated`).
#[derive(Clone, Default)]
pub struct IndexSnapshot {
    version: u64,
    /// Sorted by item id.
    entries: Vec<Arc<IndexEntry>>,
    vault_names: Arc<BTreeMap<VaultId, String>>,
    frecency: Arc<HashMap<ItemId, f64>>,
}

impl fmt::Debug for IndexSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexSnapshot")
            .field("version", &self.version)
            .field("entries", &self.entries.len())
            .field("vaults", &self.vault_names.len())
            .finish()
    }
}

impl PartialEq for IndexSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.entries == other.entries
            && self.vault_names == other.vault_names
            && self.frecency.len() == other.frecency.len()
            && self.frecency.iter().all(|(id, f)| {
                other
                    .frecency
                    .get(id)
                    .is_some_and(|g| g.to_bits() == f.to_bits())
            })
    }
}

impl Eq for IndexSnapshot {}

impl DeviceLocalLookup for IndexSnapshot {
    fn frecency(&self, item: ItemId) -> f64 {
        self.frecency.get(&item).copied().unwrap_or(0.0)
    }
}

impl IndexSnapshot {
    /// Increases with every change of the index it was taken from.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Number of indexed items.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No items.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in item-id order.
    pub fn entries(&self) -> &[Arc<IndexEntry>] {
        &self.entries
    }

    /// The entry of `item`.
    pub fn get(&self, item: ItemId) -> Option<&Arc<IndexEntry>> {
        self.entries
            .binary_search_by(|e| e.item_id.cmp(&item))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// The display name of a vault (`@vault` filter).
    pub fn vault_name(&self, vault: VaultId) -> Option<&str> {
        self.vault_names.get(&vault).map(String::as_str)
    }

    /// Run `q` in `scope`, ordered by score, then pinned → frecency → alphabetical
    /// using the frecency captured in this snapshot.
    pub fn query(&self, q: &Query, scope: Scope) -> Vec<Hit> {
        self.query_with(q, scope, self)
    }

    /// Like [`IndexSnapshot::query`] with explicit device-local data.
    pub fn query_with(&self, q: &Query, scope: Scope, lookup: &dyn DeviceLocalLookup) -> Vec<Hit> {
        if q.unknown_kind {
            return Vec::new();
        }
        let atoms = compile(q);
        let bodies = scope.searches_bodies();
        let mut matcher = Matcher::new(Config::DEFAULT);
        let mut buf = Vec::new();
        let mut hits: Vec<(u32, &Arc<IndexEntry>)> = Vec::new();
        for entry in &self.entries {
            if !scope.admits(entry.kind)
                || !(q.kinds.is_empty() || q.kinds.contains(&entry.kind))
                || !self.vault_ok(q, entry)
                || !tags_ok(q, entry)
            {
                continue;
            }
            if atoms.is_empty() {
                hits.push((0, entry));
                continue;
            }
            let hay = Utf32Str::new(&entry.search_text, &mut buf);
            let mut total = 0u32;
            let mut ok = true;
            for atom in &atoms {
                let score = atom.score(hay, &mut matcher).or_else(|| {
                    if bodies && !entry.body_text.is_empty() {
                        let mut body_buf = Vec::new();
                        atom.score(Utf32Str::new(&entry.body_text, &mut body_buf), &mut matcher)
                    } else {
                        None
                    }
                });
                match score {
                    Some(s) => total += u32::from(s),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                hits.push((total, entry));
            }
        }
        hits.sort_by(|(sa, a), (sb, b)| sb.cmp(sa).then_with(|| compare_entries(a, b, lookup)));
        hits.into_iter()
            .map(|(score, entry)| Hit {
                item_id: entry.item_id,
                score,
                highlights: highlights(&atoms, entry.display_label(), &mut matcher),
            })
            .collect()
    }

    /// Every entry in `scope` in view order (an empty query).
    pub fn ordered(&self, scope: Scope, lookup: &dyn DeviceLocalLookup) -> Vec<Arc<IndexEntry>> {
        self.query_with(&Query::default(), scope, lookup)
            .into_iter()
            .filter_map(|h| self.get(h.item_id).cloned())
            .collect()
    }

    fn vault_ok(&self, q: &Query, entry: &IndexEntry) -> bool {
        if q.vaults.is_empty() {
            return true;
        }
        let Some(name) = self.vault_names.get(&entry.vault_id) else {
            return false;
        };
        let name = name.to_lowercase();
        q.vaults.iter().any(|p| name.starts_with(p.as_str()))
    }
}

fn tags_ok(q: &Query, entry: &IndexEntry) -> bool {
    q.tags
        .iter()
        .all(|want| entry.tags.iter().any(|t| t.to_lowercase() == want.as_str()))
}

fn compile(q: &Query) -> Vec<Atom> {
    let fuzzy = q.terms.iter().map(|t| {
        Atom::new(
            t,
            CaseMatching::Smart,
            Normalization::Smart,
            AtomKind::Fuzzy,
            false,
        )
    });
    let phrases = q.phrases.iter().map(|p| {
        Atom::new(
            p,
            CaseMatching::Smart,
            Normalization::Smart,
            AtomKind::Substring,
            false,
        )
    });
    fuzzy.chain(phrases).collect()
}

fn highlights(atoms: &[Atom], label: &str, matcher: &mut Matcher) -> Vec<u32> {
    if atoms.is_empty() || label.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let hay = Utf32Str::new(label, &mut buf);
    let mut out = Vec::new();
    for atom in atoms {
        let mut idx = Vec::new();
        if atom.indices(hay, matcher, &mut idx).is_some() {
            out.extend(idx);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

// ------------------------------------------------------------------ the index

/// The indexable, non-secret source data of one item.
#[derive(Clone)]
struct Doc {
    vault_id: VaultId,
    kind: ItemKind,
    label: Text,
    address: Text,
    user: Text,
    /// Kind-specific searchable words (descriptions, key types, …).
    extra: Vec<Text>,
    /// Snippet script.
    body: Text,
    tag_ids: Vec<ItemId>,
    /// Hosts: `group_id`; groups: `parent_id`.
    group_id: Option<ItemId>,
    pinned: bool,
}

fn text(body: &ItemBody, key: &str) -> Text {
    Zeroizing::new(
        body.get(key)
            .and_then(Value::as_text)
            .map(str::to_owned)
            .unwrap_or_default(),
    )
}

fn ids(body: &ItemBody, key: &str) -> Vec<ItemId> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(ItemId::from_value).collect())
        .unwrap_or_default()
}

fn id(body: &ItemBody, key: &str) -> Option<ItemId> {
    body.get(key).and_then(ItemId::from_value)
}

fn int(body: &ItemBody, key: &str) -> Option<i128> {
    body.get(key).and_then(Value::as_integer).map(i128::from)
}

impl Doc {
    /// The whitelist of indexed fields per kind. `None`: the kind is not indexed
    /// (history entries and connection logs).
    fn from_body(vault_id: VaultId, body: &ItemBody) -> Option<Self> {
        let mut doc = Doc {
            vault_id,
            kind: body.kind,
            label: Zeroizing::default(),
            address: Zeroizing::default(),
            user: Zeroizing::default(),
            extra: Vec::new(),
            body: Zeroizing::default(),
            tag_ids: Vec::new(),
            group_id: None,
            pinned: false,
        };
        match body.kind {
            ItemKind::Host => {
                doc.label = text(body, "label");
                doc.address = text(body, "address");
                doc.user = text(body, "username");
                doc.tag_ids = ids(body, "tags");
                doc.group_id = id(body, "group_id");
                doc.pinned = body.get("pinned").and_then(Value::as_bool).unwrap_or(false);
            }
            ItemKind::Group => {
                doc.label = text(body, "name");
                doc.group_id = id(body, "parent_id");
            }
            ItemKind::Identity => {
                doc.label = text(body, "label");
                doc.user = text(body, "username");
            }
            ItemKind::Key => {
                doc.label = text(body, "label");
                doc.extra.push(text(body, "algorithm"));
            }
            ItemKind::Certificate => doc.label = text(body, "label"),
            ItemKind::KnownHost => {
                doc.label = text(body, "host_pattern");
                doc.extra.push(text(body, "key_type"));
                doc.extra.push(text(body, "comment"));
            }
            ItemKind::PortForward => {
                doc.label = text(body, "label");
                let bind = text(body, "bind_addr");
                if let Some(port) = int(body, "bind_port") {
                    doc.extra
                        .push(Zeroizing::new(format!("{}:{port}", bind.as_str())));
                }
                let dest = text(body, "dest_host");
                if !dest.is_empty() {
                    let port = int(body, "dest_port")
                        .map(|p| format!(":{p}"))
                        .unwrap_or_default();
                    doc.extra
                        .push(Zeroizing::new(format!("{}{port}", dest.as_str())));
                }
            }
            ItemKind::Snippet => {
                doc.label = text(body, "name");
                doc.extra.push(text(body, "description"));
                doc.tag_ids = ids(body, "tags");
                doc.body = text(body, "script");
                // Variable *names* only; defaults may be secrets.
                if let Some(vars) = body.get("variables").and_then(Value::as_array) {
                    for v in vars {
                        let name = v.as_map().and_then(|m| {
                            m.iter().find_map(|(k, v)| {
                                (k.as_text() == Some("name")).then(|| v.as_text()).flatten()
                            })
                        });
                        if let Some(name) = name {
                            doc.extra.push(Zeroizing::new(name.to_owned()));
                        }
                    }
                }
            }
            ItemKind::Workspace => doc.label = text(body, "name"),
            ItemKind::Tag => doc.label = text(body, "name"),
            _ => return None,
        }
        doc.extra.retain(|e| !e.is_empty());
        Some(doc)
    }

    fn same_name_and_parent(&self, other: &Doc) -> bool {
        self.label == other.label && self.group_id == other.group_id
    }
}

/// The mutable index. Owned by the vault service; never handed to the UI (the UI
/// gets [`IndexSnapshot`]s).
#[derive(Default)]
pub struct ItemIndex {
    docs: HashMap<ItemId, Doc>,
    entries: BTreeMap<ItemId, Arc<IndexEntry>>,
    vault_names: Arc<BTreeMap<VaultId, String>>,
    frecency: Arc<HashMap<ItemId, f64>>,
    version: u64,
    snapshot: Option<Arc<IndexSnapshot>>,
}

impl fmt::Debug for ItemIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemIndex")
            .field("entries", &self.entries.len())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl ItemIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Full build from decrypted items (unlock). Deleted bodies and unindexed kinds
    /// are skipped. Dependent data (tag names, group paths) is resolved once, after
    /// every item is known.
    pub fn build<'a>(items: impl IntoIterator<Item = (ItemId, VaultId, &'a ItemBody)>) -> Self {
        let mut index = Self::new();
        for (item, vault, body) in items {
            if body.is_deleted() {
                continue;
            }
            if let Some(doc) = Doc::from_body(vault, body) {
                index.docs.insert(item, doc);
            }
        }
        let ids: Vec<ItemId> = index.docs.keys().copied().collect();
        index.rederive(ids);
        index
    }

    /// Number of indexed items.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No items.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current entry of `item`.
    pub fn get(&self, item: ItemId) -> Option<&Arc<IndexEntry>> {
        self.entries.get(&item)
    }

    /// Changes on every mutation.
    pub fn version(&self) -> u64 {
        self.version
    }

    fn touch(&mut self) {
        self.version += 1;
        self.snapshot = None;
    }

    /// Set the display name of a vault (for `@vault`).
    pub fn set_vault_name(&mut self, vault: VaultId, name: impl Into<String>) {
        let name = name.into();
        if self.vault_names.get(&vault) != Some(&name) {
            Arc::make_mut(&mut self.vault_names).insert(vault, name);
            self.touch();
        }
    }

    /// Replace the frecency table (decayed to now; `DeviceLocal::score_at`).
    pub fn set_frecency(&mut self, frecency: HashMap<ItemId, f64>) {
        self.frecency = Arc::new(frecency);
        self.touch();
    }

    /// Update one item's frecency (after a connect).
    pub fn set_item_frecency(&mut self, item: ItemId, frecency: f64) {
        Arc::make_mut(&mut self.frecency).insert(item, frecency);
        self.touch();
    }

    /// Incremental update after a local write or a remote apply. A deleted body (or
    /// an unindexed kind) removes the item. Renaming a tag or a group (or moving a
    /// group) recomputes every entry that shows it.
    pub fn upsert(&mut self, item: ItemId, vault: VaultId, body: &ItemBody) {
        let new = if body.is_deleted() {
            None
        } else {
            Doc::from_body(vault, body)
        };
        let Some(new) = new else {
            self.remove(item);
            return;
        };
        let old = self.docs.insert(item, new);
        let new = &self.docs[&item];
        let dependents_changed = match new.kind {
            ItemKind::Tag | ItemKind::Group => old
                .as_ref()
                .is_none_or(|o| o.kind != new.kind || !o.same_name_and_parent(new)),
            _ => old
                .as_ref()
                .is_some_and(|o| matches!(o.kind, ItemKind::Tag | ItemKind::Group)),
        };
        let mut ids = vec![item];
        if dependents_changed {
            ids.extend(self.dependents_of(item));
        }
        self.rederive(ids);
    }

    /// Remove an item (deleted or purged).
    pub fn remove(&mut self, item: ItemId) -> bool {
        let Some(old) = self.docs.remove(&item) else {
            return false;
        };
        self.entries.remove(&item);
        if matches!(old.kind, ItemKind::Tag | ItemKind::Group) {
            let ids = self.dependents_of(item);
            self.rederive(ids);
        }
        self.touch();
        true
    }

    /// The current snapshot (cached until the next change).
    pub fn snapshot(&mut self) -> Arc<IndexSnapshot> {
        if let Some(s) = &self.snapshot {
            return Arc::clone(s);
        }
        let snap = Arc::new(IndexSnapshot {
            version: self.version,
            entries: self.entries.values().cloned().collect(),
            vault_names: Arc::clone(&self.vault_names),
            frecency: Arc::clone(&self.frecency),
        });
        self.snapshot = Some(Arc::clone(&snap));
        snap
    }

    /// Items whose entry shows tag or group `id` (directly or as an ancestor group).
    fn dependents_of(&self, id: ItemId) -> Vec<ItemId> {
        self.docs
            .iter()
            .filter(|(item, doc)| {
                **item != id
                    && (doc.tag_ids.contains(&id) || self.group_chain(doc.group_id).contains(&id))
            })
            .map(|(item, _)| *item)
            .collect()
    }

    /// Group ids from `start` up to the root (cycle-safe).
    fn group_chain(&self, start: Option<ItemId>) -> Vec<ItemId> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = start;
        while let Some(g) = cur {
            if chain.len() >= MAX_GROUP_DEPTH || !seen.insert(g) {
                break;
            }
            chain.push(g);
            cur = self
                .docs
                .get(&g)
                .filter(|d| d.kind == ItemKind::Group)
                .and_then(|d| d.group_id);
        }
        chain
    }

    fn rederive(&mut self, ids: Vec<ItemId>) {
        for item in ids {
            if let Some(entry) = self.derive(item) {
                self.entries.insert(item, Arc::new(entry));
            }
        }
        self.touch();
    }

    fn derive(&self, item: ItemId) -> Option<IndexEntry> {
        let doc = self.docs.get(&item)?;
        let tags: Vec<Text> = doc
            .tag_ids
            .iter()
            .filter_map(|t| self.docs.get(t).filter(|d| d.kind == ItemKind::Tag))
            .map(|d| d.label.clone())
            .collect();
        let mut path = Zeroizing::new(String::new());
        for g in self.group_chain(doc.group_id).iter().rev() {
            let Some(name) = self.docs.get(g).filter(|d| d.kind == ItemKind::Group) else {
                continue;
            };
            if !path.is_empty() {
                path.push_str(GROUP_PATH_SEPARATOR);
            }
            path.push_str(&name.label);
        }
        let mut search = Zeroizing::new(String::new());
        {
            let mut push = |s: &str| {
                if !s.is_empty() {
                    if !search.is_empty() {
                        search.push(' ');
                    }
                    search.push_str(s);
                }
            };
            push(&doc.label);
            if doc.address != doc.label {
                push(&doc.address);
            }
            push(&doc.user);
            for t in &tags {
                push(t);
            }
            push(&path);
            for e in &doc.extra {
                push(e);
            }
        }
        Some(IndexEntry {
            item_id: item,
            vault_id: doc.vault_id,
            kind: doc.kind,
            label: doc.label.clone(),
            address: doc.address.clone(),
            user: doc.user.clone(),
            tags,
            group_path: path,
            search_text: search,
            body_text: doc.body.clone(),
            pinned: doc.pinned,
        })
    }
}
