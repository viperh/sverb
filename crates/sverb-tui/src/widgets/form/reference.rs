//! The `Reference` field: an item of one kind (identity, key, group, …) picked
//! with a fuzzy picker over the search index.
//!
//! Closed: `Enter`/`Space` opens the picker, `Del`/`Backspace` clears the reference.
//! Picker: typing filters (the [`Query`] language, restricted to the field's kind),
//! `↑/↓` (`ctrl-p/ctrl-n`) move, `Enter` picks, `Esc` closes.
//!
//! A picker can be limited to one vault ([`ReferenceInput::set_vault`]:
//! identities are referenced only within their vault, §13.4) and can end with a
//! "create" entry ([`ReferenceInput::set_create`], e.g. `+ new identity`); picking it
//! leaves the value alone and raises a request the owner takes with
//! [`ReferenceInput::take_create`].

use crossterm::event::{KeyCode, KeyEvent};
use sverb_core::{
    model::{ItemId, ItemKind, VaultId},
    search::{IndexSnapshot, Query, Scope},
};

use super::{
    Popup, PopupItem,
    select::popup_nav,
    text::{TextEdit, TextInput},
};

/// Picker results shown at most.
pub const PICKER_LIMIT: usize = 200;

/// The referenced item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefValue {
    /// The item.
    pub id: ItemId,
    /// Its label when picked (for display).
    pub label: String,
}

/// One picker candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The item.
    pub id: ItemId,
    /// Its display label.
    pub label: String,
    /// Matched char indices into `label`.
    pub highlights: Vec<u32>,
}

/// The open picker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Picker {
    query: TextInput,
    hits: Vec<Candidate>,
    selected: usize,
}

/// A reference field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceInput {
    /// The kind of item it points to.
    pub kind: ItemKind,
    /// The current reference.
    pub value: Option<RefValue>,
    picker: Option<Picker>,
    /// Only items of this vault are offered.
    vault: Option<VaultId>,
    /// The label of a trailing "create" entry.
    create: Option<String>,
    /// The "create" entry was picked.
    create_requested: bool,
}

/// Candidates of `kind` matching `query`, in index order (score, pinned, frecency, alpha).
pub fn candidates(index: &IndexSnapshot, kind: ItemKind, query: &str) -> Vec<Candidate> {
    candidates_in(index, kind, query, None)
}

/// [`candidates`] limited to `vault` (all vaults when `None`).
pub fn candidates_in(
    index: &IndexSnapshot,
    kind: ItemKind,
    query: &str,
    vault: Option<VaultId>,
) -> Vec<Candidate> {
    index
        .query(&Query::parse(query), Scope::Kind(kind))
        .into_iter()
        .filter_map(|hit| {
            let entry = index.get(hit.item_id)?;
            // `Scope::Kind` already admits only `kind`; keep the check local too.
            (entry.kind == kind && vault.is_none_or(|v| entry.vault_id == v)).then(|| Candidate {
                id: hit.item_id,
                label: entry.display_label().to_owned(),
                highlights: hit.highlights,
            })
        })
        .take(PICKER_LIMIT)
        .collect()
}

impl ReferenceInput {
    /// A reference to an item of `kind`, currently `value`.
    pub fn new(kind: ItemKind, value: Option<RefValue>) -> Self {
        Self {
            kind,
            value,
            picker: None,
            vault: None,
            create: None,
            create_requested: false,
        }
    }

    /// Offer only items of `vault` (`None`: every vault).
    pub fn set_vault(&mut self, vault: Option<VaultId>) {
        self.vault = vault;
    }

    /// The vault the picker is limited to.
    pub fn vault(&self) -> Option<VaultId> {
        self.vault
    }

    /// End the picker with a "create" entry labelled `label`.
    pub fn set_create(&mut self, label: impl Into<String>) {
        self.create = Some(label.into());
    }

    /// Whether the "create" entry was picked (taken once).
    pub fn take_create(&mut self) -> bool {
        std::mem::take(&mut self.create_requested)
    }

    fn create_index(&self) -> Option<usize> {
        let p = self.picker.as_ref()?;
        self.create.as_ref().map(|_| p.hits.len())
    }

    fn entries(&self) -> usize {
        self.picker
            .as_ref()
            .map_or(0, |p| p.hits.len() + usize::from(self.create.is_some()))
    }

    /// The referenced id.
    pub fn id(&self) -> Option<ItemId> {
        self.value.as_ref().map(|v| v.id)
    }

    /// Whether the picker is open.
    pub fn is_open(&self) -> bool {
        self.picker.is_some()
    }

    /// The picker's candidates (empty when closed).
    pub fn candidates(&self) -> &[Candidate] {
        self.picker.as_ref().map_or(&[], |p| &p.hits)
    }

    /// Close the picker.
    pub fn blur(&mut self) {
        self.picker = None;
    }

    fn refilter(&mut self, index: Option<&IndexSnapshot>) {
        let kind = self.kind;
        let vault = self.vault;
        let extra = usize::from(self.create.is_some());
        if let Some(p) = &mut self.picker {
            p.hits = index.map_or_else(Vec::new, |ix| {
                candidates_in(ix, kind, p.query.text(), vault)
            });
            p.selected = p.selected.min((p.hits.len() + extra).saturating_sub(1));
        }
    }

    /// Insert a paste into the open picker's query.
    pub fn paste(&mut self, s: &str, index: Option<&IndexSnapshot>) -> bool {
        let Some(p) = &mut self.picker else {
            return false;
        };
        p.query.insert_str(s);
        self.refilter(index);
        true
    }

    /// Apply one key. `index` is the current search snapshot (`None` before unlock).
    pub fn handle_key(&mut self, key: &KeyEvent, index: Option<&IndexSnapshot>) -> TextEdit {
        // The "create" entry counts as one more row.
        let entries = self.entries();
        let create_at = self.create_index();
        if let Some(p) = &mut self.picker {
            if let Some(to) = popup_nav(key, p.selected, entries) {
                p.selected = to;
                return TextEdit::Moved;
            }
            match key.code {
                KeyCode::Esc => {
                    self.picker = None;
                    return TextEdit::Moved;
                }
                KeyCode::Enter if create_at == Some(p.selected) => {
                    self.picker = None;
                    self.create_requested = true;
                    return TextEdit::Moved;
                }
                KeyCode::Enter => {
                    let pick = p.hits.get(p.selected).cloned();
                    self.picker = None;
                    return match pick {
                        Some(c) if self.id() != Some(c.id) => {
                            self.value = Some(RefValue {
                                id: c.id,
                                label: c.label,
                            });
                            TextEdit::Changed
                        }
                        _ => TextEdit::Moved,
                    };
                }
                _ => {
                    if p.query.handle_key(key) == TextEdit::Changed {
                        p.selected = 0;
                        self.refilter(index);
                    }
                    return TextEdit::Moved;
                }
            }
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.picker = Some(Picker {
                    query: TextInput::default(),
                    hits: Vec::new(),
                    selected: 0,
                });
                self.refilter(index);
                TextEdit::Moved
            }
            KeyCode::Delete | KeyCode::Backspace if self.value.is_some() => {
                self.value = None;
                TextEdit::Changed
            }
            _ => TextEdit::Ignored,
        }
    }

    /// The picker, when open.
    pub fn popup(&self) -> Option<Popup> {
        let p = self.picker.as_ref()?;
        let mut items: Vec<PopupItem> = p
            .hits
            .iter()
            .map(|c| PopupItem {
                text: c.label.clone(),
                highlights: c.highlights.clone(),
                checked: None,
            })
            .collect();
        if let Some(label) = &self.create {
            items.push(PopupItem {
                text: label.clone(),
                highlights: Vec::new(),
                checked: None,
            });
        }
        Some(Popup {
            title: format!(" pick {} ", kind_name(self.kind)),
            query: Some(p.query.clone()),
            items,
            selected: p.selected,
            empty: "No matches".to_owned(),
        })
    }
}

/// A kind's name for prompts (`identity`, `key`, `known-host`, …).
pub fn kind_name(kind: ItemKind) -> &'static str {
    kind.as_str()
}
