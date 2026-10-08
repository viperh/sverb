//! M2-04: "Install key on host" dialogs (SPEC §9.4).
//!
//! Flow: Keychain → key → `H` → [`InstallPicker`] (multi-select over hosts, groups and
//! tags, filtered through the search index) → a confirmation showing the command →
//! [`InstallResults`] (the shared [`ResultsTable`]: `installed` / `already present` /
//! `error: …` per host, `r` re-runs the failed hosts, `esc` closes and cancels what is
//! still running). The reducer side is `app/keychain/install.rs`; the runs are in
//! `services/vault/items/install.rs`.
//!
//! [`expand_targets`] turns picked targets into hosts: a group means every host in it
//! and its subgroups, a tag every host carrying it; duplicates are dropped.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::app::SessionId;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::{
    model::{ItemId, ItemKind},
    search::{IndexSnapshot, Query, Scope},
};

use super::super::hosts::catalog::HostCatalog;
use crate::app::keychain::keys::KeychainAnswer;
use crate::views::{RenderCx, ViewCx, ViewEvent};
use crate::widgets::{
    results_table::{ResultsTable, RowState},
    truncate,
};

/// Something to install on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstallTarget {
    /// One host.
    Host(ItemId),
    /// Every host of a group (recursively).
    Group(ItemId),
    /// Every host with a tag.
    Tag(ItemId),
}

impl InstallTarget {
    /// The item.
    pub fn id(self) -> ItemId {
        match self {
            Self::Host(id) | Self::Group(id) | Self::Tag(id) => id,
        }
    }
}

/// One picker row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickerEntry {
    /// What it is.
    pub target: InstallTarget,
    /// Shown as.
    pub label: String,
}

/// The host picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPicker {
    /// The key to install.
    pub key: ItemId,
    /// Its label.
    pub key_label: String,
    /// The filter text.
    pub filter: String,
    /// Every entry (groups, tags, then hosts).
    pub entries: Vec<PickerEntry>,
    /// The entries the filter shows (indices into `entries`).
    pub visible: Vec<usize>,
    /// The cursor (index into `visible`).
    pub cursor: usize,
    /// Marked targets.
    pub marked: BTreeSet<InstallTarget>,
    index: Option<Arc<IndexSnapshot>>,
}

/// `group / sub / leaf` for `id`.
fn group_path(catalog: &HostCatalog, id: ItemId) -> String {
    let mut parts = Vec::new();
    let mut cur = Some(id);
    while let Some(g) = cur {
        if parts.len() > 64 {
            break;
        }
        let Some(node) = catalog.lookup.groups.get(&g) else {
            parts.push(catalog.groups.get(&g).cloned().unwrap_or_default());
            break;
        };
        parts.push(node.name.clone());
        cur = node.parent_id;
    }
    parts.reverse();
    parts.join(" / ")
}

impl InstallPicker {
    /// A picker over `catalog`'s hosts, groups and tags.
    pub fn new(
        key: ItemId,
        key_label: String,
        catalog: &HostCatalog,
        index: Option<Arc<IndexSnapshot>>,
    ) -> Self {
        let mut entries = Vec::new();
        let mut groups: Vec<PickerEntry> = catalog
            .groups
            .keys()
            .filter(|g| in_any_group(catalog, **g))
            .map(|g| PickerEntry {
                target: InstallTarget::Group(*g),
                label: format!("▸ {}", group_path(catalog, *g)),
            })
            .collect();
        groups.sort_by(|a, b| a.label.cmp(&b.label));
        entries.extend(groups);
        let mut tags: Vec<PickerEntry> = catalog
            .tags
            .iter()
            .filter(|(id, _)| catalog.hosts.values().any(|h| h.tags.contains(id)))
            .map(|(id, t)| PickerEntry {
                target: InstallTarget::Tag(*id),
                label: format!("#{}", t.name),
            })
            .collect();
        tags.sort_by(|a, b| a.label.cmp(&b.label));
        entries.extend(tags);
        let mut hosts: Vec<PickerEntry> = catalog
            .hosts
            .values()
            .map(|h| PickerEntry {
                target: InstallTarget::Host(h.id),
                label: h.display_label().to_owned(),
            })
            .collect();
        hosts.sort_by_key(|e| e.label.to_lowercase());
        entries.extend(hosts);
        let mut p = Self {
            key,
            key_label,
            filter: String::new(),
            visible: Vec::new(),
            entries,
            cursor: 0,
            marked: BTreeSet::new(),
            index,
        };
        p.refilter();
        p
    }

    /// Recompute `visible` from the filter (the search index when there is one, else a
    /// case-insensitive substring match).
    pub fn refilter(&mut self) {
        let f = self.filter.trim();
        self.visible = if f.is_empty() {
            (0..self.entries.len()).collect()
        } else if let Some(index) = &self.index {
            let hits = index.query(&Query::parse(f), Scope::All);
            let rank: BTreeMap<ItemId, usize> = hits
                .iter()
                .enumerate()
                .filter(|(_, h)| {
                    index.get(h.item_id).is_some_and(|e| {
                        matches!(e.kind, ItemKind::Host | ItemKind::Group | ItemKind::Tag)
                    })
                })
                .map(|(i, h)| (h.item_id, i))
                .collect();
            let mut v: Vec<usize> = (0..self.entries.len())
                .filter(|i| rank.contains_key(&self.entries[*i].target.id()))
                .collect();
            v.sort_by_key(|i| rank[&self.entries[*i].target.id()]);
            v
        } else {
            let needle = f.to_lowercase();
            (0..self.entries.len())
                .filter(|i| self.entries[*i].label.to_lowercase().contains(&needle))
                .collect()
        };
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    fn current(&self) -> Option<InstallTarget> {
        self.visible
            .get(self.cursor)
            .map(|i| self.entries[*i].target)
    }

    fn toggle(&mut self) {
        if let Some(t) = self.current()
            && !self.marked.remove(&t)
        {
            self.marked.insert(t);
        }
    }

    /// Handle a key or paste; `Some` when the picker is submitted.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<KeychainAnswer> {
        match ev {
            ViewEvent::Paste(t) => {
                self.filter.push_str(t.trim());
                self.refilter();
                None
            }
            ViewEvent::Key(k) => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                match k.code {
                    KeyCode::Esc => {
                        cx.close();
                        None
                    }
                    KeyCode::Down => {
                        self.cursor = (self.cursor + 1).min(self.visible.len().saturating_sub(1));
                        None
                    }
                    KeyCode::Up => {
                        self.cursor = self.cursor.saturating_sub(1);
                        None
                    }
                    KeyCode::Char('n') if ctrl => {
                        self.cursor = (self.cursor + 1).min(self.visible.len().saturating_sub(1));
                        None
                    }
                    KeyCode::Char('p') if ctrl => {
                        self.cursor = self.cursor.saturating_sub(1);
                        None
                    }
                    KeyCode::Tab | KeyCode::Char(' ') => {
                        self.toggle();
                        if k.code == KeyCode::Tab {
                            self.cursor =
                                (self.cursor + 1).min(self.visible.len().saturating_sub(1));
                        }
                        None
                    }
                    KeyCode::Enter => {
                        let mut targets: Vec<InstallTarget> = self.marked.iter().copied().collect();
                        if targets.is_empty() {
                            targets.extend(self.current());
                        }
                        (!targets.is_empty()).then(|| KeychainAnswer::InstallPick {
                            key: self.key,
                            targets,
                        })
                    }
                    KeyCode::Backspace => {
                        self.filter.pop();
                        self.refilter();
                        None
                    }
                    KeyCode::Char('u') if ctrl => {
                        self.filter.clear();
                        self.refilter();
                        None
                    }
                    KeyCode::Char(c) if !ctrl => {
                        self.filter.push(c);
                        self.refilter();
                        None
                    }
                    _ => None,
                }
            }
            ViewEvent::Mouse(_) => None,
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let w = area.width.saturating_sub(4).min(80);
        let h = area.height.saturating_sub(2).min(24);
        if w < 20 || h < 8 {
            return;
        }
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        frame.render_widget(Clear, rect);
        let inner_w = usize::from(w.saturating_sub(2));
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Filter ", theme.dim),
                Span::styled(format!("{}▏", self.filter), theme.base),
            ]),
            Line::raw(""),
        ];
        let room = usize::from(h).saturating_sub(6);
        let skip = self.cursor.saturating_sub(room.saturating_sub(1));
        if self.visible.is_empty() {
            lines.push(Line::styled("no hosts, groups or tags match", theme.dim));
        }
        for (row, i) in self.visible.iter().enumerate().skip(skip).take(room) {
            let e = &self.entries[*i];
            let mark = if self.marked.contains(&e.target) {
                "[x] "
            } else {
                "[ ] "
            };
            let style = if row == self.cursor {
                theme.selection
            } else {
                theme.base
            };
            lines.push(Line::styled(
                format!("{mark}{}", truncate(&e.label, inner_w.saturating_sub(4))),
                style,
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "{} selected · space/tab mark · ↑↓ move · enter continue · esc cancel",
                self.marked.len()
            ),
            theme.dim,
        ));
        let block = Block::bordered()
            .title(Span::styled(
                format!(
                    " Install \"{}\" on… ",
                    truncate(&self.key_label, inner_w.saturating_sub(16))
                ),
                theme.title_for(true),
            ))
            .border_style(theme.border_for(true));
        frame.render_widget(Paragraph::new(lines).style(theme.base).block(block), rect);
    }
}

/// Whether `group` or one of its subgroups holds a host.
fn in_any_group(catalog: &HostCatalog, group: ItemId) -> bool {
    catalog
        .hosts
        .values()
        .any(|h| h.group_id.is_some_and(|g| is_within(catalog, g, group)))
}

/// `g` is `ancestor` or below it.
fn is_within(catalog: &HostCatalog, g: ItemId, ancestor: ItemId) -> bool {
    let mut cur = Some(g);
    for _ in 0..64 {
        match cur {
            Some(x) if x == ancestor => return true,
            Some(x) => cur = catalog.lookup.groups.get(&x).and_then(|n| n.parent_id),
            None => return false,
        }
    }
    false
}

/// The hosts `targets` stand for (host label order, no duplicates), with their labels.
pub fn expand_targets(catalog: &HostCatalog, targets: &[InstallTarget]) -> Vec<(ItemId, String)> {
    let mut picked: BTreeSet<ItemId> = BTreeSet::new();
    for t in targets {
        match *t {
            InstallTarget::Host(h) => {
                if catalog.hosts.contains_key(&h) {
                    picked.insert(h);
                }
            }
            InstallTarget::Group(g) => picked.extend(
                catalog
                    .hosts
                    .values()
                    .filter(|h| h.group_id.is_some_and(|x| is_within(catalog, x, g)))
                    .map(|h| h.id),
            ),
            InstallTarget::Tag(tag) => picked.extend(
                catalog
                    .hosts
                    .values()
                    .filter(|h| h.tags.contains(&tag))
                    .map(|h| h.id),
            ),
        }
    }
    let mut out: Vec<(ItemId, String)> = picked
        .into_iter()
        .filter_map(|id| {
            catalog
                .hosts
                .get(&id)
                .map(|h| (id, h.display_label().to_owned()))
        })
        .collect();
    out.sort_by(|a, b| {
        a.1.to_lowercase()
            .cmp(&b.1.to_lowercase())
            .then(a.0.cmp(&b.0))
    });
    out
}

/// What an install run does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// The key.
    pub key: ItemId,
    /// Its label.
    pub key_label: String,
    /// The command (§9.4 with markers).
    pub command: String,
    /// Target hosts and labels.
    pub hosts: Vec<(ItemId, String)>,
}

/// The results dialog of one install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResults {
    /// The current run (events of other runs are ignored).
    pub run: u64,
    /// What is installed where.
    pub plan: InstallPlan,
    /// The session id each row's connection uses for prompts (this run).
    pub sessions: Vec<Option<SessionId>>,
    /// The table.
    pub table: ResultsTable,
}

/// The footer of the results dialog.
pub const RESULTS_HINT: &str = "↑↓ select · enter details · r re-run failed · esc close";

impl InstallResults {
    /// The row whose connection uses `session`.
    pub fn row_of(&self, session: SessionId) -> Option<usize> {
        self.sessions.iter().position(|s| *s == Some(session))
    }

    /// Something is still queued or running.
    pub fn running(&self) -> bool {
        !self.table.finished()
    }

    /// Handle an event; `Some` for `r`.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<KeychainAnswer> {
        let ViewEvent::Key(k) = ev else {
            return None;
        };
        if self.table.handle_key(k) {
            return None;
        }
        match k.code {
            KeyCode::Char('r') if !self.running() && !self.table.failed().is_empty() => {
                Some(KeychainAnswer::InstallRerun)
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                if self.running() {
                    cx.push(crate::app::keychain::install::cancel_effect(self.run));
                }
                cx.close();
                None
            }
            _ => None,
        }
    }

    /// Mark every unfinished row cancelled.
    pub fn cancel_pending(&mut self) {
        for row in &mut self.table.rows {
            if row.state.pending() {
                row.state = RowState::Failed("error: cancelled".to_owned());
            }
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        self.table.render(frame, area, cx.theme, RESULTS_HINT);
    }
}
