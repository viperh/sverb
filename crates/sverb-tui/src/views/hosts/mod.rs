//! The Hosts section (SPEC §8.5, §9.1) on the shared list.
//!
//! - **Rows** come from the search index in view order (pinned → frecency →
//!   A collapsible **Recent** pseudo-group on top lists the last 10 connected hosts
//!   (hidden when empty). Groups are tree nodes (collapsible with `h`/`l`),
//!   hosts sit under their group; hosts without (or with a missing) group are at the
//!   top level.
//! - **Filter** (`/`) runs the index's query language (`#tag`, `@vault`, …).
//! - **Actions** (Normal mode): `Enter` connect (all
//!   marked hosts: one tab each), `ctrl-enter`/`v` connect in a split, `a`
//!   add, `e` edit, `y` duplicate, `d` delete (confirm), `p` pin/unpin, `m` move to
//!   group and `t` tag, `c` copy the `ssh` command. The view only records the
//!   request ([`HostsView::take_request`]); the reducer (`app/hosts.rs`) carries it out.
//! - **Detail:** the shell's detail pane draws [`HostsView::render_detail`]; below
//!   100 columns `i` opens it full screen.
//!   it (move contents to the parent, or delete them), `a` adds a host in it; `A`
//!   creates a group (inside the group under the cursor), `T` manages tags, `D`
//!   edits the vault defaults. `m`/`t` on hosts move / tag them in bulk.
//!   (`views/import_wizard.rs`).
//!   vaults → Personal → each shared vault; the top bar shows it, new items go to
//!   it); in "All vaults" rows of shared vaults carry their vault's name as a badge.
//!   `M` / `C` move / copy hosts to another vault (§13.1), `O` sets "Use my own
//!   credentials…" on a shared host (§13.4).

pub mod catalog;
pub mod detail;
pub mod form;
pub mod organize;
pub mod quick;

#[cfg(test)]
mod tests;
// Vault selector, badges, read-only forms, override provenance.
#[cfg(test)]
mod vault_tests;

use std::str::FromStr;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use sverb_core::{
    model::ItemId,
    resolve::GlobalDefaults,
    search::{IndexSnapshot, Scope},
};

use self::catalog::{HostCatalog, HostSummary, TagInfo};
use super::{Outcome, RenderCx, View, ViewCx, ViewEvent};
use crate::{
    keymap::chord::KeyChord,
    theme::Theme,
    widgets::{
        form::{highlighted, match_style},
        list::{DetailRenderer, EmptyState, FilterSource, ListRow, ListView, RowCx, RowRenderer},
        truncate, width,
    },
};

/// Hosts in the Recent pseudo-group.
pub const RECENT_COUNT: usize = 10;

/// The configured leader as shown in hints (`^\`).
pub(crate) fn leader_hint(cx: &RenderCx<'_>) -> String {
    cx.config
        .general
        .leader
        .as_str()
        .parse::<KeyChord>()
        .map_or_else(|_| cx.config.general.leader.to_string(), |c| c.hint())
}

/// Identity of a row: the Recent group, a host under Recent, or a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostRowKey {
    /// The Recent pseudo-group node.
    RecentGroup,
    /// A host listed under Recent.
    Recent(ItemId),
    /// A host.
    Host(ItemId),
    /// A group node.
    Group(ItemId),
}

impl HostRowKey {
    /// The host this row stands for.
    pub fn item(self) -> Option<ItemId> {
        match self {
            Self::RecentGroup | Self::Group(_) => None,
            Self::Recent(id) | Self::Host(id) => Some(id),
        }
    }

    /// The group this row stands for.
    pub fn group(self) -> Option<ItemId> {
        match self {
            Self::Group(id) => Some(id),
            _ => None,
        }
    }
}

/// One row of the Hosts list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    /// Row identity.
    pub key: HostRowKey,
    /// Display label.
    pub label: String,
    /// `user@address:port` (port only when not 22).
    pub target: String,
    /// Tags (name, color).
    pub tags: Vec<TagInfo>,
    /// Pinned.
    pub pinned: bool,
    /// The parent row (Recent, or the host's / group's group).
    pub parent: Option<HostRowKey>,
    /// A group's icon.
    pub icon: Option<String>,
    /// A warning chip (`missing group`; `missing identity`).
    pub chip: Option<&'static str>,
    /// The shared vault's name, in the merged "All vaults" list.
    pub vault: Option<String>,
}

impl ListRow for HostRow {
    type Key = HostRowKey;

    fn key(&self) -> HostRowKey {
        self.key
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn filter_text(&self) -> String {
        // Recent rows duplicate hosts listed below: the filter shows each host once.
        match self.key {
            HostRowKey::Host(_) => format!("{} {}", self.label, self.target),
            _ => String::new(),
        }
    }

    fn item_id(&self) -> Option<ItemId> {
        match self.key {
            HostRowKey::Host(id) => Some(id),
            _ => None,
        }
    }

    fn parent(&self) -> Option<HostRowKey> {
        self.parent
    }

    fn is_group(&self) -> bool {
        matches!(self.key, HostRowKey::RecentGroup | HostRowKey::Group(_))
    }

    fn secondary(&self) -> String {
        self.target.clone()
    }
}

/// What the user asked the Hosts view for (handled by the reducer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsRequest {
    /// `Enter`: connect to these hosts (one tab each).
    Connect(Vec<ItemId>),
    /// `ctrl-enter` / `v`: connect in a split.
    ConnectSplit(Vec<ItemId>),
    /// `a`.
    Add,
    /// `e`.
    Edit(ItemId),
    /// `y`.
    Duplicate(Vec<ItemId>),
    /// `d` (confirm first).
    Delete(Vec<ItemId>),
    /// `p`: pin (`true`) or unpin.
    Pin(Vec<ItemId>, bool),
    /// `m`.
    MoveToGroup(Vec<ItemId>),
    /// `t`.
    Tag(Vec<ItemId>),
    /// `c`.
    CopyCommand(ItemId),
    /// `A`: a new group (inside this one).
    NewGroup(Option<ItemId>),
    /// `e` on a group.
    EditGroup(ItemId),
    /// `d` on a group.
    DeleteGroup(ItemId),
    /// `a` on a group: a new host in it.
    AddInGroup(ItemId),
    /// `T`: the tag manager.
    ManageTags,
    /// `D`: the vault defaults editor.
    VaultDefaults,
    /// `I`: the import wizard.
    Import,
    /// `X`: the export form.
    Export,
    /// `H`: clear the host's command history (asks first).
    ClearHistory(ItemId),
    /// `V`: the vault selector changed (`None`: All vaults).
    VaultSelected(Option<sverb_core::model::VaultId>),
    /// `M`: move hosts to another vault (§13.1).
    MoveToVault(Vec<ItemId>),
    /// `C`: copy hosts to another vault.
    CopyToVault(Vec<ItemId>),
    /// `O`: "Use my own credentials…" on a shared host (§13.4).
    Override(ItemId),
}

/// The Hosts section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsView {
    /// The list.
    pub list: ListView<HostRow>,
    index: Option<Arc<IndexSnapshot>>,
    catalog: Option<Arc<HostCatalog>>,
    request: Option<HostsRequest>,
    /// The vault selector (`None`: All vaults, merged).
    vault: Option<sverb_core::model::VaultId>,
}

impl Default for HostsView {
    fn default() -> Self {
        Self {
            list: ListView::new("Hosts")
                .with_tree(true)
                .with_empty(EmptyState::new("No hosts yet", &[("a", "add a host")])),
            index: None,
            catalog: None,
            request: None,
            vault: None,
        }
    }
}

impl HostsView {
    /// The latest index snapshot.
    pub fn index(&self) -> Option<&Arc<IndexSnapshot>> {
        self.index.as_ref()
    }

    /// The latest catalog.
    pub fn catalog(&self) -> Option<&Arc<HostCatalog>> {
        self.catalog.as_ref()
    }

    /// A new index snapshot: rows and the filter source follow.
    pub fn set_index(&mut self, index: Arc<IndexSnapshot>) {
        self.list.set_source(FilterSource::Index {
            snapshot: Arc::clone(&index),
            scope: Scope::Hosts,
        });
        self.index = Some(index);
        self.rebuild();
    }

    /// A new catalog (after the vault service decrypted the hosts).
    pub fn set_catalog(&mut self, catalog: Arc<HostCatalog>) {
        self.catalog = Some(catalog);
        self.rebuild();
    }

    /// Drop all decrypted data (the vault locked).
    pub fn clear(&mut self) {
        if self.index.is_some() || self.catalog.is_some() || !self.list.rows().is_empty() {
            self.index = None;
            self.catalog = None;
            self.list.set_source(FilterSource::Local);
            self.list.set_rows(Vec::new());
        }
    }

    /// Whether the list edits text (filter line: Insert mode).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    /// The pending request, if any.
    pub fn take_request(&mut self) -> Option<HostsRequest> {
        self.request.take()
    }

    /// Clear the marks after a bulk action.
    pub fn clear_marks(&mut self) {
        self.list.clear_marks();
    }

    /// Put the cursor on a host.
    pub fn select(&mut self, id: ItemId) -> bool {
        self.list.select_key(&HostRowKey::Host(id))
    }

    /// The summary of a host, if the catalog has it.
    pub fn host(&self, id: ItemId) -> Option<&HostSummary> {
        self.catalog.as_ref()?.hosts.get(&id)
    }

    /// The vault selector (`None`: All vaults).
    pub fn vault(&self) -> Option<sverb_core::model::VaultId> {
        self.vault
    }

    /// Selects `vault` (`None`: All vaults), e.g. `general.default_vault` at unlock.
    pub fn set_vault(&mut self, vault: Option<sverb_core::model::VaultId>) {
        if self.vault != vault {
            self.vault = vault;
            self.rebuild();
        }
    }

    /// The top bar's vault label: `All vaults` or the selected vault's name.
    pub fn vault_label(&self) -> String {
        match (self.vault, self.catalog.as_deref()) {
            (Some(v), Some(c)) => c
                .vault_names
                .get(&v)
                .cloned()
                .unwrap_or_else(|| "Vault".to_owned()),
            (Some(_), None) => "Vault".to_owned(),
            (None, Some(c)) if c.vault_names.len() > 1 => "All vaults".to_owned(),
            (None, _) => "Personal".to_owned(),
        }
    }

    /// The next vault of the selector: All → Personal → shared vaults (by name) →
    /// All. Only offered once a shared vault exists.
    fn next_vault(&self) -> Option<Option<sverb_core::model::VaultId>> {
        let c = self.catalog.as_deref()?;
        if c.vault_names.len() < 2 {
            return None;
        }
        let mut order: Vec<sverb_core::model::VaultId> = c.personal_vault.into_iter().collect();
        let mut shared: Vec<_> = c
            .vault_names
            .iter()
            .filter(|(v, _)| Some(**v) != c.personal_vault)
            .map(|(v, n)| (n.to_lowercase(), *v))
            .collect();
        shared.sort();
        order.extend(shared.into_iter().map(|(_, v)| v));
        let next = match self.vault.and_then(|v| order.iter().position(|x| *x == v)) {
            None => order.first().copied(),
            Some(i) => order.get(i + 1).copied(),
        };
        Some(next)
    }

    /// The rows for the current index and catalog.
    pub fn rows(index: Option<&IndexSnapshot>, catalog: Option<&HostCatalog>) -> Vec<HostRow> {
        Self::rows_in(index, catalog, None)
    }

    /// [`Self::rows`] limited to `vault` (`None`: every vault, with badges).
    pub fn rows_in(
        index: Option<&IndexSnapshot>,
        catalog: Option<&HostCatalog>,
        vault: Option<sverb_core::model::VaultId>,
    ) -> Vec<HostRow> {
        let Some(index) = index else {
            return Vec::new();
        };
        let row = |key: HostRowKey, id: ItemId| -> Option<HostRow> {
            let entry = index.get(id)?;
            // The vault selector.
            if vault.is_some_and(|v| v != entry.vault_id) {
                return None;
            }
            let badge = match (vault, catalog) {
                (None, Some(c)) => c.vault_badge(entry.vault_id).map(str::to_owned),
                _ => None,
            };
            let summary = catalog.and_then(|c| c.hosts.get(&id));
            // The host's group node (a missing group shows a chip instead).
            let group = summary.and_then(|h| h.group_id);
            let known = group.filter(|g| catalog.is_some_and(|c| c.lookup.groups.contains_key(g)));
            let parent = match key {
                HostRowKey::Recent(_) => Some(HostRowKey::RecentGroup),
                _ => known.map(HostRowKey::Group),
            };
            let mut chip = (group.is_some() && known.is_none() && catalog.is_some())
                .then_some("missing group");
            let (target, tags) = match (summary, catalog) {
                (Some(h), Some(c)) => {
                    // The resolved user and port (group / vault defaults).
                    let r = c.resolve(h, &GlobalDefaults::default());
                    // A deleted identity (§12.4).
                    if chip.is_none()
                        && r.warnings.iter().any(|w| {
                            matches!(w, sverb_core::resolve::ResolveWarning::MissingIdentity(_))
                        })
                    {
                        chip = Some("missing identity");
                    }
                    (
                        catalog::format_target(r.username.as_deref(), &h.address, Some(r.port)),
                        c.tags_of(h),
                    )
                }
                _ => {
                    let user = (!entry.user.is_empty()).then(|| entry.user.as_str());
                    let mut t = String::new();
                    if let Some(u) = user {
                        t.push_str(u);
                        t.push('@');
                    }
                    t.push_str(&entry.address);
                    let tags = entry
                        .tags
                        .iter()
                        .map(|n| TagInfo {
                            name: n.to_string(),
                            color: None,
                        })
                        .collect();
                    (t, tags)
                }
            };
            Some(HostRow {
                key,
                label: entry.display_label().to_owned(),
                target,
                tags,
                pinned: entry.pinned,
                parent,
                icon: None,
                chip,
                vault: badge,
            })
        };
        let mut rows = Vec::new();
        if let Some(c) = catalog {
            let recent: Vec<HostRow> = c
                .recent(RECENT_COUNT)
                .into_iter()
                .filter_map(|id| row(HostRowKey::Recent(id), id))
                .collect();
            if !recent.is_empty() {
                rows.push(HostRow {
                    key: HostRowKey::RecentGroup,
                    label: "Recent".to_owned(),
                    target: String::new(),
                    tags: Vec::new(),
                    pinned: false,
                    parent: None,
                    icon: None,
                    chip: None,
                    vault: None,
                });
                rows.extend(recent);
            }
            // Group nodes, in tree order (the list nests them by parent).
            for (gid, _) in c.group_tree() {
                // Groups of the selected vault only.
                if vault.is_some_and(|v| c.group_vaults.get(&gid) != Some(&v)) {
                    continue;
                }
                let g = &c.lookup.groups[&gid];
                rows.push(HostRow {
                    key: HostRowKey::Group(gid),
                    label: g.name.clone(),
                    target: String::new(),
                    tags: Vec::new(),
                    pinned: false,
                    parent: g
                        .parent_id
                        .filter(|p| *p != gid && c.lookup.groups.contains_key(p))
                        .map(HostRowKey::Group),
                    icon: g.icon.clone(),
                    chip: None,
                    vault: None,
                });
            }
        }
        rows.extend(
            index
                .ordered(Scope::Hosts, index)
                .into_iter()
                .filter_map(|e| row(HostRowKey::Host(e.item_id), e.item_id)),
        );
        rows
    }

    fn rebuild(&mut self) {
        // A vault that went away (left, revoked) falls back to All.
        if let (Some(v), Some(c)) = (self.vault, self.catalog.as_deref())
            && !c.vault_names.contains_key(&v)
        {
            self.vault = None;
        }
        let rows = Self::rows_in(self.index.as_deref(), self.catalog.as_deref(), self.vault);
        self.list.set_rows(rows);
    }

    /// The hosts an action applies to: the marks, else the cursor row (deduplicated).
    pub fn targets(&self) -> Vec<ItemId> {
        let mut out: Vec<ItemId> = Vec::new();
        for id in self.list.targets().into_iter().filter_map(HostRowKey::item) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }

    fn selected_item(&self) -> Option<ItemId> {
        self.list.selected_key().and_then(HostRowKey::item)
    }

    /// The group under the cursor.
    pub fn selected_group(&self) -> Option<ItemId> {
        self.list.selected_key().and_then(HostRowKey::group)
    }

    fn on_action_key(&mut self, code: KeyCode, mods: KeyModifiers) -> Option<HostsRequest> {
        let targets = self.targets();
        let any = !targets.is_empty();
        let ctrl = mods.contains(KeyModifiers::CONTROL);
        // Keys on a group row (no marks).
        if let Some(group) = self.selected_group()
            && self.list.marks().is_empty()
            && !ctrl
            && !mods.contains(KeyModifiers::ALT)
        {
            match code {
                KeyCode::Char('e') => return Some(HostsRequest::EditGroup(group)),
                KeyCode::Char('d') => return Some(HostsRequest::DeleteGroup(group)),
                KeyCode::Char('a') => return Some(HostsRequest::AddInGroup(group)),
                KeyCode::Char('A') => return Some(HostsRequest::NewGroup(Some(group))),
                _ => {}
            }
        }
        Some(match code {
            KeyCode::Enter if ctrl && any => HostsRequest::ConnectSplit(targets),
            KeyCode::Enter if any => HostsRequest::Connect(targets),
            _ if ctrl || mods.contains(KeyModifiers::ALT) => return None,
            KeyCode::Char('v') if any => HostsRequest::ConnectSplit(targets),
            KeyCode::Char('a') => HostsRequest::Add,
            KeyCode::Char('e') => HostsRequest::Edit(self.selected_item()?),
            KeyCode::Char('y') if any => HostsRequest::Duplicate(targets),
            KeyCode::Char('d') if any => HostsRequest::Delete(targets),
            KeyCode::Char('p') if any => {
                // Pin unless every target is already pinned.
                let all_pinned = targets.iter().all(|id| {
                    self.index
                        .as_ref()
                        .and_then(|i| i.get(*id))
                        .is_some_and(|e| e.pinned)
                });
                HostsRequest::Pin(targets, !all_pinned)
            }
            KeyCode::Char('m') if any => HostsRequest::MoveToGroup(targets),
            KeyCode::Char('t') if any => HostsRequest::Tag(targets),
            KeyCode::Char('c') => HostsRequest::CopyCommand(self.selected_item()?),
            KeyCode::Char('A') => HostsRequest::NewGroup(None),
            KeyCode::Char('T') => HostsRequest::ManageTags,
            KeyCode::Char('D') => HostsRequest::VaultDefaults,
            KeyCode::Char('I') => HostsRequest::Import,
            KeyCode::Char('X') => HostsRequest::Export,
            KeyCode::Char('H') => HostsRequest::ClearHistory(self.selected_item()?),
            KeyCode::Char('V') => {
                let next = self.next_vault()?;
                self.vault = next;
                self.rebuild();
                HostsRequest::VaultSelected(next)
            }
            KeyCode::Char('M') if any => HostsRequest::MoveToVault(targets),
            KeyCode::Char('C') if any => HostsRequest::CopyToVault(targets),
            KeyCode::Char('O') => {
                let id = self.selected_item()?;
                let c = self.catalog.as_deref()?;
                if !c
                    .hosts
                    .get(&id)
                    .is_some_and(|h| c.shared_vaults.contains(&h.vault))
                {
                    return None;
                }
                HostsRequest::Override(id)
            }
            _ => return None,
        })
    }

    /// Draw the selected host's details (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let selected = self.list.selected();
        let title = selected.map_or_else(|| " Details ".to_owned(), |r| format!(" {} ", r.label));
        let block = Block::bordered()
            .title(Span::styled(title, theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let inner_w = usize::from(area.width.saturating_sub(2));
        let lines = match selected {
            Some(row) => HostDetail {
                catalog: self.catalog.as_deref(),
            }
            .lines(row, theme, inner_w),
            None => vec![Line::styled("Nothing selected.", theme.dim)],
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block)
                .style(theme.base),
            area,
        );
    }
}

/// Draws a host row: pin star, label (with match highlights), `user@host:port`, tag chips.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostRowRenderer;

/// The style of a tag chip: its color, unless the theme is monochrome.
fn chip_style(tag: &TagInfo, base: Style, theme: &Theme) -> Style {
    let color = tag
        .color
        .as_deref()
        .filter(|_| !theme.monochrome)
        .and_then(|c| Color::from_str(c).ok());
    match color {
        Some(c) => base.fg(c),
        None => base.patch(theme.accent),
    }
}

impl RowRenderer<HostRow> for HostRowRenderer {
    fn spans(&self, row: &HostRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        if row.is_group() {
            // A group's icon before its name.
            let text = match &row.icon {
                Some(i) => format!("{i} {}", row.label),
                None => row.label.clone(),
            };
            return vec![Span::styled(
                truncate(&text, cx.width),
                cx.base.patch(cx.theme.accent),
            )];
        }
        let mut spans = vec![Span::styled(if row.pinned { "★ " } else { "  " }, cx.base)];
        let avail = cx.width.saturating_sub(2);
        let label = truncate(&row.label, avail);
        let mut used = 2 + width(&label);
        spans.extend(highlighted(
            &label,
            cx.highlights,
            cx.base,
            match_style(cx.base, cx.theme),
        ));
        let dim = if cx.selected { cx.base } else { cx.theme.dim };
        if !row.target.is_empty() && used + 3 < cx.width {
            let t = truncate(&row.target, cx.width - used - 2);
            used += 2 + width(&t);
            spans.push(Span::styled(format!("  {t}"), dim));
        }
        // The missing-group warning chip first.
        if let Some(w) = row.chip {
            let chip = format!("[! {w}]");
            if used + 1 + width(&chip) <= cx.width {
                used += 1 + width(&chip);
                spans.push(Span::styled(" ", cx.base));
                spans.push(Span::styled(chip, cx.base.patch(cx.theme.warn)));
            }
        }
        // The shared vault's badge (merged list).
        if let Some(v) = &row.vault {
            let chip = format!("({v})");
            if used + 1 + width(&chip) <= cx.width {
                used += 1 + width(&chip);
                spans.push(Span::styled(" ", cx.base));
                spans.push(Span::styled(chip, cx.base.patch(cx.theme.info)));
            }
        }
        for tag in &row.tags {
            let chip = format!("[{}]", tag.name);
            if used + 1 + width(&chip) > cx.width {
                break;
            }
            used += 1 + width(&chip);
            spans.push(Span::styled(" ", cx.base));
            spans.push(Span::styled(chip, chip_style(tag, cx.base, cx.theme)));
        }
        spans
    }
}

/// The detail pane renderer.
#[derive(Debug, Clone, Copy)]
pub struct HostDetail<'a> {
    /// The catalog (`None` until loaded).
    pub catalog: Option<&'a HostCatalog>,
}

impl DetailRenderer<HostRow> for HostDetail<'_> {
    fn lines(&self, row: &HostRow, theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        if let (Some(g), Some(c)) = (row.key.group(), self.catalog) {
            return detail::group_lines(g, c, theme);
        }
        let Some(id) = row.key.item() else {
            let n = self.catalog.map_or(0, |c| c.recent(RECENT_COUNT).len());
            return vec![Line::styled(
                format!("The {n} most recently connected hosts."),
                theme.dim,
            )];
        };
        match self.catalog.and_then(|c| c.hosts.get(&id).map(|h| (c, h))) {
            Some((c, h)) => detail::host_lines(h, c, theme),
            None => vec![
                Line::styled(row.label.clone(), theme.base),
                Line::styled(row.target.clone(), theme.dim),
                Line::styled("Loading…", theme.dim),
            ],
        }
    }
}

impl View for HostsView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        if self.list.handle(ev, cx) == Outcome::Consumed {
            return Outcome::Consumed;
        }
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        match self.on_action_key(key.code, key.modifiers) {
            Some(req) => {
                self.request = Some(req);
                cx.request_redraw();
                Outcome::Consumed
            }
            None => Outcome::Ignored,
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        // The shell's detail pane shows the details beside the list; the list draws
        // them itself only full screen (`i`).
        let full_detail = HostDetail {
            catalog: self.catalog.as_deref(),
        };
        let detail: Option<&dyn DetailRenderer<HostRow>> =
            self.list.detail_full().then_some(&full_detail as _);
        self.list
            .render_with(frame, area, cx, &HostRowRenderer, detail);
        // The quick-connect hint under an empty list.
        if self.list.rows().is_empty()
            && !self.list.insert_mode()
            && self.list.filter_text().is_empty()
            && area.height > 5
            && area.width > 10
        {
            let hint = format!("{:>8}  quick connect", format!("{} o", leader_hint(cx)));
            let y = area.y + 3;
            let r = Rect::new(area.x + 1, y, area.width - 2, 1);
            frame.render_widget(Line::from(vec![Span::styled(hint, cx.theme.dim)]), r);
        }
    }

    fn insert_mode(&self) -> bool {
        HostsView::insert_mode(self)
    }
}

/// Test fixtures: an index over hosts `(label, address)` with the given ids.
#[cfg(test)]
pub(crate) fn sample_index(hosts: &[(&str, &str)]) -> (Arc<IndexSnapshot>, Vec<ItemId>) {
    use sverb_core::model::{DeviceId, HlcClock, Host, ItemBody, ItemKind, VaultId};
    use sverb_core::search::ItemIndex;
    let mut clock = HlcClock::default();
    let device = DeviceId::from_bytes([1; 16]);
    let vault = VaultId::from_bytes([2; 16]);
    let mut ids = Vec::new();
    let mut bodies = Vec::new();
    for (i, (label, address)) in hosts.iter().enumerate() {
        let mut id = [0u8; 16];
        id[15] = u8::try_from(i + 1).unwrap_or(u8::MAX);
        let id = ItemId::from_bytes(id);
        let mut body = ItemBody::new(ItemKind::Host, 1);
        Host {
            label: (*label).to_owned(),
            address: (*address).to_owned(),
            ..Host::default()
        }
        .apply_to(&mut body, &mut clock, device);
        ids.push(id);
        bodies.push((id, body));
    }
    let mut index = ItemIndex::build(bodies.iter().map(|(id, b)| (*id, vault, b)));
    (index.snapshot(), ids)
}
