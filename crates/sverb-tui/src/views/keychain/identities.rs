//! M2-02: the Keychain view's Identities sub-tab (SPEC §4.4, §8.5, §9.3).
//!
//! - **Rows**: every live identity in index order (alphabetical), with its user name,
//!   the auth summary (`password`, `key: <label>`, `password + key`) and how many
//!   hosts use it. The filter (`/`) searches label and user name through the index
//!   (`kind:identity`); the password is never indexed.
//! - **Usage** ("used by N hosts"): hosts whose **resolved** identity is this one,
//!   direct or inherited from a group / the vault defaults
//!   (`sverb_core::model::identity::hosts_referencing`), recomputed per catalog.
//! - **Detail**: user, auth, key, vault and the hosts that use it (direct ones first,
//!   inherited ones marked "via group").
//! - **Actions** (Normal mode): `a` add, `e` edit, `y` duplicate, `d` delete (the
//!   dialog warns with the usage counts), `Enter` the "Used by" list (pick a host to
//!   jump to it in the Hosts view). The view only records the request
//!   ([`IdentitiesView::take_request`]); the reducer (`app/keychain.rs`) carries it out.

use std::collections::BTreeMap;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
};
use sverb_core::{
    model::{
        ItemId, ItemKind,
        identity::{IdentityUsage, auth_summary, hosts_referencing},
    },
    resolve::{GlobalDefaults, ResolvedHost},
    search::{IndexSnapshot, Scope},
};

use crate::{
    theme::Theme,
    views::{
        Outcome, RenderCx, View, ViewCx, ViewEvent,
        hosts::catalog::{HostCatalog, IdentityInfo},
    },
    widgets::{
        form::{highlighted, match_style},
        list::{DetailRenderer, EmptyState, FilterSource, ListRow, ListView, RowCx, RowRenderer},
        truncate, width,
    },
};

/// Hosts listed by name in the detail pane (the rest are counted).
pub const DETAIL_HOSTS: usize = 12;

/// One row of the Identities list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    /// The identity.
    pub id: ItemId,
    /// `label`.
    pub label: String,
    /// `username`.
    pub username: String,
    /// `password` / `key: <label>` / `password + key` / `none`.
    pub auth: String,
    /// Hosts using it (direct + inherited).
    pub used: usize,
}

impl ListRow for IdentityRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.id
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn filter_text(&self) -> String {
        format!("{} {}", self.label, self.username)
    }

    fn item_id(&self) -> Option<ItemId> {
        Some(self.id)
    }

    fn secondary(&self) -> String {
        self.username.clone()
    }
}

/// What the user asked the Identities sub-tab for (handled by the reducer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityRequest {
    /// `a`: a new identity.
    Add,
    /// `e`: edit (loads the password first).
    Edit(ItemId),
    /// `y`: duplicate.
    Duplicate(Vec<ItemId>),
    /// `d`: the delete dialog.
    Delete(ItemId),
    /// `Enter`: the "Used by" host list.
    UsedBy(ItemId),
}

/// The Identities sub-tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitiesView {
    /// The list.
    pub list: ListView<IdentityRow>,
    index: Option<Arc<IndexSnapshot>>,
    catalog: Option<Arc<HostCatalog>>,
    usage: BTreeMap<ItemId, IdentityUsage>,
    request: Option<IdentityRequest>,
}

impl Default for IdentitiesView {
    fn default() -> Self {
        Self {
            list: ListView::new("Identities").with_empty(EmptyState::new(
                "No identities yet",
                &[("a", "add an identity")],
            )),
            index: None,
            catalog: None,
            usage: BTreeMap::new(),
            request: None,
        }
    }
}

/// Usage of every identity of `catalog`, from one resolution per host.
pub fn usage_map(catalog: &HostCatalog) -> BTreeMap<ItemId, IdentityUsage> {
    let globals = GlobalDefaults::default();
    let resolved: Vec<(ItemId, ResolvedHost)> = catalog
        .hosts
        .values()
        .map(|h| (h.id, catalog.resolve(h, &globals)))
        .collect();
    catalog
        .lookup
        .identities
        .keys()
        .map(|id| {
            (
                *id,
                hosts_referencing(*id, resolved.iter().map(|(h, r)| (*h, r))),
            )
        })
        .collect()
}

/// The auth summary of an identity in `catalog`.
pub fn identity_auth(catalog: &HostCatalog, id: ItemId, info: &IdentityInfo) -> String {
    let has_password = catalog
        .lookup
        .identities
        .get(&id)
        .is_some_and(|n| n.has_password);
    let key = info.key_id.map(|k| {
        catalog
            .keys
            .get(&k)
            .cloned()
            .unwrap_or_else(|| format!("(missing {})", k.short()))
    });
    auth_summary(has_password, key.as_deref())
}

impl IdentitiesView {
    /// The latest catalog.
    pub fn catalog(&self) -> Option<&Arc<HostCatalog>> {
        self.catalog.as_ref()
    }

    /// The latest index.
    pub fn index(&self) -> Option<&Arc<IndexSnapshot>> {
        self.index.as_ref()
    }

    /// A new index snapshot.
    pub fn set_index(&mut self, index: Arc<IndexSnapshot>) {
        self.list.set_source(FilterSource::Index {
            snapshot: Arc::clone(&index),
            scope: Scope::Kind(ItemKind::Identity),
        });
        self.index = Some(index);
        self.rebuild();
    }

    /// A new catalog: rows and usage counts follow.
    pub fn set_catalog(&mut self, catalog: Arc<HostCatalog>) {
        self.usage = usage_map(&catalog);
        self.catalog = Some(catalog);
        self.rebuild();
    }

    /// Drop all decrypted data (the vault locked).
    pub fn clear(&mut self) {
        if self.index.is_some() || self.catalog.is_some() || !self.list.rows().is_empty() {
            self.index = None;
            self.catalog = None;
            self.usage.clear();
            self.list.set_source(FilterSource::Local);
            self.list.set_rows(Vec::new());
        }
    }

    /// The usage of `id` (empty if unknown).
    pub fn usage(&self, id: ItemId) -> IdentityUsage {
        self.usage.get(&id).cloned().unwrap_or_default()
    }

    /// The pending request, if any.
    pub fn take_request(&mut self) -> Option<IdentityRequest> {
        self.request.take()
    }

    /// Whether the list edits text (filter line).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    /// Put the cursor on an identity.
    pub fn select(&mut self, id: ItemId) -> bool {
        self.list.select_key(&id)
    }

    /// The label of an identity (catalog, else index).
    pub fn label_of(&self, id: ItemId) -> Option<String> {
        self.catalog
            .as_ref()
            .and_then(|c| c.identities.get(&id).map(|i| i.label.clone()))
            .or_else(|| {
                self.index
                    .as_ref()
                    .and_then(|i| i.get(id).map(|e| e.label.to_string()))
            })
    }

    /// The rows for an index and catalog.
    pub fn rows(
        index: Option<&IndexSnapshot>,
        catalog: Option<&HostCatalog>,
        usage: &BTreeMap<ItemId, IdentityUsage>,
    ) -> Vec<IdentityRow> {
        let Some(index) = index else {
            return Vec::new();
        };
        index
            .ordered(Scope::Kind(ItemKind::Identity), index)
            .into_iter()
            .map(|e| {
                let id = e.item_id;
                let info = catalog.and_then(|c| c.identities.get(&id).map(|i| (c, i)));
                IdentityRow {
                    id,
                    label: e.label.to_string(),
                    username: e.user.to_string(),
                    auth: info.map_or_else(String::new, |(c, i)| identity_auth(c, id, i)),
                    used: usage.get(&id).map_or(0, IdentityUsage::total),
                }
            })
            .collect()
    }

    fn rebuild(&mut self) {
        let rows = Self::rows(self.index.as_deref(), self.catalog.as_deref(), &self.usage);
        self.list.set_rows(rows);
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<IdentityRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        let selected = self.list.selected_key();
        let targets = self.list.targets();
        Some(match code {
            KeyCode::Char('a') => IdentityRequest::Add,
            KeyCode::Char('e') => IdentityRequest::Edit(selected?),
            KeyCode::Char('y') if !targets.is_empty() => IdentityRequest::Duplicate(targets),
            KeyCode::Char('d') => IdentityRequest::Delete(selected?),
            KeyCode::Enter => IdentityRequest::UsedBy(selected?),
            _ => return None,
        })
    }

    /// Draw the selected identity's details (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let lines = match self.list.selected() {
            Some(row) => self.detail().lines(row, cx.theme, usize::from(area.width)),
            None => vec![Line::styled("Nothing selected.", cx.theme.dim)],
        };
        let title = self
            .list
            .selected()
            .map_or_else(|| " Details ".to_owned(), |r| format!(" {} ", r.label));
        super::render_pane(frame, area, cx, &title, lines);
    }

    fn detail(&self) -> IdentityDetail<'_> {
        IdentityDetail {
            catalog: self.catalog.as_deref(),
            usage: &self.usage,
            index: self.index.as_deref(),
        }
    }

    /// Draw the list (with the full-screen detail on `i`).
    pub fn render_list(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let detail = self.detail();
        let full: Option<&dyn DetailRenderer<IdentityRow>> =
            self.list.detail_full().then_some(&detail as _);
        self.list
            .render_with(frame, area, cx, &IdentityRowRenderer, full);
    }
}

/// Draws an identity row: label, user, auth summary, `N hosts`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityRowRenderer;

impl RowRenderer<IdentityRow> for IdentityRowRenderer {
    fn spans(&self, row: &IdentityRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let dim = if cx.selected { cx.base } else { cx.theme.dim };
        let label = truncate(&row.label, cx.width);
        let mut used = width(&label);
        let mut spans = highlighted(
            &label,
            cx.highlights,
            cx.base,
            match_style(cx.base, cx.theme),
        );
        let hosts = match row.used {
            1 => "1 host".to_owned(),
            n => format!("{n} hosts"),
        };
        for part in [row.username.as_str(), row.auth.as_str(), hosts.as_str()] {
            if part.is_empty() {
                continue;
            }
            if used + 4 >= cx.width {
                break;
            }
            let t = truncate(part, cx.width - used - 2);
            used += 2 + width(&t);
            spans.push(Span::styled(format!("  {t}"), dim));
        }
        spans
    }
}

/// The detail lines of an identity.
#[derive(Debug, Clone, Copy)]
pub struct IdentityDetail<'a> {
    /// The catalog (`None` until loaded).
    pub catalog: Option<&'a HostCatalog>,
    /// Usage per identity.
    pub usage: &'a BTreeMap<ItemId, IdentityUsage>,
    /// The index (vaults).
    pub index: Option<&'a IndexSnapshot>,
}

fn row(label: &str, value: String, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<10}"), theme.dim),
        Span::styled(value, theme.base),
    ])
}

impl DetailRenderer<IdentityRow> for IdentityDetail<'_> {
    fn lines(&self, r: &IdentityRow, theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        let mut lines = vec![row("Label", r.label.clone(), theme)];
        let user = if r.username.is_empty() {
            "(none)".to_owned()
        } else {
            r.username.clone()
        };
        lines.push(row("User", user, theme));
        let Some(c) = self.catalog else {
            lines.push(Line::styled("Loading…", theme.dim));
            return lines;
        };
        lines.push(row("Auth", r.auth.clone(), theme));
        if let Some(key) = c.identities.get(&r.id).and_then(|i| i.key_id) {
            let name = c
                .keys
                .get(&key)
                .cloned()
                .unwrap_or_else(|| format!("(missing {})", key.short()));
            lines.push(row("Key", name, theme));
        }
        if let Some(v) = self
            .index
            .and_then(|i| i.get(r.id))
            .and_then(|e| c.vault_names.get(&e.vault_id))
        {
            lines.push(row("Vault", v.clone(), theme));
        }
        lines.push(Line::raw(""));
        let usage = self.usage.get(&r.id).cloned().unwrap_or_default();
        let n = usage.total();
        let head = match n {
            0 => "Not used by any host".to_owned(),
            1 => "Used by 1 host".to_owned(),
            n => format!("Used by {n} hosts"),
        };
        let mut head_spans = vec![Span::styled(head, theme.accent)];
        if !usage.inherited.is_empty() {
            head_spans.push(Span::styled(
                format!(
                    " ({} direct, {} via group)",
                    usage.direct.len(),
                    usage.inherited.len()
                ),
                theme.dim,
            ));
        }
        lines.push(Line::from(head_spans));
        let name = |h: ItemId| {
            c.hosts
                .get(&h)
                .map_or_else(|| h.short(), |s| s.display_label().to_owned())
        };
        for (shown, (h, inherited)) in usage
            .direct
            .iter()
            .map(|h| (*h, false))
            .chain(usage.inherited.iter().map(|h| (*h, true)))
            .enumerate()
        {
            if shown == DETAIL_HOSTS {
                lines.push(Line::styled(
                    format!("  … {} more", n - DETAIL_HOSTS),
                    theme.dim,
                ));
                break;
            }
            let mut spans = vec![Span::styled(format!("  {}", name(h)), theme.base)];
            if inherited {
                let via = c
                    .hosts
                    .get(&h)
                    .and_then(|s| s.group_id)
                    .and_then(|g| c.group_name(g))
                    .map_or_else(|| " (via defaults)".to_owned(), |g| format!(" (via {g})"));
                spans.push(Span::styled(via, theme.dim));
            }
            lines.push(Line::from(spans));
        }
        if n > 0 {
            lines.push(Line::raw(""));
            lines.push(Line::styled("enter: go to a host", theme.dim));
        }
        lines
    }
}

impl View for IdentitiesView {
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
        self.render_list(frame, area, cx);
    }

    fn insert_mode(&self) -> bool {
        IdentitiesView::insert_mode(self)
    }
}
