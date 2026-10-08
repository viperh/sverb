//! M2-01: organizing hosts (SPEC §4.11, §4.13, §9.2): the group editor, the vault
//! defaults editor, "move to group", bulk tagging, deleting a group and the tag
//! manager. They live on the dialog stack as `DialogKind::Organize`.
//!
//! - **Group editor** (`A` new, `e` on a group): name, parent, icon and the defaults
//!   (the host form's inheritable fields), with live inherited placeholders from the
//!   parent chain. The vault defaults editor (`D`) is the same form without name and
//!   parent. Saves go out as `ItemEffect::Save { kind: Group }`.
//! - **Move to group** (`m`, bulk): a group picker; "(no group)" moves to the top.
//! - **Tags** (`t`, bulk): every tag of the vault with a tri-state mark (`[x]` all
//!   targets have it, `[-]` some, `[ ]` none); `Space` toggles, the last row creates
//!   a new tag inline. Only the tags whose state changed are added or removed.
//! - **Delete group** (`d` on a group): "Move its N hosts and M subgroups to the
//!   parent group" (default) or "Delete them" (danger; above
//!   [`DELETE_CONFIRM_THRESHOLD`] items the count must be typed).
//! - **Tag manager** (`T`): rename (`r`), recolor (`c` cycles the palette), delete
//!   (`d`, confirm `y`), new (`n`). Deleting a tag leaves stale references on hosts;
//!   they are ignored at read time and cleaned up lazily (§12.4).

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::model::{
    ItemId, ItemKind,
    group::{DELETE_CONFIRM_THRESHOLD, DeleteGroupMode},
    tag::{TAG_COLORS, validate_tag},
};

use super::catalog::HostCatalog;
use super::form::{InheritCx, sync_inherited};
use crate::app::hosts::ItemEffect;
use crate::app::{Effect, VaultEffect, state::PendingKind};
use crate::views::{DialogId, RenderCx, View as _, ViewCx, ViewEvent};
use crate::widgets::form::{FieldChanges, FieldValue, Form, FormRequest, TextEdit, TextInput};
use crate::widgets::{truncate, width};

/// An organizing dialog (`DialogKind::Organize`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrganizeDialog {
    /// The group (or vault defaults) editor.
    GroupForm(Box<GroupFormDialog>),
    /// "Move to group".
    GroupPicker(GroupPicker),
    /// Bulk tags.
    TagPicker(TagPicker),
    /// Delete a group.
    DeleteGroup(DeleteGroupDialog),
    /// The tag manager.
    Tags(TagManager),
}

impl OrganizeDialog {
    /// The dialog edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        match self {
            Self::GroupForm(_) => true,
            Self::TagPicker(t) => t.on_new_row(),
            Self::DeleteGroup(d) => d.typing.is_some(),
            Self::Tags(t) => t.input.is_some(),
            Self::GroupPicker(_) => false,
        }
    }

    /// Handle an event (the dialog is modal: everything is consumed).
    pub fn handle(&mut self, id: DialogId, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        match self {
            Self::GroupForm(d) => d.handle(id, ev, cx),
            Self::GroupPicker(p) => {
                if let ViewEvent::Key(k) = ev {
                    p.handle_key(k, cx);
                }
            }
            Self::TagPicker(t) => match ev {
                ViewEvent::Key(k) => t.handle_key(k, cx),
                ViewEvent::Paste(s) => {
                    if t.on_new_row() {
                        t.new_tag.insert_str(s);
                    }
                }
                ViewEvent::Mouse(_) => {}
            },
            Self::DeleteGroup(d) => {
                if let ViewEvent::Key(k) = ev {
                    d.handle_key(k, cx);
                }
            }
            Self::Tags(t) => {
                if let ViewEvent::Key(k) = ev {
                    t.handle_key(k, cx);
                }
            }
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match self {
            Self::GroupForm(d) => d.form.render(frame, area, cx),
            Self::GroupPicker(p) => p.render(frame, area, cx),
            Self::TagPicker(t) => t.render(frame, area, cx),
            Self::DeleteGroup(d) => d.render(frame, area, cx),
            Self::Tags(t) => t.render(frame, area, cx),
        }
    }
}

fn items(op: ItemEffect) -> Effect {
    Effect::Vault(VaultEffect::Items(op))
}

fn plain(k: &KeyEvent) -> bool {
    !k.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// A centered box with `title` and `lines` (at least `min_w` wide).
fn boxed(
    frame: &mut Frame<'_>,
    area: Rect,
    cx: &RenderCx<'_>,
    title: &str,
    lines: Vec<Line<'static>>,
    min_w: usize,
) {
    let theme = cx.theme;
    let content_w = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .max(width(title) + 2)
        .max(min_w);
    let w = u16::try_from(content_w + 4)
        .unwrap_or(u16::MAX)
        .min(area.width);
    let h = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    if w < 3 || h < 3 {
        return;
    }
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .title(Span::styled(format!(" {title} "), theme.title_for(true)))
        .border_style(theme.border_for(true));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let padded = Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    frame.render_widget(Paragraph::new(lines).style(theme.base), padded);
}

/// A list row: `›` and the selection style on the cursor row.
fn list_line(text: String, selected: bool, style: Style, selection: Style) -> Line<'static> {
    let (mark, style) = if selected {
        ("› ", selection)
    } else {
        ("  ", style)
    };
    Line::styled(format!("{mark}{text}"), style)
}

fn move_cursor(cursor: &mut usize, len: usize, k: &KeyEvent) -> bool {
    match k.code {
        KeyCode::Down | KeyCode::Char('j') => *cursor = (*cursor + 1).min(len.saturating_sub(1)),
        KeyCode::Up | KeyCode::Char('k') => *cursor = cursor.saturating_sub(1),
        KeyCode::Home | KeyCode::Char('g') => *cursor = 0,
        KeyCode::End | KeyCode::Char('G') => *cursor = len.saturating_sub(1),
        _ => return false,
    }
    true
}

// ---------------------------------------------------------------------- group form

/// The group editor on the dialog stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFormDialog {
    /// The group (`None`: new).
    pub item: Option<ItemId>,
    /// The vault-defaults editor (§4.13).
    pub vault_defaults: bool,
    /// Groups the parent may not be (the group itself and its descendants).
    pub excluded_parents: BTreeSet<ItemId>,
    /// The form.
    pub form: Form,
    /// Placeholders.
    pub inherit: Option<InheritCx>,
}

impl GroupFormDialog {
    /// Refresh the placeholders from the draft's parent.
    pub fn sync_inherited(&mut self) {
        if let Some(cx) = &self.inherit {
            if self.vault_defaults {
                // Vault defaults inherit only from the global config.
                let mut cx = cx.clone();
                let mut cat = (*cx.catalog).clone();
                cat.lookup.vault_defaults.clear();
                cx.catalog = std::sync::Arc::new(cat);
                sync_inherited(&mut self.form, &cx, "parent_id");
            } else {
                sync_inherited(&mut self.form, cx, "parent_id");
            }
        }
    }

    fn handle(&mut self, id: DialogId, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        self.form.handle(ev, cx);
        self.sync_inherited();
        match self.form.take_request() {
            Some(FormRequest::Save(changes)) => {
                if let Some(FieldValue::Reference(Some(p))) = self.form.values().get("parent_id")
                    && self.excluded_parents.contains(p)
                {
                    self.form
                        .save_failed("A group can't be inside itself or its subgroups");
                    return;
                }
                if self.item.is_some() && changes.is_empty() {
                    cx.close();
                    return;
                }
                let mut changes = if self.item.is_some() {
                    changes
                } else {
                    FieldChanges(self.form.values().into_iter().collect())
                };
                if self.vault_defaults && self.item.is_none() {
                    changes
                        .0
                        .push(("is_vault_defaults".into(), FieldValue::Bool(true)));
                    changes.0.push((
                        "name".into(),
                        FieldValue::Text(super::form::VAULT_DEFAULTS_NAME.into()),
                    ));
                }
                let item = self.item;
                cx.issue(
                    |eid| {
                        items(ItemEffect::Save {
                            id: eid,
                            item,
                            kind: ItemKind::Group,
                            changes,
                        })
                    },
                    PendingKind::SaveItem { dialog: id },
                );
            }
            Some(FormRequest::Cancel) => cx.close(),
            None => {}
        }
    }
}

// ---------------------------------------------------------------------- move to group

/// "Move N hosts to…".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPicker {
    /// The hosts to move.
    pub hosts: Vec<ItemId>,
    /// `(group, indented label)`; `None` is "(no group)".
    pub options: Vec<(Option<ItemId>, String)>,
    /// The highlighted option.
    pub cursor: usize,
}

impl GroupPicker {
    /// The picker over the catalog's groups, in tree order.
    pub fn new(hosts: Vec<ItemId>, catalog: &HostCatalog) -> Self {
        let mut options = vec![(None, "(no group)".to_owned())];
        for (id, depth) in catalog.group_tree() {
            let g = &catalog.lookup.groups[&id];
            let icon = g
                .icon
                .as_deref()
                .map(|i| format!("{i} "))
                .unwrap_or_default();
            options.push((Some(id), format!("{}{icon}{}", "  ".repeat(depth), g.name)));
        }
        // Start on the targets' common group, if any.
        let first = hosts
            .first()
            .and_then(|h| catalog.hosts.get(h))
            .map(|h| h.group_id);
        let cursor = first
            .filter(|g| {
                hosts
                    .iter()
                    .all(|h| catalog.hosts.get(h).map(|s| s.group_id) == Some(*g))
            })
            .and_then(|g| options.iter().position(|(o, _)| *o == g))
            .unwrap_or(0);
        Self {
            hosts,
            options,
            cursor,
        }
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        if move_cursor(&mut self.cursor, self.options.len(), k) {
            return;
        }
        match k.code {
            KeyCode::Enter => {
                if let Some((group, _)) = self.options.get(self.cursor) {
                    cx.push(items(ItemEffect::MoveToGroup {
                        items: self.hosts.clone(),
                        group: *group,
                    }));
                }
                cx.close();
            }
            KeyCode::Esc | KeyCode::Char('q') => cx.close(),
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let n = self.hosts.len();
        let mut lines = vec![Line::styled(
            format!("Move {n} host{} to:", if n == 1 { "" } else { "s" }),
            theme.base,
        )];
        lines.push(Line::raw(""));
        let room = usize::from(area.height.saturating_sub(7)).max(1);
        let start = self.cursor.saturating_sub(room.saturating_sub(1));
        for (i, (_, label)) in self.options.iter().enumerate().skip(start).take(room) {
            lines.push(list_line(
                label.clone(),
                i == self.cursor,
                theme.base,
                theme.selection,
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("enter move · esc cancel", theme.dim));
        boxed(frame, area, cx, "Move to group", lines, 30);
    }
}

// ---------------------------------------------------------------------- bulk tags

/// How many of the targets carry a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagState {
    /// Every target.
    All,
    /// Some targets.
    Some,
    /// No target.
    None,
}

/// One tag row of the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagChoice {
    /// The tag.
    pub id: ItemId,
    /// `name`
    pub name: String,
    /// The state when the picker opened.
    pub initial: TagState,
    /// The current state.
    pub state: TagState,
}

/// Bulk add / remove tags on hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagPicker {
    /// The hosts.
    pub hosts: Vec<ItemId>,
    /// Every tag of the vault, by name.
    pub tags: Vec<TagChoice>,
    /// The highlighted row (`tags.len()` is the "new tag" row).
    pub cursor: usize,
    /// The new tag's name.
    pub new_tag: TextInput,
    /// Existing names (for the inline uniqueness check).
    names: Vec<(ItemId, String)>,
    /// Inline error.
    pub error: Option<String>,
}

impl TagPicker {
    /// The picker for `hosts` over the catalog's tags.
    pub fn new(hosts: Vec<ItemId>, catalog: &HostCatalog) -> Self {
        let mut tags: Vec<TagChoice> = catalog
            .tags
            .iter()
            .map(|(id, t)| {
                let have = hosts
                    .iter()
                    .filter(|h| catalog.hosts.get(h).is_some_and(|s| s.tags.contains(id)))
                    .count();
                let state = match have {
                    0 => TagState::None,
                    n if n == hosts.len() => TagState::All,
                    _ => TagState::Some,
                };
                TagChoice {
                    id: *id,
                    name: t.name.clone(),
                    initial: state,
                    state,
                }
            })
            .collect();
        tags.sort_by_key(|t| (t.name.to_lowercase(), t.id));
        let names = catalog
            .tags
            .iter()
            .map(|(id, t)| (*id, t.name.clone()))
            .collect();
        Self {
            hosts,
            tags,
            cursor: 0,
            new_tag: TextInput::new(""),
            names,
            error: None,
        }
    }

    fn on_new_row(&self) -> bool {
        self.cursor == self.tags.len()
    }

    fn toggle(&mut self) {
        if let Some(t) = self.tags.get_mut(self.cursor) {
            t.state = match (t.state, t.initial) {
                (TagState::All, TagState::Some) => TagState::None,
                (TagState::None, TagState::Some) => TagState::Some,
                (TagState::All, _) => TagState::None,
                _ => TagState::All,
            };
        }
    }

    /// The effect for the current marks (`None`: nothing changes).
    pub fn effect(&self) -> Result<Option<ItemEffect>, String> {
        let add: Vec<ItemId> = self
            .tags
            .iter()
            .filter(|t| t.state == TagState::All && t.initial != TagState::All)
            .map(|t| t.id)
            .collect();
        let remove: Vec<ItemId> = self
            .tags
            .iter()
            .filter(|t| t.state == TagState::None && t.initial != TagState::None)
            .map(|t| t.id)
            .collect();
        let create = self.new_tag.text().trim().to_owned();
        let create = if create.is_empty() {
            None
        } else {
            validate_tag(
                None,
                &create,
                None,
                self.names.iter().map(|(id, n)| (*id, n.as_str())),
            )
            .map_err(|e| {
                e.into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ")
            })?;
            Some(create)
        };
        if add.is_empty() && remove.is_empty() && create.is_none() {
            return Ok(None);
        }
        Ok(Some(ItemEffect::SetTags {
            items: self.hosts.clone(),
            add,
            remove,
            create,
        }))
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        let n = self.tags.len() + 1;
        match k.code {
            KeyCode::Esc => cx.close(),
            KeyCode::Down | KeyCode::Tab => self.cursor = (self.cursor + 1).min(n - 1),
            KeyCode::Up | KeyCode::BackTab => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Enter => match self.effect() {
                Ok(effect) => {
                    if let Some(e) = effect {
                        cx.push(items(e));
                    }
                    cx.close();
                }
                Err(msg) => {
                    self.error = Some(msg);
                    self.cursor = self.tags.len();
                }
            },
            _ if self.on_new_row() => {
                if self.new_tag.handle_key(k) == TextEdit::Changed {
                    self.error = None;
                }
            }
            KeyCode::Char(' ') if plain(k) => self.toggle(),
            KeyCode::Char('j') if plain(k) => self.cursor = (self.cursor + 1).min(n - 1),
            KeyCode::Char('k') if plain(k) => self.cursor = self.cursor.saturating_sub(1),
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let n = self.hosts.len();
        let mut lines = vec![Line::styled(
            format!("Tags for {n} host{}:", if n == 1 { "" } else { "s" }),
            theme.base,
        )];
        lines.push(Line::raw(""));
        for (i, t) in self.tags.iter().enumerate() {
            let mark = match t.state {
                TagState::All => "[x]",
                TagState::Some => "[-]",
                TagState::None => "[ ]",
            };
            lines.push(list_line(
                format!("{mark} #{}", t.name),
                i == self.cursor,
                theme.base,
                theme.selection,
            ));
        }
        let on_new = self.on_new_row();
        let mut spans = vec![Span::styled(
            if on_new {
                "› New tag: "
            } else {
                "  New tag: "
            },
            theme.accent,
        )];
        spans.extend(self.new_tag.line(24, theme.base, on_new).spans);
        lines.push(Line::from(spans));
        if let Some(e) = &self.error {
            lines.push(Line::styled(format!("! {e}"), theme.error));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "space toggle · enter apply · esc cancel",
            theme.dim,
        ));
        boxed(frame, area, cx, "Tags", lines, 36);
    }
}

// ---------------------------------------------------------------------- delete group

/// "Delete group …?" (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteGroupDialog {
    /// The group.
    pub group: ItemId,
    /// Its name.
    pub name: String,
    /// Hosts directly in it.
    pub hosts: usize,
    /// Direct subgroups.
    pub subgroups: usize,
    /// Items "Delete them" removes besides the group (the whole subtree).
    pub delete_count: usize,
    /// `0`: move to the parent (default), `1`: delete them.
    pub choice: usize,
    /// The typed count (asked for "Delete them" above the threshold).
    pub typing: Option<TextInput>,
    /// Inline error.
    pub error: Option<String>,
}

impl DeleteGroupDialog {
    fn confirm(&mut self, mode: DeleteGroupMode, cx: &mut ViewCx<'_>) {
        cx.push(items(ItemEffect::DeleteGroup {
            group: self.group,
            mode,
        }));
        cx.close();
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        if let Some(input) = &mut self.typing {
            match k.code {
                KeyCode::Esc => {
                    self.typing = None;
                    self.error = None;
                }
                KeyCode::Enter => {
                    if input.text().trim() == self.delete_count.to_string() {
                        self.confirm(DeleteGroupMode::DeleteAll, cx);
                    } else {
                        self.error = Some(format!("Type {} to confirm", self.delete_count));
                    }
                }
                _ => {
                    input.handle_key(k);
                }
            }
            return;
        }
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => cx.close(),
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => self.choice = 0,
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => self.choice = 1,
            KeyCode::Char('m') => self.confirm(DeleteGroupMode::MoveToParent, cx),
            KeyCode::Enter if self.choice == 0 => {
                self.confirm(DeleteGroupMode::MoveToParent, cx);
            }
            KeyCode::Enter => {
                if self.delete_count > DELETE_CONFIRM_THRESHOLD {
                    self.typing = Some(TextInput::new(""));
                } else {
                    self.confirm(DeleteGroupMode::DeleteAll, cx);
                }
            }
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let plural =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut lines = vec![
            Line::styled(
                format!(
                    "The group contains {} and {}.",
                    plural(self.hosts, "host", "hosts"),
                    plural(self.subgroups, "subgroup", "subgroups")
                ),
                theme.base,
            ),
            Line::raw(""),
        ];
        let options = [
            (
                format!(
                    "Move its {} and {} to the parent group",
                    plural(self.hosts, "host", "hosts"),
                    plural(self.subgroups, "subgroup", "subgroups")
                ),
                theme.base,
            ),
            (
                format!(
                    "Delete them ({} in all)",
                    plural(self.delete_count, "item", "items")
                ),
                theme.error,
            ),
        ];
        for (i, (text, style)) in options.into_iter().enumerate() {
            lines.push(list_line(text, i == self.choice, style, theme.selection));
        }
        if let Some(input) = &self.typing {
            lines.push(Line::raw(""));
            let mut spans = vec![Span::styled(
                format!("Type {} to delete them all: ", self.delete_count),
                theme.error,
            )];
            spans.extend(input.line(8, theme.base, true).spans);
            lines.push(Line::from(spans));
        }
        if let Some(e) = &self.error {
            lines.push(Line::styled(format!("! {e}"), theme.error));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("enter confirm · esc cancel", theme.dim));
        let title = format!("Delete group \"{}\"?", truncate(&self.name, 30));
        boxed(frame, area, cx, &title, lines, 40);
    }
}

// ---------------------------------------------------------------------- tag manager

/// What the tag manager's input line is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagInput {
    /// Rename the highlighted tag.
    Rename,
    /// Create a tag.
    New,
}

/// One row of the tag manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRow {
    /// The tag.
    pub id: ItemId,
    /// `name`
    pub name: String,
    /// `color`
    pub color: Option<String>,
    /// Hosts that carry it.
    pub hosts: usize,
}

/// Settings → Tags (§4.11): rename, recolor, delete, create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagManager {
    /// Tags by name.
    pub tags: Vec<TagRow>,
    /// The highlighted row.
    pub cursor: usize,
    /// The input line, if open.
    pub input: Option<(TagInput, TextInput)>,
    /// Waiting for `y` to delete the highlighted tag.
    pub confirm_delete: bool,
    /// Inline error.
    pub error: Option<String>,
}

impl TagManager {
    /// The manager over the catalog's tags.
    pub fn new(catalog: &HostCatalog) -> Self {
        let mut tags: Vec<TagRow> = catalog
            .tags
            .iter()
            .map(|(id, t)| TagRow {
                id: *id,
                name: t.name.clone(),
                color: t.color.clone(),
                hosts: catalog
                    .hosts
                    .values()
                    .filter(|h| h.tags.contains(id))
                    .count(),
            })
            .collect();
        tags.sort_by_key(|t| (t.name.to_lowercase(), t.id));
        Self {
            tags,
            cursor: 0,
            input: None,
            confirm_delete: false,
            error: None,
        }
    }

    fn check(&self, id: Option<ItemId>, name: &str, color: Option<&str>) -> Result<(), String> {
        validate_tag(
            id,
            name,
            color,
            self.tags.iter().map(|t| (t.id, t.name.as_str())),
        )
        .map_err(|e| {
            e.into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    fn save(
        &mut self,
        item: Option<ItemId>,
        name: String,
        color: Option<String>,
        cx: &mut ViewCx<'_>,
    ) {
        if let Err(e) = self.check(item, &name, color.as_deref()) {
            self.error = Some(e);
            return;
        }
        self.error = None;
        if let Some(row) = item.and_then(|id| self.tags.iter_mut().find(|t| t.id == id)) {
            row.name.clone_from(&name);
            row.color.clone_from(&color);
        }
        cx.push(items(ItemEffect::SaveTag { item, name, color }));
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        if let Some((what, input)) = &mut self.input {
            match k.code {
                KeyCode::Esc => {
                    self.input = None;
                    self.error = None;
                }
                KeyCode::Enter => {
                    let name = input.text().trim().to_owned();
                    let what = *what;
                    let (item, color) = match what {
                        TagInput::Rename => match self.tags.get(self.cursor) {
                            Some(t) => (Some(t.id), t.color.clone()),
                            None => return,
                        },
                        TagInput::New => (None, Some(TAG_COLORS[0].to_owned())),
                    };
                    self.save(item, name, color, cx);
                    if self.error.is_none() {
                        self.input = None;
                    }
                }
                _ => {
                    input.handle_key(k);
                }
            }
            return;
        }
        if self.confirm_delete {
            self.confirm_delete = false;
            if matches!(k.code, KeyCode::Char('y' | 'Y'))
                && let Some(t) = self.tags.get(self.cursor)
            {
                cx.push(items(ItemEffect::Delete(t.id)));
                self.tags.remove(self.cursor);
                self.cursor = self.cursor.min(self.tags.len().saturating_sub(1));
            }
            return;
        }
        if move_cursor(&mut self.cursor, self.tags.len(), k) {
            return;
        }
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => cx.close(),
            KeyCode::Char('n' | 'a') => self.input = Some((TagInput::New, TextInput::new(""))),
            KeyCode::Char('r' | 'e') => {
                if let Some(t) = self.tags.get(self.cursor) {
                    self.input = Some((TagInput::Rename, TextInput::new(t.name.clone())));
                }
            }
            KeyCode::Char('c') => {
                if let Some(t) = self.tags.get(self.cursor) {
                    let next = t
                        .color
                        .as_deref()
                        .and_then(|c| TAG_COLORS.iter().position(|p| *p == c))
                        .map_or(0, |i| (i + 1) % TAG_COLORS.len());
                    let (id, name) = (t.id, t.name.clone());
                    self.save(Some(id), name, Some(TAG_COLORS[next].to_owned()), cx);
                }
            }
            KeyCode::Char('d') if !self.tags.is_empty() => self.confirm_delete = true,
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let mut lines = Vec::new();
        if self.tags.is_empty() {
            lines.push(Line::styled("No tags yet.", theme.dim));
        }
        for (i, t) in self.tags.iter().enumerate() {
            let color = t.color.as_deref().unwrap_or("none");
            lines.push(list_line(
                format!(
                    "#{:<20} {:<12} {} host{}",
                    t.name,
                    color,
                    t.hosts,
                    if t.hosts == 1 { "" } else { "s" }
                ),
                i == self.cursor,
                theme.base,
                theme.selection,
            ));
        }
        if let Some((what, input)) = &self.input {
            lines.push(Line::raw(""));
            let label = match what {
                TagInput::Rename => "Rename to: ",
                TagInput::New => "New tag: ",
            };
            let mut spans = vec![Span::styled(label, theme.accent)];
            spans.extend(input.line(24, theme.base, true).spans);
            lines.push(Line::from(spans));
        }
        if self.confirm_delete
            && let Some(t) = self.tags.get(self.cursor)
        {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!("Delete #{}? y yes · any other key no", t.name),
                theme.error,
            ));
        }
        if let Some(e) = &self.error {
            lines.push(Line::styled(format!("! {e}"), theme.error));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "n new · r rename · c color · d delete · esc close",
            theme.dim,
        ));
        boxed(frame, area, cx, "Tags", lines, 44);
    }
}
