//! The identity dialogs (SPEC §4.4, §9.3) on the dialog stack
//! (`DialogKind::Identity`).
//!
//! - **Form** (add `a`, edit `e`, and "+ new identity" from the host form's picker):
//!   label, username, password, key. Saves go out as `ItemEffect::SaveIdentity`; the
//!   reducer closes the form on success (and, when it was opened from a host form,
//!   puts the new identity into that form's reference).
//! - **Delete** (`d`): warns "This identity is used by N hosts (D direct, I via
//!   group). They will fall back to inherited or inline credentials." and offers
//!   "Convert to inline credentials on those hosts" (`Space` / `c` toggles). `Enter`
//!   deletes (`ItemEffect::DeleteIdentity`), `Esc` cancels.
//! - **Used by** (`Enter` on an identity): the hosts using it; `Enter` jumps to one in
//!   the Hosts view (the reducer takes the answer after the dispatch).

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::model::{
    Identity, ItemId, ItemKind, ValidationError, VaultId, identity::IdentityUsage,
};

use crate::app::hosts::ItemEffect;
use crate::app::{Effect, VaultEffect, state::PendingKind};
use crate::views::{DialogId, RenderCx, View as _, ViewCx, ViewEvent, hosts::catalog::HostCatalog};
use crate::widgets::form::{
    Field, FieldChanges, FieldValue, FieldWidget, Form, FormRequest, RefValue, SecretValue,
};
use crate::widgets::{truncate, width};

/// The picker entry that opens a new identity form (host form).
pub const NEW_IDENTITY: &str = "+ new identity";

/// An identity loaded for the edit form (with its password).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct IdentityRecord {
    /// The identity (`None`: not saved yet).
    pub id: Option<ItemId>,
    /// Its vault (`None`: the Personal vault).
    pub vault: Option<VaultId>,
    /// `label`
    pub label: String,
    /// `username`
    pub username: String,
    /// `password` (redacted `Debug`, zeroized on drop).
    pub password: Option<SecretValue>,
    /// `key_id`
    pub key_id: Option<ItemId>,
    /// Written by a newer sverb (§4.1).
    pub read_only: bool,
}

impl fmt::Debug for IdentityRecord {
    // Decrypted user data stays out of logs (SPEC §17).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityRecord")
            .field("id", &self.id)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl IdentityRecord {
    /// From the typed view.
    pub fn from_identity(id: ItemId, vault: VaultId, i: &Identity) -> Self {
        Self {
            id: Some(id),
            vault: Some(vault),
            label: i.label.clone(),
            username: i.username.clone(),
            password: i.password.as_ref().map(|p| SecretValue::from(p.expose())),
            key_id: i.key_id,
            read_only: i.read_only,
        }
    }
}

/// Build the identity form. The key picker is limited to the identity's vault.
pub fn identity_form(
    record: &IdentityRecord,
    catalog: Option<&HostCatalog>,
    index: Option<std::sync::Arc<sverb_core::search::IndexSnapshot>>,
) -> Form {
    let key_value = record.key_id.map(|id| RefValue {
        id,
        label: catalog
            .and_then(|c| c.keys.get(&id).cloned())
            .unwrap_or_else(|| id.short()),
    });
    let vault = record
        .vault
        .or_else(|| catalog.and_then(|c| c.personal_vault));
    let mut key = Field::reference("key_id", "Key", ItemKind::Key, key_value)
        .help("Used for public-key authentication");
    if let FieldWidget::Reference(r) = &mut key.widget {
        r.set_vault(vault);
    }
    let fields = vec![
        Field::text("label", "Label", &record.label)
            .required()
            .help("Shown in lists and pickers"),
        Field::text("username", "Username", &record.username).help("The remote login user"),
        Field::secret("password", "Password", record.password.clone()),
        key,
    ];
    let title = match record.id {
        Some(_) => format!("Edit identity · {}", record.label),
        None => "New identity".to_owned(),
    };
    let mut form = Form::new(title).section("Identity", fields);
    if record.read_only {
        form = form.read_only(crate::widgets::form::ReadOnly::NewerSchema);
    }
    if let Some(index) = index {
        form.set_index(index);
    }
    form
}

fn text(v: &FieldValue) -> String {
    v.as_text().map(str::trim).unwrap_or_default().to_owned()
}

/// Apply identity-form changes to the typed identity.
///
/// # Errors
/// Field-level [`ValidationError`]s (an empty label).
pub fn apply_identity_changes(
    identity: &mut Identity,
    changes: &FieldChanges,
) -> Result<(), Vec<ValidationError>> {
    for (key, value) in &changes.0 {
        match (key.as_str(), value) {
            ("label", v) => identity.label = text(v),
            ("username", v) => identity.username = text(v),
            ("password", FieldValue::Secret(s)) => {
                identity.password = (!s.is_empty()).then(|| s.expose().into());
            }
            ("key_id", FieldValue::Reference(r)) => identity.key_id = *r,
            _ => {}
        }
    }
    sverb_core::model::identity::validate_identity(identity)
}

fn items(op: ItemEffect) -> Effect {
    Effect::Vault(VaultEffect::Items(op))
}

/// The identity form on the dialog stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFormDialog {
    /// The identity (`None`: new).
    pub item: Option<ItemId>,
    /// Where a new identity goes (`None`: the Personal vault).
    pub vault: Option<VaultId>,
    /// The host form that asked for it ("+ new identity").
    pub for_host: Option<DialogId>,
    /// The form.
    pub form: Form,
}

impl IdentityFormDialog {
    fn handle(&mut self, id: DialogId, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(changes)) => {
                if self.item.is_some() && changes.is_empty() {
                    cx.close();
                    return;
                }
                let changes = if self.item.is_some() {
                    changes
                } else {
                    FieldChanges(self.form.values().into_iter().collect())
                };
                let (item, vault) = (self.item, self.vault);
                cx.issue(
                    |eid| {
                        items(ItemEffect::SaveIdentity {
                            id: eid,
                            item,
                            vault,
                            changes,
                        })
                    },
                    PendingKind::SaveIdentity { dialog: id },
                );
            }
            Some(FormRequest::Cancel) => cx.close(),
            None => {}
        }
    }
}

/// "Delete identity …?" (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteIdentityDialog {
    /// The identity.
    pub identity: ItemId,
    /// Its label.
    pub label: String,
    /// The hosts using it.
    pub usage: IdentityUsage,
    /// "Convert to inline credentials on those hosts".
    pub convert: bool,
}

impl DeleteIdentityDialog {
    /// The warning line.
    pub fn warning(&self) -> String {
        let n = self.usage.total();
        if n == 0 {
            return "No host uses this identity.".to_owned();
        }
        let hosts = if n == 1 { "host" } else { "hosts" };
        let split = match (self.usage.direct.len(), self.usage.inherited.len()) {
            (_, 0) => String::new(),
            (0, i) => format!(" ({i} via group)"),
            (d, i) => format!(" ({d} direct, {i} via group)"),
        };
        format!(
            "This identity is used by {n} {hosts}{split}. They will fall back to inherited or inline credentials."
        )
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        if k.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return;
        }
        match k.code {
            KeyCode::Esc | KeyCode::Char('n' | 'q') => cx.close(),
            KeyCode::Char(' ' | 'c') if !self.usage.is_empty() => self.convert = !self.convert,
            KeyCode::Enter | KeyCode::Char('y') => {
                cx.push(items(ItemEffect::DeleteIdentity {
                    item: self.identity,
                    convert: self.convert && !self.usage.is_empty(),
                }));
                cx.close();
            }
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let mut lines = Vec::new();
        for l in wrap(&self.warning(), 56) {
            lines.push(Line::styled(l, theme.base));
        }
        if !self.usage.is_empty() {
            lines.push(Line::raw(""));
            let mark = if self.convert { "[x]" } else { "[ ]" };
            lines.push(Line::styled(
                format!("{mark} Convert to inline credentials on those hosts"),
                theme.base,
            ));
        }
        lines.push(Line::raw(""));
        let hint = if self.usage.is_empty() {
            "enter delete · esc cancel"
        } else {
            "space toggle · enter delete · esc cancel"
        };
        lines.push(Line::styled(hint, theme.dim));
        let title = format!("Delete identity \"{}\"?", truncate(&self.label, 30));
        boxed(frame, area, cx, &title, lines, 40);
    }
}

/// The hosts using an identity; `Enter` jumps to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedByDialog {
    /// The identity's label.
    pub label: String,
    /// `(host, label, via group)`, direct ones first.
    pub hosts: Vec<(ItemId, String, Option<String>)>,
    /// The highlighted host.
    pub cursor: usize,
    /// The picked host (taken by the reducer).
    pub answer: Option<ItemId>,
}

impl UsedByDialog {
    /// The list for `usage` from the catalog.
    pub fn new(label: String, usage: &IdentityUsage, catalog: Option<&HostCatalog>) -> Self {
        let name = |h: ItemId| {
            catalog
                .and_then(|c| c.hosts.get(&h))
                .map_or_else(|| h.short(), |s| s.display_label().to_owned())
        };
        let via = |h: ItemId| {
            let c = catalog?;
            let g = c.hosts.get(&h)?.group_id?;
            c.group_name(g).map(str::to_owned)
        };
        let mut hosts: Vec<(ItemId, String, Option<String>)> =
            usage.direct.iter().map(|h| (*h, name(*h), None)).collect();
        hosts.extend(usage.inherited.iter().map(|h| {
            (
                *h,
                name(*h),
                Some(via(*h).unwrap_or_else(|| "defaults".to_owned())),
            )
        }));
        Self {
            label,
            hosts,
            cursor: 0,
            answer: None,
        }
    }

    /// The picked host (taken once).
    pub fn take_answer(&mut self) -> Option<ItemId> {
        self.answer.take()
    }

    fn handle_key(&mut self, k: &KeyEvent, cx: &mut ViewCx<'_>) {
        let last = self.hosts.len().saturating_sub(1);
        match k.code {
            KeyCode::Down | KeyCode::Char('j') => self.cursor = (self.cursor + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = last,
            KeyCode::Enter => match self.hosts.get(self.cursor) {
                Some((h, _, _)) => self.answer = Some(*h),
                None => cx.close(),
            },
            KeyCode::Esc | KeyCode::Char('q') => cx.close(),
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let mut lines = Vec::new();
        if self.hosts.is_empty() {
            lines.push(Line::styled("Not used by any host.", theme.dim));
        }
        let max = usize::from(area.height.saturating_sub(6)).max(1);
        let skip = (self.cursor + 1).saturating_sub(max);
        for (i, (_, label, via)) in self.hosts.iter().enumerate().skip(skip).take(max) {
            let selected = i == self.cursor;
            let style = if selected {
                theme.selection
            } else {
                theme.base
            };
            let mut spans = vec![Span::styled(
                format!("{}{label}", if selected { "› " } else { "  " }),
                style,
            )];
            if let Some(g) = via {
                spans.push(Span::styled(format!(" (via {g})"), theme.dim));
            }
            lines.push(Line::from(spans));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("enter go to host · esc close", theme.dim));
        let title = format!("Used by · {}", truncate(&self.label, 30));
        boxed(frame, area, cx, &title, lines, 36);
    }
}

/// An identity dialog (`DialogKind::Identity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityDialog {
    /// Add / edit.
    Form(Box<IdentityFormDialog>),
    /// Delete, with optional conversion to inline credentials.
    Delete(DeleteIdentityDialog),
    /// The hosts using an identity.
    UsedBy(UsedByDialog),
    /// The Keys / Certificates dialogs (`views/keychain/import_dialog.rs`). They share
    /// the Keychain section's dialog slot, so no other dialog wiring is needed.
    Keychain(Box<super::import_dialog::KeychainDialog>),
}

impl IdentityDialog {
    /// The dialog edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        match self {
            Self::Form(_) => true,
            Self::Keychain(d) => d.wants_text(),
            _ => false,
        }
    }

    /// Handle an event (modal: everything is consumed).
    pub fn handle(&mut self, id: DialogId, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        match self {
            Self::Form(d) => d.handle(id, ev, cx),
            Self::Delete(d) => {
                if let ViewEvent::Key(k) = ev {
                    d.handle_key(k, cx);
                }
            }
            Self::UsedBy(d) => {
                if let ViewEvent::Key(k) = ev {
                    d.handle_key(k, cx);
                }
            }
            Self::Keychain(d) => d.handle(ev, cx),
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match self {
            Self::Form(d) => d.form.render(frame, area, cx),
            Self::Delete(d) => d.render(frame, area, cx),
            Self::UsedBy(d) => d.render(frame, area, cx),
            Self::Keychain(d) => d.render(frame, area, cx),
        }
    }
}

/// Greedy word wrap at `max` cells.
fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && width(&cur) + 1 + width(word) > max {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
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
