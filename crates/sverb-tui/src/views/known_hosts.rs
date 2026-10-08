//! M1-15: the Known Hosts section (SPEC §8.5, §9.5).
//!
//! ```text
//! ┌ Known hosts ──────────────────────────────────────────────────────────────┐
//! │ › web.example.com        ssh-ed25519   SHA256:uYxmMoF3afl…              2026-10-07 │
//! │   (hashed) laptop        ecdsa-sha2-…  SHA256:OBcyw3a+d90…              2026-10-01 │
//! │   *.test                 ssh-ed25519   SHA256:7S7L4mWFAjE…  @cert-auth… 2026-09-30 │
//! └───────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The shared list (M1-06): `/` filters (pattern, comment, key type, fingerprint),
//! `Space` marks, `s` sorts. Actions: `d` delete (asks), `e` edit (pattern, comment,
//! marker), `I` import from `~/.ssh/known_hosts` (asks for the path; M2-11 refines the
//! importer), `x` export as an OpenSSH `known_hosts` file. The detail pane shows the
//! whole pattern, the full fingerprint and the randomart. Hashed patterns show as
//! `(hashed)` plus the comment.
//!
//! Like the Hosts view, actions that need the app are left in
//! [`KnownHostsView::request`] and taken by the reducer right after the key
//! (`app/known_hosts.rs`).

use chrono::DateTime;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::{
    known_hosts::{KeyInfo, hashed::is_hashed},
    model::{ItemId, KnownHost, KnownHostMarker, UnixMillis},
};

use crate::{
    app::{Effect, KnownHostsEffect},
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
    widgets::{
        dialog::{Modal, ModalAnswer},
        form::{Field, FieldValue, Form, FormRequest, SelectOption, Validator},
        list::{DetailRenderer, EmptyState, ListRow, ListView, RowCx, RowRenderer, SortKey},
        truncate,
    },
};

/// One listed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostRow {
    /// The KnownHost item.
    pub id: ItemId,
    /// The entry.
    pub entry: KnownHost,
    /// `SHA256:…` (or `?` when the key does not decode).
    pub fingerprint: String,
    /// The randomart (empty when the key does not decode).
    pub randomart: String,
    /// What the list shows as the pattern (`(hashed) comment` for hashed entries).
    pub display: String,
}

impl KnownHostRow {
    /// A row for `entry`.
    pub fn new(id: ItemId, entry: KnownHost) -> Self {
        let info = KeyInfo::of_entry(&entry);
        let display = if is_hashed(&entry.host_pattern) {
            match entry.comment.as_deref().filter(|c| !c.is_empty()) {
                Some(c) => format!("(hashed) {c}"),
                None => "(hashed)".to_owned(),
            }
        } else {
            entry.host_pattern.clone()
        };
        Self {
            id,
            fingerprint: info
                .as_ref()
                .map_or_else(|| "?".to_owned(), |i| i.fingerprint.clone()),
            randomart: info.map(|i| i.randomart).unwrap_or_default(),
            display,
            entry,
        }
    }
}

impl ListRow for KnownHostRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.id
    }

    fn label(&self) -> &str {
        &self.display
    }

    fn filter_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.display,
            self.entry.key_type,
            self.fingerprint,
            self.entry.comment.as_deref().unwrap_or_default()
        )
    }

    fn secondary(&self) -> String {
        self.entry.key_type.clone()
    }
}

/// `@cert-authority` / `@revoked` / empty.
pub fn marker_text(marker: KnownHostMarker) -> &'static str {
    match marker {
        KnownHostMarker::None => "",
        KnownHostMarker::CertAuthority => "@cert-authority",
        KnownHostMarker::Revoked => "@revoked",
    }
}

/// `YYYY-MM-DD` (UTC) of `t`, or `-` when unknown (imported entries).
pub fn date_text(t: UnixMillis) -> String {
    if t.0 <= 0 {
        return "-".to_owned();
    }
    DateTime::from_timestamp_millis(t.0)
        .map_or_else(|| "-".to_owned(), |d| d.format("%Y-%m-%d").to_string())
}

/// What the user asked the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostsRequest {
    /// `d`: delete these entries (asks first).
    Delete(Vec<ItemId>),
    /// `e`: edit the entry.
    Edit(ItemId),
    /// `I`: import a `known_hosts` file.
    Import,
    /// `x`: export every entry as a `known_hosts` file.
    Export,
}

/// The Known Hosts section's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsView {
    /// The list.
    pub list: ListView<KnownHostRow>,
    /// The service delivered the entries (after unlock).
    pub loaded: bool,
    /// A load is in flight.
    pub loading: bool,
    /// The data changed while loading: load again.
    pub reload: bool,
    /// A request for the reducer, taken right after the key.
    pub request: Option<KnownHostsRequest>,
}

impl Default for KnownHostsView {
    fn default() -> Self {
        let by_host = SortKey::new("host", |a: &KnownHostRow, b: &KnownHostRow| {
            a.display.to_lowercase().cmp(&b.display.to_lowercase())
        });
        let by_added = SortKey::new("added", |a: &KnownHostRow, b: &KnownHostRow| {
            b.entry.added_at.cmp(&a.entry.added_at)
        });
        Self {
            list: ListView::new("Known hosts")
                .with_sort_keys(vec![by_host, by_added])
                .with_empty(EmptyState::new(
                    "No known hosts yet. Keys are added when you accept them on connect.",
                    &[("I", "import ~/.ssh/known_hosts")],
                )),
            loaded: false,
            loading: false,
            reload: false,
            request: None,
        }
    }
}

impl KnownHostsView {
    /// Replace the entries.
    pub fn set_entries(&mut self, entries: Vec<(ItemId, KnownHost)>) {
        self.list.set_rows(
            entries
                .into_iter()
                .map(|(id, e)| KnownHostRow::new(id, e))
                .collect(),
        );
        self.loaded = true;
    }

    /// Forget everything decrypted (on lock).
    pub fn clear(&mut self) {
        self.list.set_rows(Vec::new());
        self.loaded = false;
        self.loading = false;
        self.reload = false;
        self.request = None;
    }

    /// The entry with `id`.
    pub fn get(&self, id: ItemId) -> Option<&KnownHostRow> {
        self.list.rows().iter().find(|r| r.id == id)
    }

    /// The list is editing its filter (Insert mode).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<KnownHostsRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        Some(match code {
            KeyCode::Char('d') | KeyCode::Delete => {
                let targets = self.list.targets();
                if targets.is_empty() {
                    return None;
                }
                KnownHostsRequest::Delete(targets)
            }
            KeyCode::Char('e') | KeyCode::Enter => {
                KnownHostsRequest::Edit(self.list.selected_key()?)
            }
            KeyCode::Char('I') => KnownHostsRequest::Import,
            KeyCode::Char('x') => KnownHostsRequest::Export,
            _ => return None,
        })
    }

    /// Draw the selected entry's details (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let selected = self.list.selected();
        let block = Block::bordered()
            .title(Span::styled(" Details ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let width = usize::from(area.width.saturating_sub(2));
        let lines = match selected {
            Some(row) => KnownHostDetail.lines(row, theme, width),
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

/// Draws a row: pattern, key type, fingerprint (truncated), marker, added date.
#[derive(Debug, Clone, Copy, Default)]
pub struct KnownHostRowRenderer;

impl RowRenderer<KnownHostRow> for KnownHostRowRenderer {
    fn spans(&self, row: &KnownHostRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let dim = cx.base.patch(cx.theme.dim);
        let w = cx.width;
        // pattern | type | fingerprint | marker | date; the pattern takes what is left
        // and trailing columns drop out on narrow lists.
        const TYPE_W: usize = 20;
        const FP_W: usize = 22;
        const MARKER_W: usize = 15;
        const DATE_W: usize = 10;
        let pattern_w = w
            .saturating_sub(TYPE_W + FP_W + MARKER_W + DATE_W + 5)
            .clamp(10, 48);
        let mut spans = vec![Span::styled(
            format!("{:<pattern_w$} ", truncate(&row.display, pattern_w)),
            cx.base,
        )];
        let mut used = pattern_w + 1;
        let mut push = |text: String, width: usize, style| {
            if used + width <= w {
                spans.push(Span::styled(
                    format!("{:<width$} ", truncate(&text, width)),
                    style,
                ));
                used += width + 1;
            }
        };
        push(row.entry.key_type.clone(), TYPE_W, dim);
        push(row.fingerprint.clone(), FP_W, cx.base);
        let marker_style = match row.entry.marker {
            KnownHostMarker::Revoked => cx.base.patch(cx.theme.error),
            _ => cx.base.patch(cx.theme.accent),
        };
        push(
            marker_text(row.entry.marker).to_owned(),
            MARKER_W,
            marker_style,
        );
        push(date_text(row.entry.added_at), DATE_W, dim);
        spans
    }
}

/// The detail pane: everything, with the randomart.
#[derive(Debug, Clone, Copy, Default)]
pub struct KnownHostDetail;

impl DetailRenderer<KnownHostRow> for KnownHostDetail {
    fn lines(&self, row: &KnownHostRow, theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        let label = |k: &str| Span::styled(format!("{k:<12} "), theme.dim);
        let e = &row.entry;
        let mut lines = vec![Line::from(vec![
            label("Pattern:"),
            Span::raw(e.host_pattern.clone()),
        ])];
        if let Some(c) = e.comment.as_deref().filter(|c| !c.is_empty()) {
            lines.push(Line::from(vec![label("Comment:"), Span::raw(c.to_owned())]));
        }
        lines.push(Line::from(vec![
            label("Key type:"),
            Span::raw(e.key_type.clone()),
        ]));
        if e.marker != KnownHostMarker::None {
            lines.push(Line::from(vec![
                label("Marker:"),
                Span::styled(marker_text(e.marker), theme.accent),
            ]));
        }
        lines.push(Line::from(vec![
            label("Added:"),
            Span::raw(date_text(e.added_at)),
        ]));
        lines.push(Line::from(vec![
            label("Fingerprint:"),
            Span::raw(row.fingerprint.clone()),
        ]));
        if !row.randomart.is_empty() {
            lines.push(Line::raw(""));
            lines.extend(row.randomart.lines().map(|l| Line::raw(l.to_owned())));
        }
        if e.read_only {
            lines.push(Line::styled(
                "Written by a newer sverb: read-only here.",
                theme.warn,
            ));
        }
        lines
    }
}

impl View for KnownHostsView {
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
        let detail: Option<&dyn DetailRenderer<KnownHostRow>> =
            self.list.detail_full().then_some(&KnownHostDetail as _);
        self.list
            .render_with(frame, area, cx, &KnownHostRowRenderer, detail);
    }

    fn insert_mode(&self) -> bool {
        KnownHostsView::insert_mode(self)
    }
}

// ---------------------------------------------------------------------- dialogs

/// The default import source.
pub const DEFAULT_IMPORT_PATH: &str = "~/.ssh/known_hosts";
/// The default export target.
pub const DEFAULT_EXPORT_PATH: &str = "~/sverb_known_hosts";

/// Which file prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePrompt {
    /// Import from a `known_hosts` file.
    Import,
    /// Export to a `known_hosts` file.
    Export,
}

/// The Known Hosts dialogs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostsDialog {
    /// Edit an entry's pattern, comment and marker.
    Edit {
        /// The item.
        id: ItemId,
        /// The entry before editing.
        entry: KnownHost,
        /// The form.
        form: Box<Form>,
    },
    /// Ask for a file path.
    File {
        /// Import or export.
        kind: FilePrompt,
        /// The prompt.
        modal: Modal,
    },
}

const MARKER_NONE: &str = "none";
const MARKER_CA: &str = "cert-authority";
const MARKER_REVOKED: &str = "revoked";

fn check_pattern(v: &FieldValue) -> Result<(), String> {
    match v.as_text().map(str::trim) {
        Some("") | None => Err("A host pattern is required".to_owned()),
        Some(p) if p.contains(char::is_whitespace) => {
            Err("Patterns contain no spaces (separate several with commas)".to_owned())
        }
        Some(_) => Ok(()),
    }
}

impl KnownHostsDialog {
    /// The edit form for `entry`.
    pub fn edit(id: ItemId, entry: KnownHost) -> Self {
        let marker = match entry.marker {
            KnownHostMarker::None => MARKER_NONE,
            KnownHostMarker::CertAuthority => MARKER_CA,
            KnownHostMarker::Revoked => MARKER_REVOKED,
        };
        let options = vec![
            SelectOption::new(MARKER_NONE, "none (a host key)"),
            SelectOption::new(MARKER_CA, "@cert-authority"),
            SelectOption::new(MARKER_REVOKED, "@revoked"),
        ];
        let form = Form::new("Edit known host").section(
            "Entry",
            vec![
                Field::text("host_pattern", "Host pattern", &entry.host_pattern)
                    .required()
                    .validate(Validator::new("host_pattern", check_pattern))
                    .help("host, [host]:port, *.example.com,!bad.example.com or |1|… (hashed)"),
                Field::text(
                    "comment",
                    "Comment",
                    entry.comment.as_deref().unwrap_or_default(),
                ),
                Field::select("marker", "Marker", options, Some(marker)),
            ],
        );
        Self::Edit {
            id,
            entry,
            form: Box::new(form),
        }
    }

    /// The import or export path prompt.
    pub fn file(kind: FilePrompt) -> Self {
        let (title, body, default) = match kind {
            FilePrompt::Import => (
                "Import known hosts",
                "Import the entries of an OpenSSH known_hosts file (duplicates are skipped).",
                DEFAULT_IMPORT_PATH,
            ),
            FilePrompt::Export => (
                "Export known hosts",
                "Write every entry as an OpenSSH known_hosts file (an existing file is replaced).",
                DEFAULT_EXPORT_PATH,
            ),
        };
        let mut modal = Modal::prompt(title, body, "Path", false);
        modal.paste(default);
        Self::File { kind, modal }
    }

    /// The dialog edits text.
    pub fn wants_text(&self) -> bool {
        match self {
            Self::Edit { form, .. } => form.insert_mode(),
            Self::File { modal, .. } => modal.wants_text(),
        }
    }

    /// Handle input; answers push effects and close the dialog.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        match self {
            Self::Edit { id, entry, form } => {
                form.handle(ev, cx);
                match form.take_request() {
                    Some(FormRequest::Save(changes)) => {
                        let mut entry = entry.clone();
                        for (key, value) in &changes.0 {
                            match (key.as_str(), value) {
                                ("host_pattern", FieldValue::Text(t)) => {
                                    entry.host_pattern = t.trim().to_owned();
                                }
                                ("comment", FieldValue::Text(t)) => {
                                    let t = t.trim();
                                    entry.comment = (!t.is_empty()).then(|| t.to_owned());
                                }
                                ("marker", FieldValue::Choice(c)) => {
                                    entry.marker = match c.as_deref() {
                                        Some(MARKER_CA) => KnownHostMarker::CertAuthority,
                                        Some(MARKER_REVOKED) => KnownHostMarker::Revoked,
                                        _ => KnownHostMarker::None,
                                    };
                                }
                                _ => {}
                            }
                        }
                        if !changes.is_empty() {
                            cx.push(Effect::KnownHosts(KnownHostsEffect::Save {
                                item: Some(*id),
                                entry,
                            }));
                        }
                        cx.close();
                    }
                    Some(FormRequest::Cancel) => cx.close(),
                    None => {}
                }
            }
            Self::File { kind, modal } => match ev {
                ViewEvent::Key(key) => match modal.handle_key(key) {
                    Some(ModalAnswer::Text(path)) if !path.trim().is_empty() => {
                        let path = path.trim().to_owned();
                        cx.push(Effect::KnownHosts(match kind {
                            FilePrompt::Import => KnownHostsEffect::Import { path },
                            FilePrompt::Export => KnownHostsEffect::Export { path },
                        }));
                        cx.close();
                    }
                    Some(_) => cx.close(),
                    None => {}
                },
                ViewEvent::Paste(text) => modal.paste(text),
                ViewEvent::Mouse(_) => {}
            },
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match self {
            Self::Edit { form, .. } => {
                frame.render_widget(Clear, area);
                form.render(frame, area, cx);
            }
            Self::File { modal, .. } => modal.render(frame, area, cx),
        }
    }
}
