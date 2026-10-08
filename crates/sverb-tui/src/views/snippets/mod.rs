//! M2-09: the Snippets section and the snippet dialogs (SPEC §8.5, §9.7).
//!
//! ```text
//! ┌ Snippets ──────────────────────────────┐┌ Details ─────────────────────────┐
//! │ › deploy        exec    #web #prod     ││ systemctl restart {{svc}}         │
//! │   tail logs     paste   #ops           ││ Variables: svc, token (secret)    │
//! └────────────────────────────────────────┘└───────────────────────────────────┘
//! ```
//!
//! - **List** (the shared M1-06 list: `/` filters, also on `#tag` and the script; `Space`
//!   marks; `s` sorts). Keys: `Enter` run here (the snippet's run mode), `r` run on
//!   hosts…, `p` paste, `a` add, `e` edit, `y` duplicate, `d` delete. The detail pane
//!   shows the script with its variables highlighted.
//! - **Dialogs** ([`SnippetDialog`]): the `leader e` picker ([`picker`]), the variable
//!   form with its live, masked preview and the host picker ([`run_dialog`]), the
//!   editor ([`form`]) and the per-host results ([`results`]).
//!
//! Like the other sections, the view and the dialogs only record what the user asked
//! for ([`SnippetsView::request`], [`SnippetDialog::take_answer`]); the reducer turns
//! that into effects (`app/snippets.rs`). [`run_dialog::VarForm::submit`] computes the
//! exact bytes for the pane (or the exec plan), so the whole run path is testable here.

pub mod form;
pub mod picker;
pub mod results;
pub mod run_dialog;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use sverb_core::{
    model::{ItemId, RunMode, Snippet},
    snippet::{Part, Template, effective_vars, is_builtin},
};

use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
    widgets::{
        list::{DetailRenderer, EmptyState, ListRow, ListView, RowCx, RowRenderer, SortKey},
        truncate,
    },
};

pub use form::SnippetFormDialog;
pub use picker::SnippetPicker;
pub use results::SnippetResults;
pub use run_dialog::{ExecPlan, HostTargetsPicker, PaneCtx, RunRequest, RunWhere, VarForm};

/// `paste`, `paste & run`, `exec`.
pub fn mode_text(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Paste => "paste",
        RunMode::PasteAndExecute => "paste & run",
        RunMode::Exec => "exec",
    }
}

// ---------------------------------------------------------------- rows

/// One snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetRow {
    /// The item.
    pub id: ItemId,
    /// The snippet.
    pub snippet: Snippet,
    /// Its tag names.
    pub tags: Vec<String>,
}

impl ListRow for SnippetRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.id
    }

    fn label(&self) -> &str {
        &self.snippet.name
    }

    fn filter_text(&self) -> String {
        let tags: Vec<String> = self.tags.iter().map(|t| format!("#{t}")).collect();
        format!(
            "{} {} {} {}",
            self.snippet.name,
            tags.join(" "),
            self.snippet.description.as_deref().unwrap_or_default(),
            self.snippet.script
        )
    }

    fn item_id(&self) -> Option<ItemId> {
        Some(self.id)
    }

    fn secondary(&self) -> String {
        mode_text(self.snippet.run_mode).to_owned()
    }
}

/// The script as lines with `{{…}}` highlighted (built-ins dimmed); an unparsable
/// script is shown as is with the error below.
pub fn highlighted(script: &str, theme: &Theme) -> Vec<Line<'static>> {
    let template = match Template::parse(script) {
        Ok(t) => t,
        Err(e) => {
            let mut lines: Vec<Line<'static>> =
                script.lines().map(|l| Line::raw(l.to_owned())).collect();
            lines.push(Line::styled(format!("⚠ {e}"), theme.error));
            return lines;
        }
    };
    let mut lines = vec![Line::default()];
    let push = |lines: &mut Vec<Line<'static>>, text: &str, style: Style| {
        for (i, piece) in text.split('\n').enumerate() {
            if i > 0 {
                lines.push(Line::default());
            }
            if !piece.is_empty()
                && let Some(last) = lines.last_mut()
            {
                last.spans.push(Span::styled(piece.to_owned(), style));
            }
        }
    };
    for part in &template.parts {
        match part {
            Part::Literal(s) => push(&mut lines, s, theme.base),
            Part::Var(v) => {
                let style = if is_builtin(&v.name) {
                    theme.info
                } else {
                    theme.accent
                };
                push(&mut lines, &script[v.span.clone()], style);
            }
        }
    }
    lines
}

// ---------------------------------------------------------------- the view

/// What the user asked the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetsRequest {
    /// `Enter`: run in the current pane with the snippet's run mode (Exec: pick hosts).
    RunHere(ItemId),
    /// `r`: run on hosts…
    RunOnHosts(ItemId),
    /// `p`: paste into the current pane.
    Paste(ItemId),
    /// `a`
    Add,
    /// `e`
    Edit(ItemId),
    /// `y`
    Duplicate(ItemId),
    /// `d` (asks first)
    Delete(Vec<ItemId>),
}

/// The Snippets section's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetsView {
    /// The list.
    pub list: ListView<SnippetRow>,
    /// Tag names by id.
    pub tag_names: BTreeMap<ItemId, String>,
    /// The service delivered the snippets (after unlock).
    pub loaded: bool,
    /// A load is in flight.
    pub loading: bool,
    /// The data changed while loading: load again.
    pub reload: bool,
    /// A request for the reducer, taken right after the key.
    pub request: Option<SnippetsRequest>,
    /// Session ids of exec-run connections (their prompts' answers go to the run).
    pub run_sessions: std::collections::BTreeSet<crate::app::SessionId>,
    /// Sessions whose startup snippet was already checked.
    pub startup_checked: std::collections::BTreeSet<crate::app::SessionId>,
}

impl Default for SnippetsView {
    fn default() -> Self {
        let by_name = SortKey::new("name", |a: &SnippetRow, b: &SnippetRow| {
            a.snippet
                .name
                .to_lowercase()
                .cmp(&b.snippet.name.to_lowercase())
        });
        let by_mode = SortKey::new("mode", |a: &SnippetRow, b: &SnippetRow| {
            mode_text(a.snippet.run_mode).cmp(mode_text(b.snippet.run_mode))
        });
        Self {
            list: ListView::new("Snippets")
                .with_sort_keys(vec![by_name, by_mode])
                .with_empty(EmptyState::new(
                    "No snippets yet.",
                    &[("a", "add a snippet")],
                )),
            tag_names: BTreeMap::new(),
            loaded: false,
            loading: false,
            reload: false,
            request: None,
            run_sessions: std::collections::BTreeSet::new(),
            startup_checked: std::collections::BTreeSet::new(),
        }
    }
}

impl SnippetsView {
    /// Replace the snippets (and tag names).
    pub fn set_snippets(
        &mut self,
        snippets: Vec<(ItemId, Snippet)>,
        tag_names: BTreeMap<ItemId, String>,
    ) {
        let rows = snippets
            .into_iter()
            .map(|(id, snippet)| SnippetRow {
                id,
                tags: snippet
                    .tags
                    .iter()
                    .filter_map(|t| tag_names.get(t).cloned())
                    .collect(),
                snippet,
            })
            .collect();
        self.tag_names = tag_names;
        self.list.set_rows(rows);
        self.loaded = true;
    }

    /// Forget everything decrypted (on lock).
    pub fn clear(&mut self) {
        self.list.set_rows(Vec::new());
        self.tag_names.clear();
        self.loaded = false;
        self.loading = false;
        self.reload = false;
        self.request = None;
    }

    /// The snippet with `id`.
    pub fn get(&self, id: ItemId) -> Option<&Snippet> {
        self.list
            .rows()
            .iter()
            .find(|r| r.id == id)
            .map(|r| &r.snippet)
    }

    /// Every snippet (picker order: by name).
    pub fn snippets(&self) -> Vec<(ItemId, Snippet)> {
        let mut v: Vec<(ItemId, Snippet)> = self
            .list
            .rows()
            .iter()
            .map(|r| (r.id, r.snippet.clone()))
            .collect();
        v.sort_by_key(|a| a.1.name.to_lowercase());
        v
    }

    /// The list is editing its filter (Insert mode).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<SnippetsRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        let selected = || self.list.selected().map(|r| r.id);
        Some(match code {
            KeyCode::Enter => SnippetsRequest::RunHere(selected()?),
            KeyCode::Char('r') => SnippetsRequest::RunOnHosts(selected()?),
            KeyCode::Char('p') => SnippetsRequest::Paste(selected()?),
            KeyCode::Char('a') => SnippetsRequest::Add,
            KeyCode::Char('e') => SnippetsRequest::Edit(selected()?),
            KeyCode::Char('y') => SnippetsRequest::Duplicate(selected()?),
            KeyCode::Char('d') | KeyCode::Delete => {
                let targets = self.list.targets();
                if targets.is_empty() {
                    return None;
                }
                SnippetsRequest::Delete(targets)
            }
            _ => return None,
        })
    }

    /// Draw the selected snippet (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let block = Block::bordered()
            .title(Span::styled(" Details ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let width = usize::from(area.width.saturating_sub(2));
        let lines = match self.list.selected() {
            Some(row) => SnippetDetail.lines(row, theme, width),
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

/// Draws a row: name, run mode, tags, description.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnippetRowRenderer;

impl RowRenderer<SnippetRow> for SnippetRowRenderer {
    fn spans(&self, row: &SnippetRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let dim = cx.base.patch(cx.theme.dim);
        let w = cx.width;
        let name_w = (w / 3).clamp(8, 32);
        let mut spans = vec![Span::styled(
            format!("{:<name_w$} ", truncate(&row.snippet.name, name_w)),
            cx.base,
        )];
        let mut used = name_w + 1;
        let mode = format!("{:<11} ", mode_text(row.snippet.run_mode));
        if used + mode.len() <= w {
            used += mode.len();
            spans.push(Span::styled(mode, dim));
        }
        let tags: Vec<String> = row.tags.iter().map(|t| format!("#{t}")).collect();
        let rest = format!(
            "{} {}",
            tags.join(" "),
            row.snippet.description.as_deref().unwrap_or_default()
        );
        let room = w.saturating_sub(used);
        if room > 0 {
            spans.push(Span::styled(truncate(rest.trim(), room), dim));
        }
        spans
    }
}

/// The detail pane: script (variables highlighted), variables, mode, tags.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnippetDetail;

impl DetailRenderer<SnippetRow> for SnippetDetail {
    fn lines(&self, row: &SnippetRow, theme: &Theme, _width: usize) -> Vec<Line<'static>> {
        let label = |k: &str| Span::styled(format!("{k:<11} "), theme.dim);
        let s = &row.snippet;
        let mut lines = vec![Line::from(vec![
            label("Run mode:"),
            Span::raw(mode_text(s.run_mode)),
        ])];
        if let Some(d) = s.description.as_deref().filter(|d| !d.is_empty()) {
            lines.push(Line::from(vec![label("About:"), Span::raw(d.to_owned())]));
        }
        if !row.tags.is_empty() {
            let tags: Vec<String> = row.tags.iter().map(|t| format!("#{t}")).collect();
            lines.push(Line::from(vec![label("Tags:"), Span::raw(tags.join(" "))]));
        }
        if let Ok(t) = Template::parse(&s.script) {
            let vars = effective_vars(&t, &s.variables);
            if !vars.is_empty() {
                let text: Vec<String> = vars
                    .iter()
                    .map(|v| {
                        let mut x = v.name.clone();
                        if v.secret {
                            x.push_str(" (secret)");
                        } else if let Some(d) = &v.default {
                            x.push_str(&format!(" = {d}"));
                        }
                        x
                    })
                    .collect();
                lines.push(Line::from(vec![
                    label("Variables:"),
                    Span::raw(text.join(", ")),
                ]));
            }
        }
        lines.push(Line::raw(""));
        lines.extend(highlighted(&s.script, theme));
        lines
    }
}

impl View for SnippetsView {
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
        let detail: Option<&dyn DetailRenderer<SnippetRow>> =
            self.list.detail_full().then_some(&SnippetDetail as _);
        self.list
            .render_with(frame, area, cx, &SnippetRowRenderer, detail);
    }

    fn insert_mode(&self) -> bool {
        SnippetsView::insert_mode(self)
    }
}

// ---------------------------------------------------------------- dialogs

/// What a snippet dialog answered. The dialog stays open with its answer; the reducer
/// takes it after the key and pops the dialog when [`SnippetAnswer::closes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetAnswer {
    /// The picker chose a snippet (for `pane`, the focused pane when it opened).
    Picked {
        /// The snippet.
        id: ItemId,
        /// Where it runs.
        pane: Option<PaneCtx>,
    },
    /// Hosts were picked for an exec run.
    Hosts {
        /// The snippet.
        id: ItemId,
        /// What was picked.
        targets: Vec<crate::views::keychain::install::InstallTarget>,
    },
    /// The variable form was submitted.
    Run(RunRequest),
    /// The editor saved.
    Save {
        /// The item (`None`: new).
        id: Option<ItemId>,
        /// The snippet.
        snippet: Snippet,
    },
    /// Results: re-run the failed hosts.
    Rerun,
    /// Results: export (`Copy` or a file path).
    Export {
        /// JSON (else Markdown).
        json: bool,
        /// A file path; `None`: the clipboard.
        path: Option<String>,
        /// The text.
        text: String,
    },
    /// Results closed while running: cancel the run.
    Cancel(u64),
}

impl SnippetAnswer {
    /// The dialog that gave this answer goes away.
    pub fn closes(&self) -> bool {
        !matches!(self, Self::Rerun | Self::Export { .. })
    }
}

/// Which snippet dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetDialogKind {
    /// `leader e`.
    Picker(Box<SnippetPicker>),
    /// Run on hosts…: pick hosts, groups, tags.
    Hosts(Box<HostTargetsPicker>),
    /// Values and preview.
    Vars(Box<VarForm>),
    /// The editor.
    Form(Box<SnippetFormDialog>),
    /// The results of an exec run.
    Results(Box<SnippetResults>),
}

/// A snippet dialog on the app's stack (`DialogKind::Snippet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetDialog {
    /// Which one.
    pub kind: SnippetDialogKind,
    answer: Option<SnippetAnswer>,
}

impl SnippetDialog {
    /// Wrap `kind`.
    pub fn new(kind: SnippetDialogKind) -> Self {
        Self { kind, answer: None }
    }

    /// The answer, once.
    pub fn take_answer(&mut self) -> Option<SnippetAnswer> {
        self.answer.take()
    }

    /// An answer is waiting.
    pub fn has_answer(&self) -> bool {
        self.answer.is_some()
    }

    /// The dialog edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        match &self.kind {
            SnippetDialogKind::Picker(_)
            | SnippetDialogKind::Hosts(_)
            | SnippetDialogKind::Vars(_) => true,
            SnippetDialogKind::Form(f) => f.wants_text(),
            SnippetDialogKind::Results(r) => r.wants_text(),
        }
    }

    /// Handle input (modal: everything is consumed).
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        let answer = match &mut self.kind {
            SnippetDialogKind::Picker(p) => p.handle(ev, cx),
            SnippetDialogKind::Hosts(p) => p.handle(ev, cx),
            SnippetDialogKind::Vars(v) => v.handle(ev, cx).map(SnippetAnswer::Run),
            SnippetDialogKind::Form(f) => f.handle(ev, cx),
            SnippetDialogKind::Results(r) => r.handle(ev, cx),
        };
        if answer.is_some() {
            self.answer = answer;
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match &self.kind {
            SnippetDialogKind::Picker(p) => p.render(frame, area, cx),
            SnippetDialogKind::Hosts(p) => p.render(frame, area, cx),
            SnippetDialogKind::Vars(v) => v.render(frame, area, cx),
            SnippetDialogKind::Form(f) => f.render(frame, area, cx),
            SnippetDialogKind::Results(r) => r.render(frame, area, cx),
        }
    }
}

/// A centered rectangle of at most `w`×`h` inside `area` (`None`: too small).
pub(crate) fn centered(area: Rect, w: u16, h: u16, min_w: u16, min_h: u16) -> Option<Rect> {
    let w = area.width.saturating_sub(4).min(w);
    let h = area.height.saturating_sub(2).min(h);
    if w < min_w || h < min_h {
        return None;
    }
    Some(Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    ))
}
