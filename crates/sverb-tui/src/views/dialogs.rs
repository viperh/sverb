//! Modal dialogs. They sit on a stack in `App::dialogs`; the top one sees input first
//! and consumes every key while open (it is modal).
//!
//! M1-06 adds [`DialogKind::Modal`]: the generic dialogs of `widgets::dialog`
//! (`Confirm`, `Prompt`, `Choice`, `Progress`, `Info`) with answers routed to effects.
//! The minimal item form stays until M1-07 moves item editing onto `widgets::form`.

use std::fmt::Write as _;
// M1-06
use std::collections::BTreeMap;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};

use super::{Outcome, RenderCx, View, ViewCx, ViewEvent};
use crate::{
    // M1-11
    app::SessionId,
    app::{Effect, notify::Notification, state::PendingKind},
    keymap::{Keymap, Table, action::ActionName, chord::KeyChord},
    // M1-06
    widgets::dialog::{Modal, ModalAnswer},
};

// M1-15: the unknown-key modal and the changed-key screen.
pub mod host_key;
// M2-07: the `confirm_on_use` agent prompt.
pub mod agent_confirm;

/// Identifies an open dialog, so effect results can find the dialog that issued them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DialogId(pub u64);

/// An open dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    /// Stable id while the dialog is open.
    pub id: DialogId,
    /// What the dialog is.
    pub kind: DialogKind,
}

/// Dialog variants. Append-only, one block per task with a `// <task-id>` comment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialogKind {
    // M0-08
    /// "Sessions are open. Quit?" `y` quits, `n`/`Esc` cancels.
    ConfirmQuit,
    /// Full-screen help: the effective keymap, searchable with `/` (M0-11).
    Help(HelpState),
    // M0-10
    /// First-run notice about the leader (`tasks/03-KEYBINDINGS.md` §5.3). Shown once.
    LeaderNotice,
    // M0-11
    /// The notification history (`leader !`).
    Notifications(NotificationList),
    // M1-11
    /// "Paste N lines into <host>?": a multi-line paste into a pane without bracketed
    /// paste (`terminal.paste_confirm_multiline`). `y`/`Enter` pastes, `n`/`Esc` cancels.
    ConfirmPaste(PasteConfirm),
    /// "<host> wants to set your clipboard": an OSC 52 write under
    /// `clipboard.allow_remote_write = "ask"`. `a` allow once, `f` allow for this session,
    /// `d`/`Esc` deny.
    RemoteClipboard(RemoteClipboard),
    // M1-06
    /// A generic modal (`widgets::dialog::Modal`). Its answer pushes the effects
    /// registered for it and closes the dialog. Timeouts and spinners tick through
    /// `TimerKind::DialogTick` (`App::push_modal`).
    Modal(ModalDialog),
    // M3-06
    /// The Logs dialogs (error details, delete, clear older, export, the replay player).
    /// The reducer answers their keys (`app/logs.rs`).
    Logs(super::logs::LogsDialog),
    // M1-07
    /// The host form (add / edit), full screen. Saves go out as
    /// `VaultEffect::Items(ItemEffect::Save)`; the reducer closes it on success.
    HostForm(super::hosts::form::HostFormDialog),
    /// Quick connect (`leader o`): the reducer takes its answer after the dispatch.
    QuickConnect(super::hosts::quick::QuickConnect),
    /// "Save as host?" after an unsaved target connected (keys: `App::on_hosts_dialog_key`).
    SaveHostOffer(super::hosts::quick::SaveHostOffer),
    // M2-01
    /// Groups and tags: the group / vault-defaults editor, move to group, bulk tags,
    /// delete group, the tag manager (`views/hosts/organize.rs`).
    Organize(super::hosts::organize::OrganizeDialog),
    // M2-02
    /// The identity form, delete (with convert-to-inline) and "Used by" dialogs
    /// (`views/keychain/identity_form.rs`).
    Identity(super::keychain::identity_form::IdentityDialog),
    // M1-14:
    /// An authentication prompt (password, key passphrase, keyboard-interactive) from a
    /// connecting session (`widgets::auth_prompt`). The dialog records its answer; the
    /// reducer takes it after the dispatch (`App::take_auth_answer`), answers the
    /// session and shows the next queued prompt.
    AuthPrompt(crate::widgets::auth_prompt::AuthPromptDialog),
    // M1-15
    /// A session's host-key question: the unknown-key modal or the full-screen
    /// changed-key warning. Its answer is `Effect::HostKeyDecision`.
    HostKey(host_key::HostKeyDialog),
    /// The Known Hosts dialogs: edit an entry, the import / export path prompts.
    KnownHosts(super::known_hosts::KnownHostsDialog),
    // M2-08
    /// The port-forward add / edit form. Its save is `Effect::Forwards(Save)`.
    Forward(super::forwards::ForwardDialog),
    // M2-09:
    /// A snippet dialog: the `leader e` picker, the host picker, the variable form,
    /// the editor, exec results. The reducer takes its answer after the key
    /// (`App::take_snippet_answer`) and pops it.
    Snippet(Box<super::snippets::SnippetDialog>),
    // M2-11
    /// The import / export wizard (`views/import_wizard.rs`). Its requests are
    /// `Effect::Import`; results (`UiEvent::Import`) find it by its dialog id.
    ImportWizard(Box<super::import_wizard::ImportWizard>),
    // M2-12
    /// The command palette (`leader p`, `ctrl-k`). The reducer ranks its results and
    /// carries out its answer after the key (`App::take_palette_answer`).
    Palette(Box<super::palette::PaletteState>),
    // M3-03
    /// The workspaces dialog (list / picker with preview, save and rename prompts).
    /// The reducer carries out its answer after the key (`App::take_workspaces_answer`).
    Workspaces(Box<super::workspaces::WorkspacesDialog>),
    // M7-01
    /// The autocomplete / history overlay (`leader Space`), anchored at the pane's
    /// cursor. The reducer takes its answer after each key (`App::take_autocomplete_answer`).
    Autocomplete(Box<super::sessions::autocomplete::Autocomplete>),
}

// M1-06
/// A [`Modal`] on the app's dialog stack, with the effects each answer triggers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModalDialog {
    /// The dialog.
    pub modal: Modal,
    /// Effects by [`ModalAnswer::route_key`] (`button:<id>`, `choice:<n>`,
    /// `cancelled`, `timed-out`, …). Unlisted answers just close the dialog.
    pub on_answer: BTreeMap<String, Vec<Effect>>,
}

// M1-06
impl ModalDialog {
    /// A dialog whose answers do nothing but close it.
    pub fn new(modal: Modal) -> Self {
        Self {
            modal,
            on_answer: BTreeMap::new(),
        }
    }

    /// Push `effects` when the answer's route key is `route` (see
    /// [`ModalAnswer::route_key`]).
    #[must_use]
    pub fn on(mut self, route: &str, effects: Vec<Effect>) -> Self {
        self.on_answer.insert(route.to_owned(), effects);
        self
    }

    /// The effects for `answer`.
    pub fn effects_for(&self, answer: &ModalAnswer) -> Vec<Effect> {
        self.on_answer
            .get(&answer.route_key())
            .cloned()
            .unwrap_or_default()
    }
}

// M1-11
/// Lines of a paste shown in [`DialogKind::ConfirmPaste`].
pub const PASTE_PREVIEW_LINES: usize = 5;
/// Characters of a remote clipboard write shown in [`DialogKind::RemoteClipboard`].
pub const CLIPBOARD_PREVIEW_CHARS: usize = 200;

// M1-11
/// State of the multi-line paste confirmation. The keys are handled by the reducer
/// (`app/input/remote_io.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteConfirm {
    /// The session the paste goes to.
    pub session: SessionId,
    /// Host (or pane) label for the question.
    pub host: String,
    /// The full text.
    pub text: String,
    /// Its line count.
    pub lines: usize,
    /// The first [`PASTE_PREVIEW_LINES`] lines, control characters removed.
    pub preview: Vec<String>,
}

// M1-11
/// State of the remote clipboard write prompt. The keys are handled by the reducer
/// (`app/input/remote_io.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteClipboard {
    /// The session that sent OSC 52.
    pub session: SessionId,
    /// Host (or pane) label for the question.
    pub host: String,
    /// The text to copy.
    pub text: String,
}

impl RemoteClipboard {
    /// The first [`CLIPBOARD_PREVIEW_CHARS`] characters, control characters shown as `·`.
    pub fn preview(&self) -> String {
        let mut out: String = self
            .text
            .chars()
            .take(CLIPBOARD_PREVIEW_CHARS)
            .map(|c| if c.is_control() { '·' } else { c })
            .collect();
        if self.text.chars().count() > CLIPBOARD_PREVIEW_CHARS {
            out.push('…');
        }
        out
    }
}

// M0-11
/// State of the help overlay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelpState {
    /// The search text (case-insensitive substring of keys, description or action).
    pub query: String,
    /// `/` was pressed: keys edit the query until `Enter`/`Esc`.
    pub searching: bool,
    /// First row shown.
    pub scroll: usize,
}

// M0-11
/// State of the notification history overlay: a snapshot taken when it opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotificationList {
    /// Newest first.
    pub entries: Vec<Notification>,
    /// Highlighted entry.
    pub selected: usize,
    /// The highlighted entry shows its detail chain.
    pub expanded: bool,
}

impl NotificationList {
    /// A list over `entries` (newest first).
    pub fn new(entries: Vec<Notification>) -> Self {
        Self {
            entries,
            selected: 0,
            expanded: false,
        }
    }
}

impl Dialog {
    fn handle_confirm_quit(code: KeyCode, cx: &mut ViewCx<'_>) {
        match code {
            KeyCode::Char('y' | 'Y') => {
                cx.push(Effect::Quit { code: 0 });
                cx.close();
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => cx.close(),
            _ => {}
        }
    }

    // M0-11
    fn handle_help(help: &mut HelpState, code: KeyCode, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        if help.searching {
            match code {
                KeyCode::Esc => {
                    help.searching = false;
                    help.query.clear();
                }
                KeyCode::Enter => help.searching = false,
                KeyCode::Backspace => {
                    help.query.pop();
                }
                KeyCode::Char(c) => {
                    help.query.push(c);
                    help.scroll = 0;
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('/') => {
                help.searching = true;
                help.scroll = 0;
            }
            KeyCode::Char('j') | KeyCode::Down => help.scroll = help.scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => help.scroll = help.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => help.scroll = help.scroll.saturating_add(10),
            KeyCode::PageUp => help.scroll = help.scroll.saturating_sub(10),
            KeyCode::Char('g') | KeyCode::Home => help.scroll = 0,
            KeyCode::Esc if !help.query.is_empty() => help.query.clear(),
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | '?') => cx.close(),
            _ => {}
        }
    }

    // M0-11
    fn handle_notifications(list: &mut NotificationList, code: KeyCode, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        let last = list.entries.len().saturating_sub(1);
        match code {
            KeyCode::Char('j') | KeyCode::Down => {
                list.selected = (list.selected + 1).min(last);
                list.expanded = false;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                list.selected = list.selected.saturating_sub(1);
                list.expanded = false;
            }
            KeyCode::Enter | KeyCode::Char(' ' | 'l') | KeyCode::Right => {
                list.expanded = !list.expanded;
            }
            KeyCode::Esc | KeyCode::Char('q' | '!') => cx.close(),
            _ => {}
        }
    }
}

// M1-07
fn handle_host_form(
    id: DialogId,
    d: &mut super::hosts::form::HostFormDialog,
    ev: &ViewEvent,
    cx: &mut ViewCx<'_>,
) {
    use crate::widgets::form::FormRequest;
    d.form.handle(ev, cx);
    super::hosts::form::sync_identity(&mut d.form);
    // M2-01: inherited placeholders follow the draft's group.
    d.sync_inherited();
    match d.form.take_request() {
        Some(FormRequest::Save(changes)) => {
            if d.item.is_some() && changes.is_empty() {
                cx.close();
                return;
            }
            let changes = d.save_changes(changes);
            // M2-02: switching "Use identity" / "Inline" clears the other mode.
            let changes = super::hosts::form::credential_changes(&d.form, changes);
            let item = d.item;
            cx.issue(
                |eid| {
                    Effect::Vault(crate::app::VaultEffect::Items(
                        crate::app::hosts::ItemEffect::Save {
                            id: eid,
                            item,
                            kind: sverb_core::model::ItemKind::Host,
                            changes,
                        },
                    ))
                },
                PendingKind::SaveItem { dialog: id },
            );
        }
        Some(FormRequest::Cancel) => cx.close(),
        None => {}
    }
}

impl View for Dialog {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        let id = self.id;
        match &mut self.kind {
            // M1-07
            DialogKind::HostForm(d) => handle_host_form(id, d, ev, cx),
            DialogKind::QuickConnect(q) => {
                cx.request_redraw();
                match ev {
                    ViewEvent::Key(key) => {
                        if q.handle_key(key) && q.answer_pending().is_none() {
                            cx.close();
                        }
                    }
                    ViewEvent::Paste(text) => q.paste(text),
                    ViewEvent::Mouse(_) => {}
                }
            }
            // Answered by the reducer (`App::on_hosts_dialog_key`).
            DialogKind::SaveHostOffer(_) => {}
            DialogKind::ConfirmQuit => {
                if let ViewEvent::Key(key) = ev {
                    Self::handle_confirm_quit(key.code, cx);
                }
            }
            DialogKind::Help(help) => {
                if let ViewEvent::Key(key) = ev {
                    Self::handle_help(help, key.code, cx);
                }
            }
            // M0-10
            DialogKind::LeaderNotice => {
                if let ViewEvent::Key(key) = ev
                    && matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'))
                {
                    cx.close();
                }
            }
            // M0-11
            DialogKind::Notifications(list) => {
                if let ViewEvent::Key(key) = ev {
                    Self::handle_notifications(list, key.code, cx);
                }
            }
            // M1-11: the reducer answers their keys (it owns the per-session allow list).
            DialogKind::ConfirmPaste(_) | DialogKind::RemoteClipboard(_) => {}
            // M1-06
            DialogKind::Modal(m) => {
                cx.request_redraw();
                match ev {
                    ViewEvent::Key(key) => {
                        if let Some(answer) = m.modal.handle_key(key) {
                            for effect in m.effects_for(&answer) {
                                cx.push(effect);
                            }
                            cx.close();
                        }
                    }
                    ViewEvent::Paste(text) => m.modal.paste(text),
                    ViewEvent::Mouse(_) => {}
                }
            }
            // M3-06: answered by the reducer (`App::on_logs_dialog_key`).
            DialogKind::Logs(_) => {}
            // M2-01
            DialogKind::Organize(o) => o.handle(id, ev, cx),
            // M1-15
            DialogKind::HostKey(h) => {
                cx.request_redraw();
                match ev {
                    ViewEvent::Key(key) => {
                        if let Some(decision) = h.handle_key(key) {
                            cx.push(Effect::HostKeyDecision {
                                id: h.session,
                                decision,
                            });
                            cx.close();
                        }
                    }
                    ViewEvent::Paste(text) => h.paste(text),
                    ViewEvent::Mouse(_) => {}
                }
            }
            DialogKind::KnownHosts(k) => k.handle(ev, cx),
            // M2-08
            DialogKind::Forward(f) => {
                f.handle(ev, cx);
                if let Some((item, rule)) = f.take_result() {
                    cx.push(Effect::Forwards(crate::app::ForwardsEffect::Save {
                        item,
                        rule,
                    }));
                }
            }
            // M1-14:
            DialogKind::AuthPrompt(a) => {
                cx.request_redraw();
                match ev {
                    ViewEvent::Key(key) => {
                        if let Some(outcome) = a.handle_key(key) {
                            a.answer = Some(outcome);
                        }
                    }
                    ViewEvent::Paste(text) => a.paste(text),
                    ViewEvent::Mouse(_) => {}
                }
            }
            // M2-02
            DialogKind::Identity(d) => d.handle(id, ev, cx),
            // M2-09:
            DialogKind::Snippet(d) => d.handle(ev, cx),
            // M2-11
            DialogKind::ImportWizard(w) => w.handle(id, ev, cx),
            // M2-12
            DialogKind::Palette(p) => p.handle(ev, cx),
            // M3-03
            DialogKind::Workspaces(w) => {
                w.handle(ev, cx);
            }
            // M7-01
            DialogKind::Autocomplete(a) => {
                cx.request_redraw();
                match ev {
                    ViewEvent::Key(key) => a.handle_key(key),
                    ViewEvent::Paste(text) => a.paste(text),
                    ViewEvent::Mouse(_) => {}
                }
            }
        }
        // Modal: nothing behind an open dialog sees input.
        Outcome::Consumed
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let (title, lines): (&str, Vec<Line<'_>>) = match &self.kind {
            DialogKind::ConfirmQuit => (
                " Quit ",
                vec![
                    Line::raw("Sessions are open. Quit sverb?"),
                    Line::raw(""),
                    Line::raw("y quit · n / Esc cancel"),
                ],
            ),
            // M0-11: full screen, drawn by `render_help`.
            DialogKind::Help(help) => return render_help(help, frame, area, cx),
            DialogKind::Notifications(list) => {
                return render_notifications(list, frame, area, cx);
            }
            // M1-06
            DialogKind::Modal(m) => return m.modal.render(frame, area, cx),
            // M3-06
            DialogKind::Logs(d) => {
                return super::logs::detail::render_dialog(d, None, frame, area, cx);
            }
            // M1-07
            DialogKind::HostForm(d) => return d.form.render(frame, area, cx),
            DialogKind::QuickConnect(q) => return q.render(frame, area, cx),
            DialogKind::SaveHostOffer(o) => return o.render(frame, area, cx),
            // M2-01
            DialogKind::Organize(o) => return o.render(frame, area, cx),
            // M1-15
            DialogKind::HostKey(h) => return h.render(frame, area, cx),
            DialogKind::KnownHosts(k) => return k.render(frame, area, cx),
            // M2-08
            DialogKind::Forward(f) => return f.render(frame, area, cx),
            // M1-14:
            DialogKind::AuthPrompt(a) => return a.render(frame, area, cx),
            // M2-02
            DialogKind::Identity(d) => return d.render(frame, area, cx),
            // M2-09:
            DialogKind::Snippet(d) => return d.render(frame, area, cx),
            // M2-11
            DialogKind::ImportWizard(w) => return w.render(frame, area, cx),
            // M2-12
            DialogKind::Palette(p) => return p.render(frame, area, cx),
            // M3-03
            DialogKind::Workspaces(w) => return w.render(frame, area, cx),
            // M7-01: anchored at the cursor (absolute screen cells).
            DialogKind::Autocomplete(a) => return a.render(frame, area, cx.theme),
            // M0-10
            DialogKind::LeaderNotice => (" Welcome to sverb ", leader_notice(cx)),
            // M1-11
            DialogKind::ConfirmPaste(p) => {
                let mut lines = vec![
                    Line::raw(format!("Paste {} lines into {}?", p.lines, p.host)),
                    Line::raw(""),
                ];
                lines.extend(p.preview.iter().map(|l| Line::raw(format!("  {l}"))));
                if p.lines > p.preview.len() {
                    lines.push(Line::raw(format!("  … {} more", p.lines - p.preview.len())));
                }
                lines.push(Line::raw(""));
                lines.push(Line::raw("y / Enter paste · n / Esc cancel"));
                (" Paste ", lines)
            }
            DialogKind::RemoteClipboard(c) => (
                " Clipboard ",
                vec![
                    Line::raw(format!(
                        "{} wants to set your clipboard ({} chars)",
                        c.host,
                        c.text.chars().count()
                    )),
                    Line::raw(""),
                    Line::raw(c.preview()),
                    Line::raw(""),
                    Line::raw("[a]llow once · allow [f]or this session · [d]eny"),
                ],
            ),
        };
        let width = lines
            .iter()
            .map(Line::width)
            .max()
            .unwrap_or(0)
            .max(title.len())
            .saturating_add(4);
        let height = lines.len().saturating_add(2);
        let rect = centered(area, width, height);
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .style(cx.theme.base)
                .block(dialog_block(title, cx)),
            rect,
        );
    }
}

// M0-11
/// A themed dialog frame.
fn dialog_block<'a>(title: &'a str, cx: &RenderCx<'_>) -> Block<'a> {
    Block::bordered()
        .title(Span::styled(title, cx.theme.title_for(cx.focused)))
        .border_style(cx.theme.border_for(cx.focused))
}

// M0-11
/// The help overlay's rows: the effective keymap (minus `toggle_log_pane` without
/// `--debug`), filtered by the query, with a heading per table.
pub fn help_lines(query: &str, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
    let query = query.to_lowercase();
    let rows: Vec<_> = Keymap::effective(cx.config)
        .into_iter()
        .filter(|r| cx.debug || r.action != ActionName::ToggleLogPane)
        .filter(|r| {
            query.is_empty()
                || r.keys.to_lowercase().contains(&query)
                || r.description.to_lowercase().contains(&query)
                || r.action.to_string().contains(&query)
        })
        .collect();
    let key_w = rows
        .iter()
        .map(|r| r.keys.chars().count())
        .max()
        .unwrap_or(0)
        .min(20);
    let mut lines = Vec::new();
    let mut table = None;
    for r in rows {
        if table != Some(r.table) {
            table = Some(r.table);
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }
            let heading = match r.table {
                Table::Leader => "After the leader (every mode)",
                Table::Normal => "Normal mode (sverb views)",
            };
            lines.push(Line::styled(heading, cx.theme.accent));
        }
        lines.push(Line::from(vec![
            Span::raw(format!("  {:<key_w$}  ", r.keys)),
            Span::raw(format!("{:<28}", r.description)),
            Span::styled(r.action.to_string(), cx.theme.dim),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::styled("No matching keys.", cx.theme.dim));
    }
    lines
}

// M0-11
fn render_help(help: &HelpState, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    if area.width < 3 || area.height < 3 {
        return;
    }
    frame.render_widget(Clear, area);
    let block = dialog_block(" Help · keys ", cx).title_bottom(Span::styled(
        " / search · j k scroll · esc close ",
        cx.theme.dim,
    ));
    let inner = block.inner(area);
    frame.render_widget(block.style(cx.theme.base), area);
    let mut lines = Vec::new();
    if help.searching || !help.query.is_empty() {
        let cursor = if help.searching { "▏" } else { "" };
        lines.push(Line::from(vec![
            Span::styled("/", cx.theme.accent),
            Span::raw(format!("{}{cursor}", help.query)),
        ]));
    }
    let body = help_lines(&help.query, cx);
    let visible = usize::from(inner.height).saturating_sub(lines.len()).max(1);
    let scroll = help.scroll.min(body.len().saturating_sub(visible));
    lines.extend(body.into_iter().skip(scroll));
    frame.render_widget(Paragraph::new(lines), inner);
}

// M0-11
/// `ui.date_format`, or `--` before the runtime stamped the entry. Never panics on a
/// bad format (validation rejects those; a failure just shows the RFC 3339 time).
fn format_time(n: &Notification, fmt: &str) -> String {
    let Some(at) = n.at else {
        return "--".to_owned();
    };
    let mut out = String::new();
    if write!(out, "{}", at.format(fmt)).is_err() {
        out = at.to_rfc3339();
    }
    out
}

// M0-11
fn render_notifications(
    list: &NotificationList,
    frame: &mut Frame<'_>,
    area: Rect,
    cx: &RenderCx<'_>,
) {
    let theme = cx.theme;
    let mut lines: Vec<Line<'static>> = Vec::new();
    if list.entries.is_empty() {
        lines.push(Line::styled("No notifications yet.", theme.dim));
    }
    for (i, n) in list.entries.iter().enumerate() {
        let level_style = match n.level {
            crate::app::ToastLevel::Error => theme.error,
            crate::app::ToastLevel::Warning => theme.warn,
            crate::app::ToastLevel::Success => theme.ok,
            _ => theme.info,
        };
        let count = if n.count > 1 {
            format!(" (×{})", n.count)
        } else {
            String::new()
        };
        let more = if n.detail.is_empty() { " " } else { "+" };
        let time = format_time(n, &cx.config.ui.date_format);
        let mut spans = vec![
            Span::styled(format!("{time} "), theme.dim),
            Span::styled(format!("{:<7} ", n.level.label()), level_style),
            Span::raw(format!("{more} {}{count}", n.message)),
        ];
        if i == list.selected && cx.focused {
            let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
            spans = vec![Span::styled(text, theme.selection)];
        }
        lines.push(Line::from(spans));
        if i == list.selected && list.expanded {
            if n.detail.is_empty() {
                lines.push(Line::styled("    (no details)", theme.dim));
            }
            for cause in &n.detail {
                lines.push(Line::styled(format!("    ↳ {cause}"), theme.dim));
            }
        }
    }
    let width = usize::from(area.width.saturating_sub(4)).clamp(1, 100);
    let height = (lines.len() + 2).min(usize::from(area.height.saturating_sub(2)).max(3));
    let rect = centered(area, width, height);
    if rect.width < 3 || rect.height < 3 {
        return;
    }
    // Keep the selection on screen.
    let inner_h = usize::from(rect.height - 2);
    // The selected entry is line `selected` (details only follow it).
    let skip = (list.selected + 1).saturating_sub(inner_h);
    frame.render_widget(Clear, rect);
    let block = dialog_block(" Notifications ", cx)
        .title_bottom(Span::styled(" enter details · esc close ", theme.dim));
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(skip).collect::<Vec<_>>())
            .style(theme.base)
            .block(block),
        rect,
    );
}

// M0-10
/// The §5.3 first-run text, rendered from the configured leader.
fn leader_notice(cx: &RenderCx<'_>) -> Vec<Line<'static>> {
    let leader = cx
        .config
        .general
        .leader
        .as_str()
        .parse::<KeyChord>()
        .map_or_else(|_| cx.config.general.leader.to_string(), |c| c.to_string());
    vec![
        Line::raw(format!("sverb's command key is {leader}.")),
        Line::raw("Every other key goes to your SSH session."),
        Line::raw(format!("Press {leader} then ? for help.")),
        Line::raw(format!("Press it twice to send {leader} itself.")),
        Line::raw(""),
        Line::raw("If \\ is awkward on your keyboard layout, set"),
        Line::raw("general.leader = \"ctrl-g\" in config.toml."),
        Line::raw(""),
        Line::raw("Enter / Esc close"),
    ]
}

/// A `width`×`height` rect centered in `area`, clamped to it.
pub(crate) fn centered(area: Rect, width: usize, height: usize) -> Rect {
    let w = u16::try_from(width).unwrap_or(u16::MAX).min(area.width);
    let h = u16::try_from(height).unwrap_or(u16::MAX).min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}
