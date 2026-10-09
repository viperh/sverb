//! Running a snippet (SPEC §9.7): the variable form and the host picker.
//!
//! [`VarForm`]: one field per variable (defaults prefilled, secret fields masked) and
//! a **live preview** of the final text (secrets as `••••`). It is shown before every
//! run, also without variables: the final text is always previewed. `Tab`/`↓` and
//! `shift-Tab`/`↑` move between fields, `Enter` runs, `Esc` cancels.
//! [`VarForm::submit`] computes what runs:
//! - [`RunRequest::Paste`]: the text without a trailing newline (the session brackets
//! - [`RunRequest::Execute`]: every line followed by `\r`, sent raw (never bracketed);
//! - [`RunRequest::Exec`]: the exec plan for the picked hosts (built-ins are rendered
//!   per host by the runner).
//!
//! Pane runs carry a [`HistoryRecord`] whose command keeps secrets as `{{name}}`.
//!
//! [`HostTargetsPicker`]: multi-select over groups, tags and hosts ("Run on hosts…").

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::{
    model::{ItemId, RunMode, Snippet, VarDef},
    snippet::{
        Builtins, HistoryRecord, RenderStyle, Template, Values, effective_vars,
        history::history_command, paste_execute_bytes, paste_text,
    },
};

use super::{SnippetAnswer, centered, mode_text};
use crate::app::SessionId;
use crate::views::{
    RenderCx, ViewCx, ViewEvent, hosts::catalog::HostCatalog, keychain::install::InstallTarget,
};
use crate::widgets::truncate;

/// The pane a snippet runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneCtx {
    /// Its session.
    pub session: SessionId,
    /// Its label.
    pub label: String,
    /// The saved host, if any.
    pub host_id: Option<ItemId>,
    /// Built-ins for this pane's host.
    pub builtins: Builtins,
}

/// Where a run goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunWhere {
    /// Into a pane, with the form's run mode.
    Pane(PaneCtx),
    /// Exec on these hosts (id, label).
    Hosts(Vec<(ItemId, String)>),
    /// A host's startup snippet at connect time (Paste & execute).
    Startup(PaneCtx),
}

/// An exec run to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    /// The snippet.
    pub snippet: ItemId,
    /// Its name (results title).
    pub name: String,
    /// The script.
    pub template: Template,
    /// Values (defaults filled in, secrets marked).
    pub values: Values,
    /// Target hosts and labels.
    pub hosts: Vec<(ItemId, String)>,
}

/// What the form's `Enter` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunRequest {
    /// `SessionInput::PasteUnchecked(text)`.
    Paste {
        /// The pane.
        session: SessionId,
        /// No trailing newline.
        text: String,
        /// For history (secrets as placeholders).
        history: HistoryRecord,
    },
    /// Raw bytes for the pane (`l1\rl2\r`).
    Execute {
        /// The pane.
        session: SessionId,
        /// Every line followed by `\r`.
        bytes: Vec<u8>,
        /// For history (secrets as placeholders).
        history: HistoryRecord,
    },
    /// An exec run on hosts.
    Exec(ExecPlan),
}

/// The variable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarForm {
    /// The snippet.
    pub snippet: ItemId,
    /// Its name.
    pub name: String,
    /// The script.
    pub template: Template,
    /// Its variables (declared, then auto-added).
    pub vars: Vec<VarDef>,
    /// The values being edited (every variable; secrets marked).
    pub values: Values,
    /// The focused field.
    pub focus: usize,
    /// Paste or Paste & execute for panes (Exec for hosts).
    pub mode: RunMode,
    /// Where it runs.
    pub target: RunWhere,
    /// The last submit error.
    pub error: Option<String>,
}

impl VarForm {
    /// The form for `snippet`, run with `mode` at `target`.
    ///
    /// # Errors
    /// The script does not parse (the message names the position).
    pub fn new(
        id: ItemId,
        snippet: &Snippet,
        mode: RunMode,
        target: RunWhere,
    ) -> Result<Self, String> {
        let template = Template::parse(&snippet.script).map_err(|e| e.to_string())?;
        let vars = effective_vars(&template, &snippet.variables);
        let mut values = Values::new();
        for v in &vars {
            values.set(v.name.clone(), v.default.as_deref().unwrap_or(""), v.secret);
        }
        let mode = match &target {
            RunWhere::Hosts(_) => RunMode::Exec,
            RunWhere::Startup(_) => RunMode::PasteAndExecute,
            RunWhere::Pane(_) if mode == RunMode::Exec => RunMode::PasteAndExecute,
            RunWhere::Pane(_) => mode,
        };
        Ok(Self {
            snippet: id,
            name: snippet.name.clone(),
            template,
            vars,
            values,
            focus: 0,
            mode,
            target,
            error: None,
        })
    }

    /// The value of field `i`.
    pub fn value(&self, i: usize) -> &str {
        self.vars
            .get(i)
            .and_then(|v| self.values.get(&v.name))
            .map_or("", |(v, _)| v)
    }

    fn edit(&mut self, f: impl FnOnce(&mut String)) {
        let Some(v) = self.vars.get(self.focus) else {
            return;
        };
        let mut text = self.value(self.focus).to_owned();
        f(&mut text);
        let (name, secret) = (v.name.clone(), v.secret);
        self.values.set(name, &text, secret);
        self.error = None;
    }

    /// Built-ins for the preview (the first host for exec runs: label only until the
    /// runner resolves it).
    fn preview_builtins(&self) -> Builtins {
        match &self.target {
            RunWhere::Pane(p) | RunWhere::Startup(p) => p.builtins.clone(),
            RunWhere::Hosts(h) => Builtins {
                label: h.first().map(|(_, l)| l.clone()).unwrap_or_default(),
                address: "{{host.address}}".into(),
                user: "{{host.user}}".into(),
                date: sverb_conn::ssh::exec::snippets::today(),
            },
        }
    }

    /// The preview text (secrets masked).
    pub fn preview(&self) -> String {
        let values = self.effective_values();
        self.template
            .render(&values, &self.preview_builtins(), RenderStyle::Preview)
            .unwrap_or_default()
    }

    /// The values to run with: an empty field of a variable with a default counts as
    /// its default; one without a default stays empty (and is refused on submit).
    fn effective_values(&self) -> Values {
        let mut values = Values::new();
        for (i, v) in self.vars.iter().enumerate() {
            let text = self.value(i);
            if text.is_empty() {
                if let Some(d) = &v.default {
                    values.set(v.name.clone(), d, v.secret);
                }
            } else {
                values.set(v.name.clone(), text, v.secret);
            }
        }
        values
    }

    /// What `Enter` runs.
    ///
    /// # Errors
    /// A variable without a default is empty; a `|q` value cannot be quoted.
    pub fn submit(&self) -> Result<RunRequest, String> {
        let values = self.effective_values();
        if let Some(v) = self.vars.iter().find(|v| !values.contains(&v.name)) {
            return Err(format!("Enter a value for {}", v.name));
        }
        let pane = match &self.target {
            RunWhere::Hosts(hosts) => {
                return Ok(RunRequest::Exec(ExecPlan {
                    snippet: self.snippet,
                    name: self.name.clone(),
                    template: self.template.clone(),
                    values,
                    hosts: hosts.clone(),
                }));
            }
            RunWhere::Pane(p) | RunWhere::Startup(p) => p,
        };
        let text = self
            .template
            .render(&values, &pane.builtins, RenderStyle::Final)
            .map_err(|e| e.to_string())?;
        let history = HistoryRecord {
            command: history_command(&self.template, &values, &pane.builtins),
            host_id: pane.host_id,
            snippet: Some(self.snippet),
        };
        Ok(match self.mode {
            RunMode::Paste => RunRequest::Paste {
                session: pane.session,
                text: paste_text(&text),
                history,
            },
            RunMode::PasteAndExecute | RunMode::Exec => RunRequest::Execute {
                session: pane.session,
                bytes: paste_execute_bytes(&text),
                history,
            },
        })
    }

    /// Handle a key or paste; `Some` when submitted.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<RunRequest> {
        let n = self.vars.len();
        match ev {
            ViewEvent::Paste(t) => {
                let t = t.replace(['\r', '\n'], "");
                self.edit(|s| s.push_str(&t));
                None
            }
            ViewEvent::Key(k) => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                match k.code {
                    KeyCode::Esc => cx.close(),
                    KeyCode::Enter => match self.submit() {
                        Ok(req) => return Some(req),
                        Err(e) => self.error = Some(e),
                    },
                    KeyCode::Tab | KeyCode::Down if n > 0 => self.focus = (self.focus + 1) % n,
                    KeyCode::BackTab | KeyCode::Up if n > 0 => {
                        self.focus = (self.focus + n - 1) % n;
                    }
                    KeyCode::Backspace => self.edit(|s| {
                        s.pop();
                    }),
                    KeyCode::Char('u') if ctrl => self.edit(String::clear),
                    KeyCode::Char(c) if !ctrl => self.edit(|s| s.push(c)),
                    _ => {}
                }
                None
            }
            ViewEvent::Mouse(_) => None,
        }
    }

    fn target_text(&self) -> String {
        match &self.target {
            RunWhere::Pane(p) => format!("{} into {}", mode_text(self.mode), p.label),
            RunWhere::Startup(p) => format!("startup snippet of {}", p.label),
            RunWhere::Hosts(h) => {
                let names: Vec<&str> = h.iter().take(5).map(|(_, l)| l.as_str()).collect();
                let more = h.len().saturating_sub(names.len());
                let mut s = format!("exec on {} host(s): {}", h.len(), names.join(", "));
                if more > 0 {
                    s.push_str(&format!(" and {more} more"));
                }
                s
            }
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let Some(rect) = centered(area, 90, 28, 30, 8) else {
            return;
        };
        frame.render_widget(Clear, rect);
        let inner_w = usize::from(rect.width.saturating_sub(2));
        let mut lines = vec![
            Line::styled(truncate(&self.target_text(), inner_w), theme.dim),
            Line::raw(""),
        ];
        let label_w = self
            .vars
            .iter()
            .map(|v| v.name.chars().count())
            .max()
            .unwrap_or(0)
            .min(24);
        for (i, v) in self.vars.iter().enumerate() {
            let value = self.value(i);
            let shown = if v.secret {
                "•".repeat(value.chars().count())
            } else {
                value.to_owned()
            };
            let focused = i == self.focus;
            let cursor = if focused { "▏" } else { "" };
            let hint = if value.is_empty() {
                v.default
                    .as_deref()
                    .map(|d| format!(" (default: {d})"))
                    .unwrap_or_default()
            } else {
                String::new()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<label_w$} ", truncate(&v.name, label_w)),
                    if focused { theme.accent } else { theme.dim },
                ),
                Span::styled(format!("{shown}{cursor}"), theme.base),
                Span::styled(hint, theme.dim),
            ]));
        }
        if !self.vars.is_empty() {
            lines.push(Line::raw(""));
        }
        if let Some(e) = &self.error {
            lines.push(Line::styled(e.clone(), theme.error));
            lines.push(Line::raw(""));
        }
        lines.push(Line::styled("Preview", theme.dim));
        for l in self.preview().lines() {
            lines.push(Line::styled(format!("  {l}"), theme.base));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "tab next field · enter run · esc cancel",
            theme.dim,
        ));
        let block = Block::bordered()
            .title(Span::styled(
                format!(
                    " Run \"{}\" ",
                    truncate(&self.name, inner_w.saturating_sub(10))
                ),
                theme.title_for(true),
            ))
            .border_style(theme.border_for(true));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .style(theme.base)
                .block(block),
            rect,
        );
    }
}

// ---------------------------------------------------------------- host picker

/// "Run on hosts…": groups, tags and hosts to mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTargetsPicker {
    /// The snippet.
    pub snippet: ItemId,
    /// Its name.
    pub name: String,
    /// The filter.
    pub filter: String,
    /// Every entry: target and label (groups, tags, then hosts).
    pub entries: Vec<(InstallTarget, String)>,
    /// Shown entries (indices).
    pub visible: Vec<usize>,
    /// Cursor (into `visible`).
    pub cursor: usize,
    /// Marked targets.
    pub marked: BTreeSet<InstallTarget>,
}

impl HostTargetsPicker {
    /// A picker over `catalog`.
    pub fn new(snippet: ItemId, name: String, catalog: &HostCatalog) -> Self {
        let mut groups: Vec<(InstallTarget, String)> = catalog
            .groups
            .iter()
            .filter(|(g, _)| {
                catalog.hosts.values().any(|h| {
                    let mut cur = h.group_id;
                    for _ in 0..64 {
                        match cur {
                            Some(x) if x == **g => return true,
                            Some(x) => {
                                cur = catalog.lookup.groups.get(&x).and_then(|n| n.parent_id);
                            }
                            None => return false,
                        }
                    }
                    false
                })
            })
            .map(|(g, n)| (InstallTarget::Group(*g), format!("▸ {n}")))
            .collect();
        groups.sort_by(|a, b| a.1.cmp(&b.1));
        let mut tags: Vec<(InstallTarget, String)> = catalog
            .tags
            .iter()
            .filter(|(id, _)| catalog.hosts.values().any(|h| h.tags.contains(id)))
            .map(|(id, t)| (InstallTarget::Tag(*id), format!("#{}", t.name)))
            .collect();
        tags.sort_by(|a, b| a.1.cmp(&b.1));
        let mut hosts: Vec<(InstallTarget, String)> = catalog
            .hosts
            .values()
            .map(|h| (InstallTarget::Host(h.id), h.display_label().to_owned()))
            .collect();
        hosts.sort_by_key(|e| e.1.to_lowercase());
        let entries: Vec<(InstallTarget, String)> =
            groups.into_iter().chain(tags).chain(hosts).collect();
        Self {
            snippet,
            name,
            filter: String::new(),
            visible: (0..entries.len()).collect(),
            entries,
            cursor: 0,
            marked: BTreeSet::new(),
        }
    }

    fn refilter(&mut self) {
        let needle = self.filter.trim().to_lowercase();
        self.visible = (0..self.entries.len())
            .filter(|i| needle.is_empty() || self.entries[*i].1.to_lowercase().contains(&needle))
            .collect();
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    fn current(&self) -> Option<InstallTarget> {
        self.visible.get(self.cursor).map(|i| self.entries[*i].0)
    }

    /// Handle a key; `Some` when submitted.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<SnippetAnswer> {
        let ViewEvent::Key(k) = ev else {
            if let ViewEvent::Paste(t) = ev {
                self.filter.push_str(t.trim());
                self.refilter();
            }
            return None;
        };
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let last = self.visible.len().saturating_sub(1);
        match k.code {
            KeyCode::Esc => cx.close(),
            KeyCode::Down => self.cursor = (self.cursor + 1).min(last),
            KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Tab | KeyCode::Char(' ') => {
                if let Some(t) = self.current()
                    && !self.marked.remove(&t)
                {
                    self.marked.insert(t);
                }
                if k.code == KeyCode::Tab {
                    self.cursor = (self.cursor + 1).min(last);
                }
            }
            KeyCode::Enter => {
                let mut targets: Vec<InstallTarget> = self.marked.iter().copied().collect();
                if targets.is_empty() {
                    targets.extend(self.current());
                }
                if !targets.is_empty() {
                    return Some(SnippetAnswer::Hosts {
                        id: self.snippet,
                        targets,
                    });
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.refilter();
            }
            KeyCode::Char('u') if ctrl => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Char(c) if !ctrl => {
                self.filter.push(c);
                self.refilter();
            }
            _ => {}
        }
        None
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let Some(rect) = centered(area, 80, 24, 20, 8) else {
            return;
        };
        frame.render_widget(Clear, rect);
        let inner_w = usize::from(rect.width.saturating_sub(2));
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Filter ", theme.dim),
                Span::styled(format!("{}▏", self.filter), theme.base),
            ]),
            Line::raw(""),
        ];
        let room = usize::from(rect.height).saturating_sub(6);
        let skip = self.cursor.saturating_sub(room.saturating_sub(1));
        if self.visible.is_empty() {
            lines.push(Line::styled("no hosts, groups or tags match", theme.dim));
        }
        for (row, i) in self.visible.iter().enumerate().skip(skip).take(room) {
            let (t, label) = &self.entries[*i];
            let mark = if self.marked.contains(t) {
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
                format!("{mark}{}", truncate(label, inner_w.saturating_sub(4))),
                style,
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "{} selected · space/tab mark · enter continue · esc cancel",
                self.marked.len()
            ),
            theme.dim,
        ));
        let block = Block::bordered()
            .title(Span::styled(
                format!(
                    " Run \"{}\" on… ",
                    truncate(&self.name, inner_w.saturating_sub(12))
                ),
                theme.title_for(true),
            ))
            .border_style(theme.border_for(true));
        frame.render_widget(Paragraph::new(lines).style(theme.base).block(block), rect);
    }
}
