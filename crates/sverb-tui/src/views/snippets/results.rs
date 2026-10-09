//! The results of an exec run on hosts (SPEC §9.7).
//!
//! The shared [`ResultsTable`]: per host the status (`queued`, `running`, `ok`,
//! `exit N`, `timeout`, `error: …`), the duration and an expandable detail (stderr,
//! then stdout) with a "truncated" badge. Keys: the table's (`↑↓`, `Enter` expand), `r`
//! re-runs the failed hosts, `x` exports, `esc` closes (cancelling what still runs).
//!
//! Export (`x`): `j` JSON or `m` Markdown, then `c` clipboard or `f` a file (a path
//! prompt). The texts are `sverb_core::snippet::results::{to_json_string, to_markdown}`.

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::{
    model::ItemId,
    snippet::{HostRunResult, RunStatus, results},
};

use super::{SnippetAnswer, centered};
use crate::app::SessionId;
use crate::views::{RenderCx, ViewCx, ViewEvent};
use crate::widgets::results_table::{ResultsTable, RowState};

/// The footer.
pub const RESULTS_HINT: &str = "↑↓ select · enter details · r re-run failed · x export · esc close";

/// The export steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportStep {
    /// `j` JSON or `m` Markdown?
    Format,
    /// `c` clipboard or `f` file?
    Dest {
        /// JSON (else Markdown).
        json: bool,
    },
    /// The file path.
    Path {
        /// JSON (else Markdown).
        json: bool,
        /// The path typed so far.
        path: String,
    },
}

/// The results dialog of one exec run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetResults {
    /// The current run (events of other runs are ignored).
    pub run: u64,
    /// The snippet.
    pub snippet: ItemId,
    /// Target hosts and labels (row order).
    pub hosts: Vec<(ItemId, String)>,
    /// The session id each row's connection uses for prompts (this run).
    pub sessions: Vec<Option<SessionId>>,
    /// Finished results by row.
    pub results: Vec<Option<HostRunResult>>,
    /// The table.
    pub table: ResultsTable,
    /// An export in progress.
    pub export: Option<ExportStep>,
    /// What runs (kept for `r`, re-running the failed hosts).
    pub plan: Option<Box<super::ExecPlan>>,
}

/// The row state for a result.
pub fn row_state(r: &HostRunResult) -> RowState {
    match r.status() {
        RunStatus::Ok => RowState::Ok("ok".to_owned()),
        other => RowState::Failed(other.to_string()),
    }
}

/// The expandable detail: stderr, then stdout.
pub fn detail(r: &HostRunResult) -> String {
    let mut out = String::new();
    for (label, bytes) in [("stderr", &r.stderr), ("stdout", &r.stdout)] {
        if bytes.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("{label}:\n"));
        out.push_str(String::from_utf8_lossy(bytes).trim_end_matches('\n'));
    }
    out
}

impl SnippetResults {
    /// A table with a queued row per host.
    pub fn new(
        run: u64,
        snippet: ItemId,
        title: String,
        hosts: Vec<(ItemId, String)>,
        sessions: Vec<Option<SessionId>>,
    ) -> Self {
        Self {
            run,
            snippet,
            table: ResultsTable::new(title, hosts.iter().map(|(_, l)| l.clone())),
            results: vec![None; hosts.len()],
            hosts,
            sessions,
            export: None,
            plan: None,
        }
    }

    /// Something is still queued or running.
    pub fn running(&self) -> bool {
        !self.table.finished()
    }

    /// The row whose connection uses `session`.
    pub fn row_of(&self, session: SessionId) -> Option<usize> {
        self.sessions.iter().position(|s| *s == Some(session))
    }

    /// A host got a slot.
    pub fn started(&mut self, index: usize) {
        if let Some(row) = self.table.rows.get_mut(index) {
            row.state = RowState::Running("running".to_owned());
        }
    }

    /// A host finished.
    pub fn finished(&mut self, index: usize, r: HostRunResult) {
        if let Some(row) = self.table.rows.get_mut(index) {
            row.state = row_state(&r);
            row.duration = Some(r.duration);
            row.detail = detail(&r);
            row.truncated = r.truncated;
        }
        if let Some(slot) = self.results.get_mut(index) {
            *slot = Some(r);
        }
    }

    /// Rows to re-run (failed), reset to queued.
    pub fn reset_failed(&mut self) -> Vec<usize> {
        let failed = self.table.failed();
        for i in &failed {
            self.table.rows[*i].reset();
            self.results[*i] = None;
            self.sessions[*i] = None;
        }
        failed
    }

    /// Finished results, in row order.
    pub fn done(&self) -> Vec<HostRunResult> {
        self.results.iter().flatten().cloned().collect()
    }

    /// The export text.
    pub fn export_text(&self, json: bool) -> String {
        let done = self.done();
        if json {
            results::to_json_string(&done)
        } else {
            results::to_markdown(&self.table.title, &done)
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

    /// Typing a path.
    pub fn wants_text(&self) -> bool {
        matches!(self.export, Some(ExportStep::Path { .. }))
    }

    fn on_export_key(&mut self, code: KeyCode, ctrl: bool) -> Option<SnippetAnswer> {
        let step = self.export.take()?;
        match (step, code) {
            (_, KeyCode::Esc) => None,
            (ExportStep::Format, KeyCode::Char('j')) => {
                self.export = Some(ExportStep::Dest { json: true });
                None
            }
            (ExportStep::Format, KeyCode::Char('m')) => {
                self.export = Some(ExportStep::Dest { json: false });
                None
            }
            (ExportStep::Dest { json }, KeyCode::Char('c')) => Some(SnippetAnswer::Export {
                json,
                path: None,
                text: self.export_text(json),
            }),
            (ExportStep::Dest { json }, KeyCode::Char('f')) => {
                let ext = if json { "json" } else { "md" };
                self.export = Some(ExportStep::Path {
                    json,
                    path: format!("snippet-results.{ext}"),
                });
                None
            }
            (ExportStep::Path { json, path }, KeyCode::Enter) if !path.trim().is_empty() => {
                Some(SnippetAnswer::Export {
                    json,
                    path: Some(path.trim().to_owned()),
                    text: self.export_text(json),
                })
            }
            (ExportStep::Path { json, mut path }, KeyCode::Backspace) => {
                path.pop();
                self.export = Some(ExportStep::Path { json, path });
                None
            }
            (ExportStep::Path { json, .. }, KeyCode::Char('u')) if ctrl => {
                self.export = Some(ExportStep::Path {
                    json,
                    path: String::new(),
                });
                None
            }
            (ExportStep::Path { json, mut path }, KeyCode::Char(c)) if !ctrl => {
                path.push(c);
                self.export = Some(ExportStep::Path { json, path });
                None
            }
            (step, _) => {
                self.export = Some(step);
                None
            }
        }
    }

    /// Handle an event.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<SnippetAnswer> {
        if let (ViewEvent::Paste(t), Some(ExportStep::Path { path, .. })) = (ev, &mut self.export) {
            path.push_str(t.trim());
            return None;
        }
        let ViewEvent::Key(k) = ev else {
            return None;
        };
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if self.export.is_some() {
            return self.on_export_key(k.code, ctrl);
        }
        if self.table.handle_key(k) {
            return None;
        }
        match k.code {
            KeyCode::Char('r') if !self.running() && !self.table.failed().is_empty() => {
                Some(SnippetAnswer::Rerun)
            }
            KeyCode::Char('x') if !self.done().is_empty() => {
                self.export = Some(ExportStep::Format);
                None
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                if self.running() {
                    return Some(SnippetAnswer::Cancel(self.run));
                }
                cx.close();
                None
            }
            _ => None,
        }
    }

    /// Draw (the table, and the export prompt over it).
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        self.table.render(frame, area, theme, RESULTS_HINT);
        let Some(step) = &self.export else {
            return;
        };
        let Some(rect) = centered(area, 60, 7, 24, 5) else {
            return;
        };
        frame.render_widget(Clear, rect);
        let lines = match step {
            ExportStep::Format => vec![Line::raw("j JSON · m Markdown · esc cancel")],
            ExportStep::Dest { .. } => vec![Line::raw("c clipboard · f file · esc cancel")],
            ExportStep::Path { path, .. } => vec![
                Line::from(vec![
                    Span::styled("Path ", theme.dim),
                    Span::styled(format!("{path}▏"), theme.base),
                ]),
                Line::raw(""),
                Line::styled("enter save · esc cancel", theme.dim),
            ],
        };
        let block = Block::bordered()
            .title(Span::styled(" Export results ", theme.title_for(true)))
            .border_style(theme.border_for(true));
        frame.render_widget(Paragraph::new(lines).style(theme.base).block(block), rect);
    }
}
