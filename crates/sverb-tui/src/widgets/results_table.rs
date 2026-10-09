//! The per-host results table of exec runs (install key on host, SPEC §9.4;
//!
//! Plain state ([`ResultsTable`]): one [`ResultRow`] per target with its state, the
//! duration, an expandable detail (stderr / stdout) and a "truncated" badge. Keys:
//! `j`/`k`/arrows move, `g`/`G` jump, `Enter`/`space` expand or collapse the selected
//! row's detail. The owner handles everything else (`r` re-runs failed rows, `esc`).

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use super::{truncate, width};
use crate::theme::Theme;

/// Where a target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowState {
    /// Waiting for a slot.
    Queued,
    /// In progress (the phase: `connecting`, `checking shell`, …).
    Running(String),
    /// Done, fine (`installed`, `ok`).
    Ok(String),
    /// Done, fine but notable (`already present`).
    Notice(String),
    /// Failed (`error: …`, `exit 3`, `timeout`, `unsupported: …`).
    Failed(String),
}

impl RowState {
    /// Still queued or running.
    pub fn pending(&self) -> bool {
        matches!(self, Self::Queued | Self::Running(_))
    }

    /// Failed.
    pub fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// The status text.
    pub fn text(&self) -> &str {
        match self {
            Self::Queued => "queued",
            Self::Running(s) | Self::Ok(s) | Self::Notice(s) | Self::Failed(s) => s,
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            Self::Queued => "·",
            Self::Running(_) => "…",
            Self::Ok(_) | Self::Notice(_) => "✓",
            Self::Failed(_) => "✗",
        }
    }

    fn style(&self, theme: &Theme) -> Style {
        match self {
            Self::Queued => theme.dim,
            Self::Running(_) => theme.info,
            Self::Ok(_) => theme.ok,
            Self::Notice(_) => theme.accent,
            Self::Failed(_) => theme.error,
        }
    }
}

/// One target's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRow {
    /// The target (host label).
    pub label: String,
    /// Its state.
    pub state: RowState,
    /// How long it took (set when done).
    pub duration: Option<Duration>,
    /// The expandable detail (stderr, else stdout); may be empty.
    pub detail: String,
    /// Output was cut at the cap.
    pub truncated: bool,
}

impl ResultRow {
    /// A queued row.
    pub fn queued(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            state: RowState::Queued,
            duration: None,
            detail: String::new(),
            truncated: false,
        }
    }

    /// Back to queued (a re-run).
    pub fn reset(&mut self) {
        self.state = RowState::Queued;
        self.duration = None;
        self.detail.clear();
        self.truncated = false;
    }
}

/// The table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultsTable {
    /// The title.
    pub title: String,
    /// The rows, in target order.
    pub rows: Vec<ResultRow>,
    /// The selected row.
    pub selected: usize,
    /// The expanded row, if any.
    pub expanded: Option<usize>,
}

/// `1.2s` / `850ms`.
pub fn format_duration(d: Duration) -> String {
    if d < Duration::from_secs(1) {
        format!("{}ms", d.as_millis())
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

impl ResultsTable {
    /// A table titled `title` with a queued row per label.
    pub fn new(title: impl Into<String>, labels: impl IntoIterator<Item = String>) -> Self {
        Self {
            title: title.into(),
            rows: labels.into_iter().map(ResultRow::queued).collect(),
            selected: 0,
            expanded: None,
        }
    }

    /// Indices of failed rows.
    pub fn failed(&self) -> Vec<usize> {
        (0..self.rows.len())
            .filter(|i| self.rows[*i].state.failed())
            .collect()
    }

    /// Every row is done.
    pub fn finished(&self) -> bool {
        self.rows.iter().all(|r| !r.state.pending())
    }

    /// `2 ok · 1 failed · 3 running`.
    pub fn summary(&self) -> String {
        let ok = self
            .rows
            .iter()
            .filter(|r| matches!(r.state, RowState::Ok(_) | RowState::Notice(_)))
            .count();
        let failed = self.rows.iter().filter(|r| r.state.failed()).count();
        let pending = self.rows.iter().filter(|r| r.state.pending()).count();
        let mut parts = vec![format!("{ok} ok")];
        if failed > 0 {
            parts.push(format!("{failed} failed"));
        }
        if pending > 0 {
            parts.push(format!("{pending} running"));
        }
        parts.join(" · ")
    }

    /// Navigation and expand/collapse. Returns whether the key was used.
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return false;
        }
        let last = self.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => self.selected = last,
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.expanded = if self.expanded == Some(self.selected) {
                    None
                } else {
                    Some(self.selected)
                };
            }
            _ => return false,
        }
        true
    }

    /// The lines of the table body (for rendering and snapshot-free tests).
    pub fn lines(&self, inner_w: usize, theme: &Theme) -> Vec<Line<'static>> {
        let label_w = self
            .rows
            .iter()
            .map(|r| width(&r.label))
            .max()
            .unwrap_or(0)
            .clamp(4, 28);
        let mut lines = Vec::new();
        for (i, row) in self.rows.iter().enumerate() {
            let sel = i == self.selected;
            let marker = if sel { "▸ " } else { "  " };
            let label = truncate(&row.label, label_w);
            let pad = " ".repeat(label_w.saturating_sub(width(&label)) + 2);
            let dur = row.duration.map(format_duration).unwrap_or_default();
            let used = 2 + 2 + label_w + 2 + width(&dur) + 2;
            let status = truncate(row.state.text(), inner_w.saturating_sub(used).max(4));
            let base = if sel { theme.selection } else { theme.base };
            let mut spans = vec![
                Span::styled(marker.to_owned(), base),
                Span::styled(format!("{} ", row.state.icon()), row.state.style(theme)),
                Span::styled(format!("{label}{pad}"), base),
                Span::styled(status, row.state.style(theme)),
            ];
            if !dur.is_empty() {
                spans.push(Span::styled(format!("  {dur}"), theme.dim));
            }
            if row.truncated {
                spans.push(Span::styled(" [truncated]".to_owned(), theme.warn));
            }
            lines.push(Line::from(spans));
            if self.expanded == Some(i) {
                let detail = if row.detail.trim().is_empty() {
                    "(no output)".to_owned()
                } else {
                    row.detail.clone()
                };
                let all: Vec<&str> = detail.lines().collect();
                for l in all.iter().take(12) {
                    lines.push(Line::styled(
                        format!("      {}", truncate(l, inner_w.saturating_sub(6))),
                        theme.dim,
                    ));
                }
                if all.len() > 12 {
                    lines.push(Line::styled(
                        format!("      … {} more lines", all.len() - 12),
                        theme.dim,
                    ));
                }
            }
        }
        lines
    }

    /// Draw as a centered modal with `hint` (the owner's keys) at the bottom.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme, hint: &str) {
        let w = area.width.saturating_sub(4).min(110);
        if w < 20 || area.height < 6 {
            return;
        }
        let inner_w = usize::from(w.saturating_sub(2));
        let mut lines = vec![Line::styled(self.summary(), theme.accent), Line::raw("")];
        let body = self.lines(inner_w, theme);
        // Keep the selected row visible.
        let room = usize::from(area.height.saturating_sub(4)).saturating_sub(4);
        let skip = self.selected.saturating_sub(room.saturating_sub(1));
        lines.extend(body.into_iter().skip(skip).take(room));
        lines.push(Line::raw(""));
        lines.push(Line::styled(hint.to_owned(), theme.dim));
        let h = u16::try_from(lines.len() + 2)
            .unwrap_or(u16::MAX)
            .min(area.height);
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(
                format!(" {} ", truncate(&self.title, inner_w.saturating_sub(2))),
                theme.title_for(true),
            ))
            .border_style(theme.border_for(true));
        frame.render_widget(Paragraph::new(lines).style(theme.base).block(block), rect);
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyEvent;

    use super::*;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn navigation_expand_and_summary() {
        let mut t = ResultsTable::new("Install", ["a".to_owned(), "b".to_owned()]);
        assert!(!t.finished());
        t.rows[0].state = RowState::Ok("installed".into());
        t.rows[1].state = RowState::Failed("error: nope".into());
        t.rows[1].detail = "line1\nline2".into();
        assert!(t.finished());
        assert_eq!(t.failed(), vec![1]);
        assert_eq!(t.summary(), "1 ok · 1 failed");
        assert!(t.handle_key(&key(KeyCode::Char('j'))));
        assert!(t.handle_key(&key(KeyCode::Enter)));
        assert_eq!(t.expanded, Some(1));
        let theme = Theme::default();
        let text: Vec<String> = t
            .lines(80, &theme)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(text[1].contains("error: nope"), "{text:?}");
        assert!(text[2].contains("line1") && text[3].contains("line2"));
        assert!(!t.handle_key(&key(KeyCode::Char('r'))));
        assert_eq!(format_duration(Duration::from_millis(1234)), "1.2s");
    }
}
