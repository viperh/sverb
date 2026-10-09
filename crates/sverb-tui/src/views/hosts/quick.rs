//! The quick-connect dialog (`leader o`, SPEC §9.1) and the "Save as host?"
//! offer after an ephemeral connection succeeds.
//!
//! The dialog is an input with a fuzzy list of saved hosts under it. The first row
//! is the typed target (`Connect to deploy@10.0.0.5:2222`) when it parses with
//! [`quick_connect::parse`], else the inline parse error; the saved hosts matching
//! the text follow. `↓`/`↑` (`ctrl-n`/`ctrl-p`, `Tab`) move, `Enter` connects to the
//! highlighted row, `Esc` cancels. The reducer reads the answer with
//! [`QuickConnect::take_answer`].

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::{
    model::ItemId,
    quick_connect::{self, QuickTarget},
    search::{IndexSnapshot, Query, Scope},
};

use crate::{
    views::{RenderCx, dialogs::centered},
    widgets::{
        form::{TextEdit, TextInput, highlighted, match_style},
        truncate,
    },
};

/// Saved hosts listed at most.
pub const QUICK_LIMIT: usize = 8;

/// What the user picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickPick {
    /// A saved host.
    Host(ItemId),
    /// A typed, unsaved target.
    Target(QuickTarget),
}

/// One listed saved host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickMatch {
    /// The host.
    pub id: ItemId,
    /// Its label.
    pub label: String,
    /// `user@address`.
    pub target: String,
    /// Matched char indices into `label`.
    pub highlights: Vec<u32>,
}

/// State of the quick-connect dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickConnect {
    /// The input.
    pub input: TextInput,
    index: Option<Arc<IndexSnapshot>>,
    /// The parsed input (`Err`: the inline error; empty input is `Ok(None)`).
    parsed: Result<Option<QuickTarget>, String>,
    /// Matching saved hosts.
    pub matches: Vec<QuickMatch>,
    /// Highlighted row: 0 is the typed target when it parses.
    pub selected: usize,
    answer: Option<QuickPick>,
}

impl QuickConnect {
    /// A dialog over the hosts of `index`.
    pub fn new(index: Option<Arc<IndexSnapshot>>) -> Self {
        let mut q = Self {
            input: TextInput::default(),
            index,
            parsed: Ok(None),
            matches: Vec::new(),
            selected: 0,
            answer: None,
        };
        q.refresh();
        q
    }

    /// The answer, once `Enter` picked something.
    pub fn take_answer(&mut self) -> Option<QuickPick> {
        self.answer.take()
    }

    /// The answer, without taking it.
    pub fn answer_pending(&self) -> Option<&QuickPick> {
        self.answer.as_ref()
    }

    /// The inline error for the typed text.
    pub fn error(&self) -> Option<&str> {
        self.parsed.as_ref().err().map(String::as_str)
    }

    fn target_row(&self) -> Option<&QuickTarget> {
        self.parsed.as_ref().ok().and_then(Option::as_ref)
    }

    fn rows(&self) -> usize {
        usize::from(self.target_row().is_some()) + self.matches.len()
    }

    fn refresh(&mut self) {
        let text = self.input.text().trim().to_owned();
        self.parsed = if text.is_empty() {
            Ok(None)
        } else {
            quick_connect::parse(&text).map(Some).map_err(|e| e.0)
        };
        self.matches = match &self.index {
            Some(index) => index
                .query(&Query::parse(&text), Scope::Hosts)
                .into_iter()
                .take(QUICK_LIMIT)
                .filter_map(|hit| {
                    let e = index.get(hit.item_id)?;
                    let target = if e.user.is_empty() {
                        e.address.to_string()
                    } else {
                        format!("{}@{}", e.user.as_str(), e.address.as_str())
                    };
                    Some(QuickMatch {
                        id: e.item_id,
                        label: e.display_label().to_owned(),
                        target,
                        highlights: hit.highlights,
                    })
                })
                .collect(),
            None => Vec::new(),
        };
        self.selected = 0;
    }

    /// Apply a paste.
    pub fn paste(&mut self, text: &str) {
        let line: String = text.lines().next().unwrap_or_default().to_owned();
        if self.input.insert_str(&line) {
            self.refresh();
        }
    }

    /// Apply one key. Returns `true` when the dialog should close (`Esc`, or `Enter`
    /// with an answer).
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let last = self.rows().saturating_sub(1);
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1).min(last),
            KeyCode::Char('n') if ctrl => self.selected = (self.selected + 1).min(last),
            KeyCode::Up | KeyCode::BackTab => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('p') if ctrl => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter => {
                let offset = usize::from(self.target_row().is_some());
                self.answer = if self.selected < offset {
                    self.target_row().cloned().map(QuickPick::Target)
                } else {
                    self.matches
                        .get(self.selected - offset)
                        .map(|m| QuickPick::Host(m.id))
                };
                return self.answer.is_some();
            }
            _ => {
                if self.input.handle_key(key) == TextEdit::Changed {
                    self.refresh();
                }
            }
        }
        false
    }

    /// Draw the dialog.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let width = usize::from(area.width.saturating_sub(4)).clamp(20, 70);
        let height = 4 + self.rows().max(1);
        let rect = centered(area, width, height);
        if rect.width < 6 || rect.height < 3 {
            return;
        }
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(" Quick connect ", theme.title_for(cx.focused)))
            .title_bottom(Span::styled(
                " enter connect · ↑↓ hosts · esc cancel ",
                theme.dim,
            ))
            .border_style(theme.border_for(cx.focused));
        let inner = block.inner(rect);
        frame.render_widget(block.style(theme.base), rect);
        let iw = usize::from(inner.width);
        let mut lines = Vec::new();
        let mut input = vec![Span::styled("› ", theme.accent)];
        input.extend(
            self.input
                .line(iw.saturating_sub(2), theme.base, cx.focused)
                .spans,
        );
        lines.push(Line::from(input));
        match &self.parsed {
            Err(e) => lines.push(Line::styled(truncate(&format!("! {e}"), iw), theme.error)),
            Ok(None) => lines.push(Line::styled(
                truncate("user@host:port, ssh://… or a saved host", iw),
                theme.dim,
            )),
            Ok(Some(_)) => lines.push(Line::raw("")),
        }
        let mut row = 0;
        let line_for = |selected: bool, spans: Vec<Span<'static>>| -> Line<'static> {
            let mut all = vec![Span::styled(
                if selected { "› " } else { "  " },
                if selected {
                    theme.selection
                } else {
                    theme.base
                },
            )];
            all.extend(spans);
            let used: usize = all.iter().map(Span::width).sum();
            if selected && used < iw {
                all.push(Span::styled(" ".repeat(iw - used), theme.selection));
            }
            Line::from(all)
        };
        if let Some(t) = self.target_row() {
            let selected = self.selected == row;
            let base = if selected {
                theme.selection
            } else {
                theme.base
            };
            lines.push(line_for(
                selected,
                vec![Span::styled(
                    truncate(&format!("Connect to {}", t.display()), iw.saturating_sub(2)),
                    base,
                )],
            ));
            row += 1;
        }
        for m in &self.matches {
            let selected = self.selected == row;
            let base = if selected {
                theme.selection
            } else {
                theme.base
            };
            let label = truncate(&m.label, iw.saturating_sub(4));
            let mut spans = highlighted(&label, &m.highlights, base, match_style(base, theme));
            let used = crate::widgets::width(&label) + 2;
            if used + 4 < iw {
                let dim = if selected { base } else { theme.dim };
                spans.push(Span::styled(
                    format!("  {}", truncate(&m.target, iw - used - 2)),
                    dim,
                ));
            }
            lines.push(line_for(selected, spans));
            row += 1;
        }
        if self.rows() == 0 && self.index.is_some() && !self.input.is_empty() {
            lines.push(Line::styled("  No saved host matches", theme.dim));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

/// "Save as host?" after an unsaved target connected (`s` saves, `Esc` dismisses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveHostOffer {
    /// The target that connected.
    pub target: QuickTarget,
}

impl SaveHostOffer {
    /// Draw the offer (a small box at the bottom right, like a toast).
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let text = format!("Connected to {}", self.target.display());
        let hint = "Save as host? [s]ave · esc dismiss";
        let w = text.chars().count().max(hint.chars().count()) + 4;
        let w = u16::try_from(w).unwrap_or(u16::MAX).min(area.width);
        let h = 4u16.min(area.height);
        if w < 6 || h < 3 {
            return;
        }
        let rect = Rect::new(
            area.right().saturating_sub(w + 1).max(area.x),
            area.bottom().saturating_sub(h + 1).max(area.y),
            w,
            h,
        );
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(" Quick connect ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(text, theme.ok),
                Line::styled(hint, theme.base),
            ])
            .style(theme.toast)
            .block(block),
            rect,
        );
    }
}
