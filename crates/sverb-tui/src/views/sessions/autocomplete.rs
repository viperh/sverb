//! The autocomplete / history overlay (`leader Space`, SPEC §9.10).
//!
//! A small list anchored at the focused pane's cursor (below it, or above when there is
//! no room). Typing filters (fuzzy) over per-host and global history, snippets and the
//! common commands; with shell integration the rows are pre-filtered by the command line
//! typed so far ([`Autocomplete::prefix`]). Each row shows its source (`H` history, `G`
//! global, `S` snippet, `C` common), `?` for an unverified (heuristic) entry and the
//! last exit code (red when not 0).
//!
//! Keys: `Enter` types the remainder and runs it (`\r`), `Tab` types the remainder only,
//! `↑`/`↓` (`ctrl-p`/`ctrl-n`) move, `Backspace` / `ctrl-u` edit the filter, `Esc`
//! closes. A snippet row starts the snippet's run flow (its variable form) instead.
//! Without shell integration `F2` offers to install it. The reducer
//! (`app/history.rs`) takes [`Autocomplete::answer`] after each key.

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use sverb_core::{
    history::{SnippetSource, Source, SuggestRequest, Suggestion, remainder, suggest},
    model::{HistoryEntry, ItemId},
};

use crate::{app::SessionId, theme::Theme};

/// Rows shown at once.
pub const VISIBLE_ROWS: usize = 10;
/// Suggestions computed per filter change.
pub const MAX_ROWS: usize = 200;
const MIN_WIDTH: u16 = 36;
const MAX_WIDTH: u16 = 80;

/// What the overlay asks the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutocompleteAnswer {
    /// Type `text` into the pane; `execute` also sends `\r`.
    Type {
        /// The remainder (what is not on the command line yet).
        text: String,
        /// `Enter` (true) or `Tab` (false).
        execute: bool,
    },
    /// Run a snippet through its normal flow.
    Snippet(ItemId),
    /// Add / run the "Install sverb shell integration" snippet.
    InstallIntegration,
    /// Closed without a choice.
    Cancel,
}

/// The overlay's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autocomplete {
    /// The pane.
    pub session: SessionId,
    /// The pane's host (`None`: local or unsaved).
    pub host: Option<ItemId>,
    /// The screen cell of the pane's cursor.
    pub anchor: (u16, u16),
    /// The command line typed so far (tier 1), else empty.
    pub prefix: String,
    /// Shell integration is active in the pane.
    pub integrated: bool,
    /// The filter.
    pub query: String,
    /// The highlighted row.
    pub selected: usize,
    /// The current rows.
    pub rows: Vec<Suggestion>,
    history: Arc<Vec<HistoryEntry>>,
    snippets: Arc<Vec<SnippetSource>>,
    commons: &'static [&'static str],
    /// Set by a key; taken by the reducer.
    pub answer: Option<AutocompleteAnswer>,
}

impl Autocomplete {
    /// An overlay over `history`, `snippets` and `commons`, filtered by `prefix`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: SessionId,
        host: Option<ItemId>,
        anchor: (u16, u16),
        prefix: String,
        integrated: bool,
        history: Arc<Vec<HistoryEntry>>,
        snippets: Arc<Vec<SnippetSource>>,
        commons: &'static [&'static str],
    ) -> Self {
        let mut me = Self {
            session,
            host,
            anchor,
            prefix,
            integrated,
            query: String::new(),
            selected: 0,
            rows: Vec::new(),
            history,
            snippets,
            commons,
            answer: None,
        };
        me.refilter();
        me
    }

    fn refilter(&mut self) {
        let req = SuggestRequest {
            host: self.host,
            prefix: &self.prefix,
            query: &self.query,
            limit: MAX_ROWS,
        };
        self.rows = suggest(&req, &self.history, &self.snippets, self.commons);
        self.selected = 0;
    }

    /// The highlighted suggestion.
    pub fn current(&self) -> Option<&Suggestion> {
        self.rows.get(self.selected)
    }

    fn choose(&mut self, execute: bool) {
        let Some(row) = self.current() else {
            return;
        };
        self.answer = Some(match row.snippet {
            Some(id) => AutocompleteAnswer::Snippet(id),
            None => AutocompleteAnswer::Type {
                text: remainder(&row.text, &self.prefix).to_owned(),
                execute,
            },
        });
    }

    /// Handle a key. Every key is consumed (the overlay is modal).
    pub fn handle_key(&mut self, key: &KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => self.answer = Some(AutocompleteAnswer::Cancel),
            KeyCode::Char('c' | 'g') if ctrl => self.answer = Some(AutocompleteAnswer::Cancel),
            KeyCode::Enter => self.choose(true),
            KeyCode::Tab => self.choose(false),
            KeyCode::Up => self.move_by(-1),
            KeyCode::Char('p') if ctrl => self.move_by(-1),
            KeyCode::Down => self.move_by(1),
            KeyCode::Char('n') if ctrl => self.move_by(1),
            KeyCode::PageUp => self.move_by(-(VISIBLE_ROWS as isize)),
            KeyCode::PageDown => self.move_by(VISIBLE_ROWS as isize),
            KeyCode::F(2) if !self.integrated => {
                self.answer = Some(AutocompleteAnswer::InstallIntegration);
            }
            KeyCode::Backspace => {
                if self.query.pop().is_some() {
                    self.refilter();
                }
            }
            KeyCode::Char('u') if ctrl => {
                self.query.clear();
                self.refilter();
            }
            KeyCode::Char(c) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.query.push(c);
                self.refilter();
            }
            _ => {}
        }
    }

    /// A paste goes into the filter (first line only).
    pub fn paste(&mut self, text: &str) {
        let line = text.lines().next().unwrap_or_default();
        self.query.extend(line.chars().filter(|c| !c.is_control()));
        self.refilter();
    }

    fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }

    /// Where the overlay goes in `area`: below the anchor row when it fits, else above.
    pub fn placement(&self, area: Rect) -> Rect {
        let rows = self.rows.len().clamp(1, VISIBLE_ROWS);
        // Borders, the filter line, the rows.
        let want_h = u16::try_from(rows + 3).unwrap_or(u16::MAX);
        let longest = self
            .rows
            .iter()
            .map(|r| r.text.chars().count() + r.name.as_ref().map_or(0, |n| n.chars().count() + 3))
            .max()
            .unwrap_or(0);
        let want_w = u16::try_from(longest + 14)
            .unwrap_or(u16::MAX)
            .clamp(MIN_WIDTH, MAX_WIDTH);
        let width = want_w.min(area.width);
        let (ax, ay) = self.anchor;
        let below = ay.saturating_add(1);
        let room_below = area.bottom().saturating_sub(below);
        let room_above = ay.saturating_sub(area.y);
        let (y, height) = if room_below >= want_h || room_below >= room_above {
            (below, want_h.min(room_below))
        } else {
            let h = want_h.min(room_above);
            (ay - h, h)
        };
        let x = ax.clamp(area.x, area.right().saturating_sub(width).max(area.x));
        Rect::new(x, y, width, height).intersection(area)
    }

    /// Draw the overlay. Never panics, whatever the area.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
        let rect = self.placement(area);
        if rect.width < 4 || rect.height < 3 {
            return;
        }
        let footer = if self.integrated {
            " ⏎ run · ⇥ insert · esc "
        } else {
            " ⏎ run · ⇥ insert · F2 shell integration "
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border_focused)
            .title(Span::styled(" History ", theme.title_focused))
            .title_bottom(Span::styled(footer, theme.dim));
        let inner = block.inner(rect);
        frame.render_widget(Clear, rect);
        frame.render_widget(block, rect);
        let mut lines = Vec::with_capacity(VISIBLE_ROWS + 1);
        let mut filter = vec![
            Span::styled("› ", theme.accent),
            Span::raw(self.query.clone()),
        ];
        if !self.prefix.is_empty() {
            filter.push(Span::styled(format!("  ({}…)", self.prefix), theme.dim));
        }
        lines.push(Line::from(filter));
        let visible = usize::from(inner.height.saturating_sub(1));
        let start = self.selected.saturating_sub(visible.saturating_sub(1));
        if self.rows.is_empty() {
            lines.push(Line::styled("  no suggestions", theme.dim));
        }
        for (i, row) in self.rows.iter().enumerate().skip(start).take(visible) {
            lines.push(row_line(row, i == self.selected, theme));
        }
        frame.render_widget(Paragraph::new(lines).style(theme.base), inner);
    }
}

fn row_line<'a>(row: &'a Suggestion, selected: bool, theme: &Theme) -> Line<'a> {
    let icon_style = match row.source {
        Source::Host | Source::Global => theme.accent,
        Source::Snippet => theme.info,
        Source::Common => theme.dim,
    };
    let mut spans = vec![
        Span::styled(format!("{} ", row.source.icon()), icon_style),
        Span::raw(row.text.as_str()),
    ];
    if let Some(name) = &row.name {
        spans.push(Span::styled(format!("  {name}"), theme.dim));
    }
    if row.unverified {
        spans.push(Span::styled(" ?", theme.warn));
    }
    if let Some(code) = row.exit_code {
        let style = if code == 0 { theme.dim } else { theme.error };
        spans.push(Span::styled(format!(" [{code}]"), style));
    }
    let line = Line::from(spans);
    if selected {
        line.style(theme.selection.add_modifier(Modifier::BOLD))
    } else {
        line.style(Style::default())
    }
}
