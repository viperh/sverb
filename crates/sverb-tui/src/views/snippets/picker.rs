//! M2-09: the snippet picker (`leader e`, SPEC §9.7, §8.3).
//!
//! A fuzzy list (name, description, tags and script; `nucleo`) with a preview of the
//! selected script (variables highlighted). Typing filters; `↑`/`↓` (`ctrl-p`/`ctrl-n`)
//! move; `Enter` answers [`SnippetAnswer::Picked`]; `Esc` closes. The reducer then runs
//! the snippet in the pane that was focused when the picker opened, with the snippet's
//! run mode (Exec opens the host picker).

use crossterm::event::{KeyCode, KeyModifiers};
use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::model::{ItemId, Snippet};

use super::{PaneCtx, SnippetAnswer, centered, highlighted, mode_text};
use crate::views::{RenderCx, ViewCx, ViewEvent};
use crate::widgets::truncate;

/// The picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetPicker {
    /// Every snippet, by name.
    pub entries: Vec<(ItemId, Snippet)>,
    /// Their tag names (same order).
    pub tags: Vec<Vec<String>>,
    /// The filter.
    pub filter: String,
    /// Shown entries (indices into `entries`), best match first.
    pub visible: Vec<usize>,
    /// The cursor (into `visible`).
    pub cursor: usize,
    /// The focused pane when the picker opened.
    pub pane: Option<PaneCtx>,
}

impl SnippetPicker {
    /// A picker over `entries` (with their tag names) for `pane`.
    pub fn new(entries: Vec<(ItemId, Snippet, Vec<String>)>, pane: Option<PaneCtx>) -> Self {
        let (entries, tags): (Vec<(ItemId, Snippet)>, Vec<Vec<String>>) =
            entries.into_iter().map(|(id, s, t)| ((id, s), t)).unzip();
        let mut p = Self {
            visible: (0..entries.len()).collect(),
            entries,
            tags,
            filter: String::new(),
            cursor: 0,
            pane,
        };
        p.refilter();
        p
    }

    fn haystack(&self, i: usize) -> String {
        let (_, s) = &self.entries[i];
        let tags: Vec<String> = self.tags[i].iter().map(|t| format!("#{t}")).collect();
        format!(
            "{} {} {} {}",
            s.name,
            tags.join(" "),
            s.description.as_deref().unwrap_or_default(),
            s.script
        )
    }

    /// Recompute `visible` (fuzzy, best score first; ties keep name order).
    pub fn refilter(&mut self) {
        let f = self.filter.trim();
        if f.is_empty() {
            self.visible = (0..self.entries.len()).collect();
        } else {
            let pattern = Pattern::parse(f, CaseMatching::Ignore, Normalization::Smart);
            let mut matcher = Matcher::new(Config::DEFAULT);
            let mut buf = Vec::new();
            let mut scored: Vec<(u32, usize)> = (0..self.entries.len())
                .filter_map(|i| {
                    let hay = self.haystack(i);
                    pattern
                        .score(Utf32Str::new(&hay, &mut buf), &mut matcher)
                        .map(|s| (s, i))
                })
                .collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            self.visible = scored.into_iter().map(|(_, i)| i).collect();
        }
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    /// The highlighted snippet.
    pub fn current(&self) -> Option<&(ItemId, Snippet)> {
        self.visible.get(self.cursor).map(|i| &self.entries[*i])
    }

    /// Handle a key or paste; `Some` when a snippet is chosen.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<SnippetAnswer> {
        match ev {
            ViewEvent::Paste(t) => {
                self.filter.push_str(t.trim());
                self.refilter();
                None
            }
            ViewEvent::Key(k) => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                let down = |p: &mut Self| {
                    p.cursor = (p.cursor + 1).min(p.visible.len().saturating_sub(1));
                };
                match k.code {
                    KeyCode::Esc => cx.close(),
                    KeyCode::Down => down(self),
                    KeyCode::Char('n') if ctrl => down(self),
                    KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
                    KeyCode::Char('p') if ctrl => self.cursor = self.cursor.saturating_sub(1),
                    KeyCode::Enter => {
                        let (id, _) = self.current()?;
                        let id = *id;
                        return Some(SnippetAnswer::Picked {
                            id,
                            pane: self.pane.clone(),
                        });
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
                        self.cursor = 0;
                        self.refilter();
                    }
                    _ => {}
                }
                None
            }
            ViewEvent::Mouse(_) => None,
        }
    }

    /// Draw: the list on the left, the preview on the right.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let Some(rect) = centered(area, 110, 26, 30, 8) else {
            return;
        };
        frame.render_widget(Clear, rect);
        let target = self
            .pane
            .as_ref()
            .map_or_else(String::new, |p| format!(" → {}", p.label));
        let block = Block::bordered()
            .title(Span::styled(
                format!(" Snippets{} ", truncate(&target, 40)),
                theme.title_for(true),
            ))
            .border_style(theme.border_for(true));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let [list_area, preview_area] = if inner.width >= 60 {
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                .areas(inner)
        } else {
            [inner, Rect::default()]
        };
        let lw = usize::from(list_area.width);
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Filter ", theme.dim),
                Span::styled(format!("{}▏", self.filter), theme.base),
            ]),
            Line::raw(""),
        ];
        let room = usize::from(list_area.height).saturating_sub(4);
        let skip = self.cursor.saturating_sub(room.saturating_sub(1));
        if self.visible.is_empty() {
            lines.push(Line::styled(
                if self.entries.is_empty() {
                    "no snippets yet"
                } else {
                    "no snippet matches"
                },
                theme.dim,
            ));
        }
        for (row, i) in self.visible.iter().enumerate().skip(skip).take(room) {
            let (_, s) = &self.entries[*i];
            let style = if row == self.cursor {
                theme.selection
            } else {
                theme.base
            };
            let mode = mode_text(s.run_mode);
            let name_w = lw.saturating_sub(mode.len() + 2);
            lines.push(Line::styled(
                format!("{:<name_w$} {mode}", truncate(&s.name, name_w)),
                style,
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("↑↓ move · enter run · esc close", theme.dim));
        frame.render_widget(Paragraph::new(lines).style(theme.base), list_area);
        if preview_area.width > 2 {
            let mut preview = Vec::new();
            if let Some((_, s)) = self.current() {
                if let Some(d) = s.description.as_deref().filter(|d| !d.is_empty()) {
                    preview.push(Line::styled(d.to_owned(), theme.dim));
                    preview.push(Line::raw(""));
                }
                preview.extend(highlighted(&s.script, theme));
            }
            let block = Block::bordered()
                .title(Span::styled(" Preview ", theme.dim))
                .border_style(theme.border_for(false));
            frame.render_widget(
                Paragraph::new(preview)
                    .wrap(Wrap { trim: false })
                    .style(theme.base)
                    .block(block),
                preview_area,
            );
        }
    }
}
