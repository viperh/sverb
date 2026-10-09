//! The sidebar: the section switcher (SPEC §8.5).
//!
//! `j`/`k` (or the arrows) move the cursor, `Enter` opens the section under it. The
//! active section carries the `▸` marker; the cursor row uses the theme's selection
//! style while the sidebar has focus.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use super::{Outcome, RenderCx, View, ViewCx, ViewEvent, shell::Section};

/// The sidebar's state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SidebarView {
    /// Cursor position in [`Section::ALL`].
    pub cursor: usize,
    /// The section shown in the main area (the `▸` marker).
    pub active: Section,
    /// Set by `Enter`; the reducer takes it and switches the main view.
    pub chosen: Option<Section>,
}

impl SidebarView {
    /// Point the cursor and the marker at `section`.
    pub fn select(&mut self, section: Section) {
        self.active = section;
        self.cursor = section.index();
    }
}

impl View for SidebarView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        if !key.modifiers.is_empty() {
            return Outcome::Ignored;
        }
        let last = Section::ALL.len() - 1;
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.cursor = (self.cursor + 1).min(last),
            KeyCode::Char('k') | KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => self.cursor = 0,
            KeyCode::Char('G') | KeyCode::End => self.cursor = last,
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                self.chosen = Section::ALL.get(self.cursor).copied();
            }
            _ => return Outcome::Ignored,
        }
        cx.request_redraw();
        Outcome::Consumed
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let inner = usize::from(area.width.saturating_sub(2));
        let lines: Vec<Line<'_>> = Section::ALL
            .iter()
            .enumerate()
            .map(|(i, section)| {
                let active = *section == self.active;
                let marker = if active { "▸ " } else { "  " };
                let text = format!("{marker}{}", section.title());
                if i == self.cursor && cx.focused {
                    Line::from(Span::styled(format!("{text:<inner$}"), theme.selection))
                } else if active {
                    Line::from(Span::styled(text, theme.accent))
                } else {
                    Line::raw(text)
                }
            })
            .collect();
        frame.render_widget(Clear, area);
        let block = Block::bordered()
            .border_style(theme.border_for(cx.focused))
            .style(theme.sidebar);
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }
}
