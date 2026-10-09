//! The `Multiline` field (notes, snippet scripts), backed by
//! `ratatui-textarea` (the ratatui-0.30 successor of `tui-textarea`).
//!
//! Every key except the form's own (`Tab`/`Shift-Tab`, `ctrl-s`, `Esc`) goes to the
//! text area, so `Enter` inserts a newline here.

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Frame, layout::Rect, style::Style};
use ratatui_textarea::{Input, Key, TextArea};

use super::text::TextEdit;

/// A multi-line editor.
#[derive(Clone)]
pub struct MultilineInput {
    area: TextArea<'static>,
}

impl MultilineInput {
    /// An editor holding `text` (lines split on `\n`).
    pub fn new(text: &str) -> Self {
        let lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
        let mut area = TextArea::new(lines);
        area.set_cursor_line_style(Style::new());
        Self { area }
    }

    /// The text, lines joined with `\n`.
    pub fn text(&self) -> String {
        self.area.lines().join("\n")
    }

    /// The lines.
    pub fn lines(&self) -> &[String] {
        self.area.lines()
    }

    /// The cursor (row, column).
    pub fn cursor(&self) -> (usize, usize) {
        let c = self.area.cursor();
        (c.0, c.1)
    }

    /// Insert a paste.
    pub fn paste(&mut self, s: &str) -> bool {
        self.area.insert_str(s)
    }

    /// Apply one key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let Some(input) = to_input(key) else {
            return TextEdit::Ignored;
        };
        if self.area.input(input) {
            TextEdit::Changed
        } else {
            TextEdit::Moved
        }
    }

    /// Draw the text area into `area` (cursor shown only when `focused`).
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, style: Style, focused: bool) {
        let mut ta = self.area.clone();
        ta.set_style(style);
        if !focused {
            ta.set_cursor_style(style);
        }
        frame.render_widget(&ta, area);
    }
}

impl PartialEq for MultilineInput {
    fn eq(&self, other: &Self) -> bool {
        self.area.lines() == other.area.lines() && self.area.cursor() == other.area.cursor()
    }
}

impl Eq for MultilineInput {}

impl fmt::Debug for MultilineInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Notes may be private; only the shape goes to logs.
        f.debug_struct("MultilineInput")
            .field("lines", &self.area.lines().len())
            .finish_non_exhaustive()
    }
}

/// Convert a crossterm key to a text-area input (no crossterm feature on the crate).
fn to_input(key: &KeyEvent) -> Option<Input> {
    let k = match key.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Delete => Key::Delete,
        KeyCode::F(n) => Key::F(n),
        _ => return None,
    };
    Some(Input {
        key: k,
        ctrl: key.modifiers.contains(KeyModifiers::CONTROL),
        alt: key.modifiers.contains(KeyModifiers::ALT),
        shift: key.modifiers.contains(KeyModifiers::SHIFT),
    })
}
