//! M1-06: a single-line text editor (`Text` fields, the list filter line, prompts).
//!
//! Plain state: the text and a cursor (a **char** index). Keys (Insert mode,
//! `tasks/03-KEYBINDINGS.md` §4.3): printable characters insert, `←/→` move,
//! `ctrl-←/→` and `alt-b/alt-f` move by word, `Home`/`ctrl-a` and `End`/`ctrl-e` jump,
//! `Backspace`/`Delete` erase, `ctrl-w` deletes the word before the cursor, `ctrl-u`
//! deletes to the start and `ctrl-k` to the end.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

/// What a key did to a [`TextInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEdit {
    /// The text changed.
    Changed,
    /// Only the cursor moved.
    Moved,
    /// The key is not an editing key.
    Ignored,
}

impl TextEdit {
    /// The key was handled (changed or moved).
    pub fn handled(self) -> bool {
        self != Self::Ignored
    }
}

/// A single-line editor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    text: String,
    /// Cursor position in chars (0..=len).
    cursor: usize,
    /// Maximum length in chars (`None`: unlimited).
    max_chars: Option<usize>,
}

impl TextInput {
    /// An editor holding `text`, cursor at the end.
    pub fn new(text: impl Into<String>) -> Self {
        let text: String = text.into();
        let cursor = text.chars().count();
        Self {
            text,
            cursor,
            max_chars: None,
        }
    }

    /// Limit the length in chars.
    #[must_use]
    pub fn with_max_chars(mut self, max: usize) -> Self {
        self.max_chars = Some(max);
        self
    }

    /// The text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The cursor position (chars).
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Replace the text; the cursor goes to the end.
    pub fn set(&mut self, text: impl Into<String>) {
        *self = Self {
            max_chars: self.max_chars,
            ..Self::new(text)
        };
    }

    /// Clear the text.
    pub fn clear(&mut self) {
        self.set(String::new());
    }

    fn len(&self) -> usize {
        self.text.chars().count()
    }

    fn byte(&self, char_idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_idx)
            .map_or(self.text.len(), |(b, _)| b)
    }

    /// Insert `c` at the cursor (control characters are dropped).
    pub fn insert(&mut self, c: char) -> bool {
        if c.is_control() || self.max_chars.is_some_and(|m| self.len() >= m) {
            return false;
        }
        let at = self.byte(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
        true
    }

    /// Insert a paste; newlines become spaces, other control characters are dropped.
    pub fn insert_str(&mut self, s: &str) -> bool {
        let mut changed = false;
        for c in s.chars() {
            let c = if c == '\n' || c == '\t' { ' ' } else { c };
            changed |= self.insert(c);
        }
        changed
    }

    fn remove_range(&mut self, from: usize, to: usize) -> bool {
        if from >= to {
            return false;
        }
        let (a, b) = (self.byte(from), self.byte(to));
        self.text.replace_range(a..b, "");
        self.cursor = from;
        true
    }

    fn is_word(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// Start of the word before the cursor.
    fn word_left(&self) -> usize {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.cursor;
        while i > 0 && !Self::is_word(chars[i - 1]) {
            i -= 1;
        }
        while i > 0 && Self::is_word(chars[i - 1]) {
            i -= 1;
        }
        i
    }

    /// End of the word after the cursor.
    fn word_right(&self) -> usize {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.cursor;
        while i < chars.len() && !Self::is_word(chars[i]) {
            i += 1;
        }
        while i < chars.len() && Self::is_word(chars[i]) {
            i += 1;
        }
        i
    }

    fn moved(&mut self, to: usize) -> TextEdit {
        self.cursor = to.min(self.len());
        TextEdit::Moved
    }

    /// Apply one key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let changed = |c: bool| {
            if c {
                TextEdit::Changed
            } else {
                TextEdit::Moved
            }
        };
        match key.code {
            KeyCode::Char(c) if !ctrl && !alt => changed(self.insert(c)),
            KeyCode::Char('w') if ctrl => {
                let from = self.word_left();
                changed(self.remove_range(from, self.cursor))
            }
            KeyCode::Backspace if ctrl || alt => {
                let from = self.word_left();
                changed(self.remove_range(from, self.cursor))
            }
            KeyCode::Char('u') if ctrl => changed(self.remove_range(0, self.cursor)),
            KeyCode::Char('k') if ctrl => changed(self.remove_range(self.cursor, self.len())),
            KeyCode::Char('a') if ctrl => self.moved(0),
            KeyCode::Char('e') if ctrl => self.moved(usize::MAX),
            KeyCode::Char('b') if alt => self.moved(self.word_left()),
            KeyCode::Char('f') if alt => self.moved(self.word_right()),
            KeyCode::Left if ctrl || alt => self.moved(self.word_left()),
            KeyCode::Right if ctrl || alt => self.moved(self.word_right()),
            KeyCode::Left => self.moved(self.cursor.saturating_sub(1)),
            KeyCode::Right => self.moved(self.cursor + 1),
            KeyCode::Home => self.moved(0),
            KeyCode::End => self.moved(usize::MAX),
            KeyCode::Backspace => {
                let from = self.cursor.saturating_sub(1);
                changed(self.remove_range(from, self.cursor))
            }
            KeyCode::Delete => changed(self.remove_range(self.cursor, self.cursor + 1)),
            _ => TextEdit::Ignored,
        }
    }

    /// The text as spans fitting `width` cells, scrolled so the cursor is visible.
    /// With `cursor`, the cursor cell is drawn reversed (works without color).
    pub fn line(&self, width: usize, style: Style, cursor: bool) -> Line<'static> {
        render_line(&self.text, self.cursor, width, style, cursor)
    }
}

/// Render `text` (already masked if needed) with a reversed cursor cell at char
/// `cursor`, horizontally scrolled to keep it inside `width` cells.
pub(crate) fn render_line(
    text: &str,
    cursor: usize,
    width: usize,
    style: Style,
    show_cursor: bool,
) -> Line<'static> {
    let chars: Vec<char> = text.chars().collect();
    let width = width.max(1);
    // Keep one cell for the cursor at the end.
    let avail = if show_cursor { width - 1 } else { width };
    let start = if show_cursor && cursor > avail {
        cursor - avail
    } else {
        0
    };
    let end = (start + width).min(chars.len());
    let mut spans = Vec::new();
    if !show_cursor {
        let s: String = chars[start..end].iter().collect();
        return Line::from(Span::styled(crate::widgets::truncate(&s, width), style));
    }
    let before: String = chars[start..cursor.min(chars.len())].iter().collect();
    spans.push(Span::styled(before, style));
    let at = chars.get(cursor).map_or(" ".to_owned(), char::to_string);
    spans.push(Span::styled(at, style.add_modifier(Modifier::REVERSED)));
    if cursor + 1 < end {
        let after: String = chars[cursor + 1..end].iter().collect();
        spans.push(Span::styled(after, style));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    fn typed(s: &str) -> TextInput {
        let mut t = TextInput::default();
        for c in s.chars() {
            t.handle_key(&key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        t
    }

    #[test]
    fn editing_keys() {
        let mut t = typed("hello big world");
        assert_eq!(t.text(), "hello big world");
        t.handle_key(&key(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(t.text(), "hello big ");
        t.handle_key(&key(KeyCode::Left, KeyModifiers::CONTROL));
        assert_eq!(t.cursor(), 6);
        t.handle_key(&key(KeyCode::Char('k'), KeyModifiers::CONTROL));
        assert_eq!(t.text(), "hello ");
        t.handle_key(&key(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(t.text(), "");
        let mut t = typed("ab");
        t.handle_key(&key(KeyCode::Home, KeyModifiers::NONE));
        t.handle_key(&key(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(t.text(), "b");
        t.handle_key(&key(KeyCode::Char('é'), KeyModifiers::NONE));
        t.handle_key(&key(KeyCode::Right, KeyModifiers::ALT));
        t.handle_key(&key(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(t.text(), "é");
        assert_eq!(
            t.handle_key(&key(KeyCode::Char('x'), KeyModifiers::CONTROL)),
            TextEdit::Ignored
        );
    }

    #[test]
    fn scrolls_to_the_cursor() {
        let t = typed("abcdefghij");
        let line = t.line(5, Style::new(), true);
        let s: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(s, "ghij ");
    }
}
