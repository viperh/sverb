//! M1-06: the `Secret` field (passwords, passphrases).
//!
//! - The value lives in a [`SecretString`] (zeroized on drop, `[REDACTED]` in `Debug`);
//!   every edit builds the next value in a `Zeroizing` buffer.
//! - It renders as `•` per character. `ctrl-r` reveals **this field only**; the form
//!   re-masks it as soon as the field loses focus ([`SecretInput::blur`]).
//! - `ctrl-w` and `ctrl-u` both clear to the start: word boundaries would leak
//!   structure, and a masked field has no visible words anyway.

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{style::Style, text::Line};
use sverb_core::secret::SecretString;
use zeroize::Zeroizing;

use super::text::{TextEdit, render_line};

/// The mask character.
pub const MASK: char = '•';

/// A [`SecretString`] that forms can compare and copy explicitly.
///
/// `Clone` copies the secret into a new zeroizing box (forms snapshot their initial
/// values); `PartialEq` is constant time; `Debug` is redacted.
pub struct SecretValue(pub SecretString);

impl SecretValue {
    /// An empty secret.
    pub fn empty() -> Self {
        Self(SecretString::from(""))
    }

    /// The secret.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.expose().is_empty()
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        Self(SecretString::from(s))
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self(SecretString::from(self.0.expose()))
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for SecretValue {}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Default for SecretValue {
    fn default() -> Self {
        Self::empty()
    }
}

/// A masked single-line editor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretInput {
    value: SecretValue,
    /// Cursor in chars.
    cursor: usize,
    /// `ctrl-r` reveal, until the field loses focus.
    revealed: bool,
}

impl SecretInput {
    /// A field holding `value`, masked, cursor at the end.
    pub fn new(value: SecretValue) -> Self {
        let cursor = value.expose().chars().count();
        Self {
            value,
            cursor,
            revealed: false,
        }
    }

    /// The value.
    pub fn value(&self) -> &SecretValue {
        &self.value
    }

    /// Whether the value is shown in clear.
    pub fn revealed(&self) -> bool {
        self.revealed
    }

    /// The field lost focus: mask it again.
    pub fn blur(&mut self) {
        self.revealed = false;
    }

    fn len(&self) -> usize {
        self.value.expose().chars().count()
    }

    /// Rebuild the value with `edit` applied to a zeroizing copy.
    fn edit(&mut self, edit: impl FnOnce(&mut Vec<char>, &mut usize)) {
        let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(self.value.expose().chars().collect());
        let mut cursor = self.cursor;
        edit(&mut chars, &mut cursor);
        let s: Zeroizing<String> = Zeroizing::new(chars.iter().collect());
        self.value = SecretValue(SecretString::from(s.as_str()));
        self.cursor = cursor.min(chars.len());
    }

    /// Insert a paste (control characters dropped).
    pub fn insert_str(&mut self, s: &str) -> bool {
        let new: Vec<char> = s.chars().filter(|c| !c.is_control()).collect();
        if new.is_empty() {
            return false;
        }
        self.edit(|chars, cursor| {
            for c in new {
                chars.insert(*cursor, c);
                *cursor += 1;
            }
        });
        true
    }

    /// Apply one key. `ctrl-r` toggles the reveal.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let len = self.len();
        match key.code {
            KeyCode::Char('r') if ctrl => {
                self.revealed = !self.revealed;
                TextEdit::Moved
            }
            KeyCode::Char(c) if !ctrl && !alt && !c.is_control() => {
                self.edit(|chars, cursor| {
                    chars.insert(*cursor, c);
                    *cursor += 1;
                });
                TextEdit::Changed
            }
            KeyCode::Char('w' | 'u') if ctrl => {
                if self.cursor == 0 {
                    return TextEdit::Moved;
                }
                self.edit(|chars, cursor| {
                    chars.drain(..*cursor);
                    *cursor = 0;
                });
                TextEdit::Changed
            }
            KeyCode::Char('k') if ctrl => {
                self.edit(|chars, cursor| chars.truncate(*cursor));
                TextEdit::Changed
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.edit(|chars, cursor| {
                    *cursor -= 1;
                    chars.remove(*cursor);
                });
                TextEdit::Changed
            }
            KeyCode::Delete if self.cursor < len => {
                self.edit(|chars, cursor| {
                    chars.remove(*cursor);
                });
                TextEdit::Changed
            }
            KeyCode::Backspace | KeyCode::Delete => TextEdit::Moved,
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                TextEdit::Moved
            }
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(len);
                TextEdit::Moved
            }
            KeyCode::Home => {
                self.cursor = 0;
                TextEdit::Moved
            }
            KeyCode::Char('a') if ctrl => {
                self.cursor = 0;
                TextEdit::Moved
            }
            KeyCode::End => {
                self.cursor = len;
                TextEdit::Moved
            }
            KeyCode::Char('e') if ctrl => {
                self.cursor = len;
                TextEdit::Moved
            }
            _ => TextEdit::Ignored,
        }
    }

    /// The field's line: masked unless revealed.
    pub fn line(&self, width: usize, style: Style, cursor: bool) -> Line<'static> {
        if self.revealed {
            render_line(self.value.expose(), self.cursor, width, style, cursor)
        } else {
            let masked: String = std::iter::repeat_n(MASK, self.len()).collect();
            render_line(&masked, self.cursor, width, style, cursor)
        }
    }
}
