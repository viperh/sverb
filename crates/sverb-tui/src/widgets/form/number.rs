//! M1-06: the `Number` field: digits only, with an inclusive range.
//!
//! Non-digit characters are rejected as they are typed (the key is consumed and
//! nothing changes). The range is checked on blur and on save, so a half-typed value
//! is never flagged while the user is still typing.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{style::Style, text::Line};

use super::text::{TextEdit, TextInput};

/// A digits-only editor with a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumberInput {
    input: TextInput,
    /// Smallest allowed value.
    pub min: u64,
    /// Largest allowed value.
    pub max: u64,
}

impl NumberInput {
    /// An editor for `min..=max` holding `value` (empty for `None`).
    pub fn new(value: Option<u64>, min: u64, max: u64) -> Self {
        let digits = u64::MAX.to_string().len();
        Self {
            input: TextInput::new(value.map(|v| v.to_string()).unwrap_or_default())
                .with_max_chars(digits),
            min,
            max,
        }
    }

    /// The raw text.
    pub fn text(&self) -> &str {
        self.input.text()
    }

    /// The parsed value: `Ok(None)` when empty, `Err` with a message when out of range.
    pub fn value(&self) -> Result<Option<u64>, String> {
        let text = self.input.text();
        if text.is_empty() {
            return Ok(None);
        }
        match text.parse::<u64>() {
            Ok(v) if (self.min..=self.max).contains(&v) => Ok(Some(v)),
            _ => Err(format!("must be between {} and {}", self.min, self.max)),
        }
    }

    /// The value as far as it parses (ignoring the range), for change tracking.
    pub fn raw_value(&self) -> Option<u64> {
        self.input.text().parse().ok()
    }

    /// Insert a paste: accepted only if it is all digits.
    pub fn insert_str(&mut self, s: &str) -> bool {
        let s = s.trim();
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && self.input.insert_str(s)
    }

    /// Apply one key. Printable non-digits are consumed and rejected.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match key.code {
            KeyCode::Char(c) if plain && !c.is_ascii_digit() => TextEdit::Moved,
            _ => self.input.handle_key(key),
        }
    }

    /// The field's line.
    pub fn line(&self, width: usize, style: Style, cursor: bool) -> Line<'static> {
        self.input.line(width, style, cursor)
    }
}
