//! The `RefList` field: an **ordered** list of item references (the host form's
//! jump chain), with a fuzzy picker to add entries.
//!
//! Closed: `↑/↓` select a row (past the ends the form moves to the neighbouring
//! field), `a`/`Enter` opens the picker (the pick is inserted after the selected
//! row), `d`/`Del`/`Backspace` removes the selected row, `K`/`J` (or `Shift-↑/↓`)
//! move it up/down. Picker: as the `Reference` field's.
//!
//! The owner can attach a read-only `note` shown below the rows (the effective route)
//! and an `error` that fails the field's check (an inline cycle message).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_core::{
    model::{ItemId, ItemKind},
    search::IndexSnapshot,
};

use super::{
    Popup,
    reference::{RefValue, ReferenceInput},
    text::TextEdit,
};

/// An ordered reference list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefListInput {
    /// The kind of item the entries point to.
    pub kind: ItemKind,
    /// The entries, in order.
    pub rows: Vec<RefValue>,
    /// The selected row.
    pub selected: usize,
    /// The picker that adds an entry.
    adder: ReferenceInput,
    /// Read-only text below the rows.
    pub note: Option<String>,
    /// A problem with the list as a whole (fails the field's check).
    pub error: Option<String>,
}

impl RefListInput {
    /// A list of `kind` references.
    pub fn new(kind: ItemKind, rows: Vec<RefValue>) -> Self {
        Self {
            kind,
            rows,
            selected: 0,
            adder: ReferenceInput::new(kind, None),
            note: None,
            error: None,
        }
    }

    /// The referenced ids, in order.
    pub fn ids(&self) -> Vec<ItemId> {
        self.rows.iter().map(|r| r.id).collect()
    }

    /// Whether the picker is open.
    pub fn is_open(&self) -> bool {
        self.adder.is_open()
    }

    /// Close the picker.
    pub fn blur(&mut self) {
        self.adder.blur();
    }

    /// The picker, when open.
    pub fn popup(&self) -> Option<Popup> {
        self.adder.popup()
    }

    /// Insert a paste into the open picker's query.
    pub fn paste(&mut self, s: &str, index: Option<&IndexSnapshot>) -> bool {
        self.adder.paste(s, index)
    }

    /// Move the selected row by `delta` (−1 up, +1 down).
    fn shift(&mut self, up: bool) -> TextEdit {
        let i = self.selected;
        let to = if up {
            i.checked_sub(1)
        } else {
            (i + 1 < self.rows.len()).then_some(i + 1)
        };
        match to {
            Some(to) if i < self.rows.len() => {
                self.rows.swap(i, to);
                self.selected = to;
                TextEdit::Changed
            }
            _ => TextEdit::Moved,
        }
    }

    /// Apply one key. `index` is the current search snapshot (`None` before unlock).
    pub fn handle_key(&mut self, key: &KeyEvent, index: Option<&IndexSnapshot>) -> TextEdit {
        if self.adder.is_open() {
            let r = self.adder.handle_key(key, index);
            if let Some(pick) = self.adder.value.take() {
                let at = if self.rows.is_empty() {
                    0
                } else {
                    self.selected + 1
                };
                self.rows.insert(at, pick);
                self.selected = at;
                return TextEdit::Changed;
            }
            return r;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return TextEdit::Ignored;
        }
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let last = self.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Up if shift => self.shift(true),
            KeyCode::Down if shift => self.shift(false),
            KeyCode::Char('K') => self.shift(true),
            KeyCode::Char('J') => self.shift(false),
            KeyCode::Down if self.selected < last => {
                self.selected += 1;
                TextEdit::Moved
            }
            KeyCode::Up if self.selected > 0 => {
                self.selected -= 1;
                TextEdit::Moved
            }
            KeyCode::Char('a') | KeyCode::Enter => {
                // Opens the picker (the adder's own Enter handling).
                self.adder
                    .handle_key(&KeyEvent::from(KeyCode::Enter), index)
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if !self.rows.is_empty() => {
                self.rows.remove(self.selected);
                self.selected = self.selected.min(self.rows.len().saturating_sub(1));
                TextEdit::Changed
            }
            _ => TextEdit::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn rv(b: u8, label: &str) -> RefValue {
        RefValue {
            id: ItemId::from_bytes([b; 16]),
            label: label.into(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn labels(l: &RefListInput) -> Vec<&str> {
        l.rows.iter().map(|r| r.label.as_str()).collect()
    }

    #[test]
    fn move_select_and_delete() {
        let mut l = RefListInput::new(ItemKind::Host, vec![rv(1, "a"), rv(2, "b"), rv(3, "c")]);
        assert_eq!(l.handle_key(&key(KeyCode::Down), None), TextEdit::Moved);
        assert_eq!(
            l.handle_key(&key(KeyCode::Char('K')), None),
            TextEdit::Changed
        );
        assert_eq!(labels(&l), ["b", "a", "c"]);
        assert_eq!(l.selected, 0);
        // Already first: nothing moves.
        assert_eq!(
            l.handle_key(&key(KeyCode::Char('K')), None),
            TextEdit::Moved
        );
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT);
        l.handle_key(&down, None);
        l.handle_key(&down, None);
        assert_eq!(labels(&l), ["a", "c", "b"]);
        assert_eq!(l.selected, 2);
        // Past the end: ignored (the form moves on).
        assert_eq!(l.handle_key(&key(KeyCode::Down), None), TextEdit::Ignored);
        assert_eq!(
            l.handle_key(&key(KeyCode::Char('d')), None),
            TextEdit::Changed
        );
        assert_eq!(labels(&l), ["a", "c"]);
        assert_eq!(l.selected, 1);
        assert_eq!(
            l.ids(),
            [ItemId::from_bytes([1; 16]), ItemId::from_bytes([3; 16])]
        );
    }

    #[test]
    fn a_opens_the_picker_and_esc_closes_it() {
        let mut l = RefListInput::new(ItemKind::Host, Vec::new());
        assert_eq!(
            l.handle_key(&key(KeyCode::Char('d')), None),
            TextEdit::Ignored
        );
        l.handle_key(&key(KeyCode::Char('a')), None);
        assert!(l.is_open());
        assert!(l.popup().is_some());
        l.handle_key(&key(KeyCode::Esc), None);
        assert!(!l.is_open());
        assert!(l.rows.is_empty());
    }
}
