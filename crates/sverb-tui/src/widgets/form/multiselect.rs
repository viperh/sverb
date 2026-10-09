//! The `MultiSelect` field (tags, …): a checklist popup.
//!
//! `Enter`/`Space` opens the checklist; there `↑/↓` move, `Space` toggles, and
//! `Enter`/`Esc` close it.

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent};

use super::{
    Popup, PopupItem,
    select::{SelectOption, popup_nav},
    text::TextEdit,
};

/// A multiple-choice field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiSelectInput {
    /// The choices.
    pub options: Vec<SelectOption>,
    /// Indices of the checked options.
    pub checked: BTreeSet<usize>,
    open: Option<usize>,
}

impl MultiSelectInput {
    /// A checklist over `options` with the options whose values are in `values` checked.
    pub fn new(options: Vec<SelectOption>, values: &[String]) -> Self {
        let checked = options
            .iter()
            .enumerate()
            .filter(|(_, o)| values.contains(&o.value))
            .map(|(i, _)| i)
            .collect();
        Self {
            options,
            checked,
            open: None,
        }
    }

    /// The checked values, in option order.
    pub fn values(&self) -> Vec<String> {
        self.checked
            .iter()
            .filter_map(|i| self.options.get(*i))
            .map(|o| o.value.clone())
            .collect()
    }

    /// The checked labels joined for display.
    pub fn summary(&self) -> String {
        self.checked
            .iter()
            .filter_map(|i| self.options.get(*i))
            .map(|o| o.label.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether the checklist is open.
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Close the checklist.
    pub fn blur(&mut self) {
        self.open = None;
    }

    /// Apply one key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let n = self.options.len();
        if let Some(at) = self.open {
            if let Some(to) = popup_nav(key, at, n) {
                self.open = Some(to);
                return TextEdit::Moved;
            }
            return match key.code {
                KeyCode::Char(' ') if n > 0 => {
                    if !self.checked.remove(&at) {
                        self.checked.insert(at);
                    }
                    TextEdit::Changed
                }
                KeyCode::Enter | KeyCode::Esc => {
                    self.open = None;
                    TextEdit::Moved
                }
                _ => TextEdit::Moved,
            };
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.open = Some(0);
                TextEdit::Moved
            }
            _ => TextEdit::Ignored,
        }
    }

    /// The checklist, when open.
    pub fn popup(&self) -> Option<Popup> {
        let at = self.open?;
        Some(Popup {
            title: " space toggle · enter done ".to_owned(),
            query: None,
            items: self
                .options
                .iter()
                .enumerate()
                .map(|(i, o)| PopupItem {
                    text: o.label.clone(),
                    highlights: Vec::new(),
                    checked: Some(self.checked.contains(&i)),
                })
                .collect(),
            selected: at,
            empty: "No options".to_owned(),
        })
    }
}
