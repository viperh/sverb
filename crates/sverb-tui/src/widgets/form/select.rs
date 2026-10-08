//! M1-06: `Select` (single choice) and `Toggle` fields.
//!
//! `Select`: `←/→` cycle through the options in place; `Enter` (or `Space`) opens a
//! dropdown, where `↑/↓` (`ctrl-p/ctrl-n`) move, `Enter` picks and `Esc` closes.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{Popup, PopupItem, text::TextEdit};

/// One option of a select: the stored `value` and the shown `label`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectOption {
    /// What is saved.
    pub value: String,
    /// What is shown.
    pub label: String,
}

impl SelectOption {
    /// An option.
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
        }
    }
}

/// Options where value and label are the same text.
pub fn options(values: &[&str]) -> Vec<SelectOption> {
    values.iter().map(|v| SelectOption::new(*v, *v)).collect()
}

/// Move a highlight in a popup with `len` entries. Returns `None` for other keys.
pub(crate) fn popup_nav(key: &KeyEvent, at: usize, len: usize) -> Option<usize> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let last = len.saturating_sub(1);
    match key.code {
        KeyCode::Up => Some(at.saturating_sub(1)),
        KeyCode::Char('p') if ctrl => Some(at.saturating_sub(1)),
        KeyCode::Down => Some((at + 1).min(last)),
        KeyCode::Char('n') if ctrl => Some((at + 1).min(last)),
        KeyCode::Home => Some(0),
        KeyCode::End => Some(last),
        KeyCode::PageUp => Some(at.saturating_sub(10)),
        KeyCode::PageDown => Some((at + 10).min(last)),
        _ => None,
    }
}

/// A single-choice field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectInput {
    /// The choices.
    pub options: Vec<SelectOption>,
    /// The chosen option (`None`: unset, e.g. inherited).
    pub selected: Option<usize>,
    /// The open dropdown's highlight.
    open: Option<usize>,
}

impl SelectInput {
    /// A select over `options` with the option whose value is `value` chosen.
    pub fn new(options: Vec<SelectOption>, value: Option<&str>) -> Self {
        let selected = value.and_then(|v| options.iter().position(|o| o.value == v));
        Self {
            options,
            selected,
            open: None,
        }
    }

    /// The chosen value.
    pub fn value(&self) -> Option<&str> {
        self.selected
            .and_then(|i| self.options.get(i))
            .map(|o| o.value.as_str())
    }

    /// The chosen label (empty when unset).
    pub fn label(&self) -> &str {
        self.selected
            .and_then(|i| self.options.get(i))
            .map_or("", |o| o.label.as_str())
    }

    /// Whether the dropdown is open.
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Close the dropdown.
    pub fn blur(&mut self) {
        self.open = None;
    }

    /// Apply one key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        let n = self.options.len();
        if n == 0 {
            return TextEdit::Ignored;
        }
        if let Some(at) = self.open {
            if let Some(to) = popup_nav(key, at, n) {
                self.open = Some(to);
                return TextEdit::Moved;
            }
            return match key.code {
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.open = None;
                    let changed = self.selected != Some(at);
                    self.selected = Some(at);
                    if changed {
                        TextEdit::Changed
                    } else {
                        TextEdit::Moved
                    }
                }
                KeyCode::Esc => {
                    self.open = None;
                    TextEdit::Moved
                }
                // The dropdown is modal within the form.
                _ => TextEdit::Moved,
            };
        }
        match key.code {
            KeyCode::Left => {
                self.selected = Some(self.selected.map_or(n - 1, |i| (i + n - 1) % n));
                TextEdit::Changed
            }
            KeyCode::Right => {
                self.selected = Some(self.selected.map_or(0, |i| (i + 1) % n));
                TextEdit::Changed
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.open = Some(self.selected.unwrap_or(0));
                TextEdit::Moved
            }
            _ => TextEdit::Ignored,
        }
    }

    /// The dropdown, when open.
    pub fn popup(&self) -> Option<Popup> {
        let at = self.open?;
        Some(Popup {
            title: String::new(),
            query: None,
            items: self
                .options
                .iter()
                .enumerate()
                .map(|(i, o)| PopupItem {
                    text: o.label.clone(),
                    highlights: Vec::new(),
                    checked: (Some(i) == self.selected).then_some(true),
                })
                .collect(),
            selected: at,
            empty: "No options".to_owned(),
        })
    }
}
