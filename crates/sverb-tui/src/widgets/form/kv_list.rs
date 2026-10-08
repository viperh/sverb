//! M1-06: the `KeyValueList` field (`env`): rows of `key = value`.
//!
//! Browsing: `↑/↓` move, `a` adds a row (editing its key), `e`/`Enter` edits the
//! selected row, `d`/`Del` deletes it.
//! Editing a cell: the usual text keys; `Enter` goes from the key to the value and then
//! commits, `Esc` abandons the edit (an added row whose key is still empty goes away).
//!
//! Keys are checked with [`KeyCheck`] (e.g. env names via
//! `sverb_core::model::validate::validate_env_name`); errors show under their row.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_core::model::validate::validate_env_name;

use super::text::{TextEdit, TextInput};

/// How keys are validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum KeyCheck {
    /// Any non-empty key.
    #[default]
    NonEmpty,
    /// Environment variable names (`[A-Za-z_][A-Za-z0-9_]*`).
    EnvName,
}

impl KeyCheck {
    /// Check one key.
    pub fn check(self, key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("name is required".to_owned());
        }
        match self {
            Self::NonEmpty => Ok(()),
            Self::EnvName => validate_env_name(key).map_err(|e| e.message),
        }
    }
}

/// The cell being edited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvEdit {
    /// Row index.
    pub row: usize,
    /// `false`: the key, `true`: the value.
    pub value: bool,
    /// The editor.
    pub input: TextInput,
    /// The row was just added.
    pub added: bool,
}

/// A list of key/value pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvListInput {
    /// The pairs.
    pub rows: Vec<(String, String)>,
    /// Highlighted row.
    pub selected: usize,
    /// The cell being edited.
    pub editing: Option<KvEdit>,
    /// Key validation.
    pub check: KeyCheck,
}

impl KvListInput {
    /// A list holding `rows`.
    pub fn new(rows: Vec<(String, String)>, check: KeyCheck) -> Self {
        Self {
            rows,
            selected: 0,
            editing: None,
            check,
        }
    }

    /// Per-row key errors, in row order (also duplicate keys).
    pub fn errors(&self) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        for (i, (k, _)) in self.rows.iter().enumerate() {
            if let Err(msg) = self.check.check(k) {
                out.push((i, msg));
            } else if self.rows[..i].iter().any(|(other, _)| other == k) {
                out.push((i, format!("duplicate name {k:?}")));
            }
        }
        out
    }

    /// Whether a cell is being edited.
    pub fn is_editing(&self) -> bool {
        self.editing.is_some()
    }

    /// Commit an open edit (the field lost focus).
    pub fn blur(&mut self) {
        self.commit();
    }

    fn commit(&mut self) {
        let Some(edit) = self.editing.take() else {
            return;
        };
        if let Some(row) = self.rows.get_mut(edit.row) {
            if edit.value {
                row.1 = edit.input.text().to_owned();
            } else {
                row.0 = edit.input.text().to_owned();
            }
        }
    }

    fn start_edit(&mut self, row: usize, value: bool, added: bool) {
        let text = self
            .rows
            .get(row)
            .map(|(k, v)| if value { v.clone() } else { k.clone() })
            .unwrap_or_default();
        self.editing = Some(KvEdit {
            row,
            value,
            input: TextInput::new(text),
            added,
        });
    }

    /// Insert a paste into the edited cell.
    pub fn paste(&mut self, s: &str) -> bool {
        self.editing.as_mut().is_some_and(|e| e.input.insert_str(s))
    }

    /// Apply one key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> TextEdit {
        if let Some(edit) = &mut self.editing {
            return match key.code {
                KeyCode::Esc => {
                    let (row, added) = (edit.row, edit.added);
                    self.editing = None;
                    if added && self.rows.get(row).is_some_and(|(k, _)| k.is_empty()) {
                        self.rows.remove(row);
                        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
                        return TextEdit::Changed;
                    }
                    TextEdit::Moved
                }
                KeyCode::Enter => {
                    let (row, value, added) = (edit.row, edit.value, edit.added);
                    self.commit();
                    if !value {
                        self.start_edit(row, true, added);
                    }
                    TextEdit::Changed
                }
                _ => {
                    let r = edit.input.handle_key(key);
                    if r == TextEdit::Ignored {
                        // Modal while editing: unknown keys do nothing.
                        TextEdit::Moved
                    } else {
                        r
                    }
                }
            };
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return TextEdit::Ignored;
        }
        let last = self.rows.len().saturating_sub(1);
        match key.code {
            KeyCode::Down if self.selected < last => {
                self.selected += 1;
                TextEdit::Moved
            }
            KeyCode::Up if self.selected > 0 => {
                self.selected -= 1;
                TextEdit::Moved
            }
            KeyCode::Char('a') => {
                self.rows.push((String::new(), String::new()));
                self.selected = self.rows.len() - 1;
                self.start_edit(self.selected, false, true);
                TextEdit::Changed
            }
            KeyCode::Char('e') | KeyCode::Enter if !self.rows.is_empty() => {
                self.start_edit(self.selected, false, false);
                TextEdit::Moved
            }
            KeyCode::Char('d') | KeyCode::Delete if !self.rows.is_empty() => {
                self.rows.remove(self.selected);
                self.selected = self.selected.min(self.rows.len().saturating_sub(1));
                TextEdit::Changed
            }
            _ => TextEdit::Ignored,
        }
    }
}
