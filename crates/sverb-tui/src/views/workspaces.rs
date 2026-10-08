//! M3-03: the workspaces dialog (SPEC §9.9): the list of saved workspaces with a fuzzy
//! filter and an ASCII preview of the selected one (`Open workspace`, `Workspaces`),
//! and the prompts of the save / rename / delete flows.
//!
//! The dialog only records what the user chose ([`WorkspacesDialog::answer`]); the
//! reducer (`app/workspaces.rs`) takes it after the key, issues the effects and moves
//! the dialog to its next [`Stage`] (or closes it).
//!
//! List keys: type to filter, `↑/↓` (`ctrl-p`/`ctrl-n`) move, `Enter` open, `ctrl-r`
//! rename, `ctrl-d` delete, `ctrl-y` duplicate, `Esc` clears the filter, then closes.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::model::ItemId;

use super::{Outcome, RenderCx, ViewCx, ViewEvent};
use crate::widgets::dialog::{Modal, ModalAnswer};

/// One saved workspace as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    /// Its item.
    pub id: ItemId,
    /// Its name.
    pub name: String,
    /// `3 tabs · 8 panes`, the vault, or why it can't be opened.
    pub detail: String,
    /// The preview: tab titles and the ASCII layout of each tab.
    pub preview: Vec<String>,
}

/// What a prompt of the dialog is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// The name of the workspace being saved.
    SaveName,
    /// Which vault to save into (`Personal` or the hosts' shared vault).
    SaveVault,
    /// "A workspace with this name exists. Overwrite?"
    ConfirmOverwrite,
    /// The new name of a workspace.
    Rename(ItemId),
    /// "Delete workspace?"
    ConfirmDelete(ItemId),
}

/// What the dialog is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// The list.
    List,
    /// A prompt, confirmation or choice (drawn over the list when it has rows).
    Modal {
        /// The modal.
        modal: Modal,
        /// What its answer is for.
        purpose: Purpose,
    },
}

/// What the user chose (taken by the reducer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacesAnswer {
    /// Open this workspace.
    Open(ItemId),
    /// Duplicate this workspace.
    Duplicate(ItemId),
    /// `Esc` in the list.
    Close,
    /// A prompt was answered.
    Modal {
        /// What for.
        purpose: Purpose,
        /// The answer.
        answer: ModalAnswer,
    },
}

/// The dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacesDialog {
    /// The title (`Open workspace`, `Workspaces`, `Save workspace`).
    pub title: String,
    /// Every workspace, by name.
    pub rows: Vec<WorkspaceRow>,
    /// The list has been loaded at least once.
    pub loaded: bool,
    /// The filter text.
    pub filter: String,
    /// The highlighted row among the visible ones.
    pub cursor: usize,
    /// The current stage.
    pub stage: Stage,
    /// The answer waiting for the reducer.
    pub answer: Option<WorkspacesAnswer>,
}

/// Whether `query` matches `name` as a case-insensitive subsequence; the score is
/// lower for tighter matches (`None`: no match).
pub fn fuzzy_score(query: &str, name: &str) -> Option<usize> {
    let name: Vec<char> = name.to_lowercase().chars().collect();
    let mut pos = 0;
    let mut first = None;
    let mut last = 0;
    for q in query.to_lowercase().chars() {
        let at = name[pos..].iter().position(|c| *c == q)? + pos;
        first.get_or_insert(at);
        last = at;
        pos = at + 1;
    }
    Some(first.map_or(0, |f| last - f))
}

impl WorkspacesDialog {
    /// The list (`Open workspace` / `Workspaces`).
    pub fn list(title: &str, rows: Vec<WorkspaceRow>, loaded: bool) -> Self {
        Self {
            title: title.to_owned(),
            rows,
            loaded,
            filter: String::new(),
            cursor: 0,
            stage: Stage::List,
            answer: None,
        }
    }

    /// A dialog that starts at a prompt (the save flow).
    pub fn prompt(title: &str, modal: Modal, purpose: Purpose) -> Self {
        Self {
            stage: Stage::Modal { modal, purpose },
            ..Self::list(title, Vec::new(), true)
        }
    }

    /// The rows that match the filter (best match first, then by name).
    pub fn visible(&self) -> Vec<&WorkspaceRow> {
        let mut rows: Vec<(usize, &WorkspaceRow)> = self
            .rows
            .iter()
            .filter_map(|r| fuzzy_score(&self.filter, &r.name).map(|s| (s, r)))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
        rows.into_iter().map(|(_, r)| r).collect()
    }

    /// The highlighted row.
    pub fn selected(&self) -> Option<&WorkspaceRow> {
        self.visible().get(self.cursor).copied()
    }

    /// Replace the rows (a reload), keeping the selection on the same workspace.
    pub fn set_rows(&mut self, rows: Vec<WorkspaceRow>) {
        let keep = self.selected().map(|r| r.id);
        self.rows = rows;
        self.loaded = true;
        self.cursor = keep
            .and_then(|id| self.visible().iter().position(|r| r.id == id))
            .unwrap_or(0);
        self.clamp();
    }

    fn clamp(&mut self) {
        self.cursor = self.cursor.min(self.visible().len().saturating_sub(1));
    }

    /// Whether keys edit text (the filter line or a name prompt).
    pub fn wants_text(&self) -> bool {
        match &self.stage {
            Stage::List => true,
            Stage::Modal { modal, .. } => modal.wants_text(),
        }
    }

    fn rename_prompt(row: &WorkspaceRow) -> Stage {
        Stage::Modal {
            modal: name_prompt("Rename workspace", "New name for the workspace.", &row.name),
            purpose: Purpose::Rename(row.id),
        }
    }

    fn list_key(&mut self, key: &KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.cursor = 0;
            }
            KeyCode::Esc => self.answer = Some(WorkspacesAnswer::Close),
            KeyCode::Enter => {
                if let Some(r) = self.selected() {
                    self.answer = Some(WorkspacesAnswer::Open(r.id));
                }
            }
            KeyCode::Up | KeyCode::Char('p') if key.code == KeyCode::Up || ctrl => {
                self.cursor = self.cursor.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('n') if key.code == KeyCode::Down || ctrl => {
                self.cursor += 1;
                self.clamp();
            }
            KeyCode::Char('r') if ctrl => {
                if let Some(r) = self.selected() {
                    self.stage = Self::rename_prompt(r);
                }
            }
            KeyCode::Char('d') if ctrl => {
                if let Some(r) = self.selected() {
                    self.stage = Stage::Modal {
                        modal: delete_confirm(&r.name),
                        purpose: Purpose::ConfirmDelete(r.id),
                    };
                }
            }
            KeyCode::Char('y') if ctrl => {
                if let Some(r) = self.selected() {
                    self.answer = Some(WorkspacesAnswer::Duplicate(r.id));
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.cursor = 0;
            }
            KeyCode::Char(c) if !ctrl => {
                self.filter.push(c);
                self.cursor = 0;
            }
            _ => {}
        }
    }

    /// Handle an event (the dialog is modal: it consumes everything).
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        cx.request_redraw();
        match (&mut self.stage, ev) {
            (Stage::List, ViewEvent::Key(key)) => self.list_key(key),
            (Stage::List, ViewEvent::Paste(text)) => {
                self.filter.extend(text.chars().filter(|c| !c.is_control()));
                self.cursor = 0;
            }
            (Stage::Modal { modal, purpose }, ViewEvent::Key(key)) => {
                if let Some(answer) = modal.handle_key(key) {
                    self.answer = Some(WorkspacesAnswer::Modal {
                        purpose: purpose.clone(),
                        answer,
                    });
                }
            }
            (Stage::Modal { modal, .. }, ViewEvent::Paste(text)) => modal.paste(text),
            (_, ViewEvent::Mouse(_)) => {}
        }
        Outcome::Consumed
    }

    /// Draw the dialog.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let list_shown = matches!(self.stage, Stage::List) || !self.rows.is_empty();
        if list_shown {
            self.render_list(frame, area, cx);
        }
        if let Stage::Modal { modal, .. } = &self.stage {
            modal.render(frame, area, cx);
        }
    }

    fn render_list(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        if area.width < 10 || area.height < 6 {
            return;
        }
        let w = (area.width.saturating_mul(4) / 5).max(10);
        let h = (area.height.saturating_mul(4) / 5).max(6);
        let rect = super::dialogs::centered(area, usize::from(w), usize::from(h));
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(
                format!(" {} ", self.title),
                cx.theme.title_for(cx.focused),
            ))
            .title_bottom(Span::styled(
                " Enter open · ^r rename · ^d delete · ^y duplicate · Esc close ",
                cx.theme.dim,
            ))
            .border_style(cx.theme.border_for(cx.focused))
            .style(cx.theme.base);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        if inner.width < 4 || inner.height < 2 {
            return;
        }
        let with_preview = inner.width >= 60;
        let list_w = if with_preview {
            inner.width * 2 / 5
        } else {
            inner.width
        };
        let list = Rect::new(inner.x, inner.y, list_w, inner.height);
        let mut lines = vec![Line::from(vec![
            Span::styled("> ", cx.theme.accent),
            Span::raw(self.filter.clone()),
        ])];
        let visible = self.visible();
        if visible.is_empty() {
            let msg = if !self.loaded {
                "Loading…"
            } else if self.rows.is_empty() {
                "No saved workspaces (\"Save workspace\" in the palette)"
            } else {
                "No match"
            };
            lines.push(Line::styled(msg, cx.theme.dim));
        }
        let rows = usize::from(list.height.saturating_sub(1));
        let skip = self.cursor.saturating_sub(rows.saturating_sub(1));
        for (i, r) in visible.iter().enumerate().skip(skip).take(rows) {
            let style = if i == self.cursor {
                cx.theme.selection
            } else {
                cx.theme.base
            };
            let marker = if i == self.cursor { "› " } else { "  " };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{}", r.name), style),
                Span::styled(format!("  {}", r.detail), cx.theme.dim),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), list);
        if with_preview && let Some(r) = self.selected() {
            let p = Rect::new(
                inner.x + list_w + 1,
                inner.y,
                inner.width - list_w - 1,
                inner.height,
            );
            let lines: Vec<Line<'_>> = r.preview.iter().map(|l| Line::raw(l.clone())).collect();
            frame.render_widget(Paragraph::new(lines).style(cx.theme.dim), p);
        }
    }
}

/// A name prompt prefilled with `value`.
pub fn name_prompt(title: &str, body: &str, value: &str) -> Modal {
    let mut modal = Modal::prompt(title, body, "Name", false);
    if let crate::widgets::dialog::ModalKind::Prompt {
        input: crate::widgets::dialog::PromptInput::Text(t),
        ..
    } = &mut modal.kind
    {
        *t = crate::widgets::form::TextInput::new(value);
    }
    modal
}

fn delete_confirm(name: &str) -> Modal {
    use crate::widgets::dialog::Button;
    Modal::confirm(
        "Delete workspace?",
        &format!("Delete the workspace \"{name}\"? Open sessions are not affected."),
        vec![
            Button::new("delete", "Delete", 'd').danger(),
            Button::new("cancel", "Cancel", 'c').safe(),
        ],
        1,
        true,
    )
}

/// "A workspace named … exists. Overwrite?"
pub fn overwrite_confirm(name: &str) -> Modal {
    use crate::widgets::dialog::Button;
    Modal::confirm(
        "Overwrite workspace?",
        &format!("A workspace named \"{name}\" already exists. Replace it?"),
        vec![
            Button::new("overwrite", "Overwrite", 'o').danger(),
            Button::new("cancel", "Cancel", 'c').safe(),
        ],
        1,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_matches_subsequences() {
        assert_eq!(fuzzy_score("", "dev"), Some(0));
        assert_eq!(fuzzy_score("dv", "Dev"), Some(2));
        assert_eq!(fuzzy_score("x", "dev"), None);
        assert!(fuzzy_score("pr", "prod") < fuzzy_score("pr", "p-r"));
    }
}
