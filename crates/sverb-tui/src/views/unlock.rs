//! §2.5, §2.6).
//!
//! Plain data plus pure key handling and infallible rendering. The reducer
//! (`app/vault.rs`) owns these forms, turns [`FormAction`]s into vault effects and
//! never holds key material: the only secret here is the typed password, kept in a
//! zeroizing [`MaskedField`] and handed to the vault service once.

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use zeroize::Zeroizing;

use super::dialogs::centered;
use super::first_run::{NewPassword, NewPasswordField, render_meter};
use crate::theme::Theme;

/// A masked text field. `Debug` never prints the text; the buffer is zeroized on drop.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct MaskedField {
    text: Zeroizing<String>,
}

impl fmt::Debug for MaskedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaskedField({} chars)", self.len())
    }
}

impl MaskedField {
    /// Number of characters typed.
    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    /// Nothing typed.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The text (keep borrows short).
    pub fn expose(&self) -> &str {
        &self.text
    }

    /// Append one character (control characters are ignored).
    pub fn push(&mut self, c: char) {
        if !c.is_control() {
            self.text.push(c);
        }
    }

    /// Append pasted text (control characters and newlines are dropped).
    pub fn push_str(&mut self, s: &str) {
        for c in s.chars() {
            self.push(c);
        }
    }

    /// Delete the last character.
    pub fn pop(&mut self) {
        self.text.pop();
    }

    /// Clear (zeroizes the old buffer).
    pub fn clear(&mut self) {
        self.text = Zeroizing::new(String::new());
    }

    /// Take the text out, leaving the field empty.
    pub fn take(&mut self) -> Zeroizing<String> {
        std::mem::take(&mut self.text)
    }

    /// The masked display (`•` per character, capped).
    pub fn masked(&self, max: usize) -> String {
        "•".repeat(self.len().min(max))
    }

    /// Edit with a key: characters and Backspace. Returns whether the text changed.
    pub fn edit(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.push(c);
                true
            }
            KeyCode::Backspace => {
                let had = !self.is_empty();
                self.pop();
                had
            }
            _ => false,
        }
    }
}

/// What a form wants after a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormAction {
    /// Nothing to do (the key was swallowed).
    None,
    /// Redraw (the form changed).
    Changed,
    /// Submit the form.
    Submit,
    /// Cancel the form (change password only).
    Cancel,
    /// "Forgot password?": keyring unlock, then set a new password (§2.6).
    Forgot,
}

/// The unlock prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnlockForm {
    /// The master password.
    pub password: MaskedField,
    /// The last error ("Wrong password", …).
    pub error: Option<String>,
    /// An unlock is running ("Unlocking…"); input is ignored.
    pub busy: Option<String>,
    /// Backoff countdown in whole seconds; input is ignored while set.
    pub countdown: Option<u64>,
    /// Keyring unlock is enabled: offer the keyring recovery.
    pub keyring_enabled: bool,
    /// Sessions are open behind the overlay (changes the title).
    pub sessions_open: bool,
}

impl UnlockForm {
    /// Whether keys are ignored (busy or counting down).
    pub fn input_disabled(&self) -> bool {
        self.busy.is_some() || self.countdown.is_some()
    }

    /// Handle a key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> FormAction {
        if self.input_disabled() {
            return FormAction::None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter if !self.password.is_empty() => FormAction::Submit,
            KeyCode::Esc => {
                self.password.clear();
                self.error = None;
                FormAction::Changed
            }
            KeyCode::Char('r') if ctrl && self.keyring_enabled => FormAction::Forgot,
            _ if self.password.edit(key) => {
                self.error = None;
                FormAction::Changed
            }
            _ => FormAction::None,
        }
    }

    /// Draw the prompt centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme, spinner: char) {
        let mut lines = vec![
            Line::styled(
                if self.sessions_open {
                    "The vault is locked. Sessions stay connected."
                } else {
                    "Enter your master password to unlock sverb."
                },
                theme.base,
            ),
            Line::raw(""),
            Line::from(vec![
                Span::styled("Password: ", theme.dim),
                Span::styled(self.password.masked(32), theme.accent),
                Span::styled(if self.input_disabled() { "" } else { "▏" }, theme.accent),
            ]),
            Line::raw(""),
        ];
        if let Some(busy) = &self.busy {
            lines.push(Line::styled(format!("{spinner} {busy}"), theme.info));
        } else if let Some(secs) = self.countdown {
            lines.push(Line::styled(
                format!("Too many failed attempts. Try again in {secs}s."),
                theme.warn,
            ));
        } else if let Some(err) = &self.error {
            lines.push(Line::styled(err.clone(), theme.error));
        } else {
            lines.push(Line::raw(""));
        }
        let mut hints = "Enter unlock · Esc clear".to_owned();
        if self.keyring_enabled {
            hints.push_str(" · Ctrl-r forgot password? (unlock with keyring)");
        }
        lines.push(Line::styled(hints, theme.dim));
        render_box(frame, area, " 🔒 Unlock sverb ", lines, theme, 64);
    }
}

/// Change the master password (§2.5), or set a new one after a keyring recovery
/// (§2.6: no current password).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangePasswordForm {
    /// The current password; `None` in the keyring recovery flow.
    pub current: Option<MaskedField>,
    /// New password + confirmation + strength meter.
    pub new: NewPassword,
    /// Focused row: 0 = current (if any), then the new-password fields.
    pub focus: usize,
    /// The last error.
    pub error: Option<String>,
    /// A change is running.
    pub busy: bool,
}

impl ChangePasswordForm {
    /// The normal flow (asks for the current password).
    pub fn new() -> Self {
        Self {
            current: Some(MaskedField::default()),
            ..Self::default()
        }
    }

    /// The keyring recovery flow (no current password).
    pub fn recovery() -> Self {
        Self::default()
    }

    fn rows(&self) -> usize {
        usize::from(self.current.is_some()) + 2
    }

    fn new_field(&self) -> Option<NewPasswordField> {
        let offset = usize::from(self.current.is_some());
        match self.focus.checked_sub(offset) {
            Some(0) => Some(NewPasswordField::Password),
            Some(1) => Some(NewPasswordField::Confirm),
            _ => None,
        }
    }

    /// Validate before submitting.
    ///
    /// # Errors
    /// A message for the form.
    pub fn validate(&self) -> Result<(), String> {
        if self.current.as_ref().is_some_and(MaskedField::is_empty) {
            return Err("Enter your current password".into());
        }
        self.new.validate()
    }

    /// Handle a key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> FormAction {
        if self.busy {
            return FormAction::None;
        }
        match key.code {
            KeyCode::Esc => return FormAction::Cancel,
            KeyCode::Tab | KeyCode::Down => {
                self.focus = (self.focus + 1) % self.rows();
                return FormAction::Changed;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.rows() - 1) % self.rows();
                return FormAction::Changed;
            }
            KeyCode::Enter if self.focus + 1 < self.rows() => {
                self.focus += 1;
                return FormAction::Changed;
            }
            KeyCode::Enter => {
                return match self.validate() {
                    Ok(()) => FormAction::Submit,
                    Err(e) => {
                        self.error = Some(e);
                        FormAction::Changed
                    }
                };
            }
            _ => {}
        }
        let changed = match (self.new_field(), self.current.as_mut()) {
            (Some(field), _) => self.new.edit(field, key),
            (None, Some(cur)) => cur.edit(key),
            (None, None) => false,
        };
        if changed {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// Draw the form centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
        let mut lines = Vec::new();
        if self.current.is_none() {
            lines.push(Line::styled(
                "Unlocked with the keyring. Choose a new master password.",
                theme.base,
            ));
            lines.push(Line::raw(""));
        }
        let field = |label: &str, value: String, focused: bool| {
            let style = if focused { theme.accent } else { theme.base };
            Line::from(vec![
                Span::styled(format!("{label:<18}"), theme.dim),
                Span::styled(value, style),
                Span::styled(if focused { "▏" } else { "" }, theme.accent),
            ])
        };
        let mut row = 0;
        if let Some(cur) = &self.current {
            lines.push(field("Current password", cur.masked(32), self.focus == row));
            row += 1;
        }
        lines.push(field(
            "New password",
            self.new.password.masked(32),
            self.focus == row,
        ));
        lines.push(field(
            "Confirm",
            self.new.confirm.masked(32),
            self.focus == row + 1,
        ));
        lines.push(Line::raw(""));
        lines.push(render_meter(&self.new.strength, theme));
        lines.push(Line::raw(""));
        if self.busy {
            lines.push(Line::styled("Changing the password…", theme.info));
        } else if let Some(err) = &self.error {
            lines.push(Line::styled(err.clone(), theme.error));
        } else {
            lines.push(Line::raw(""));
        }
        lines.push(Line::styled(
            "Tab next field · Enter save · Esc cancel",
            theme.dim,
        ));
        render_box(frame, area, " Change master password ", lines, theme, 72);
    }
}

/// A centered, cleared, bordered box sized to its content (at most `max_width`).
pub(crate) fn render_box(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'_>>,
    theme: &Theme,
    max_width: usize,
) {
    let width = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .max(title.chars().count())
        .saturating_add(4)
        .min(max_width);
    // Wrapped lines may need more rows; be generous.
    let extra: usize = lines
        .iter()
        .map(|l| l.width().saturating_sub(1) / width.saturating_sub(4).max(1))
        .sum();
    let height = lines.len().saturating_add(2).saturating_add(extra);
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(theme.base)
            .block(
                Block::bordered()
                    .title(Span::styled(title.to_owned(), theme.title_for(true)))
                    .border_style(theme.border_for(true)),
            ),
        rect,
    );
}

/// The style for a meter cell.
pub(crate) fn meter_style(score: u8, theme: &Theme) -> Style {
    match score {
        0 | 1 => theme.error,
        2 => theme.warn,
        _ => theme.ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn masked_field_never_debugs_its_text() {
        let mut f = MaskedField::default();
        f.push_str("hunter2\n");
        assert_eq!(f.expose(), "hunter2");
        assert_eq!(format!("{f:?}"), "MaskedField(7 chars)");
        assert_eq!(f.masked(3), "•••");
        assert_eq!(f.take().as_str(), "hunter2");
        assert!(f.is_empty());
    }

    #[test]
    fn unlock_form_keys() {
        let mut form = UnlockForm::default();
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::None);
        assert_eq!(
            form.handle_key(&key(KeyCode::Char('q'))),
            FormAction::Changed
        );
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::Submit);
        let ctrl_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);
        assert_eq!(form.handle_key(&ctrl_r), FormAction::None);
        form.keyring_enabled = true;
        assert_eq!(form.handle_key(&ctrl_r), FormAction::Forgot);
        form.countdown = Some(3);
        assert_eq!(form.handle_key(&key(KeyCode::Char('x'))), FormAction::None);
        assert_eq!(form.password.expose(), "q");
    }

    #[test]
    fn change_form_validates() {
        let mut form = ChangePasswordForm::new();
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::Changed);
        assert_eq!(form.focus, 1);
        form.focus = 2;
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::Changed);
        assert!(form.error.is_some());
        assert_eq!(form.handle_key(&key(KeyCode::Esc)), FormAction::Cancel);
    }
}
