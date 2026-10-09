//! M1-04: the first-run screen (task M1-04 §2.2, SPEC §1.1, §11.2): a welcome
//! explanation, master password + confirmation, a zxcvbn strength meter, the
//! no-recovery warning, and "Also unlock with OS keyring" when a keyring works.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
};
use sverb_core::vault::{MIN_SCORE, PasswordStrength, estimate, password::NO_RECOVERY_WARNING};

use super::unlock::{FormAction, MaskedField, meter_style, render_box};
use crate::theme::Theme;

/// Words a master password should not be built from.
const USER_INPUTS: [&str; 1] = ["sverb"];

/// Which of the two new-password fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewPasswordField {
    /// The password.
    Password,
    /// The confirmation.
    Confirm,
}

/// A new password with confirmation and a live strength estimate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewPassword {
    /// The password.
    pub password: MaskedField,
    /// The confirmation.
    pub confirm: MaskedField,
    /// zxcvbn estimate of `password` (updated on every edit).
    pub strength: PasswordStrength,
}

impl NewPassword {
    /// Edit one field with a key; returns whether it changed.
    pub fn edit(&mut self, field: NewPasswordField, key: &KeyEvent) -> bool {
        let changed = match field {
            NewPasswordField::Password => self.password.edit(key),
            NewPasswordField::Confirm => self.confirm.edit(key),
        };
        if changed && field == NewPasswordField::Password {
            self.strength = estimate(self.password.expose(), &USER_INPUTS);
        }
        changed
    }

    /// Non-empty, matching and strong enough (score ≥ 3).
    ///
    /// # Errors
    /// A message for the form (with zxcvbn feedback for weak passwords).
    pub fn validate(&self) -> Result<(), String> {
        if self.password.is_empty() {
            return Err("Enter a master password".into());
        }
        if self.password.expose() != self.confirm.expose() {
            return Err("The passwords do not match".into());
        }
        if self.strength.score < MIN_SCORE {
            let feedback = self.strength.feedback();
            return Err(if feedback.is_empty() {
                format!(
                    "Too weak ({}); use a longer passphrase",
                    self.strength.label()
                )
            } else {
                format!("Too weak ({}): {feedback}", self.strength.label())
            });
        }
        Ok(())
    }
}

/// Focus on the first-run screen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FirstRunFocus {
    /// The password field.
    #[default]
    Password,
    /// The confirmation field.
    Confirm,
    /// The keyring checkbox (only when a keyring is available).
    Keyring,
}

/// The first-run form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirstRunForm {
    /// New password, confirmation, strength.
    pub new: NewPassword,
    /// Focused row.
    pub focus: FirstRunFocus,
    /// A keyring works on this machine (probed by writing and deleting an entry).
    pub keyring_available: bool,
    /// "Also unlock with OS keyring".
    pub use_keyring: bool,
    /// The last validation or creation error.
    pub error: Option<String>,
    /// Creating the vault ("Creating your vault…").
    pub busy: bool,
}

impl FirstRunForm {
    /// A form; the checkbox is offered only if `keyring_available`.
    pub fn new(keyring_available: bool) -> Self {
        Self {
            keyring_available,
            ..Self::default()
        }
    }

    fn next(&self) -> FirstRunFocus {
        match self.focus {
            FirstRunFocus::Password => FirstRunFocus::Confirm,
            FirstRunFocus::Confirm if self.keyring_available => FirstRunFocus::Keyring,
            FirstRunFocus::Confirm | FirstRunFocus::Keyring => FirstRunFocus::Password,
        }
    }

    fn prev(&self) -> FirstRunFocus {
        match self.focus {
            FirstRunFocus::Password if self.keyring_available => FirstRunFocus::Keyring,
            FirstRunFocus::Password | FirstRunFocus::Keyring => FirstRunFocus::Confirm,
            FirstRunFocus::Confirm => FirstRunFocus::Password,
        }
    }

    /// Handle a key.
    pub fn handle_key(&mut self, key: &KeyEvent) -> FormAction {
        if self.busy {
            return FormAction::None;
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                self.focus = self.next();
                return FormAction::Changed;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = self.prev();
                return FormAction::Changed;
            }
            KeyCode::Enter if self.focus == FirstRunFocus::Password => {
                self.focus = FirstRunFocus::Confirm;
                return FormAction::Changed;
            }
            KeyCode::Enter => {
                return match self.new.validate() {
                    Ok(()) => FormAction::Submit,
                    Err(e) => {
                        self.error = Some(e);
                        FormAction::Changed
                    }
                };
            }
            KeyCode::Char(' ') if self.focus == FirstRunFocus::Keyring => {
                self.use_keyring = !self.use_keyring;
                return FormAction::Changed;
            }
            _ => {}
        }
        let changed = match self.focus {
            FirstRunFocus::Password => self.new.edit(NewPasswordField::Password, key),
            FirstRunFocus::Confirm => self.new.edit(NewPasswordField::Confirm, key),
            FirstRunFocus::Keyring => false,
        };
        if changed {
            self.error = None;
            FormAction::Changed
        } else {
            FormAction::None
        }
    }

    /// Draw the screen centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme, spinner: char) {
        let field = |label: &str, value: String, focused: bool| {
            let style = if focused { theme.accent } else { theme.base };
            Line::from(vec![
                Span::styled(format!("{label:<18}"), theme.dim),
                Span::styled(value, style),
                Span::styled(if focused { "▏" } else { "" }, theme.accent),
            ])
        };
        let mut lines = vec![
            Line::styled(
                "sverb keeps your hosts, keys and snippets encrypted on this machine.",
                theme.base,
            ),
            Line::styled(
                "Local-only by default: no account and no server. Choose a master password.",
                theme.base,
            ),
            Line::raw(""),
            field(
                "Master password",
                self.new.password.masked(32),
                self.focus == FirstRunFocus::Password,
            ),
            field(
                "Confirm",
                self.new.confirm.masked(32),
                self.focus == FirstRunFocus::Confirm,
            ),
            Line::raw(""),
            render_meter(&self.new.strength, theme),
        ];
        if self.keyring_available {
            let focused = self.focus == FirstRunFocus::Keyring;
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(
                    if self.use_keyring { "[x] " } else { "[ ] " },
                    if focused { theme.accent } else { theme.base },
                ),
                Span::styled("Also unlock with OS keyring", theme.base),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(NO_RECOVERY_WARNING, theme.warn));
        lines.push(Line::raw(""));
        if self.busy {
            lines.push(Line::styled(
                format!("{spinner} Creating your vault…"),
                theme.info,
            ));
        } else if let Some(err) = &self.error {
            lines.push(Line::styled(err.clone(), theme.error));
        } else {
            lines.push(Line::raw(""));
        }
        let hints = if self.keyring_available {
            "Tab next field · Space toggle · Enter create"
        } else {
            "Tab next field · Enter create"
        };
        lines.push(Line::styled(hints, theme.dim));
        render_box(frame, area, " Welcome to sverb ", lines, theme, 80);
    }
}

/// `Strength: ████░ strong — feedback`.
pub(crate) fn render_meter(strength: &PasswordStrength, theme: &Theme) -> Line<'static> {
    let filled = usize::from(strength.score.min(4)) + 1;
    let style = meter_style(strength.score, theme);
    let mut spans = vec![
        Span::styled("Strength          ", theme.dim),
        Span::styled("█".repeat(filled), style),
        Span::styled("░".repeat(5 - filled), theme.dim),
        Span::styled(format!(" {}", strength.label()), style),
    ];
    let feedback = strength.feedback();
    if !feedback.is_empty() && strength.score < MIN_SCORE {
        spans.push(Span::styled(format!(" — {feedback}"), theme.dim));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(form: &mut FirstRunForm, s: &str) {
        for c in s.chars() {
            form.handle_key(&key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn weak_and_mismatched_passwords_are_refused() {
        let mut form = FirstRunForm::new(false);
        type_str(&mut form, "password123");
        assert!(form.new.strength.score < MIN_SCORE);
        form.handle_key(&key(KeyCode::Enter));
        type_str(&mut form, "password123");
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::Changed);
        assert!(
            form.error
                .as_deref()
                .is_some_and(|e| e.starts_with("Too weak"))
        );

        let mut form = FirstRunForm::new(true);
        type_str(&mut form, "correct horse battery staple violin");
        form.handle_key(&key(KeyCode::Tab));
        type_str(&mut form, "nope");
        form.handle_key(&key(KeyCode::Enter));
        assert_eq!(form.error.as_deref(), Some("The passwords do not match"));
    }

    #[test]
    fn strong_matching_password_submits_and_checkbox_toggles() {
        let mut form = FirstRunForm::new(true);
        type_str(&mut form, "correct horse battery staple violin");
        form.handle_key(&key(KeyCode::Tab));
        type_str(&mut form, "correct horse battery staple violin");
        form.handle_key(&key(KeyCode::Tab));
        assert_eq!(form.focus, FirstRunFocus::Keyring);
        form.handle_key(&key(KeyCode::Char(' ')));
        assert!(form.use_keyring);
        assert_eq!(form.handle_key(&key(KeyCode::Enter)), FormAction::Submit);
    }
}
