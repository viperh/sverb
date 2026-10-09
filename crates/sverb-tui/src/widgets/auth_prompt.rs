//! M1-14: the authentication prompt dialog and the per-session prompt queue
//! (SPEC §6.1.1 step 4, task M1-14 §2.3).
//!
//! - [`AuthPromptDialog`]: one dialog per request — "Authenticate to `<label>`", the
//!   server's name and instruction (already sanitized by the connector:
//!   `sverb_conn::ssh::sanitize_server_text`), one field per prompt line (masked unless
//!   the server allows echo; `ctrl-r` reveals), and the "Save … to vault" checkbox for a
//!   password (saved inline on the host) or a key passphrase (saved on the Key item).
//!   `Tab`/`↑↓` move, `Enter` goes to the next field or submits, `Space` (on the
//!   checkbox) or `ctrl-s` toggles saving, `Esc` cancels (the method is skipped).
//! - [`AuthPrompts`]: prompts waiting for the screen (at most one per session; the
//!   focused session's comes first) and the credentials the user asked to save. A
//!   credential is saved only when its session reports `SessionEvent::PromptAccepted`
//!   (the login succeeded with it), so a wrong password is never stored.
//!
//! Answers are [`SecretValue`]s (zeroized on drop); the dialog clears its inputs when
//! it is answered.

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_conn::{AuthPrompt, PromptKind};
use sverb_core::model::{ItemId, ItemKind};

use crate::{
    app::SessionId,
    views::RenderCx,
    widgets::{
        dialog::PromptInput,
        form::{FieldChanges, FieldValue, SecretInput, SecretValue, TextInput},
        truncate, width, wrap,
    },
};

/// The user's answer to an auth prompt, for `SessionCmd::AuthAnswer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthReply {
    /// One response per prompt line.
    Responses(Vec<SecretValue>),
    /// Cancelled: the connector skips the method.
    Cancel,
}

impl AuthReply {
    /// As the session command's answer.
    pub fn into_answer(self) -> sverb_conn::AuthAnswer {
        match self {
            Self::Responses(values) => {
                sverb_conn::AuthAnswer::Responses(values.into_iter().map(|v| v.0).collect())
            }
            Self::Cancel => sverb_conn::AuthAnswer::Cancel,
        }
    }
}

/// A credential to store after a successful login: one secret field of one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveCredential {
    /// The session it was typed for (failures are reported there).
    pub session: SessionId,
    /// The host (password) or Key item (passphrase).
    pub item: ItemId,
    /// Its kind.
    pub kind: ItemKind,
    /// The field: `password` or `passphrase`.
    pub field: &'static str,
    /// The value.
    pub secret: SecretValue,
}

impl SaveCredential {
    /// The item change: only this field.
    pub fn changes(&self) -> FieldChanges {
        FieldChanges(vec![(
            self.field.to_owned(),
            FieldValue::Secret(self.secret.clone()),
        )])
    }

    /// What the toast calls it.
    pub fn noun(&self) -> &'static str {
        if self.kind == ItemKind::Key {
            "passphrase"
        } else {
            "password"
        }
    }
}

/// What [`AuthPromptDialog::handle_key`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDialogOutcome {
    /// Submitted: the answers, and whether to save the (single) secret.
    Answered {
        /// One per prompt line.
        responses: Vec<SecretValue>,
        /// "Save to vault" was checked.
        save: bool,
    },
    /// `Esc`.
    Cancelled,
}

/// The dialog's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPromptDialog {
    /// The session asking.
    pub session: SessionId,
    /// The prompt (title, name, instruction, lines, kind).
    pub prompt: AuthPrompt,
    /// One input per prompt line.
    pub fields: Vec<PromptInput>,
    /// The "save to vault" checkbox, when the credential can be saved.
    pub save: Option<bool>,
    /// The focused row: a field index, or `fields.len()` for the checkbox.
    pub focus: usize,
    /// Set when answered; the reducer takes it (`App::take_auth_answer`).
    pub answer: Option<AuthDialogOutcome>,
}

/// The checkbox label for `kind`, if it can be saved.
pub fn save_label(kind: &PromptKind) -> Option<&'static str> {
    kind.save_target()?;
    match kind {
        PromptKind::Password { .. } => Some("Save password to vault"),
        PromptKind::Passphrase { .. } => Some("Save passphrase to vault"),
        _ => None,
    }
}

impl AuthPromptDialog {
    /// A dialog for `prompt` from `session`.
    pub fn new(session: SessionId, prompt: AuthPrompt) -> Self {
        let fields = prompt
            .prompts
            .iter()
            .map(|p| {
                if p.echo {
                    PromptInput::Text(TextInput::default())
                } else {
                    PromptInput::Secret(SecretInput::default())
                }
            })
            .collect();
        let save = save_label(&prompt.kind).map(|_| false);
        Self {
            session,
            prompt,
            fields,
            save,
            focus: 0,
            answer: None,
        }
    }

    fn rows(&self) -> usize {
        self.fields.len() + usize::from(self.save.is_some())
    }

    fn on_checkbox(&self) -> bool {
        self.save.is_some() && self.focus == self.fields.len()
    }

    fn toggle_save(&mut self) {
        if let Some(s) = &mut self.save {
            *s = !*s;
        }
    }

    fn submit(&mut self) -> AuthDialogOutcome {
        let responses = self
            .fields
            .iter_mut()
            .map(|f| {
                let v = match f {
                    PromptInput::Text(t) => SecretValue::from(t.text()),
                    PromptInput::Secret(s) => s.value().clone(),
                };
                // Clear the inputs (the old values are zeroized as they drop).
                *f = match f {
                    PromptInput::Text(_) => PromptInput::Text(TextInput::default()),
                    PromptInput::Secret(_) => PromptInput::Secret(SecretInput::default()),
                };
                v
            })
            .collect();
        AuthDialogOutcome::Answered {
            responses,
            save: self.save.unwrap_or(false),
        }
    }

    /// Apply one key. `Some(outcome)`: the dialog is answered and should close.
    pub fn handle_key(&mut self, key: &KeyEvent) -> Option<AuthDialogOutcome> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let rows = self.rows().max(1);
        match key.code {
            KeyCode::Esc => return Some(AuthDialogOutcome::Cancelled),
            KeyCode::Char('s') if ctrl => self.toggle_save(),
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % rows,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + rows - 1) % rows,
            KeyCode::Enter => {
                if self.focus + 1 < self.fields.len() {
                    self.focus += 1;
                } else {
                    return Some(self.submit());
                }
            }
            KeyCode::Char(' ') if self.on_checkbox() => self.toggle_save(),
            _ => {
                if let Some(f) = self.fields.get_mut(self.focus) {
                    match f {
                        PromptInput::Text(t) => {
                            t.handle_key(key);
                        }
                        PromptInput::Secret(s) => {
                            s.handle_key(key);
                        }
                    }
                }
            }
        }
        // Leaving a secret field masks it again.
        for (i, f) in self.fields.iter_mut().enumerate() {
            if let PromptInput::Secret(s) = f
                && i != self.focus
            {
                s.blur();
            }
        }
        None
    }

    /// Insert a paste into the focused field.
    pub fn paste(&mut self, text: &str) {
        match self.fields.get_mut(self.focus) {
            Some(PromptInput::Text(t)) => {
                t.insert_str(text);
            }
            Some(PromptInput::Secret(s)) => {
                s.insert_str(text);
            }
            None => {}
        }
    }

    /// Draw the dialog centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let max_w = (usize::from(area.width) * 4 / 5).max(10);
        let label_w = self
            .prompt
            .prompts
            .iter()
            .map(|p| width(p.text.trim_end()))
            .max()
            .unwrap_or(0)
            .min(30);
        let body_w = self
            .prompt
            .instruction
            .lines()
            .chain(std::iter::once(self.prompt.name.as_str()))
            .map(width)
            .max()
            .unwrap_or(0);
        let inner_w = body_w
            .max(label_w + 24)
            .max(width(&self.prompt.title) + 2)
            .max(44)
            .min(max_w.saturating_sub(4))
            .max(1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        if !self.prompt.name.is_empty() {
            lines.push(Line::styled(
                truncate(&self.prompt.name, inner_w),
                theme.accent,
            ));
        }
        for para in self.prompt.instruction.split('\n') {
            if para.trim().is_empty() {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                }
                continue;
            }
            for l in wrap(para, inner_w, 12) {
                lines.push(Line::styled(l, theme.base));
            }
        }
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        for (i, (p, f)) in self.prompt.prompts.iter().zip(&self.fields).enumerate() {
            let label = format!("{:<label_w$} ", truncate(p.text.trim_end(), label_w));
            let w = inner_w.saturating_sub(width(&label)).max(1);
            let focused = cx.focused && i == self.focus;
            let mut spans = vec![Span::styled(label, theme.accent)];
            let field = match f {
                PromptInput::Text(t) => t.line(w, theme.base, focused),
                PromptInput::Secret(s) => s.line(w, theme.base, focused),
            };
            spans.extend(field.spans);
            lines.push(Line::from(spans));
        }
        if let (Some(checked), Some(label)) = (self.save, save_label(&self.prompt.kind)) {
            lines.push(Line::raw(""));
            let mark = if checked { "[x]" } else { "[ ]" };
            let style = if self.on_checkbox() && cx.focused {
                theme.selection
            } else {
                theme.base
            };
            lines.push(Line::styled(format!("{mark} {label}"), style));
        }
        lines.push(Line::raw(""));
        let mut hint = String::from("enter ok · tab next · esc cancel");
        if self.save.is_some() {
            hint.push_str(" · ctrl-s save");
        }
        if self
            .fields
            .iter()
            .any(|f| matches!(f, PromptInput::Secret(_)))
        {
            hint.push_str(" · ctrl-r reveal");
        }
        lines.push(Line::styled(truncate(&hint, inner_w), theme.dim));

        let h = (lines.len() + 2).min(usize::from(area.height));
        let rect = crate::views::dialogs::centered(area, inner_w + 4, h);
        if rect.width < 3 || rect.height < 3 {
            return;
        }
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(
                format!(" {} ", truncate(&self.prompt.title, inner_w)),
                theme.title_for(true),
            ))
            .border_style(theme.border_focused);
        let inner = block.inner(rect);
        frame.render_widget(block.style(theme.base), rect);
        let inner = Rect {
            x: inner.x + 1,
            width: inner.width.saturating_sub(2),
            ..inner
        };
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

/// Prompts waiting to be shown and credentials waiting for a successful login.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthPrompts {
    /// Waiting prompts in arrival order, at most one per session (a newer prompt from
    /// the same session replaces the older one).
    pub queue: Vec<(SessionId, AuthPrompt)>,
    /// Typed credentials the user asked to save, per session, until it reports
    /// `PromptAccepted` (then saved) or disconnects (then dropped).
    pub to_save: BTreeMap<SessionId, Vec<(PromptKind, SecretValue)>>,
    /// The session whose prompt is on screen (its dialog is on the dialog stack).
    pub showing: Option<SessionId>,
}

impl AuthPrompts {
    /// Queue `prompt` from `id`.
    pub fn push(&mut self, id: SessionId, prompt: AuthPrompt) {
        self.queue.retain(|(s, _)| *s != id);
        self.queue.push((id, prompt));
    }

    /// The next prompt to show: the focused session's, else the oldest.
    pub fn take_next(&mut self, focused: Option<SessionId>) -> Option<(SessionId, AuthPrompt)> {
        let pos = focused
            .and_then(|f| self.queue.iter().position(|(s, _)| *s == f))
            .or_else(|| (!self.queue.is_empty()).then_some(0))?;
        Some(self.queue.remove(pos))
    }

    /// The user answered a prompt of `kind` from `id`: remember `secret` when `save` is
    /// checked; otherwise forget an earlier saved answer of the same kind (it was
    /// wrong, or the user changed their mind).
    pub fn answered(&mut self, id: SessionId, kind: &PromptKind, save: bool, secret: &SecretValue) {
        if kind.save_target().is_none() {
            return;
        }
        let entry = self.to_save.entry(id).or_default();
        entry.retain(|(k, _)| k != kind);
        if save {
            entry.push((kind.clone(), secret.clone()));
        }
        if entry.is_empty() {
            self.to_save.remove(&id);
        }
    }

    /// Session `id` logged in with the answer to `kind`: what to save, if the user asked.
    pub fn accepted(&mut self, id: SessionId, kind: &PromptKind) -> Option<SaveCredential> {
        let entry = self.to_save.get_mut(&id)?;
        let pos = entry.iter().position(|(k, _)| k == kind)?;
        let (kind, secret) = entry.remove(pos);
        if entry.is_empty() {
            self.to_save.remove(&id);
        }
        let item = kind.save_target()?;
        let (item_kind, field) = match kind {
            PromptKind::Passphrase { .. } => (ItemKind::Key, "passphrase"),
            _ => (ItemKind::Host, "password"),
        };
        Some(SaveCredential {
            session: id,
            item,
            kind: item_kind,
            field,
            secret,
        })
    }

    /// Forget everything about `id` (it connected, disconnected or closed).
    pub fn forget(&mut self, id: SessionId) {
        self.queue.retain(|(s, _)| *s != id);
        self.to_save.remove(&id);
        if self.showing == Some(id) {
            self.showing = None;
        }
    }

    /// Whether `id` has a prompt waiting.
    pub fn is_waiting(&self, id: SessionId) -> bool {
        self.queue.iter().any(|(s, _)| *s == id)
    }

    /// Drop every waiting and shown prompt and every saved answer (the vault locked);
    /// returns the sessions whose prompts were dropped (they get a `Cancel`).
    pub fn clear(&mut self) -> Vec<SessionId> {
        self.to_save.clear();
        self.showing
            .take()
            .into_iter()
            .chain(self.queue.drain(..).map(|(s, _)| s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use sverb_conn::PromptLine;

    use super::*;
    use crate::widgets::test_util::{draw_with, text};

    const HOST: ItemId = ItemId::from_bytes([1; 16]);
    const KEY: ItemId = ItemId::from_bytes([2; 16]);

    fn password_prompt() -> AuthPrompt {
        let mut p = AuthPrompt::new(
            PromptKind::Password { host: Some(HOST) },
            "Authenticate to db".into(),
            vec![PromptLine {
                text: "Password:".into(),
                echo: false,
            }],
        );
        p.instruction = "Password for deploy@db.example".into();
        p
    }

    fn kbd_prompt() -> AuthPrompt {
        let mut p = AuthPrompt::new(
            PromptKind::KeyboardInteractive,
            "Authenticate to db".into(),
            vec![
                PromptLine {
                    text: "Username:".into(),
                    echo: true,
                },
                PromptLine {
                    text: "Verification code:".into(),
                    echo: false,
                },
            ],
        );
        p.name = "Duo".into();
        p.instruction = "Enter the code from your app".into();
        p
    }

    fn press(d: &mut AuthPromptDialog, code: KeyCode) -> Option<AuthDialogOutcome> {
        d.handle_key(&KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(d: &mut AuthPromptDialog, s: &str) {
        for c in s.chars() {
            assert_eq!(press(d, KeyCode::Char(c)), None);
        }
    }

    fn secrets(o: &AuthDialogOutcome) -> (Vec<String>, bool) {
        match o {
            AuthDialogOutcome::Answered { responses, save } => (
                responses.iter().map(|r| r.expose().to_owned()).collect(),
                *save,
            ),
            AuthDialogOutcome::Cancelled => panic!("cancelled"),
        }
    }

    #[test]
    fn password_dialog_answers_and_offers_saving() {
        let mut d = AuthPromptDialog::new(SessionId(1), password_prompt());
        assert_eq!(d.save, Some(false));
        type_text(&mut d, "hunter 2");
        // Space types into the field; ctrl-s toggles saving.
        d.handle_key(&KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        let out = press(&mut d, KeyCode::Enter).unwrap();
        assert_eq!(secrets(&out), (vec!["hunter 2".to_owned()], true));
        // The inputs are cleared once answered.
        assert!(matches!(&d.fields[0], PromptInput::Secret(s) if s.value().is_empty()));

        // The checkbox row: Space toggles, Enter submits.
        let mut d = AuthPromptDialog::new(SessionId(1), password_prompt());
        type_text(&mut d, "pw");
        press(&mut d, KeyCode::Tab);
        press(&mut d, KeyCode::Char(' '));
        assert_eq!(d.save, Some(true));
        press(&mut d, KeyCode::Char(' '));
        let out = press(&mut d, KeyCode::Enter).unwrap();
        assert_eq!(secrets(&out), (vec!["pw".to_owned()], false));

        let mut d = AuthPromptDialog::new(SessionId(1), password_prompt());
        assert_eq!(
            press(&mut d, KeyCode::Esc),
            Some(AuthDialogOutcome::Cancelled)
        );
    }

    #[test]
    fn kbd_dialog_has_one_field_per_prompt_and_no_save() {
        let mut d = AuthPromptDialog::new(SessionId(1), kbd_prompt());
        assert_eq!(d.save, None);
        assert!(matches!(d.fields[0], PromptInput::Text(_)));
        assert!(matches!(d.fields[1], PromptInput::Secret(_)));
        type_text(&mut d, "me");
        // Enter on the first field moves on.
        assert_eq!(press(&mut d, KeyCode::Enter), None);
        d.paste("123456");
        let out = press(&mut d, KeyCode::Enter).unwrap();
        assert_eq!(
            secrets(&out),
            (vec!["me".to_owned(), "123456".to_owned()], false)
        );
    }

    #[test]
    fn renders_title_name_instruction_masked_fields_and_checkbox() {
        let mut d = AuthPromptDialog::new(SessionId(1), kbd_prompt());
        type_text(&mut d, "me");
        press(&mut d, KeyCode::Tab);
        type_text(&mut d, "999");
        let buf = draw_with(80, 20, false, |f, cx| d.render(f, f.area(), cx));
        let screen = text(&buf);
        assert!(screen.contains("Authenticate to db"), "{screen}");
        assert!(screen.contains("Duo"));
        assert!(screen.contains("Enter the code from your app"));
        assert!(screen.contains("Username:"));
        assert!(screen.contains("me"));
        assert!(screen.contains("•••"));
        assert!(!screen.contains("999"));

        let d = AuthPromptDialog::new(SessionId(1), password_prompt());
        let screen = text(&draw_with(80, 20, true, |f, cx| d.render(f, f.area(), cx)));
        assert!(screen.contains("[ ] Save password to vault"), "{screen}");
        assert!(screen.contains("Password for deploy@db.example"));
        // Tiny areas never panic.
        for (w, h) in [(0, 0), (1, 1), (5, 3), (20, 4)] {
            let _ = draw_with(w, h, false, |f, cx| d.render(f, f.area(), cx));
        }
    }

    #[test]
    fn unsaved_targets_offer_no_saving() {
        let mut p = password_prompt();
        p.kind = PromptKind::Password { host: None };
        assert_eq!(AuthPromptDialog::new(SessionId(1), p).save, None);
        let p = AuthPrompt::new(
            PromptKind::Passphrase {
                key: Some(KEY),
                label: "work".into(),
            },
            "t".into(),
            Vec::new(),
        );
        assert_eq!(save_label(&p.kind), Some("Save passphrase to vault"));
    }

    /// T-09 (queue): two panes prompt; the focused one's prompt comes first.
    #[test]
    fn t09_queue_shows_the_focused_session_first() {
        let mut q = AuthPrompts::default();
        q.push(SessionId(1), password_prompt());
        q.push(SessionId(2), kbd_prompt());
        assert!(q.is_waiting(SessionId(1)) && q.is_waiting(SessionId(2)));
        assert_eq!(q.take_next(Some(SessionId(2))).unwrap().0, SessionId(2));
        assert_eq!(q.take_next(Some(SessionId(2))).unwrap().0, SessionId(1));
        assert_eq!(q.take_next(None), None);
        // A newer prompt from the same session replaces the older one.
        q.push(SessionId(1), password_prompt());
        q.push(SessionId(3), password_prompt());
        q.push(SessionId(1), kbd_prompt());
        assert_eq!(q.queue.len(), 2);
        assert_eq!(q.take_next(None).unwrap().0, SessionId(3));
        q.showing = Some(SessionId(3));
        assert_eq!(q.clear(), [SessionId(3), SessionId(1)]);
        assert_eq!(q.showing, None);
    }

    /// T-10 (queue): a wrong password typed with "save" is never saved; the right one
    /// is, with only `password` changed.
    #[test]
    fn t10_only_accepted_credentials_are_saved() {
        let id = SessionId(4);
        let kind = PromptKind::Password { host: Some(HOST) };
        let mut q = AuthPrompts::default();
        q.answered(id, &kind, true, &SecretValue::from("wrong"));
        // The server rejects it and asks again; the user types the right one.
        q.answered(id, &kind, true, &SecretValue::from("right"));
        let save = q.accepted(id, &kind).unwrap();
        assert_eq!(save.item, HOST);
        assert_eq!(save.kind, ItemKind::Host);
        assert_eq!(save.secret.expose(), "right");
        assert_eq!(save.changes().keys(), ["password"]);
        assert_eq!(q.accepted(id, &kind), None);

        // Typed right without "save" after a saved wrong one: nothing is stored.
        q.answered(id, &kind, true, &SecretValue::from("wrong"));
        q.answered(id, &kind, false, &SecretValue::from("right"));
        assert_eq!(q.accepted(id, &kind), None);

        // A disconnect drops what was waiting.
        q.answered(id, &kind, true, &SecretValue::from("x"));
        q.forget(id);
        assert_eq!(q.accepted(id, &kind), None);

        // Passphrases are saved on the key.
        let pk = PromptKind::Passphrase {
            key: Some(KEY),
            label: "work".into(),
        };
        q.answered(id, &pk, true, &SecretValue::from("pp"));
        let save = q.accepted(id, &pk).unwrap();
        assert_eq!(
            (save.item, save.kind, save.field),
            (KEY, ItemKind::Key, "passphrase")
        );
        assert_eq!(save.noun(), "passphrase");

        // keyboard-interactive answers are never kept.
        q.answered(
            id,
            &PromptKind::KeyboardInteractive,
            true,
            &SecretValue::from("otp"),
        );
        assert!(q.to_save.is_empty());
    }

    #[test]
    fn replies_become_session_answers() {
        let r = AuthReply::Responses(vec![SecretValue::from("a"), SecretValue::from("b")]);
        match r.into_answer() {
            sverb_conn::AuthAnswer::Responses(v) => {
                assert_eq!(v.iter().map(|s| s.expose()).collect::<Vec<_>>(), ["a", "b"]);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            AuthReply::Cancel.into_answer(),
            sverb_conn::AuthAnswer::Cancel
        ));
    }
}
