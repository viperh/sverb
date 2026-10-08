//! M1-14: authentication prompts in the reducer (SPEC §6.1.1 step 4, task §2.3, §2.5).
//!
//! - `SessionEvent::Prompt(p)` queues the prompt ([`AuthPrompts`]); one dialog is on
//!   screen at a time, the focused session's prompt first. The tab bar's 🔑 marker comes
//!   from the session's `AwaitingUser` state (M1-17).
//! - The dialog records its answer; after the dispatch [`App::take_auth_answer`] sends
//!   `Effect::AuthAnswer` (responses or cancel), remembers a credential the user asked to
//!   save, and shows the next prompt.
//! - `SessionEvent::PromptAccepted(kind)` (the login succeeded with that answer) turns a
//!   remembered credential into `Effect::SaveCredential` (only that field changes). A
//!   disconnect or close drops what was remembered, so a wrong password is never stored.
//! - Locking the vault cancels every outstanding prompt (the dialog stack is cleared).

use sverb_conn::{SessionEvent, SessionState};
use sverb_core::vault::LockState;

use super::{App, Effect, SessionId, ToastLevel};
use crate::{
    views::DialogKind,
    widgets::auth_prompt::{AuthDialogOutcome, AuthPromptDialog, AuthReply},
};

impl App {
    /// Session events that concern auth prompts.
    pub(crate) fn auth_on_session(
        &mut self,
        id: SessionId,
        ev: &SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        match ev {
            SessionEvent::Prompt(prompt) => {
                if self.lock_state() != LockState::Unlocked {
                    // Nothing is shown behind the lock: the method is skipped.
                    effects.push(Effect::AuthAnswer {
                        id,
                        reply: AuthReply::Cancel,
                    });
                    return;
                }
                self.auth.push(id, prompt.clone());
                self.show_next_auth_prompt();
            }
            SessionEvent::PromptAccepted(kind) => {
                if let Some(req) = self.auth.accepted(id, kind) {
                    let noun = req.noun();
                    effects.push(Effect::SaveCredential(req));
                    self.push_toast(
                        ToastLevel::Success,
                        format!("Saved the {noun} to the vault"),
                        effects,
                    );
                }
            }
            SessionEvent::State(
                SessionState::Connected { .. }
                | SessionState::Disconnected { .. }
                | SessionState::Closed,
            ) => {
                self.auth.forget(id);
                self.close_auth_dialog(id);
                self.show_next_auth_prompt();
            }
            _ => {}
        }
    }

    fn auth_dialog_open(&self) -> bool {
        self.dialogs
            .iter()
            .any(|d| matches!(d.kind, DialogKind::AuthPrompt(_)))
    }

    /// Show the next queued prompt (the focused session's first) unless one is open.
    pub(crate) fn show_next_auth_prompt(&mut self) {
        if self.auth_dialog_open() {
            return;
        }
        let focused = self.focused_session();
        if let Some((session, prompt)) = self.auth.take_next(focused) {
            self.auth.showing = Some(session);
            self.push_dialog(DialogKind::AuthPrompt(AuthPromptDialog::new(
                session, prompt,
            )));
        }
    }

    /// Remove `id`'s dialog (its session moved on without an answer).
    fn close_auth_dialog(&mut self, id: SessionId) {
        let before = self.dialogs.len();
        self.dialogs
            .retain(|d| !matches!(&d.kind, DialogKind::AuthPrompt(a) if a.session == id));
        if self.dialogs.len() != before {
            self.needs_redraw = true;
        }
    }

    /// After a dispatch: answer the session whose dialog was answered.
    pub(crate) fn take_auth_answer(&mut self, effects: &mut Vec<Effect>) {
        let Some(pos) = self
            .dialogs
            .iter()
            .rposition(|d| matches!(&d.kind, DialogKind::AuthPrompt(a) if a.answer.is_some()))
        else {
            return;
        };
        let DialogKind::AuthPrompt(mut dialog) = self.dialogs.remove(pos).kind else {
            return;
        };
        let session = dialog.session;
        if self.auth.showing == Some(session) {
            self.auth.showing = None;
        }
        let reply = match dialog.answer.take() {
            Some(AuthDialogOutcome::Answered { responses, save }) => {
                if let Some(secret) = responses.first() {
                    self.auth
                        .answered(session, &dialog.prompt.kind, save, secret);
                }
                AuthReply::Responses(responses)
            }
            Some(AuthDialogOutcome::Cancelled) | None => AuthReply::Cancel,
        };
        effects.push(Effect::AuthAnswer { id: session, reply });
        self.needs_redraw = true;
        self.show_next_auth_prompt();
        // M2-04: an install connection's prompt answers go to its run.
        self.reroute_install_answers(effects);
    }

    /// After every event: on lock, cancel every outstanding prompt (their dialogs are
    /// already gone with the rest of the dialog stack).
    pub(crate) fn auth_lock_transition(&mut self, was: LockState, effects: &mut Vec<Effect>) {
        if was != LockState::Unlocked || self.lock_state() == LockState::Unlocked {
            return;
        }
        for id in self.auth.clear() {
            effects.push(Effect::AuthAnswer {
                id,
                reply: AuthReply::Cancel,
            });
        }
        self.dialogs
            .retain(|d| !matches!(d.kind, DialogKind::AuthPrompt(_)));
        // M2-04
        self.reroute_install_answers(effects);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use pretty_assertions::assert_eq;
    use sverb_conn::{AuthPrompt, PromptKind, PromptLine};
    use sverb_core::model::{ItemId, ItemKind};

    use super::*;
    use crate::app::{Config, UiEvent, event::InputEvent};

    const HOST: ItemId = ItemId::from_bytes([1; 16]);

    fn prompt(kind: PromptKind) -> AuthPrompt {
        AuthPrompt::new(
            kind,
            "Authenticate to db".into(),
            vec![PromptLine {
                text: "Password:".into(),
                echo: false,
            }],
        )
    }

    fn password() -> PromptKind {
        PromptKind::Password { host: Some(HOST) }
    }

    fn key(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Vec<Effect> {
        app.handle(UiEvent::Input(InputEvent::Key(KeyEvent::new(code, mods))))
    }

    fn type_text(app: &mut App, s: &str) {
        for c in s.chars() {
            key(app, KeyCode::Char(c), KeyModifiers::NONE);
        }
    }

    fn shown(app: &App) -> Option<SessionId> {
        app.dialogs.iter().rev().find_map(|d| match &d.kind {
            DialogKind::AuthPrompt(a) => Some(a.session),
            _ => None,
        })
    }

    fn answers(effects: &[Effect]) -> Vec<(SessionId, Option<Vec<String>>)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::AuthAnswer { id, reply } => Some((
                    *id,
                    match reply {
                        AuthReply::Responses(r) => {
                            Some(r.iter().map(|s| s.expose().to_owned()).collect())
                        }
                        AuthReply::Cancel => None,
                    },
                )),
                _ => None,
            })
            .collect()
    }

    fn saves(effects: &[Effect]) -> Vec<(ItemId, ItemKind, Vec<String>, String)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::SaveCredential(req) => Some((
                    req.item,
                    req.kind,
                    req.changes()
                        .keys()
                        .iter()
                        .map(|k| (*k).to_owned())
                        .collect(),
                    req.secret.expose().to_owned(),
                )),
                _ => None,
            })
            .collect()
    }

    /// T-09: two panes prompt at once; the focused pane's dialog is shown first, the
    /// other one after it is answered.
    #[test]
    fn t09_prompt_queueing_focused_first() {
        let mut app = App::new(Arc::new(Config::default()));
        let (a, b) = (SessionId(1), SessionId(2));
        app.focus_session(a);
        app.focus_session(b);
        assert_eq!(app.focused_session(), Some(b));
        // Both prompts arrive while another dialog is open (from session a first).
        app.push_dialog(DialogKind::AuthPrompt(AuthPromptDialog::new(
            SessionId(9),
            prompt(password()),
        )));
        app.handle(UiEvent::Session(
            a,
            SessionEvent::Prompt(prompt(password())),
        ));
        app.handle(UiEvent::Session(
            b,
            SessionEvent::Prompt(prompt(PromptKind::KeyboardInteractive)),
        ));
        assert!(app.auth.is_waiting(a) && app.auth.is_waiting(b));
        // The first dialog goes away (its session disconnected): b (focused) is next.
        app.handle(UiEvent::Session(
            SessionId(9),
            SessionEvent::State(SessionState::Closed),
        ));
        assert_eq!(shown(&app), Some(b));
        type_text(&mut app, "123");
        let effects = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(answers(&effects), [(b, Some(vec!["123".to_owned()]))]);
        // Then a's.
        assert_eq!(shown(&app), Some(a));
        let effects = key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(answers(&effects), [(a, None)]);
        assert_eq!(shown(&app), None);
    }

    /// T-10: a wrong password typed with "save" checked → no save; the right one → a
    /// save of the host with only `password` changed, once the login succeeded.
    #[test]
    fn t10_save_password_only_after_success() {
        let mut app = App::new(Arc::new(Config::default()));
        let id = SessionId(3);
        app.focus_session(id);
        let ask = |app: &mut App, pw: &str| {
            app.handle(UiEvent::Session(
                id,
                SessionEvent::Prompt(prompt(password())),
            ));
            type_text(app, pw);
            key(app, KeyCode::Char('s'), KeyModifiers::CONTROL);
            key(app, KeyCode::Enter, KeyModifiers::NONE)
        };
        let effects = ask(&mut app, "wrong");
        assert_eq!(answers(&effects), [(id, Some(vec!["wrong".to_owned()]))]);
        assert!(saves(&effects).is_empty());
        // The server rejects it: the connector asks again (no PromptAccepted).
        let effects = ask(&mut app, "right");
        assert!(saves(&effects).is_empty());
        let effects = app.handle(UiEvent::Session(
            id,
            SessionEvent::PromptAccepted(password()),
        ));
        assert_eq!(
            saves(&effects),
            [(
                HOST,
                ItemKind::Host,
                vec!["password".to_owned()],
                "right".to_owned()
            )]
        );

        // A failed login: nothing is saved, even with "save" checked.
        let effects = ask(&mut app, "nope");
        assert!(saves(&effects).is_empty());
        let effects = app.handle(UiEvent::Session(
            id,
            SessionEvent::State(SessionState::Disconnected {
                reason: sverb_conn::DisconnectReason::Auth,
                // The harness's virtual clock (reducer code never reads the clock).
                at: crate::testing::AppHarness::new(Config::default()).now(),
            }),
        ));
        assert!(saves(&effects).is_empty());
        let effects = app.handle(UiEvent::Session(
            id,
            SessionEvent::PromptAccepted(password()),
        ));
        assert!(saves(&effects).is_empty());
    }

    /// Locking cancels the prompt on screen and the queued ones.
    #[test]
    fn lock_cancels_outstanding_prompts() {
        let mut app = App::new(Arc::new(Config::default()));
        app.focus_session(SessionId(1));
        app.handle(UiEvent::Session(
            SessionId(1),
            SessionEvent::Prompt(prompt(password())),
        ));
        app.handle(UiEvent::Session(
            SessionId(2),
            SessionEvent::Prompt(prompt(password())),
        ));
        assert_eq!(shown(&app), Some(SessionId(1)));
        app.vault.lock = LockState::Locked;
        app.dialogs.clear();
        let mut effects = Vec::new();
        app.auth_lock_transition(LockState::Unlocked, &mut effects);
        let mut got = answers(&effects);
        got.sort_by_key(|(id, _)| *id);
        assert_eq!(got, [(SessionId(1), None), (SessionId(2), None)]);
        // While locked, a new prompt is cancelled at once.
        let effects = app.handle(UiEvent::Session(
            SessionId(3),
            SessionEvent::Prompt(prompt(password())),
        ));
        assert_eq!(answers(&effects), [(SessionId(3), None)]);
        assert_eq!(shown(&app), None);
    }
}
