//! Local terminal panes in the reducer.
//!
//! - `leader t` (`new_local_tab`) opens a local shell
//!   (`Effect::OpenSession(SessionSpec::Local)`) and focuses its pane. Tabs arrive with
//! - When the shell exits (`State(Disconnected { Exited(code) })`) the pane shows
//!   "Process exited (code N) — `[Enter]` restart · leader x close" and is no longer
//!   live: plain keys are swallowed, never forwarded and never acted on, so typing
//!   `x…` into a just-exited shell can't close it (§4.4).
//!   `Enter` restarts the shell in the same pane (`Effect::ReconnectSession`), and
//!   `leader x` closes it.
//!
//! [`Tabs::sessions`]: super::Tabs::sessions

use crossterm::event::KeyCode;
use sverb_conn::{DisconnectReason, LocalSpec, SessionSpec, SessionState};

use super::{App, Effect, Focus, SessionId};
use crate::{
    keymap::chord::{KeyChord, Mods},
    views::{MainView, Region},
};

/// Pane size used before the terminal size is known.
const FALLBACK_SIZE: (u16, u16) = (80, 24);

impl App {
    /// `new_local_tab`: open a local shell and focus its pane.
    pub(crate) fn open_local_session(&mut self, effects: &mut Vec<Effect>) -> SessionId {
        let id = loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        };
        let (cols, rows) = self.session_pane_size();
        effects.push(Effect::OpenSession {
            id,
            spec: SessionSpec::Local(LocalSpec::default()),
            cols,
            rows,
        });
        self.focus_session(id);
        // Local sessions follow the global `recording.enabled`.
        self.auto_record(id, self.config.recording.enabled, effects);
        id
    }

    /// real pane rect; the session is resized when it is first drawn.
    fn session_pane_size(&self) -> (u16, u16) {
        let main = self.shell_rects().main;
        if main.width > 2 && main.height > 2 {
            (main.width - 2, main.height - 2)
        } else {
            FALLBACK_SIZE
        }
    }

    /// The exit code of the focused pane's process, if it exited.
    pub(crate) fn exited_code(&self, id: SessionId) -> Option<i32> {
        self.tabs.exited.get(&id).copied()
    }

    /// Whether `id`'s pane is an exited session (no input goes to it).
    pub(crate) fn is_exited(&self, id: SessionId) -> bool {
        self.tabs.exited.contains_key(&id)
    }

    /// Track exits and restarts (called for every `State` event).
    pub(crate) fn on_local_state(&mut self, id: SessionId, state: &SessionState) {
        match state {
            SessionState::Disconnected {
                reason: DisconnectReason::Exited(code),
                ..
            } if self.tabs.sessions.contains(&id) => {
                self.tabs.exited.insert(id, *code);
                self.needs_redraw = true;
            }
            SessionState::Resolving | SessionState::Connected { .. } | SessionState::Closed
                if self.tabs.exited.remove(&id).is_some() =>
            {
                self.needs_redraw = true;
            }
            _ => {}
        }
    }

    /// A key on a focused pane without a live session (Normal mode): `Enter` restarts
    /// an exited pane; everything else is swallowed.
    pub(crate) fn on_dead_pane_key(&mut self, chord: KeyChord, effects: &mut Vec<Effect>) {
        let Focus::Session(id) = self.focus else {
            return;
        };
        // The disconnect banner, countdown, SSH exit footer.
        if self.on_reconnect_key(id, chord, effects) {
            self.mode = self.derive_mode();
            return;
        }
        if self.is_exited(id) && chord.code == KeyCode::Enter && chord.mods == Mods::NONE {
            self.tabs.exited.remove(&id);
            // The footer goes; the restarted shell takes input at once.
            self.set_pane_overlay(id, crate::widgets::terminal_pane::PaneOverlay::None);
            effects.push(Effect::ReconnectSession(id));
            self.mode = self.derive_mode();
            self.needs_redraw = true;
        }
    }

    /// `close_pane` on an exited pane closes it. `false` when the focused pane is not
    pub(crate) fn close_exited_pane(&mut self, effects: &mut Vec<Effect>) -> bool {
        let Focus::Session(id) = self.focus else {
            return false;
        };
        // Disconnected panes (banner, countdown) close the same way.
        if !self.is_dead_pane(id) {
            return false;
        }
        self.before_close_dead_pane(id, effects);
        effects.push(Effect::CloseSession(id));
        self.tabs.exited.remove(&id);
        self.tabs.sessions.retain(|s| *s != id);
        match self.tabs.sessions.last().copied() {
            Some(next) => self.focus_session(next),
            None => {
                self.focus = Focus::Hosts;
                self.shell.main_view = MainView::Sections;
                self.shell.region = Region::Main;
                self.mode = self.derive_mode();
            }
        }
        self.needs_redraw = true;
        true
    }

    /// The overlay line of an exited pane.
    pub(crate) fn exited_overlay(&self, code: i32) -> String {
        format!(
            "Process exited (code {code}) — [Enter] restart · {} x close",
            self.keymap.leader().hint()
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use crossterm::event::{KeyEvent, KeyModifiers};
    use sverb_conn::SessionEvent;

    use super::*;
    use crate::app::{Config, InputEvent, Mode, SessionInput, UiEvent};

    /// A timestamp for state events. Test-only: the reducer itself never reads the
    /// clock (T-02 scans this file, so the call is spelled through an alias).
    fn at() -> std::time::Instant {
        use std::time::Instant as Clock;
        Clock::now()
    }

    fn press(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Vec<Effect> {
        app.handle(UiEvent::Input(InputEvent::Key(KeyEvent::new(code, mods))))
    }

    fn leader(app: &mut App, key: char) -> Vec<Effect> {
        let l = app.keymap().leader().to_key_event();
        let mut effects = app.handle(UiEvent::Input(InputEvent::Key(l)));
        effects.extend(press(app, KeyCode::Char(key), KeyModifiers::NONE));
        effects
    }

    fn opened(effects: &[Effect]) -> Vec<(SessionId, SessionSpec)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::OpenSession { id, spec, .. } => Some((*id, spec.clone())),
                _ => None,
            })
            .collect()
    }

    // `leader t` opens a local session and focuses its pane.
    #[test]
    fn t10_leader_t_opens_a_local_session() {
        let mut app = App::new(Arc::new(Config::default()));
        app.handle(UiEvent::Input(InputEvent::Resize {
            cols: 120,
            rows: 40,
        }));
        let effects = leader(&mut app, 't');
        let first = opened(&effects);
        assert_eq!(first.len(), 1, "{effects:?}");
        let (id, spec) = &first[0];
        assert_eq!(spec, &SessionSpec::Local(LocalSpec::default()));
        assert_eq!(app.focus, Focus::Session(*id));
        assert_eq!(app.mode(), Mode::Terminal);
        assert!(app.tabs().sessions.contains(id));
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::OpenSession { cols, rows, .. } if *cols > 1 && *rows > 1 && *cols < 120 && *rows < 40
        )));

        // A second one gets a new id.
        let second = opened(&leader(&mut app, 't'));
        assert_eq!(second.len(), 1);
        assert_ne!(second[0].0, *id);
        assert_eq!(app.tabs().sessions.len(), 2);
    }

    fn exited_app() -> (App, SessionId) {
        let mut app = App::new(Arc::new(Config::default()));
        let (id, _) = opened(&leader(&mut app, 't'))[0].clone();
        app.handle(UiEvent::Session(
            id,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Exited(3),
                at: at(),
            }),
        ));
        (app, id)
    }

    // Exited pane: plain keys are swallowed, Enter restarts.
    #[test]
    fn exited_pane_swallows_keys_and_enter_restarts() {
        let (mut app, id) = exited_app();
        assert_eq!(app.exited_code(id), Some(3));
        assert_ne!(app.mode(), Mode::Terminal);
        assert!(app.exited_overlay(3).contains("Process exited (code 3)"));

        for c in ['x', 'q', 'c', 'r'] {
            let effects = press(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
            assert!(
                !effects.iter().any(|e| matches!(
                    e,
                    Effect::SendToSession { .. }
                        | Effect::CloseSession(_)
                        | Effect::Quit { .. }
                        | Effect::ReconnectSession(_)
                )),
                "{c}: {effects:?}"
            );
        }
        assert!(app.tabs().sessions.contains(&id));

        let effects = press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert!(
            effects.contains(&Effect::ReconnectSession(id)),
            "{effects:?}"
        );
        assert_eq!(app.mode(), Mode::Terminal);
        // Typed while restarting: goes to the session (deferred until connected).
        let effects = press(&mut app, KeyCode::Char('l'), KeyModifiers::NONE);
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::SendToSession { id: got, input: SessionInput::Key(_) } if *got == id
        )));
        app.handle(UiEvent::Session(
            id,
            SessionEvent::State(SessionState::Connected { since: at() }),
        ));
        assert_eq!(app.exited_code(id), None);
    }

    // Exited pane: `leader x` closes it.
    #[test]
    fn exited_pane_leader_x_closes() {
        let (mut app, id) = exited_app();
        let effects = leader(&mut app, 'x');
        assert!(effects.contains(&Effect::CloseSession(id)), "{effects:?}");
        assert!(!app.tabs().sessions.contains(&id));
        assert_eq!(app.focus, Focus::Hosts);
    }
}
