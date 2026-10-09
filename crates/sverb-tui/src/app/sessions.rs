//! Session events in the reducer.
//!
//! Errors become error toasts; `State(Closed)` removes the session from the tabs (its
//! pane loses focus through `focused_session`). Titles, bells, prompts, host keys,
//! exit codes and the other states are handled by the tasks that draw them

use sverb_conn::{SessionEvent, SessionState};

use super::{App, Effect, SessionId};

// `leader R`, auto-recording, recording status (`sessions/recording.rs`).
mod recording;
// Disconnect banner, reconnect, auto-reconnect (`sessions/reconnect.rs`).
mod reconnect;

impl App {
    pub(crate) fn on_session(
        &mut self,
        id: SessionId,
        ev: SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        // Exited panes (overlay, restart).
        if let SessionEvent::State(state) = &ev {
            self.on_local_state(id, state);
            // Banner, exited footer, auto-reconnect countdown.
            self.reconnect_on_state(id, state, effects);
            // Record the connection; offer to save an unsaved target.
            self.hosts_on_session_state(id, state, effects);
            // An answered or abandoned host-key prompt closes.
            self.host_key_on_state(id, state);
        }
        // Auth prompts (queued, focused pane first), credentials saved only after
        // the login they were typed for succeeded (`app/auth.rs`).
        self.auth_on_session(id, &ev, effects);
        match ev {
            SessionEvent::Error(report) => {
                // Kept for `leader i` on the disconnected pane.
                self.reconnect_on_error(id, &report);
                self.push_error(&report, effects);
            }
            SessionEvent::State(SessionState::Closed) => {
                self.tabs.sessions.retain(|s| *s != id);
                self.tabs.ssh.remove(&id);
                self.needs_redraw = true;
                self.forget_remote_io(id);
                self.forget_recording(id);
            }
            // OSC 52 writes and multi-line paste confirmation (`input/remote_io.rs`).
            SessionEvent::ClipboardWrite { text, .. } => {
                self.on_remote_clipboard(id, text, effects);
            }
            SessionEvent::PasteConfirm(text) => self.on_paste_confirm(id, text),
            SessionEvent::Recording(status) => self.on_recording_status(id, status, effects),
            // SSH details and keepalive latency (status bar, session info panel).
            SessionEvent::SshInfo(info) => {
                let entry = self.tabs.ssh.entry(id).or_default();
                entry.info = info;
                entry.latency = None;
                self.needs_redraw |= self.focused_session() == Some(id);
            }
            SessionEvent::Latency(rtt) => {
                if let Some(entry) = self.tabs.ssh.get_mut(&id) {
                    entry.latency = Some(rtt);
                    self.needs_redraw |= self.focused_session() == Some(id);
                }
            }
            SessionEvent::State(SessionState::Disconnected { .. }) => {
                if let Some(entry) = self.tabs.ssh.get_mut(&id) {
                    entry.latency = None;
                }
            }
            // The unknown-key modal / changed-key screen (`app/known_hosts.rs`).
            SessionEvent::HostKey(v) => self.on_host_key(id, v),
            // Mouse events the remote didn't capture (or with Shift): selection,
            // word/line clicks, wheel scrollback, link hover and ctrl-click.
            SessionEvent::Mouse(ev) => self.copy_on_mouse(id, ev, effects),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use sverb_core::error_report::ErrorReport;

    use super::*;
    use crate::app::{Config, Mode, ToastLevel, UiEvent};

    #[test]
    fn errors_toast_and_closed_sessions_leave_the_tabs() {
        let mut app = App::new(std::sync::Arc::new(Config::default()));
        let id = SessionId(3);
        app.focus_session(id);
        assert_eq!(app.mode(), Mode::Terminal);

        app.handle(UiEvent::Session(
            id,
            SessionEvent::Error(ErrorReport::msg("session crashed (see log)")),
        ));
        assert!(
            app.toasts()
                .iter()
                .any(|t| t.level == ToastLevel::Error && t.message.contains("session crashed"))
        );

        app.handle(UiEvent::Session(id, SessionEvent::Title("vim".to_owned())));
        assert!(app.tabs().sessions.contains(&id));

        app.handle(UiEvent::Session(
            id,
            SessionEvent::State(SessionState::Closed),
        ));
        assert!(!app.tabs().sessions.contains(&id));
        assert!(app.visible_sessions().is_empty());
        assert_ne!(app.mode(), Mode::Terminal);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn ssh_details_and_latency_feed_the_status_bar_and_info_panel() {
        use std::time::Duration;

        use crate::keymap::action::ActionName;
        use crate::views::DialogKind;
        use crate::widgets::session_info::status_segment;

        let mut app = App::new(std::sync::Arc::new(Config::default()));
        let id = SessionId(4);
        app.focus_session(id);
        app.set_pane_label(id, "db");
        let info = sverb_conn::SshSessionInfo {
            kex: "curve25519-sha256".into(),
            keepalive_secs: 30,
            ..sverb_conn::SshSessionInfo::default()
        };
        app.handle(UiEvent::Session(id, SessionEvent::SshInfo(info.clone())));
        app.handle(UiEvent::Session(
            id,
            SessionEvent::Latency(Duration::from_millis(23)),
        ));
        let ssh = app.tabs().ssh.get(&id).cloned().unwrap();
        assert_eq!(ssh.info, info);
        assert_eq!(status_segment("db", &ssh), "db · ssh · 23ms");

        let mut effects = Vec::new();
        app.apply_action(ActionName::SessionInfo, &mut effects);
        assert!(
            app.dialogs()
                .iter()
                .any(|d| matches!(&d.kind, DialogKind::Modal(m) if m.modal.body.contains("Key exchange:  curve25519-sha256"))),
            "{:?}",
            app.dialogs()
        );

        app.handle(UiEvent::Session(
            id,
            SessionEvent::State(SessionState::Closed),
        ));
        assert!(!app.tabs().ssh.contains_key(&id));
    }
}
