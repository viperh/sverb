//! Session recording in the reducer (SPEC §7.5).
//!
//! - `leader R` (`toggle_recording`) starts or stops recording the focused session. The
//!   flag is set at once (the status bar shows `REC ●`); the recording service answers
//!   with `SessionEvent::Recording` and a `Failed` clears the flag with an error toast.
//! - New local sessions are recorded when `recording.enabled` is on. SSH sessions
//!    call [`App::auto_record`] with
//!   `sverb_core::model::resolve_record_sessions` (host → groups → global).
//! - With `recording.include_input`, the first recording shows a one-time warning that
//!   typed passwords end up in the recording.
//! - Each start gets a token, so a late `Stopped` from an earlier recording of the same
//!   session does not clear a newer one.

use sverb_conn::session::event::RecordingStatus;

use crate::app::{App, Effect, SessionId, ToastLevel};

/// The one-time warning for `recording.include_input`.
pub(crate) const INPUT_WARNING: &str =
    "Recording includes keyboard input: typed passwords end up in the recording";

impl App {
    /// `leader R`.
    pub(crate) fn toggle_recording(&mut self, effects: &mut Vec<Effect>) {
        let Some(id) = self.focused_session() else {
            self.push_toast(
                ToastLevel::Info,
                "Recording needs a focused session".to_owned(),
                effects,
            );
            return;
        };
        if self.tabs.recording.remove(&id).is_some() {
            effects.push(Effect::StopRecording(id));
            self.push_toast(ToastLevel::Info, "Recording stopped".to_owned(), effects);
        } else {
            self.start_recording(id, effects);
        }
        self.needs_redraw = true;
    }

    /// Start recording `id` (no-op if it already is).
    pub(crate) fn start_recording(&mut self, id: SessionId, effects: &mut Vec<Effect>) {
        if self.tabs.recording.contains_key(&id) {
            return;
        }
        let token = self.tabs.next_recording_token;
        self.tabs.next_recording_token = token.wrapping_add(1);
        self.tabs.recording.insert(id, token);
        let include_input = self.config.recording.include_input;
        if include_input && !self.tabs.recording_input_warned {
            self.tabs.recording_input_warned = true;
            self.push_toast(ToastLevel::Warning, INPUT_WARNING.to_owned(), effects);
        }
        effects.push(Effect::StartRecording {
            id,
            token,
            title: self.pane(id).label,
            include_input,
        });
        self.needs_redraw = true;
    }

    /// Start recording a new session when `record` (the resolved setting) is on.
    pub(crate) fn auto_record(&mut self, id: SessionId, record: bool, effects: &mut Vec<Effect>) {
        if record {
            self.start_recording(id, effects);
        }
    }

    /// Whether `id` is being recorded.
    pub fn is_recording(&self, id: SessionId) -> bool {
        self.tabs.recording.contains_key(&id)
    }

    /// The recording service's answer.
    pub(crate) fn on_recording_status(
        &mut self,
        id: SessionId,
        status: RecordingStatus,
        effects: &mut Vec<Effect>,
    ) {
        let current = self.tabs.recording.get(&id).copied();
        match status {
            RecordingStatus::Started { .. } => {}
            RecordingStatus::Stopped { token } => {
                if current == Some(token) {
                    self.tabs.recording.remove(&id);
                    self.needs_redraw = true;
                }
            }
            RecordingStatus::Failed { token, error } => {
                if current == Some(token) {
                    self.tabs.recording.remove(&id);
                    self.needs_redraw = true;
                }
                self.push_error(&error, effects);
            }
            _ => {}
        }
    }

    /// The session closed: its recording ends with it.
    pub(crate) fn forget_recording(&mut self, id: SessionId) {
        self.tabs.recording.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use sverb_conn::SessionEvent;
    use sverb_core::{config::Config, error_report::ErrorReport};

    use super::*;
    use crate::{app::UiEvent, testing::AppHarness};

    fn harness(config: Config) -> (AppHarness, SessionId) {
        let mut h = AppHarness::new(config);
        let id = SessionId(7);
        h.app_mut().focus_session(id);
        h.app_mut().set_pane_label(id, "web-1");
        (h, id)
    }

    fn starts(effects: &[Effect]) -> Vec<(SessionId, u64, String, bool)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::StartRecording {
                    id,
                    token,
                    title,
                    include_input,
                } => Some((*id, *token, title.clone(), *include_input)),
                _ => None,
            })
            .collect()
    }

    fn status_line(h: &AppHarness) -> String {
        let buf = h.render_buffer(100, 24);
        let y = buf.area.height - 1;
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().to_owned())
            .collect()
    }

    #[test]
    fn t10_leader_r_toggles_recording_and_shows_rec() {
        let (mut h, id) = harness(Config::default());
        assert!(!status_line(&h).contains("REC ●"));

        h.keys("ctrl-\\ R");
        assert!(h.app().is_recording(id));
        assert_eq!(starts(h.effects()), [(id, 0, "web-1".to_owned(), false)]);
        assert!(status_line(&h).contains("REC ●"), "{}", status_line(&h));

        h.take_effects();
        h.keys("ctrl-\\ R");
        assert!(!h.app().is_recording(id));
        assert!(h.effects().contains(&Effect::StopRecording(id)));
        assert!(!status_line(&h).contains("REC ●"));
    }

    #[test]
    fn failures_clear_the_flag_and_late_stops_are_ignored() {
        let (mut h, id) = harness(Config::default());
        h.keys("ctrl-\\ R"); // token 0
        h.keys("ctrl-\\ R"); // stop
        h.keys("ctrl-\\ R"); // token 1
        // The first recording's writer finishes late: ignored.
        h.send(UiEvent::Session(
            id,
            SessionEvent::Recording(RecordingStatus::Stopped { token: 0 }),
        ));
        assert!(h.app().is_recording(id));
        h.send(UiEvent::Session(
            id,
            SessionEvent::Recording(RecordingStatus::Failed {
                token: 1,
                error: ErrorReport::msg("the vault is locked"),
            }),
        ));
        assert!(!h.app().is_recording(id));
        assert!(
            h.app()
                .toasts()
                .iter()
                .any(|t| t.level == ToastLevel::Error && t.message.contains("vault is locked"))
        );
    }

    #[test]
    fn include_input_warns_once_and_global_flag_records_new_sessions() {
        let mut config = Config::default();
        config.recording.enabled = true;
        config.recording.include_input = true;
        let mut h = AppHarness::new(config);
        h.keys("ctrl-\\ t");
        let started = starts(h.effects());
        assert_eq!(started.len(), 1, "{:?}", h.effects());
        assert!(started[0].3, "include_input is passed on");
        let warnings = |h: &AppHarness| {
            h.app()
                .toasts()
                .iter()
                .filter(|t| t.message == INPUT_WARNING)
                .count()
        };
        assert_eq!(warnings(&h), 1);
        h.keys("ctrl-\\ t");
        assert_eq!(starts(h.effects()).len(), 2);
        assert_eq!(warnings(&h), 1, "warned only once");

        // Without the global flag, new sessions are not recorded.
        let mut h = AppHarness::new(Config::default());
        h.keys("ctrl-\\ t");
        assert!(starts(h.effects()).is_empty());
    }

    #[test]
    fn closing_the_session_forgets_the_recording() {
        let (mut h, id) = harness(Config::default());
        h.keys("ctrl-\\ R");
        h.send(UiEvent::Session(
            id,
            SessionEvent::State(sverb_conn::SessionState::Closed),
        ));
        assert!(!h.app().is_recording(id));
    }
}
