//! M1-11: the reducer side of pastes and remote clipboard writes (SPEC §7.3, §17).
//!
//! - `SessionEvent::PasteConfirm(text)`: the session found a multi-line paste and no
//!   bracketed paste, and sent nothing. A dialog asks "Paste N lines into <host>?" with
//!   the first 5 lines; `y`/`Enter` sends it as `SessionInput::PasteUnchecked` (the session
//!   turns newlines into `\r`), `n`/`Esc` drops it.
//! - `SessionEvent::ClipboardWrite`: an OSC 52 write from the remote, under
//!   `clipboard.allow_remote_write`: `never` → ignored (debug log), `always` → copied,
//!   `ask` → a dialog with the first 200 chars: `a` allow once, `f` allow for this session
//!   (later writes from that session are copied silently), `d`/`Esc` deny. Reads are
//!   never allowed (the emulator denies them, M1-09).
//! - [`App::copy_to_clipboard`]: `Effect::CopyToClipboard`, plus a toast when the text is
//!   over the OSC 52 cap (the clipboard service truncates OSC 52 payloads at 100 KB).

use crossterm::event::KeyCode;
use sverb_core::config::RemoteWritePolicy;
use sverb_term::modes::input::preview;

use super::super::{App, Effect, SessionId, ToastLevel, effect::SessionInput};
use crate::{
    app::{LevelMsg, LogLevel},
    keymap::chord::KeyChord,
    services::clipboard::OSC52_MAX_TEXT_BYTES,
    views::{
        DialogKind,
        dialogs::{PASTE_PREVIEW_LINES, PasteConfirm, RemoteClipboard},
    },
};

impl App {
    /// The label used for a session in prompts. M1-13/M1-17 replace it with the host
    /// name once sessions carry one.
    fn session_label(id: SessionId) -> String {
        format!("session {}", id.0)
    }

    /// `SessionEvent::PasteConfirm`: ask before pasting several lines.
    pub(crate) fn on_paste_confirm(&mut self, id: SessionId, text: String) {
        let p = preview(&text, PASTE_PREVIEW_LINES);
        self.push_dialog(DialogKind::ConfirmPaste(PasteConfirm {
            session: id,
            host: Self::session_label(id),
            text,
            lines: p.lines,
            preview: p.head,
        }));
    }

    /// `SessionEvent::ClipboardWrite`: apply `clipboard.allow_remote_write`.
    pub(crate) fn on_remote_clipboard(
        &mut self,
        id: SessionId,
        text: String,
        effects: &mut Vec<Effect>,
    ) {
        match self.config.clipboard.allow_remote_write {
            RemoteWritePolicy::Never => effects.push(Effect::Log(LevelMsg {
                level: LogLevel::Debug,
                msg: format!(
                    "session {}: remote clipboard write ignored (allow_remote_write = never)",
                    id.0
                ),
            })),
            RemoteWritePolicy::Always => self.copy_to_clipboard(text, effects),
            RemoteWritePolicy::Ask if self.input.remote_clipboard_allowed.contains(&id) => {
                self.copy_to_clipboard(text, effects);
            }
            RemoteWritePolicy::Ask => {
                self.push_dialog(DialogKind::RemoteClipboard(RemoteClipboard {
                    session: id,
                    host: Self::session_label(id),
                    text,
                }));
            }
        }
    }

    /// Copy `text` (copy mode, "copy public key", allowed remote writes).
    pub(crate) fn copy_to_clipboard(&mut self, text: String, effects: &mut Vec<Effect>) {
        if self.config.clipboard.osc52 && text.len() > OSC52_MAX_TEXT_BYTES {
            self.push_toast(
                ToastLevel::Warning,
                "Large copy: terminals reached through OSC 52 get only the first 100 KB".to_owned(),
                effects,
            );
        }
        effects.push(Effect::CopyToClipboard(text));
    }

    /// A session closed: forget its "allow for this session".
    pub(crate) fn forget_remote_io(&mut self, id: SessionId) {
        self.input.remote_clipboard_allowed.remove(&id);
    }

    /// Keys for the paste and clipboard dialogs. `true`: the key was theirs.
    pub(super) fn on_remote_io_dialog_key(
        &mut self,
        chord: KeyChord,
        effects: &mut Vec<Effect>,
    ) -> bool {
        let Some(top) = self.dialogs.last() else {
            return false;
        };
        let key = if chord.mods.is_empty() {
            chord.code
        } else {
            KeyCode::Null
        };
        match &top.kind {
            DialogKind::ConfirmPaste(p) => {
                let (id, text) = (p.session, p.text.clone());
                match key {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        self.close_top_dialog();
                        effects.push(Effect::SendToSession {
                            id,
                            input: SessionInput::PasteUnchecked(text),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Esc => self.close_top_dialog(),
                    _ => {}
                }
                true
            }
            DialogKind::RemoteClipboard(c) => {
                let (id, text) = (c.session, c.text.clone());
                match key {
                    KeyCode::Char('a') => {
                        self.close_top_dialog();
                        self.copy_to_clipboard(text, effects);
                    }
                    KeyCode::Char('f') => {
                        self.close_top_dialog();
                        self.input.remote_clipboard_allowed.insert(id);
                        self.copy_to_clipboard(text, effects);
                    }
                    KeyCode::Char('d') | KeyCode::Esc => self.close_top_dialog(),
                    _ => {}
                }
                true
            }
            _ => false,
        }
    }

    fn close_top_dialog(&mut self) {
        self.dialogs.pop();
        self.mode = self.derive_mode();
        self.needs_redraw = true;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sverb_conn::SessionEvent;
    use sverb_core::config::Config;
    use sverb_term::ClipboardTarget;

    use super::*;
    use crate::{app::UiEvent, testing::AppHarness};

    fn harness(cfg: Config) -> AppHarness {
        AppHarness::new(cfg).with_live_session()
    }

    fn session(h: &AppHarness) -> SessionId {
        h.app().focused_session().unwrap()
    }

    fn sent(effects: &[Effect]) -> Vec<SessionInput> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::SendToSession { input, .. } => Some(input.clone()),
                _ => None,
            })
            .collect()
    }

    fn copies(effects: &[Effect]) -> Vec<String> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::CopyToClipboard(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    fn top(h: &AppHarness) -> Option<&DialogKind> {
        h.app().dialogs().last().map(|d| &d.kind)
    }

    /// Terminal-mode pastes ask the session to check (or not) for multi-line pastes.
    #[test]
    fn paste_input_follows_the_config() {
        let mut h = harness(Config::default());
        h.send(UiEvent::Input(crate::app::InputEvent::Paste("a\nb".into())));
        assert_eq!(
            sent(&h.take_effects()),
            [SessionInput::Paste("a\nb".into())]
        );
        let mut cfg = Config::default();
        cfg.terminal.paste_confirm_multiline = false;
        let mut h = harness(cfg);
        h.send(UiEvent::Input(crate::app::InputEvent::Paste("a\nb".into())));
        assert_eq!(
            sent(&h.take_effects()),
            [SessionInput::PasteUnchecked("a\nb".into())]
        );
    }

    /// T-12: multi-line paste confirmation. Cancel → nothing sent; confirm → the text
    /// goes out unchecked (the session encodes newlines as `\r`).
    #[test]
    fn t12_multiline_paste_confirm() {
        let mut h = harness(Config::default());
        let id = session(&h);
        let text = "1\n2\n3\n4\n5\n6\n7".to_owned();
        h.send(UiEvent::Session(
            id,
            SessionEvent::PasteConfirm(text.clone()),
        ));
        match top(&h) {
            Some(DialogKind::ConfirmPaste(p)) => {
                assert_eq!(p.lines, 7);
                assert_eq!(p.preview, ["1", "2", "3", "4", "5"]);
                assert_eq!(p.session, id);
            }
            other => panic!("no paste dialog: {other:?}"),
        }
        // Keys typed while the dialog is open never reach the session.
        h.keys("x");
        assert!(sent(&h.take_effects()).is_empty());
        h.keys("esc");
        assert!(h.app().dialogs().is_empty());
        assert!(sent(&h.take_effects()).is_empty());

        h.send(UiEvent::Session(
            id,
            SessionEvent::PasteConfirm(text.clone()),
        ));
        h.take_effects();
        h.keys("y");
        assert!(h.app().dialogs().is_empty());
        assert_eq!(
            sent(&h.take_effects()),
            [SessionInput::PasteUnchecked(text.clone())]
        );
        // Enter confirms too; `n` cancels.
        h.send(UiEvent::Session(
            id,
            SessionEvent::PasteConfirm(text.clone()),
        ));
        h.keys("n");
        assert!(sent(&h.take_effects()).is_empty());
        h.send(UiEvent::Session(
            id,
            SessionEvent::PasteConfirm(text.clone()),
        ));
        h.keys("enter");
        assert_eq!(
            sent(&h.take_effects()),
            [SessionInput::PasteUnchecked(text)]
        );
    }

    fn clipboard_write(id: SessionId, text: &str) -> UiEvent {
        UiEvent::Session(
            id,
            SessionEvent::ClipboardWrite {
                target: ClipboardTarget::Clipboard,
                text: text.to_owned(),
            },
        )
    }

    /// T-14: `ask` shows a dialog; "allow for session" makes later writes from that
    /// session silent; "deny" copies nothing.
    #[test]
    fn t14_remote_clipboard_ask() {
        let mut h = harness(Config::default());
        let id = session(&h);
        h.send(clipboard_write(id, "secret"));
        match top(&h) {
            Some(DialogKind::RemoteClipboard(c)) => {
                assert_eq!(c.text, "secret");
                assert_eq!(c.preview(), "secret");
            }
            other => panic!("no clipboard dialog: {other:?}"),
        }
        assert!(copies(&h.take_effects()).is_empty());
        h.keys("d");
        assert!(h.app().dialogs().is_empty());
        assert!(copies(&h.take_effects()).is_empty());

        // Allow once: copied, and the next write asks again.
        h.send(clipboard_write(id, "once"));
        h.keys("a");
        assert_eq!(copies(&h.take_effects()), ["once"]);
        h.send(clipboard_write(id, "again"));
        assert!(matches!(top(&h), Some(DialogKind::RemoteClipboard(_))));
        h.keys("esc");
        assert!(copies(&h.take_effects()).is_empty());

        // Allow for this session: copied now and silently later.
        h.send(clipboard_write(id, "one"));
        h.keys("f");
        assert_eq!(copies(&h.take_effects()), ["one"]);
        h.send(clipboard_write(id, "two"));
        assert!(h.app().dialogs().is_empty());
        assert_eq!(copies(&h.take_effects()), ["two"]);
        // Another session still asks.
        let other = SessionId(id.0 + 100);
        h.send(clipboard_write(other, "three"));
        assert!(matches!(top(&h), Some(DialogKind::RemoteClipboard(_))));
        assert!(copies(&h.take_effects()).is_empty());
    }

    #[test]
    fn remote_clipboard_never_and_always() {
        let mut cfg = Config::default();
        cfg.clipboard.allow_remote_write = RemoteWritePolicy::Never;
        let mut h = harness(cfg);
        let id = session(&h);
        h.send(clipboard_write(id, "x"));
        let effects = h.take_effects();
        assert!(copies(&effects).is_empty());
        assert!(h.app().dialogs().is_empty());
        assert!(effects.iter().any(|e| matches!(e, Effect::Log(_))));

        let mut cfg = Config::default();
        cfg.clipboard.allow_remote_write = RemoteWritePolicy::Always;
        let mut h = harness(cfg);
        let id = session(&h);
        h.send(clipboard_write(id, "x"));
        assert_eq!(copies(&h.take_effects()), ["x"]);
        assert!(h.app().dialogs().is_empty());
    }

    #[test]
    fn large_copies_warn_about_the_osc52_cap() {
        let mut h = harness(Config::default());
        let mut effects = Vec::new();
        let big = "x".repeat(OSC52_MAX_TEXT_BYTES + 1);
        h.app_mut().copy_to_clipboard(big.clone(), &mut effects);
        assert_eq!(copies(&effects), [big]);
        assert!(
            h.app()
                .toasts()
                .iter()
                .any(|t| t.message.contains("100 KB"))
        );
    }
}
