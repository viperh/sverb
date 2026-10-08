//! [`SessionCmd`]: UI → session commands (SPEC §2.1), over a bounded channel of
//! capacity [`CMD_CAPACITY`].
//!
//! # Append-only convention
//! Later tasks add variants **at the end**, one block per task with a `// <task-id>`
//! comment (M1-11: `Key(KeyInput)`, encoded by the session with its own modes).

use bytes::Bytes;
use sverb_core::secret::SecretString;
// M1-11
use sverb_term::modes::input::{KeyInput, MouseInput};

/// Capacity of a session's command channel (SPEC §2.1).
pub const CMD_CAPACITY: usize = 256;

/// A command for a session actor.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionCmd {
    // M1-08
    /// Bytes for the remote (already encoded keys, pastes).
    Input(Bytes),
    /// The pane was resized (the 50 ms debounce lives in the UI; the actor applies
    /// it immediately).
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
        /// Pane width in pixels (0 if unknown).
        px_w: u16,
        /// Pane height in pixels (0 if unknown).
        px_h: u16,
    },
    /// Close gracefully; the actor ends in `Closed`.
    Close,
    /// Start recording (M3-05). Unused: the recording service sends
    /// [`SessionCmd::AttachRecorder`] with the writer's tap instead.
    StartRecording,
    /// Stop recording (M3-05): drop the tap; the writer seals the final chunk.
    StopRecording,
    /// The user's answer to a host-key prompt (M1-15).
    HostKeyDecision(Decision),
    /// The user's answer to an auth prompt (M1-14).
    AuthAnswer(AuthAnswer),
    /// Reconnect a disconnected session (M1-16).
    Reconnect,
    // M1-11
    /// A key press, encoded by the actor with **its own** emulator's modes (DECCKM,
    /// DECKPAM, modifyOtherKeys, remote kitty flags) and the session's
    /// [`EncodeOpts`](sverb_term::modes::input::EncodeOpts) (SPEC §7.3, §9.8).
    Key(KeyInput),
    /// A paste, encoded with the emulator's modes: bracketed when the remote enabled
    /// `?2004`. Otherwise, when `confirm_multiline` is set and the text has a line break,
    /// nothing is sent and the actor answers `SessionEvent::PasteConfirm` (the UI asks the
    /// user, then sends the paste again with `confirm_multiline: false`).
    Paste {
        /// The pasted text.
        text: String,
        /// `terminal.paste_confirm_multiline` and not yet confirmed.
        confirm_multiline: bool,
    },
    /// A mouse event inside the pane (pane-relative, 0-based). The actor routes it with
    /// its emulator's modes (`sverb_term::modes::input::route_mouse`): a report or
    /// alternate-scroll arrows go to the remote; what the remote didn't ask for comes back
    /// as `SessionEvent::Mouse` for sverb (focus, scrollback, selection).
    Mouse(MouseInput),
    // M3-05
    /// Start recording into this tap (`sverb_term::recording`). The actor reports its
    /// current size to the tap, then feeds it every output read, resizes, and input when
    /// the tap records input. Never blocks the session. A previous tap is dropped
    /// (closing that recording); `StopRecording` drops this one.
    AttachRecorder(sverb_term::recording::RecordingTap),
}

impl SessionCmd {
    /// The variant name, for logs (never the payload: input can be a typed password).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Input(_) => "Input",
            Self::Resize { .. } => "Resize",
            Self::Close => "Close",
            Self::StartRecording => "StartRecording",
            Self::StopRecording => "StopRecording",
            Self::HostKeyDecision(_) => "HostKeyDecision",
            Self::AuthAnswer(_) => "AuthAnswer",
            Self::Reconnect => "Reconnect",
            // M1-11
            Self::Key(_) => "Key",
            Self::Paste { .. } => "Paste",
            Self::Mouse(_) => "Mouse",
            // M3-05
            Self::AttachRecorder(_) => "AttachRecorder",
        }
    }
}

/// Host-key decision (SPEC §9.5). M1-15 may refine it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Decision {
    /// Trust and remember the key.
    AcceptAndSave,
    /// Trust the key for this connection only.
    AcceptOnce,
    /// Abort the connection.
    Reject,
}

/// Answer to an [`AuthPrompt`](super::AuthPrompt). Secrets are redacted in `Debug`.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthAnswer {
    /// One response per prompt line, in order.
    Responses(Vec<SecretString>),
    /// The user cancelled the prompt.
    Cancel,
}
