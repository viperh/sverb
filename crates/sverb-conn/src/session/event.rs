//! [`SessionEvent`]: session → UI events (SPEC §2.1), unbounded but coalesced.
//!
//! `Dirty` is sent at most once until the UI acknowledges it by clearing the session's
//! dirty flag (see `sverb_tui::runtime::sessions` for the UI side of the contract).
//! Titles are sent only when they change. Everything else is rare.
//!
//! # Append-only convention
//! Later tasks add variants **at the end**, one block per task with a `// <task-id>`
//! comment.

use std::time::Duration;

use sverb_core::error_report::ErrorReport;
// M1-11
use sverb_term::{ClipboardTarget, modes::input::MouseInput};

use super::state::{AuthPrompt, SessionState, Verification};

/// Maximum title length in characters (SPEC §17).
pub const MAX_TITLE_CHARS: usize = 256;

/// An event from a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    // M1-08
    /// The emulator has undrawn output (at most one outstanding per session).
    Dirty,
    /// The window title changed (≤ [`MAX_TITLE_CHARS`] chars, no control characters;
    /// empty means "back to the default title").
    Title(String),
    /// BEL.
    Bell,
    /// The state machine moved.
    State(SessionState),
    /// Authentication needs the user (M1-14).
    Prompt(AuthPrompt),
    /// A host key needs a decision (M1-15).
    HostKey(Verification),
    /// The remote process exited.
    Exit {
        /// Exit status.
        code: i32,
    },
    /// Round-trip time of the last keepalive (M1-13).
    Latency(Duration),
    /// Something went wrong that the user should see (a toast).
    Error(ErrorReport),
    // M1-11
    /// The remote asked to set the local clipboard (OSC 52 write). The UI applies
    /// `clipboard.allow_remote_write` (SPEC §7.3, §17). Reads are never reported: the
    /// emulator denies them.
    ClipboardWrite {
        /// Which clipboard (`c`, or `p`/`s`).
        target: ClipboardTarget,
        /// The decoded text (≤ 1 MiB, enforced by the emulator).
        text: String,
    },
    /// A multi-line paste into a pane without bracketed paste needs confirmation
    /// (`terminal.paste_confirm_multiline`). Nothing was sent.
    PasteConfirm(String),
    /// A mouse event the remote didn't ask for (or with Shift held): sverb handles it.
    Mouse(MouseInput),
    // M3-05
    /// A recording of this session started, stopped or failed. Sent by the UI's recording
    /// service (not the actor) through the session event channel, so the reducer sees it
    /// in order with the session's other events.
    Recording(RecordingStatus),
    // M1-13
    /// The SSH session is up: negotiated algorithms, server version and the address
    /// actually connected to (for the session info panel, SPEC §6.1.8). Sent once per
    /// connection, just before `State(Connected)`.
    SshInfo(SshSessionInfo),
    // M1-14
    /// Authentication succeeded, and the answer the user typed into this prompt was part
    /// of it (the password was accepted, or the key whose passphrase was typed
    /// authenticated). Sent just before `AuthSucceeded`, so the UI saves a credential
    /// the user asked to save only once it is known to be right (SPEC §6.1.1 step 4).
    PromptAccepted(super::state::PromptKind),
    // M7-01
    /// The shell ran a command, captured through OSC 133 shell integration
    /// (`sverb_term::osc133`): exact text and exit code. The UI records it in the history.
    Command(sverb_term::osc133::ShellCommand),
}

// M1-13
/// What the session info panel shows about an SSH connection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshSessionInfo {
    /// The server's identification string (`SSH-2.0-OpenSSH_9.6`).
    pub server_version: String,
    /// The socket address connected to (`[2001:db8::1]:22`). UI only, never logged at
    /// `info` (SPEC §17).
    pub peer: String,
    /// Key exchange.
    pub kex: String,
    /// Host key algorithm.
    pub host_key: String,
    /// Cipher.
    pub cipher: String,
    /// MAC (`none` for AEAD ciphers).
    pub mac: String,
    /// Compression.
    pub compression: String,
    /// The keepalive interval in seconds (0: keepalive and latency are off).
    pub keepalive_secs: u32,
    /// When the session connected (wall clock).
    pub connected_at: Option<sverb_core::model::UnixMillis>,
    // M3-07
    /// The connection is shared (`ssh.multiplex`): its channels (shells, exec runs,
    /// tunnels, jump hops through it) when this session connected. `None`: the
    /// session has a connection of its own.
    pub shared_channels: Option<usize>,
}

// M3-05
/// What happened to a session recording. `token` is the reducer's id for one
/// start/stop cycle, so a late `Stopped` of an earlier recording is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordingStatus {
    /// The writer is running and the tap was sent to the session.
    Started {
        /// The reducer's token.
        token: u64,
        /// The `.cast.sv` file.
        path: std::path::PathBuf,
    },
    /// The recording was closed and its final chunk written.
    Stopped {
        /// The reducer's token.
        token: u64,
    },
    /// The recording could not start or failed while writing.
    Failed {
        /// The reducer's token.
        token: u64,
        /// Why.
        error: ErrorReport,
    },
}

/// Sanitize a title: drop control characters and cap at [`MAX_TITLE_CHARS`] chars.
pub fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TITLE_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_capped_and_cleaned() {
        let long = "é".repeat(1000);
        assert_eq!(sanitize_title(&long).chars().count(), MAX_TITLE_CHARS);
        assert_eq!(sanitize_title("a\u{7}b\u{1b}c"), "abc");
    }
}
