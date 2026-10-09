//! [`Effect`]: side-effect requests returned by the reducer.
//!
//! The reducer never performs I/O. It describes what should happen, and
//! [`Services`](crate::services::Services) (or the runtime loop, for `Quit`,
//! `Suspend` and `SetMouseCapture`) carries it out. Effects that produce a result
//! carry an [`EffectId`]; the result comes back as `UiEvent::EffectDone`.
//!
//! # Append-only convention (hotspot, see `tasks/01-DEPENDENCIES.md` §3)
//! Add new variants **at the end**, in one block per task introduced by a
//! `// <task-id>` comment.

use std::time::Duration;

use super::event::TimerKind;
// M0-10
use super::state::{MetaFlag, SessionId};
use crate::keymap::chord::KeyChord;

/// Correlates an effect with its `UiEvent::EffectDone`. Assigned monotonically by the reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EffectId(pub u64);

/// A side-effect request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    // M0-08
    /// Leave the event loop and exit with `code` (executed by the runtime loop).
    Quit {
        /// Process exit code.
        code: i32,
    },
    /// Suspend the process (SIGTSTP; executed by the runtime loop).
    Suspend,
    /// Deliver `UiEvent::Timer` for `kind` after `after`. Replaces a pending timer of the same kind.
    ScheduleTimer {
        /// Which timer.
        kind: TimerKind,
        /// Delay from now.
        after: Duration,
    },
    /// Cancel a pending timer. No-op if it is not pending.
    CancelTimer(TimerKind),
    /// Turn mouse capture on or off (executed by the runtime loop).
    SetMouseCapture(bool),
    /// Write a log line (the reducer itself never logs).
    Log(LevelMsg),
    // M0-10
    /// Input for a session. M1-08 routes it to the session actor (`try_send`, input is
    /// never dropped); M1-11 replaces the interim key encoding with the pane's modes.
    SendToSession {
        /// The focused session.
        id: SessionId,
        /// What to send.
        input: SessionInput,
    },
    /// Persist a one-time flag in the store's `meta` table (M1-03 wires the store).
    SetMetaFlag(MetaFlag),
    // M1-08
    /// Open a session with the reducer-allocated `id` (so the pane can be focused at
    /// once). Results arrive as `SessionEvent`s; a failure is an `Error` event.
    OpenSession {
        /// The new session's id (unique for the app's lifetime).
        id: SessionId,
        /// What to open (M1-12: `Local`, M1-13: `Ssh`).
        spec: sverb_conn::SessionSpec,
        /// Initial pane size in cells.
        cols: u16,
        /// Initial pane size in cells.
        rows: u16,
    },
    /// Close a session gracefully (the session reports `State(Closed)`).
    CloseSession(SessionId),
    // M1-12
    /// Restart a disconnected session in place (`SessionCmd::Reconnect`): a new shell
    /// for an exited local pane (`Enter` on its overlay), a reconnect for SSH (M1-16).
    ReconnectSession(SessionId),
    // M1-03: DeleteItem { .. }
    // M1-04
    /// A vault operation (first run, unlock, lock, change password) for the vault
    /// service (`services::vault`). Results come back as `UiEvent::Vault`. `Lock`
    /// zeroizes the keys synchronously.
    Vault(super::vault::VaultEffect),
    // M1-11
    /// Put text on the clipboard: OSC 52 to the outer terminal and/or the local clipboard
    /// (`services::clipboard`, SPEC §7.3).
    CopyToClipboard(String),
    // M3-05
    /// Start recording a session (`services::recording`): derive the recording key from
    /// the unlocked vault, create `<conn_id>.cast.sv`, start the writer and hand its tap
    /// to the session. Answered with `SessionEvent::Recording` (`Started`/`Failed`).
    StartRecording {
        /// The session.
        id: SessionId,
        /// The reducer's token for this recording.
        token: u64,
        /// Header title (the host label).
        title: String,
        /// `recording.include_input`.
        include_input: bool,
    },
    /// Stop recording a session (the writer seals the final chunk and answers
    /// `SessionEvent::Recording(Stopped)`).
    StopRecording(SessionId),
    // M3-06
    /// A connection-log request (`services::connlog`): maintenance, delete, replay,
    /// export, `logs.sync`. Results come back as `UiEvent::ConnLog`.
    Logs(super::logs::LogsEffect),
    // M1-17
    /// A pane's terminal size changed (debounced 50 ms): `SessionCmd::Resize` with the
    /// pixel size computed by the service from the outer terminal's cell size.
    ResizeSession {
        /// The session.
        id: SessionId,
        /// Columns inside the pane border.
        cols: u16,
        /// Rows inside the pane border.
        rows: u16,
    },
    // M1-14:
    /// The user's answer to an auth prompt: `SessionCmd::AuthAnswer` to the session
    /// (`services::ssh::send_auth_answer`).
    AuthAnswer {
        /// The session that asked.
        id: SessionId,
        /// The answer (secrets zeroized on drop).
        reply: crate::widgets::auth_prompt::AuthReply,
    },
    /// Store a credential typed into an auth prompt with "save to vault" checked, after
    /// the login succeeded (`services::ssh::save_credential`): only that field changes.
    SaveCredential(crate::widgets::auth_prompt::SaveCredential),
    // M1-15
    /// Answer a session's host-key question (`SessionCmd::HostKeyDecision`). "Accept &
    /// save" is saved by the verifier's known-hosts store.
    HostKeyDecision {
        /// The session whose handshake waits.
        id: SessionId,
        /// The answer.
        decision: sverb_conn::Decision,
    },
    /// A known-hosts request (`services::known_hosts`): load, save, import, export.
    /// Results come back as `UiEvent::KnownHosts`.
    KnownHosts(super::known_hosts::KnownHostsEffect),
    // M2-08
    /// A port-forward request (`services::forwards`): load, refresh, save, start,
    /// start without terminal, stop, approve. Results come back as `UiEvent::Forwards`.
    Forwards(super::forwards::ForwardsEffect),
    // M3-04
    /// Open a link in the user's browser (`services::opener`). Only issued after the user
    /// confirmed the dialog that shows the URL (SPEC §17); the opener refuses schemes other
    /// than `http`, `https`, `ftp` and `mailto`.
    OpenUrl(String),
    // M2-07
    /// The answer to a `confirm_on_use` prompt (`UiEvent::AgentConfirm`).
    AgentConfirm {
        /// The prompt.
        id: u64,
        /// Allow this one signature.
        allow: bool,
    },
    // M2-09:
    /// A snippet request (`services::snippets`): load, save, delete, duplicate, exec runs
    /// on hosts (and their prompt answers / cancel), exports, startup checks, history.
    /// Results come back as `UiEvent::Snippets`.
    Snippets(super::snippets::SnippetsEffect),
    // M2-11
    /// An import wizard request (`services::import`): the dry run, the confirmed
    /// import, an export. Results come back as `UiEvent::Import`.
    Import(crate::views::import_wizard::ImportEffect),
    // M2-12
    /// The command palette's recent picks (`services::palette`): load them (answered
    /// with `UiEvent::Palette`) or store them, in the device-local `meta` table.
    Palette(crate::views::palette::PaletteEffect),
    // M3-03
    /// A workspace request (`services::workspaces`): load, save, rename, delete,
    /// duplicate. Results come back as `UiEvent::Workspaces`.
    Workspaces(super::workspaces::WorkspacesEffect),
    // M7-01:
    /// A command history request (`services::history`): load, record a captured
    /// command, purge a host, the `[history]` policy. Results come back as
    /// `UiEvent::History`.
    History(super::history::HistoryEffect),
    // M4-09
    /// A sync request (`services::sync`): start / stop with the lock, sync now, the
    /// local state, devices, disconnect, the account wizard, team pins. Results come
    /// back as `UiEvent::Sync` / `UiEvent::SyncUi`; local-only builds drop it.
    Sync(super::sync_ui::SyncEffect),
    // M6-03
    /// A terminal-sharing request (`services::share`): start / stop a share, approve,
    /// deny, control, kick, join a share in a viewer pane. Results come back as
    /// `UiEvent::Share`; builds without sharing answer `ShareEvent::Unavailable`.
    Share(super::share::ShareEffect),
}

// M0-10
/// Input for a session (Terminal mode). Keys stay chords; M1-11 encodes them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionInput {
    /// A key press, normalized.
    Key(KeyChord),
    /// A paste. The session brackets it when the remote enabled `?2004`; otherwise a
    /// multi-line paste comes back as `SessionEvent::PasteConfirm` first (sent only while
    /// `terminal.paste_confirm_multiline` is on).
    Paste(String),
    // M1-11
    /// A paste sent without the multi-line confirmation (confirmed by the user, or
    /// `terminal.paste_confirm_multiline = false`). Still bracketed when the remote asks.
    PasteUnchecked(String),
    // M1-17
    /// A mouse event inside the pane (pane-relative, 0-based): `SessionCmd::Mouse`; the
    /// session routes it to the remote or back to sverb (M1-11).
    Mouse(sverb_term::modes::input::MouseInput),
    // M2-09:
    /// Bytes typed as is (`SessionCmd::Input`): a snippet's *Paste & execute* lines
    /// (`l1\rl2\r`), never bracketed.
    Raw(Vec<u8>),
}

/// A log line requested by the reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelMsg {
    /// Severity.
    pub level: LogLevel,
    /// Message text. Must not contain secrets.
    pub msg: String,
}

/// Log severity for [`Effect::Log`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// `tracing::error!`
    Error,
    /// `tracing::warn!`
    Warn,
    /// `tracing::info!`
    Info,
    /// `tracing::debug!`
    Debug,
}
