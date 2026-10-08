//! [`UiEvent`]: everything the reducer can react to.
//!
//! # Append-only convention (hotspot, see `tasks/01-DEPENDENCIES.md` §3)
//! Nearly every UI task adds variants here. Add new variants **at the end** of an
//! enum, in one block per task introduced by a `// <task-id>` comment, so parallel
//! merges stay mechanical. Never reorder or rename existing variants in passing.

use std::time::Instant;

use crossterm::event::{KeyEvent, MouseEvent};
use sverb_core::error_report::ErrorReport;

use super::effect::EffectId;
use super::state::ToastId;

/// An event delivered to [`App::handle`](crate::app::App::handle).
///
/// Time never comes from the clock inside the reducer: events that need it carry
/// the `Instant` they happened at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UiEvent {
    // M0-08
    /// Terminal input (converted from crossterm in the runtime layer).
    Input(InputEvent),
    /// The result of an [`Effect`](crate::app::Effect) that carried an [`EffectId`].
    EffectDone {
        /// The id the reducer assigned when it issued the effect.
        id: EffectId,
        /// What happened.
        result: EffectResult,
    },
    /// A timer scheduled with `Effect::ScheduleTimer` fired.
    Timer(TimerFired),
    // M0-06
    /// `config.toml` changed on disk (from `sverb_core::config::ConfigWatcher`).
    Config(sverb_core::config::ConfigEvent),
    // M0-07
    /// What the user asked for on the command line. Delivered once, as the first
    /// event after unlock (before M1-04 adds the lock screen: the first event).
    Launch(LaunchIntent),
    // M0-10
    /// Persistent one-time flags, read at startup (M1-03 sends it once the store is open).
    Meta(super::state::MetaFlags),
    // M0-09
    /// SIGTERM/SIGHUP/SIGINT or a Windows console close: quit now, exit code 0,
    /// without the quit confirmation.
    ShutdownRequested,
    // M1-08:
    /// An event from a session actor (title, bell, state, prompts, errors). `Dirty` is
    /// handled by the runtime loop and never reaches the reducer.
    Session(super::state::SessionId, sverb_conn::SessionEvent),
    // M4-07
    /// From the sync engine (`services::sync`): status, applied remote changes,
    /// toasts, read-only notices.
    #[cfg(feature = "sync")]
    Sync(sverb_sync::SyncEvent),
    // M1-04
    /// From the vault service: startup status, unlock results, password changes, and
    /// lock requests from outside the UI (`sverb lock`, suspend).
    Vault(super::vault::VaultEvent),
    // M1-05
    /// A new read-only snapshot of the decrypted search index (after unlock, item
    /// writes and remote applies). Ignored while locked.
    IndexUpdated(std::sync::Arc<sverb_core::search::IndexSnapshot>),
    // M3-06
    /// From the ConnLog service (`services::connlog`): attempts, the list, replays.
    ConnLog(super::logs::ConnLogEvent),
    // M1-15
    /// From the known-hosts service: the entries, saved host keys (accept-new toasts),
    /// import / export results.
    KnownHosts(super::known_hosts::KnownHostsEvent),
    // M2-08
    /// From the forwards service: rules, live statuses, approvals to ask for.
    Forwards(super::forwards::ForwardsEvent),
    // M2-07
    /// The built-in agent asks whether a `confirm_on_use` key may sign (answered with
    /// `Effect::AgentConfirm`).
    AgentConfirm(sverb_conn::agent::AgentConfirmRequest),
    // M2-09:
    /// From the snippet service: snippets loaded, saves, exec-run progress (and the
    /// run connections' prompts), exports, startup snippets that need values.
    Snippets(super::snippets::SnippetsEvent),
    // M2-11
    /// From the import service: the dry-run preview, import and export results.
    Import(crate::views::import_wizard::ImportEvent),
    // M2-12
    /// From the palette service: the stored recent picks (device-local `meta`).
    Palette(crate::views::palette::PaletteEvent),
    // M3-03
    /// From the workspace service: the saved workspaces, write results.
    Workspaces(super::workspaces::WorkspacesEvent),
    // M7-01:
    /// From the history service: entries loaded, added, trimmed or purged.
    History(super::history::HistoryEvent),
    // M4-09
    /// From the sync service: local state, devices, the account wizard, team pins.
    #[cfg(feature = "sync")]
    SyncUi(super::sync::SyncUiEvent),
}

// M0-07
/// How the TUI was launched (`sverb`, `sverb connect`, `--workspace`, `sverb join`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LaunchIntent {
    /// `sverb`: just the UI.
    #[default]
    Plain,
    /// `sverb connect <target>`: open a session to a host (fuzzy) or `user@host:port`.
    Connect(String),
    /// `sverb --workspace <name>`: open a saved workspace.
    Workspace(String),
    /// `sverb join <share-link>`: join a shared terminal (sync builds).
    Join(String),
}

/// Terminal input, as seen by the reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputEvent {
    // M0-08
    /// A key press or repeat. Releases are dropped by the runtime and ignored here.
    Key(KeyEvent),
    /// A mouse event (only when mouse capture is on).
    Mouse(MouseEvent),
    /// A bracketed paste.
    Paste(String),
    /// The terminal window gained focus.
    FocusGained,
    /// The terminal window lost focus.
    FocusLost,
    /// The terminal was resized.
    Resize {
        /// New width in cells.
        cols: u16,
        /// New height in cells.
        rows: u16,
    },
}

/// A fired timer: which one, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerFired {
    /// Which timer.
    pub kind: TimerKind,
    /// When it fired (supplied by the timer service or the test harness).
    pub at: Instant,
}

/// Identifies a timer. Scheduling a kind that is already pending replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TimerKind {
    // M0-08
    /// A toast reached its expiry.
    ToastExpiry(ToastId),
    /// The which-key popup delay elapsed.
    WhichKey,
    /// The leader (or any pending key sequence) timed out.
    LeaderTimeout,
    /// M1-04: the idle auto-lock timer (re-armed on every input while unlocked).
    AutoLockCheck,
    /// Resize debounce (handled from M1-17).
    ResizeDebounce,
    // M0-11
    /// A toast's 2 s duplicate-coalescing window closed.
    ToastCoalesce(ToastId),
    // M1-04
    /// One second of the unlock backoff countdown elapsed.
    UnlockCountdown,
    // M1-06
    /// One second passed for a ticking modal dialog (timeout countdown, spinner).
    DialogTick(crate::views::DialogId),
    // M3-06
    /// The replay player's next frame is due (`app/logs.rs`).
    ReplayTick,
    /// Daily connection-log maintenance (retention) while unlocked.
    LogsMaintenance,
    // M3-01
    /// Resize mode was idle for 10 s: leave it.
    ResizeModeIdle,
    // M2-08
    /// Refresh the port forwards' live status (≤ 2 Hz while unlocked).
    ForwardsRefresh,
    // M3-04
    /// The double/triple-click window after a mouse press closed (`app/copy.rs`).
    MultiClick,
}

/// The outcome of an effect, correlated by [`EffectId`].
pub type EffectResult = Result<EffectOutput, ErrorReport>;

/// Successful effect outputs. Later tasks add variants (append-only, per task).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectOutput {
    // M0-08
    /// The effect completed and has nothing to report.
    Done,
    // M1-07
    /// An item was saved (its id).
    Item(sverb_core::model::ItemId),
    /// The Hosts catalog (`ItemEffect::LoadHosts`).
    Hosts(std::sync::Arc<crate::views::hosts::catalog::HostCatalog>),
    /// A host for the edit form (`ItemEffect::LoadHost`).
    Host(Box<crate::views::hosts::catalog::HostRecord>),
    // M2-02:
    /// An identity for the edit form (`ItemEffect::LoadIdentity`).
    Identity(Box<crate::views::keychain::identity_form::IdentityRecord>),
}
