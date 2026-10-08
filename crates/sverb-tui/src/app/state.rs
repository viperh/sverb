//! Plain-data pieces of [`App`](crate::app::App) state.
//!
//! Everything here is `Clone + Debug + PartialEq` and free of channels, tokio
//! types and closures, so state can be snapshotted and diffed in tests.
//!
//! # Append-only convention (hotspot, see `tasks/01-DEPENDENCIES.md` §3)
//! Add new enum variants and struct fields **at the end**, in one block per task
//! introduced by a `// <task-id>` comment.

use serde::{Deserialize, Serialize};

use super::effect::EffectId;
use crate::views::dialogs::DialogId;

/// Input mode (SPEC §8.2). Derived from focus by the reducer, never set ad hoc (M0-10).
///
/// `Serialize`/`Deserialize` keep the template's `config.json` keybinding tables
/// (keyed by mode name) loading until M0-06/M0-10 replace them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mode {
    // M0-08
    /// Focus is in sverb's own views.
    #[default]
    Normal,
    // M0-10
    /// A live session pane has focus: every key except the leader goes to the session.
    Terminal,
    /// Copy mode in a session pane (`leader [`, M3-04).
    Copy,
    /// A form field has focus: keys go to the field, `Esc` leaves, the leader still works.
    Insert,
}

// M0-10
impl Mode {
    /// Status-bar label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Terminal => "TERMINAL",
            Self::Copy => "COPY",
            Self::Insert => "INSERT",
        }
    }
}

/// Which view has keyboard focus (dialogs always take precedence while open).
///
/// M0-11: `Hosts` means "the section views" (the main area shows the active sidebar
/// section; the shell's `Region` says whether the sidebar, the section or its detail
/// pane has focus). `Session` means the session area.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Focus {
    // M0-08
    /// The section views (sidebar sections; the Hosts section is the default).
    #[default]
    Hosts,
    // M0-10
    /// A session pane (live if the session is in [`Tabs::sessions`]). M1-17 owns panes.
    Session(SessionId),
}

/// Screen layout state. M0-11's shell state (sections, sidebar, regions) is `views::shell::ShellState`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Layout {
    // M0-08
    /// Last known terminal size in cells (`cols`, `rows`), from `InputEvent::Resize`.
    pub size: Option<(u16, u16)>,
    /// Whether the terminal window has focus (focus-change events).
    pub terminal_focused: bool,
}

/// Identifies a session. M1-08 owns the real type; this placeholder keeps the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// Open tabs and their sessions. M1-17 replaces this with the tab/layout tree.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tabs {
    // M0-08
    /// Sessions that are open, in tab order.
    pub sessions: Vec<SessionId>,
    // M1-12
    /// Sessions whose process exited, with the exit code. Their panes show the
    /// "Process exited" overlay and take no input (`03-KEYBINDINGS.md` §4.4).
    pub exited: std::collections::BTreeMap<SessionId, i32>,
    // M3-05
    /// Sessions being recorded, with the token of the current recording (`REC ●`).
    pub recording: std::collections::BTreeMap<SessionId, u64>,
    /// The one-time "input recording can capture passwords" warning was shown.
    pub recording_input_warned: bool,
    /// Next recording token.
    pub next_recording_token: u64,
    // M1-13
    /// SSH sessions' details (algorithms, latency) for the status bar and info panel.
    pub ssh: std::collections::BTreeMap<SessionId, crate::widgets::session_info::SshPaneInfo>,
    // M1-17
    /// The tabs, in order; each holds a layout tree of panes (`views::sessions`).
    /// Every session in [`Tabs::sessions`] has exactly one pane (`app/tabs.rs` keeps
    /// them in sync after every event).
    pub list: Vec<crate::views::sessions::Tab>,
    /// Index of the active tab in [`Tabs::list`].
    pub active: usize,
    /// Next tab id.
    pub next_tab: u64,
    /// The terminal size each session was opened with or last resized to.
    pub sent_sizes: std::collections::BTreeMap<SessionId, (u16, u16)>,
    /// The pane sizes the layout wanted after the last event (a change starts the 50 ms
    /// resize debounce).
    pub wanted_sizes: std::collections::BTreeMap<SessionId, (u16, u16)>,
    /// Where the next new session's pane goes (`None`: a new tab). Set around the
    /// call that opens a session in a split.
    pub placement: Option<crate::views::sessions::Placement>,
    // M3-01
    /// Resize mode, a mouse drag of a split border, the open rename-tab prompt.
    pub pane_ops: super::resize::PaneOps,
    // M3-02
    /// The large-broadcast confirmation (asked once per run).
    pub broadcast: super::broadcast::BroadcastUi,
    // M3-03
    /// Saved workspaces, the save / open dialogs and the bounded open queue.
    pub workspaces: super::workspaces::WorkspacesUi,
}

impl Tabs {
    /// Whether any session is open (drives the quit confirmation).
    pub fn has_sessions(&self) -> bool {
        !self.sessions.is_empty()
    }
}

/// Identifies a toast, so its expiry timer can find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToastId(pub u64);

/// Toast severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToastLevel {
    // M0-08
    /// Informational. Fades after 4 s.
    Info,
    /// Something went wrong. Sticky until dismissed (SPEC §8.7).
    Error,
    // M0-11
    /// Something worked. Fades after 4 s.
    Success,
    /// Worth a look. Fades after 4 s.
    Warning,
}

// M0-11
impl ToastLevel {
    /// Errors stay until dismissed; everything else fades.
    pub fn is_sticky(self) -> bool {
        matches!(self, Self::Error)
    }

    /// Short label (toast title, history column).
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Error => "error",
            Self::Success => "ok",
            Self::Warning => "warning",
        }
    }
}

/// A visible notification (M0-11 owns the widget and styling, `widgets/toast.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    // M0-08
    /// Id used by the expiry timer.
    pub id: ToastId,
    /// Severity.
    pub level: ToastLevel,
    /// Message (wrapped to at most 3 lines when shown).
    pub message: String,
    // M0-11
    /// How many identical toasts were coalesced into this one (`(×3)`).
    pub count: u32,
    /// Still inside the 2 s window in which duplicates coalesce.
    pub coalescing: bool,
}

/// What an in-flight effect was issued for, so its result can be routed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PendingKind {
    // M0-08
    /// A form dialog asked to save an item; on success the dialog closes.
    SaveItem {
        /// The form dialog that issued the save.
        dialog: DialogId,
    },
    // M1-07
    /// The Hosts catalog load.
    HostsLoad,
    /// A host loaded for the edit form.
    EditHost,
    // M2-02:
    /// An identity form asked to save; on success the dialog closes.
    SaveIdentity {
        /// The identity form dialog.
        dialog: DialogId,
    },
    /// An identity loaded for the edit form.
    EditIdentity,
}

// M0-10
/// Persistent one-time flags kept in the store's `meta` table (M1-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetaFlag {
    /// The first-run leader notice was shown (`meta.seen_leader_notice`).
    SeenLeaderNotice,
}

impl MetaFlag {
    /// The key in the `meta` table.
    pub fn key(self) -> &'static str {
        match self {
            Self::SeenLeaderNotice => "seen_leader_notice",
        }
    }
}

/// Persistent flags read at startup, delivered as `UiEvent::Meta`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetaFlags {
    /// `meta.seen_leader_notice`.
    pub seen_leader_notice: bool,
}

/// Allocates the monotonically increasing ids the reducer hands out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdGen {
    next_effect: u64,
    next_toast: u64,
    next_dialog: u64,
    // M1-12
    next_session: u64,
}

impl IdGen {
    /// Next [`EffectId`].
    pub fn effect(&mut self) -> EffectId {
        let id = EffectId(self.next_effect);
        self.next_effect = self.next_effect.wrapping_add(1);
        id
    }

    /// Next [`ToastId`].
    pub fn toast(&mut self) -> ToastId {
        let id = ToastId(self.next_toast);
        self.next_toast = self.next_toast.wrapping_add(1);
        id
    }

    /// Next [`DialogId`].
    pub fn dialog(&mut self) -> DialogId {
        let id = DialogId(self.next_dialog);
        self.next_dialog = self.next_dialog.wrapping_add(1);
        id
    }

    // M1-12
    /// Next [`SessionId`] (from 1; unique for the app's lifetime).
    pub fn session(&mut self) -> SessionId {
        self.next_session = self.next_session.wrapping_add(1);
        SessionId(self.next_session)
    }
}
