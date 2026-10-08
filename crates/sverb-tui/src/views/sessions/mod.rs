//! M1-17: the session area model (SPEC §8.1, §8.4): tabs, each with a layout tree of
//! panes, each pane holding one session.
//!
//! - [`Tab`] owns a [`Layout`] (`sverb_core::layout`, pure and serializable for
//!   workspaces) plus the per-tab focus, focus history and markers.
//! - [`Pane`] maps a pane to its session and remembers what it opened ([`PaneKind`]), so
//!   `leader -`/`leader |` can open "the same kind of session" next to it.
//! - [`tabs`]: titles, markers and the tab bar's items, overflow scrolling and hit
//!   testing. [`panes`]: pane geometry inside the main area.
//!
//! **Pane ids.** A pane keeps its session for its whole life (a restart or reconnect
//! reuses the session id), so a pane's id is its session's id (`PaneId(session.0)`).
//! The two id types stay distinct so the layout tree stays UI-agnostic.
//!
//! The reducer side (actions, events, resize debounce, drawing) is `app/tabs.rs`.

// M7-01: the autocomplete / history overlay (`leader Space`).
pub mod autocomplete;
// M3-02: broadcast sets.
pub mod broadcast;
// M3-04: copy mode (key table, state machine).
pub mod copy_mode;
pub mod panes;
pub mod tabs;

use std::collections::BTreeMap;

use sverb_conn::{LocalSpec, SshSpec};
pub use sverb_core::layout::{Direction, Layout, PaneId, SplitDir};

use crate::app::SessionId;

/// Identifies a tab (stable while it is open; tab numbers are positions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabId(pub u64);

/// The pane id of a session (see the module docs).
pub fn pane_of(session: SessionId) -> PaneId {
    PaneId(session.0)
}

/// The session of a pane (see the module docs).
pub fn session_of(pane: PaneId) -> SessionId {
    SessionId(pane.0)
}

/// What a pane's session connects to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaneKind {
    /// Not known (a session focused without an `OpenSession`, e.g. in tests).
    #[default]
    Unknown,
    /// An SSH session (saved host when `spec.host_id` is set).
    Ssh(SshSpec),
    /// A local shell.
    Local(LocalSpec),
    // M6: `Viewer(share)` for shared terminals.
}

/// Connection state of a pane, for markers and the close confirmation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PaneLife {
    /// Resolving, connecting, authenticating, host-key prompt.
    #[default]
    Connecting,
    /// Waiting for the user (password / passphrase / keyboard-interactive): `🔑`.
    AuthPending,
    /// The shell channel is open.
    Connected,
    /// Disconnected or exited: `✕`; closing needs no confirmation.
    Down,
}

impl PaneLife {
    /// Whether closing the pane needs a confirmation (the session is alive).
    pub fn alive(self) -> bool {
        !matches!(self, Self::Down)
    }
}

/// A pane: one session in a tab's layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pane {
    /// Its id in the layout tree.
    pub id: PaneId,
    /// The session it shows.
    pub session: SessionId,
    /// What it opened (for splits).
    pub kind: PaneKind,
    /// Connection state.
    pub life: PaneLife,
}

impl Pane {
    /// A pane for `session` of unknown kind, connecting.
    pub fn new(session: SessionId) -> Self {
        Self {
            id: pane_of(session),
            session,
            kind: PaneKind::Unknown,
            life: PaneLife::Connecting,
        }
    }
}

/// Tab markers (SPEC §8.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TabMarkers {
    /// Output while the tab was in the background (`●`; cleared on focus).
    pub activity: bool,
    /// A BEL arrived while the tab was in the background (`🔔`; cleared on focus).
    pub bell: bool,
}

/// A tab: a layout tree of panes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab {
    /// Stable id.
    pub id: TabId,
    /// A user-set title (`leader ,`, M3-01).
    pub title_override: Option<String>,
    /// The pane tree.
    pub layout: Layout,
    /// The focused pane.
    pub focused: PaneId,
    /// The panes, by id.
    pub panes: BTreeMap<PaneId, Pane>,
    /// Panes from least to most recently focused (ties in geometric focus moves).
    pub recency: Vec<PaneId>,
    /// Activity / bell markers.
    pub markers: TabMarkers,
    /// M3-02: the tab's broadcast set (`leader b` / `leader B`).
    pub broadcast: broadcast::BroadcastSet,
    /// The zoomed pane (M3-01).
    pub zoomed: Option<PaneId>,
}

impl Tab {
    /// A tab with one pane.
    pub fn new(id: TabId, pane: Pane) -> Self {
        let pid = pane.id;
        Self {
            id,
            title_override: None,
            layout: Layout::leaf(pid),
            focused: pid,
            panes: BTreeMap::from([(pid, pane)]),
            recency: vec![pid],
            markers: TabMarkers::default(),
            broadcast: broadcast::BroadcastSet::new(),
            zoomed: None,
        }
    }

    /// The focused pane's session.
    pub fn focused_session(&self) -> SessionId {
        self.panes
            .get(&self.focused)
            .map_or_else(|| session_of(self.focused), |p| p.session)
    }

    /// Sessions of all panes, in layout order.
    pub fn sessions(&self) -> Vec<SessionId> {
        self.layout
            .panes()
            .into_iter()
            .map(|p| {
                self.panes
                    .get(&p)
                    .map_or_else(|| session_of(p), |x| x.session)
            })
            .collect()
    }

    /// Whether the tab holds `session`.
    pub fn has_session(&self, session: SessionId) -> bool {
        self.panes.values().any(|p| p.session == session)
    }

    /// Focus `pane` (records it as most recent).
    pub fn focus(&mut self, pane: PaneId) {
        if self.panes.contains_key(&pane) {
            self.focused = pane;
            self.recency.retain(|p| *p != pane);
            self.recency.push(pane);
        }
    }

    /// Add `pane` next to `target` (split in `dir`), focusing it. Returns `false` (and
    /// changes nothing) when `target` is not in this tab.
    pub fn split(&mut self, target: PaneId, dir: SplitDir, pane: Pane) -> bool {
        let id = pane.id;
        let Some(layout) = self.layout.split(target, dir, id) else {
            return false;
        };
        self.layout = layout;
        self.panes.insert(id, pane);
        self.zoomed = None;
        self.focus(id);
        true
    }

    /// Remove `pane`; focus goes to the most recently focused remaining pane. Returns
    /// `false` when the tab is now empty (the caller removes it).
    pub fn remove(&mut self, pane: PaneId) -> bool {
        self.panes.remove(&pane);
        self.recency.retain(|p| *p != pane);
        self.broadcast.remove(&pane);
        if self.zoomed == Some(pane) {
            self.zoomed = None;
        }
        match self.layout.remove(pane) {
            Some(layout) => {
                self.layout = layout;
                if self.focused == pane {
                    let next = self
                        .recency
                        .last()
                        .copied()
                        .or_else(|| self.layout.panes().first().copied());
                    if let Some(next) = next {
                        self.focus(next);
                    }
                }
                true
            }
            None => false,
        }
    }
}

/// Where the next new session's pane goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// A new tab (the default).
    NewTab,
    /// Split `pane` of tab `tab` in `dir`.
    Split {
        /// The tab.
        tab: TabId,
        /// The pane to split.
        pane: PaneId,
        /// Divider orientation.
        dir: SplitDir,
    },
}
