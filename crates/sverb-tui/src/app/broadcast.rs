//! M3-02: broadcast input in the reducer (SPEC §9.8, §7.3, §9.7).
//!
//! - **Actions**: `leader b` toggles `AllPanes` for the active tab (a custom set turns
//!   off); `leader B` toggles the focused pane in a custom set
//!   (`views::sessions::broadcast` holds the set logic).
//! - **Routing**: Terminal-mode keys, pastes and snippet runs (*Paste* and *Paste &
//!   execute*) typed into a member of an active set go to every member as the same
//!   `SessionInput`; each session encodes it with **its own** terminal modes (§7.3), so
//!   the focused pane's bytes are never copied. Members that are disconnected, exited,
//!   reconnecting, locked or waiting for a password are skipped. The leader, sverb
//!   actions, mouse input and resizes are never broadcast.
//! - **Safety**: turning broadcast on for more than
//!   [`crate::views::sessions::broadcast::CONFIRM_ABOVE`] panes asks
//!   "Broadcast input to N panes?" once per run.
//! - **Visuals**: members get the theme's `broadcast_border` and a `≋` in their border
//!   title, the tab title gets `≋`, the status bar shows `BROADCAST ×N` (`(M skipped)`,
//!   or `(pending)` for a custom set with one member).

use crossterm::event::KeyEvent;

use super::{App, Effect, SessionId, ToastLevel, effect::SessionInput};
use crate::keymap::action::ActionName;
use crate::views::{
    DialogId, DialogKind,
    dialogs::ModalDialog,
    sessions::{
        PaneLife, Tab, TabId,
        broadcast::{self, BroadcastSet, CONFIRM_ABOVE, MARKER},
        pane_of, session_of,
    },
};
use crate::widgets::dialog::{Button, Modal, ModalAnswer};
use crate::widgets::terminal_pane::PaneOverlay;

/// Button id of "Broadcast" in the confirmation.
const CONFIRM: &str = "broadcast";

/// Broadcast state outside the tabs (`Tabs::broadcast`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BroadcastUi {
    /// A large broadcast was confirmed in this run: don't ask again.
    pub confirmed: bool,
    /// The open confirmation: its dialog, the tab and the set it would apply.
    pub confirm: Option<(DialogId, TabId, BroadcastSet)>,
}

/// The status-bar segment: `BROADCAST ×count` plus an optional note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastStatus {
    /// Panes the next input reaches (members for a pending set).
    pub count: u32,
    /// `M skipped` / `pending`.
    pub note: Option<String>,
}

impl App {
    /// `leader b` / `leader B`. Returns `false` for other actions.
    pub(crate) fn apply_broadcast_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        if !matches!(
            action,
            ActionName::ToggleBroadcast | ActionName::MarkBroadcastPane
        ) {
            return false;
        }
        let Some(tab) = self.active_tab() else {
            self.push_toast(
                ToastLevel::Info,
                "No panes to broadcast to".to_owned(),
                effects,
            );
            return true;
        };
        let panes = tab.layout.panes();
        let next = if action == ActionName::ToggleBroadcast {
            tab.broadcast.toggled_all()
        } else {
            tab.broadcast.toggled_member(tab.focused, &panes)
        };
        let (id, before) = (tab.id, tab.broadcast.members(&panes).len());
        let after = next.members(&panes).len();
        if after > CONFIRM_ABOVE && before <= CONFIRM_ABOVE && !self.tabs.broadcast.confirmed {
            let modal = Modal::confirm(
                "Broadcast input?",
                &format!("Broadcast input to {after} panes?"),
                vec![
                    Button::new(CONFIRM, "Broadcast", 'b'),
                    Button::new("cancel", "Cancel", 'c').safe(),
                ],
                0,
                false,
            );
            let dialog = self.push_modal(ModalDialog::new(modal), effects);
            self.tabs.broadcast.confirm = Some((dialog, id, next));
            return true;
        }
        self.set_broadcast(id, next);
        true
    }

    fn set_broadcast(&mut self, tab: TabId, set: BroadcastSet) {
        if let Some(t) = self.tabs.list.iter_mut().find(|t| t.id == tab)
            && t.broadcast != set
        {
            t.broadcast = set;
            self.needs_redraw = true;
        }
    }

    /// Keys for the "Broadcast input to N panes?" confirmation (the top dialog).
    /// Returns whether the key was handled here.
    pub(crate) fn on_broadcast_dialog_key(
        &mut self,
        key: KeyEvent,
        _effects: &mut Vec<Effect>,
    ) -> bool {
        let Some((dialog, tab, set)) = self.tabs.broadcast.confirm.clone() else {
            return false;
        };
        let Some(top) = self.dialogs.last_mut() else {
            self.tabs.broadcast.confirm = None;
            return false;
        };
        if top.id != dialog {
            // Closed some other way (or covered by another dialog): forget it if gone.
            if !self.dialogs.iter().any(|d| d.id == dialog) {
                self.tabs.broadcast.confirm = None;
            }
            return false;
        }
        let DialogKind::Modal(m) = &mut top.kind else {
            return false;
        };
        let answer = m.modal.handle_key(&key);
        self.needs_redraw = true;
        let Some(answer) = answer else {
            return true;
        };
        self.dialogs.pop();
        self.tabs.broadcast.confirm = None;
        if matches!(&answer, ModalAnswer::Button(b) if b == CONFIRM) {
            self.tabs.broadcast.confirmed = true;
            self.set_broadcast(tab, set);
        }
        true
    }

    /// The tab holding `session`.
    fn tab_of(&self, session: SessionId) -> Option<&Tab> {
        self.tabs.list.iter().find(|t| t.has_session(session))
    }

    /// Whether a member pane can take input now: live, not exited / disconnected /
    /// reconnecting, not locked, not waiting for a password.
    fn broadcast_available(&self, tab: &Tab, session: SessionId) -> bool {
        let life_ok = tab
            .panes
            .get(&pane_of(session))
            .is_none_or(|p| !matches!(p.life, PaneLife::Down | PaneLife::AuthPending));
        life_ok
            && self.tabs.sessions.contains(&session)
            && !self.is_dead_pane(session)
            && self
                .panes
                .get(&session)
                .is_none_or(|p| p.overlay != PaneOverlay::Locked)
    }

    /// Where input typed into `session` goes: `session` first, then the other members
    /// of its tab's active broadcast set (unavailable ones skipped), plus the number
    /// skipped.
    pub(crate) fn broadcast_targets(&self, session: SessionId) -> (Vec<SessionId>, usize) {
        let Some(tab) = self.tab_of(session) else {
            return (vec![session], 0);
        };
        let panes = tab.layout.panes();
        let plan = broadcast::plan(&tab.broadcast, pane_of(session), &panes, |p| {
            let s = tab.panes.get(&p).map_or(session_of(p), |x| x.session);
            self.broadcast_available(tab, s)
        });
        let targets = plan
            .targets
            .into_iter()
            .map(|p| tab.panes.get(&p).map_or(session_of(p), |x| x.session))
            .collect();
        (targets, plan.skipped)
    }

    /// Send `input` (typed into `session`) to every broadcast target.
    pub(crate) fn broadcast_send(
        &self,
        session: SessionId,
        input: SessionInput,
        effects: &mut Vec<Effect>,
    ) {
        let (targets, _) = self.broadcast_targets(session);
        for id in targets {
            effects.push(Effect::SendToSession {
                id,
                input: input.clone(),
            });
        }
    }

    /// Whether `session`'s pane is a broadcast member (highlighted, also when pending).
    pub fn broadcast_highlight(&self, session: SessionId) -> bool {
        self.tab_of(session)
            .is_some_and(|t| t.broadcast.contains(pane_of(session), &t.layout.panes()))
    }

    /// The tab title's `≋` marker (with a leading space) when the tab broadcasts.
    pub(crate) fn broadcast_tab_marker(tab: &Tab) -> String {
        if tab.broadcast.members(&tab.layout.panes()).is_empty() {
            String::new()
        } else {
            format!(" {MARKER}")
        }
    }

    /// The status segment for the focused session: shown while its input is broadcast,
    /// or while it is the only member of a pending custom set.
    pub(crate) fn broadcast_status(&self) -> Option<BroadcastStatus> {
        let session = self.focused_session()?;
        let tab = self.tab_of(session)?;
        let panes = tab.layout.panes();
        if !tab.broadcast.contains(pane_of(session), &panes) {
            return None;
        }
        if tab.broadcast.is_pending(&panes) {
            return Some(BroadcastStatus {
                count: 1,
                note: Some("pending".to_owned()),
            });
        }
        let (targets, skipped) = self.broadcast_targets(session);
        Some(BroadcastStatus {
            count: u32::try_from(targets.len()).unwrap_or(u32::MAX),
            note: (skipped > 0).then(|| format!("{skipped} skipped")),
        })
    }
}

#[cfg(test)]
#[path = "broadcast_tests.rs"]
mod tests;
