//! M1-17: tabs and panes in the reducer (SPEC §8.1, §8.3, §8.4).
//!
//! - **Model**: [`Tabs::list`] holds the tabs (`views::sessions::Tab`, a layout tree of
//!   panes each). Every session in [`Tabs::sessions`] has exactly one pane:
//!   [`App::sync_tabs`] places new sessions (a new tab, or the split requested through
//!   [`Tabs::placement`]) and moves the active tab to the focused session. It runs
//!   after every event (and right after a split opens a session).
//! - **Actions** (`03-KEYBINDINGS.md` §4.1): `leader c` (host picker: quick connect's
//!   fuzzy host list) and `leader o` open a new tab; `leader t` a local tab;
//!   `leader 1..9`, `n`/`N` switch tabs (wrapping); `leader -`/`|` split the focused pane
//!   with **the same kind of session** (same saved host, same unsaved target, or a
//!   local shell); `leader h j k l`/arrows move focus geometrically (ties → most recently
//!   focused); `leader x`/`X` close the pane / tab, with a confirmation while a session
//!   is alive (connected or connecting). Closing the last pane closes the tab; closing
//!   the last tab returns the main area to the section views.
//! - **Closing** is driven by `Effect::CloseSession`: whenever the reducer emits one
//!   (directly, from a confirmation's answer, or on lock), the pane leaves its layout at
//!   once; `State(Closed)` does the same for sessions that end on their own.
//! - **Markers**: background output (`Dirty`, forwarded by the runtime for hidden
//!   sessions) sets `●`, a background BEL sets `🔔`; focusing the tab clears both.
//!   Disconnected/exited panes show `✕`, a pending password prompt `🔑`.
//! - **Resize** (§8.4): after every event the wanted pane sizes are recomputed from the
//!   layout; when they changed, `TimerKind::ResizeDebounce` is (re)scheduled for 50 ms
//!   (scheduling replaces a pending timer, so a burst of terminal resizes ends in one
//!   timer). When it fires, every session whose size differs from what it was last sent
//!   gets one `Effect::ResizeSession`. New sessions open at their pane's size.
//! - **Mouse**: a click on a tab switches to it, on `‹`/`›` scrolls, on `+` opens the host
//!   picker; a click on an unfocused pane focuses it; other events inside the focused
//!   live pane go to its session with pane-relative coordinates (`SessionCmd::Mouse`,
//!   routed by the session, M1-11).
//!
//! [`Tabs::list`]: super::Tabs::list
//! [`Tabs::sessions`]: super::Tabs::sessions
//! [`Tabs::placement`]: super::Tabs::placement

use std::collections::BTreeMap;
use std::time::Duration;

use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Frame, layout::Rect};
use sverb_conn::{SessionEvent, SessionSpec, SessionState};
use sverb_core::layout::neighbor_by_recency;
use sverb_core::model::ItemId;
use sverb_term::modes::input::{KeyMods, MouseAction, MouseButton as TermButton, MouseInput};

use super::{App, Effect, Focus, Mode, SessionId, TimerKind, ToastLevel, effect::SessionInput};
use crate::keymap::action::ActionName;
use crate::views::{
    MainView, Region,
    dialogs::ModalDialog,
    sessions::{
        Direction, Pane, PaneKind, PaneLife, Placement, SplitDir, Tab, TabId, pane_of,
        panes::{content_rect, content_size, pane_rects, to_core},
        tabs::{self as tabbar, MarkerSet, Segment, TabItem},
    },
};
use crate::widgets::dialog::{Button, Modal};
use crate::widgets::terminal_pane::{PaneCursor, PaneSource};

/// The resize debounce (SPEC §8.4).
pub(crate) const RESIZE_DEBOUNCE: Duration = Duration::from_millis(50);

/// Longest OSC title kept (SPEC §17; the session already caps it).
const MAX_TITLE_CHARS: usize = 256;

/// Button id of "Close" in the close confirmations.
const CLOSE: &str = "close";

impl App {
    // ------------------------------------------------------------------ queries

    /// The active tab, if any.
    pub fn active_tab(&self) -> Option<&Tab> {
        self.tabs.list.get(self.tabs.active)
    }

    fn tab_index_of(&self, session: SessionId) -> Option<usize> {
        self.tabs.list.iter().position(|t| t.has_session(session))
    }

    fn pane_mut(&mut self, session: SessionId) -> Option<&mut Pane> {
        self.tabs
            .list
            .iter_mut()
            .find_map(|t| t.panes.get_mut(&pane_of(session)))
    }

    /// Whether the session area shows the active tab.
    fn sessions_shown(&self) -> bool {
        self.shell.main_view == MainView::Sessions
    }

    /// Sessions drawn by the next frame: the active tab's live panes (only while the
    /// session area is shown), plus a focused session not placed yet.
    pub(crate) fn tabs_visible_sessions(&self) -> Vec<SessionId> {
        let mut out: Vec<SessionId> = match self.active_tab() {
            Some(tab) if self.sessions_shown() => {
                let rects = pane_rects(&tab.layout, tab.zoomed, Rect::new(0, 0, 1, 1));
                rects
                    .into_iter()
                    .filter_map(|(p, _)| tab.panes.get(&p).map(|x| x.session))
                    .filter(|s| self.tabs.sessions.contains(s))
                    .collect()
            }
            _ => Vec::new(),
        };
        if let Some(f) = self.focused_session()
            && !out.contains(&f)
        {
            out.push(f);
        }
        out
    }

    // ------------------------------------------------------------------ sync

    /// Make the tabs match [`Tabs::sessions`](super::Tabs::sessions) and the focus (see
    /// the module docs). Idempotent.
    pub(crate) fn sync_tabs(&mut self) {
        let mut changed = false;
        // New sessions.
        for s in self.tabs.sessions.clone() {
            if self.tab_index_of(s).is_some() {
                continue;
            }
            let placement = self.tabs.placement.take().unwrap_or(Placement::NewTab);
            self.place(s, placement);
            changed = true;
        }
        if self.tabs.active >= self.tabs.list.len() {
            self.tabs.active = self.tabs.list.len().saturating_sub(1);
        }
        // Follow the focus.
        if let Focus::Session(id) = self.focus
            && let Some(i) = self.tab_index_of(id)
        {
            self.tabs.active = i;
            let tab = &mut self.tabs.list[i];
            if tab.focused != pane_of(id) {
                tab.focus(pane_of(id));
            }
        }
        if self.sessions_shown()
            && let Some(tab) = self.tabs.list.get_mut(self.tabs.active)
            && tab.markers != Default::default()
        {
            tab.markers = Default::default();
            changed = true;
        }
        if changed {
            self.mode = self.derive_mode();
            self.needs_redraw = true;
        }
    }

    /// Put session `s` in a pane per `placement`.
    fn place(&mut self, s: SessionId, placement: Placement) {
        if let Placement::Split { tab, pane, dir } = placement
            && let Some(t) = self.tabs.list.iter_mut().find(|t| t.id == tab)
            && t.split(pane, dir, Pane::new(s))
        {
            return;
        }
        let id = TabId(self.tabs.next_tab);
        self.tabs.next_tab += 1;
        self.tabs.list.push(Tab::new(id, Pane::new(s)));
    }

    /// Focus a session that is already placed (no sync).
    fn set_focus(&mut self, s: SessionId) {
        self.focus = Focus::Session(s);
        self.input.copy_mode = false;
        self.mode = self.derive_mode();
        self.needs_redraw = true;
    }

    /// A session is closing (`Effect::CloseSession`) or closed (`State(Closed)`): its
    /// pane leaves the layout at once (an emptied tab closes), and focus moves to the
    /// tab's next pane, a neighbor tab, or the section views.
    pub(crate) fn remove_session_pane(&mut self, id: SessionId) {
        self.tabs.sessions.retain(|s| *s != id);
        self.tabs.exited.remove(&id);
        self.tabs.sent_sizes.remove(&id);
        self.tabs.wanted_sizes.remove(&id);
        // M1-10: the pane's state goes with it.
        self.panes.remove(&id);
        if let Some(i) = self.tab_index_of(id) {
            if !self.tabs.list[i].remove(pane_of(id)) {
                self.tabs.list.remove(i);
                if i < self.tabs.active {
                    self.tabs.active -= 1;
                }
            }
            self.tabs.active = self.tabs.active.min(self.tabs.list.len().saturating_sub(1));
            self.needs_redraw = true;
        }
        if self.focus == Focus::Session(id) {
            match self.active_tab().map(Tab::focused_session) {
                Some(next) => self.set_focus(next),
                None => {
                    self.focus = Focus::Hosts;
                    self.shell.main_view = MainView::Sections;
                    self.shell.region = Region::Main;
                    self.input.copy_mode = false;
                    self.mode = self.derive_mode();
                }
            }
            self.needs_redraw = true;
        }
    }

    /// After every event: closes, placement, the kinds and sizes of new sessions, and
    /// the resize debounce.
    pub(crate) fn tabs_after_handle(&mut self, effects: &mut Vec<Effect>) {
        let closing: Vec<SessionId> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::CloseSession(id) => Some(*id),
                _ => None,
            })
            .collect();
        for id in closing {
            self.remove_session_pane(id);
        }
        self.sync_tabs();
        // M3-03: release queued workspace session opens (bounded concurrency).
        self.workspaces_pump(effects);
        let wanted = self.wanted_sizes();
        let mut local_labels = Vec::new();
        for effect in effects.iter_mut() {
            let Effect::OpenSession {
                id,
                spec,
                cols,
                rows,
            } = effect
            else {
                continue;
            };
            let kind = match spec {
                SessionSpec::Ssh(s) => PaneKind::Ssh(s.clone()),
                SessionSpec::Local(l) => {
                    local_labels.push((*id, local_label(l)));
                    PaneKind::Local(l.clone())
                }
                _ => PaneKind::Unknown,
            };
            if let Some(pane) = self.pane_mut(*id) {
                pane.kind = kind;
            }
            if let Some(size) = wanted.as_ref().and_then(|w| w.get(id)) {
                (*cols, *rows) = *size;
            }
            self.tabs.sent_sizes.insert(*id, (*cols, *rows));
        }
        for (id, label) in local_labels {
            if !self.panes.contains_key(&id) {
                self.set_pane_label(id, label);
            }
        }
        let Some(wanted) = wanted else {
            return;
        };
        // Sessions placed without an `OpenSession` (restored, tests) are taken to have
        // been opened at their pane's size.
        for (id, size) in &wanted {
            self.tabs.sent_sizes.entry(*id).or_insert(*size);
        }
        if wanted != self.tabs.wanted_sizes {
            let differs = wanted
                .iter()
                .any(|(id, size)| self.tabs.sent_sizes.get(id) != Some(size));
            self.tabs.wanted_sizes = wanted;
            if differs {
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::ResizeDebounce,
                    after: RESIZE_DEBOUNCE,
                });
            }
        }
    }

    /// The terminal size every pane wants (all tabs; a zoomed tab only sizes its zoomed
    /// pane). `None` while the terminal is too small to draw the session area.
    fn wanted_sizes(&self) -> Option<BTreeMap<SessionId, (u16, u16)>> {
        let rects = self.shell_rects();
        let main = rects.main;
        if rects.too_small || main.width < 3 || main.height < 3 {
            return None;
        }
        let mut out = BTreeMap::new();
        for tab in &self.tabs.list {
            for (p, r) in pane_rects(&tab.layout, tab.zoomed, main) {
                if let Some(pane) = tab.panes.get(&p) {
                    out.insert(pane.session, content_size(r));
                }
            }
        }
        Some(out)
    }

    /// `TimerKind::ResizeDebounce`: one `ResizeSession` per live session whose size changed.
    pub(crate) fn on_resize_debounce(&mut self, effects: &mut Vec<Effect>) {
        let Some(wanted) = self.wanted_sizes() else {
            return;
        };
        for (id, (cols, rows)) in &wanted {
            if self.tabs.sessions.contains(id)
                && self.tabs.sent_sizes.get(id) != Some(&(*cols, *rows))
            {
                effects.push(Effect::ResizeSession {
                    id: *id,
                    cols: *cols,
                    rows: *rows,
                });
                self.tabs.sent_sizes.insert(*id, (*cols, *rows));
            }
        }
        self.tabs.wanted_sizes = wanted;
    }

    // ------------------------------------------------------------------ session events

    /// Markers, titles and pane states from session events (before `on_session`).
    pub(crate) fn tabs_on_session(&mut self, id: SessionId, ev: &SessionEvent) {
        let background = match self.tab_index_of(id) {
            Some(i) => !(self.sessions_shown() && i == self.tabs.active),
            None => return,
        };
        match ev {
            SessionEvent::Dirty | SessionEvent::Bell if background => {
                if let Some(i) = self.tab_index_of(id) {
                    let m = &mut self.tabs.list[i].markers;
                    let before = *m;
                    if matches!(ev, SessionEvent::Bell) {
                        m.bell = true;
                    } else {
                        m.activity = true;
                    }
                    self.needs_redraw |= *m != before;
                }
            }
            SessionEvent::Title(t) => {
                let t: String = t.chars().take(MAX_TITLE_CHARS).collect();
                self.set_pane_title(id, (!t.is_empty()).then_some(t));
                // The tab bar shows the title of every tab.
                self.needs_redraw |= self.config.terminal.use_osc_title;
            }
            SessionEvent::State(SessionState::Closed) => self.remove_session_pane(id),
            SessionEvent::State(state) => {
                let life = match state {
                    SessionState::Connected { .. } => PaneLife::Connected,
                    SessionState::AwaitingUser(_) => PaneLife::AuthPending,
                    SessionState::Disconnected { .. } => PaneLife::Down,
                    _ => PaneLife::Connecting,
                };
                if let Some(pane) = self.pane_mut(id)
                    && pane.life != life
                {
                    pane.life = life;
                    self.needs_redraw = true;
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------ actions

    /// The tab and pane actions. Returns `false` for actions it doesn't own.
    pub(crate) fn apply_tab_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        // M3-03: save / open / manage workspaces.
        if self.apply_workspace_action(action, effects) {
            return true;
        }
        use ActionName as A;
        let go = |n: usize| Some(n);
        let tab_number = match action {
            A::GoToTab1 => go(0),
            A::GoToTab2 => go(1),
            A::GoToTab3 => go(2),
            A::GoToTab4 => go(3),
            A::GoToTab5 => go(4),
            A::GoToTab6 => go(5),
            A::GoToTab7 => go(6),
            A::GoToTab8 => go(7),
            A::GoToTab9 => go(8),
            _ => None,
        };
        if let Some(i) = tab_number {
            // Past the last tab: nothing happens.
            self.activate_tab(i);
            return true;
        }
        match action {
            // The host picker: quick connect's fuzzy host list; the session opens in a
            // new tab.
            A::NewTabPickHost => self.open_quick_connect(),
            A::NextTab | A::PrevTab => {
                let n = self.tabs.list.len();
                if n > 0 {
                    let cur = self.tabs.active.min(n - 1);
                    let next = if action == A::NextTab {
                        (cur + 1) % n
                    } else {
                        (cur + n - 1) % n
                    };
                    self.activate_tab(next);
                }
            }
            A::SplitHorizontal => self.split_focused(SplitDir::Horizontal, effects),
            A::SplitVertical => self.split_focused(SplitDir::Vertical, effects),
            A::FocusLeft => self.focus_direction(Direction::Left),
            A::FocusRight => self.focus_direction(Direction::Right),
            A::FocusUp => self.focus_direction(Direction::Up),
            A::FocusDown => self.focus_direction(Direction::Down),
            A::ClosePane => self.close_pane(effects),
            A::CloseTab => self.close_tab(effects),
            _ => return false,
        }
        true
    }

    /// Show tab `i` (no-op past the last tab).
    pub(crate) fn activate_tab(&mut self, i: usize) {
        let Some(tab) = self.tabs.list.get(i) else {
            return;
        };
        let s = tab.focused_session();
        self.tabs.active = i;
        self.focus_session(s);
    }

    /// The active tab's focused pane (the session area may be hidden).
    fn focused_pane(&self) -> Option<(TabId, Pane)> {
        let tab = self.active_tab()?;
        let pane = tab.panes.get(&tab.focused)?.clone();
        Some((tab.id, pane))
    }

    fn focus_direction(&mut self, dir: Direction) {
        let main = self.shell_rects().main;
        let Some(tab) = self.tabs.list.get_mut(self.tabs.active) else {
            return;
        };
        // M3-01: moving focus while zoomed unzooms first.
        tab.zoomed = None;
        let rects: Vec<_> = pane_rects(&tab.layout, None, main)
            .into_iter()
            .map(|(p, r)| (p, to_core(r)))
            .collect();
        let Some(next) = neighbor_by_recency(tab.focused, dir, &rects, &tab.recency) else {
            return;
        };
        tab.focus(next);
        let s = tab.focused_session();
        self.focus_session(s);
    }

    /// `leader -` / `leader |`: the same kind of session next to the focused pane.
    fn split_focused(&mut self, dir: SplitDir, effects: &mut Vec<Effect>) {
        let Some((tab, pane)) = self.focused_pane() else {
            self.push_toast(ToastLevel::Info, "No pane to split".to_owned(), effects);
            return;
        };
        let placement = Placement::Split {
            tab,
            pane: pane.id,
            dir,
        };
        match pane.kind {
            PaneKind::Ssh(spec) => match spec.host_id {
                // A saved host resolves anew (group defaults, scheme, recording).
                Some(item) if self.host_known(item) => {
                    self.with_placement(placement, |app| app.connect_host(item, effects));
                }
                _ => {
                    let label = self.pane(pane.session).label;
                    self.with_placement(placement, |app| {
                        app.open_spec(SessionSpec::Ssh(spec), label, effects);
                    });
                }
            },
            PaneKind::Local(spec) => {
                let label = local_label(&spec);
                self.with_placement(placement, |app| {
                    app.open_spec(SessionSpec::Local(spec), label, effects);
                });
            }
            _ => {
                self.push_toast(
                    ToastLevel::Info,
                    "This pane's session can't be duplicated".to_owned(),
                    effects,
                );
            }
        }
    }

    // M3-03: also used by workspaces (missing hosts become placeholders).
    pub(crate) fn host_known(&self, item: ItemId) -> bool {
        self.views
            .hosts
            .catalog()
            .is_some_and(|c| c.hosts.contains_key(&item))
            || self
                .views
                .hosts
                .index()
                .is_some_and(|i| i.get(item).is_some())
    }

    /// Run `f` (which opens one session) with the new session's pane going to `placement`.
    fn with_placement(&mut self, placement: Placement, f: impl FnOnce(&mut Self)) {
        self.tabs.placement = Some(placement);
        f(self);
        // Place it now, while the placement applies.
        self.sync_tabs();
        self.tabs.placement = None;
    }

    /// Open `spec` in a new pane (placed by [`Tabs::placement`](super::Tabs::placement)).
    fn open_spec(&mut self, spec: SessionSpec, label: String, effects: &mut Vec<Effect>) {
        let id = loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        };
        let (cols, rows) = (80, 24); // replaced by the pane's size after the event
        effects.push(Effect::OpenSession {
            id,
            spec,
            cols,
            rows,
        });
        self.focus_session(id);
        self.set_pane_label(id, label);
        // M3-05: the global flag (a saved host's own setting goes through `connect_host`).
        self.auto_record(id, self.config.recording.enabled, effects);
    }

    /// M1-07 `ctrl-enter`/`v` in the Hosts view: each host in a split of the current tab
    /// (side by side); the first one opens a tab when there is none.
    pub(crate) fn connect_split(&mut self, items: Vec<ItemId>, effects: &mut Vec<Effect>) {
        for item in items {
            match self.focused_pane() {
                Some((tab, pane)) => {
                    let placement = Placement::Split {
                        tab,
                        pane: pane.id,
                        dir: SplitDir::Vertical,
                    };
                    self.with_placement(placement, |app| app.connect_host(item, effects));
                }
                None => self.connect_host(item, effects),
            }
            self.sync_tabs();
        }
    }

    /// `leader x`: close the focused pane (confirm while its session is alive).
    fn close_pane(&mut self, effects: &mut Vec<Effect>) {
        let Some((_, pane)) = self.focused_pane() else {
            self.push_toast(ToastLevel::Info, "No pane to close".to_owned(), effects);
            return;
        };
        let s = pane.session;
        if self.pane_alive(&pane) {
            let label = self.pane(s).label;
            let modal = close_confirm("Close pane?", &format!("{label} is still connected."));
            let route = format!("button:{CLOSE}");
            self.push_modal(
                ModalDialog::new(modal).on(&route, vec![Effect::CloseSession(s)]),
                effects,
            );
        } else {
            // M1-16: stop an auto-reconnect countdown first.
            self.before_close_dead_pane(s, effects);
            effects.push(Effect::CloseSession(s));
        }
    }

    /// `leader X`: close every pane of the active tab (confirm if any is alive).
    fn close_tab(&mut self, effects: &mut Vec<Effect>) {
        let Some(tab) = self.active_tab() else {
            self.push_toast(ToastLevel::Info, "No tab to close".to_owned(), effects);
            return;
        };
        let alive = tab.panes.values().filter(|p| self.pane_alive(p)).count();
        let sessions = tab.sessions();
        let closes: Vec<Effect> = sessions.iter().copied().map(Effect::CloseSession).collect();
        if alive == 0 {
            // M1-16: stop auto-reconnect countdowns first.
            for s in sessions {
                self.before_close_dead_pane(s, effects);
            }
            effects.extend(closes);
            return;
        }
        let body = if alive == 1 {
            "1 session is still connected.".to_owned()
        } else {
            format!("{alive} sessions are still connected.")
        };
        let route = format!("button:{CLOSE}");
        self.push_modal(
            ModalDialog::new(close_confirm("Close tab?", &body)).on(&route, closes),
            effects,
        );
    }

    fn pane_alive(&self, pane: &Pane) -> bool {
        pane.life.alive()
            && self.tabs.sessions.contains(&pane.session)
            && !self.is_dead_pane(pane.session)
    }

    // ------------------------------------------------------------------ mouse

    /// A mouse event on the tab bar or the session area. Returns whether it was handled.
    pub(crate) fn tabs_on_mouse(&mut self, mouse: MouseEvent, effects: &mut Vec<Effect>) -> bool {
        if !self.dialogs.is_empty() {
            return false;
        }
        let rects = self.shell_rects();
        if rects.too_small {
            return false;
        }
        let (col, row) = (mouse.column, mouse.row);
        let bar = self.tab_bar_area(&rects);
        if bar.contains((col, row).into()) {
            if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
                return true;
            }
            let items = self.tab_items();
            if items.is_empty() {
                return false;
            }
            let segments = tabbar::bar_segments(&items, bar.width);
            match tabbar::hit(&segments, col - bar.x) {
                Some(Segment::Tab(i) | Segment::MoreLeft(i) | Segment::MoreRight(i)) => {
                    self.activate_tab(i);
                }
                Some(Segment::Plus) => self.open_quick_connect(),
                _ => {}
            }
            return true;
        }
        if !self.sessions_shown() || !rects.main.contains((col, row).into()) {
            return false;
        }
        let Some(tab) = self.active_tab() else {
            return false;
        };
        let Some((pane, rect)) = pane_rects(&tab.layout, tab.zoomed, rects.main)
            .into_iter()
            .find(|(_, r)| r.contains((col, row).into()))
        else {
            return true;
        };
        let session = tab.panes.get(&pane).map(|p| p.session);
        let focused = pane == tab.focused && self.focus == Focus::Session(tab.focused_session());
        if !focused {
            if matches!(mouse.kind, MouseEventKind::Down(_))
                && let Some(s) = session
            {
                if let Some(t) = self.tabs.list.get_mut(self.tabs.active) {
                    t.focus(pane);
                }
                self.focus_session(s);
            }
            return true;
        }
        let inner = content_rect(rect);
        if self.derive_mode() == Mode::Terminal
            && inner.contains((col, row).into())
            && let Some(id) = session
            && let Some(ev) = mouse_input(mouse, col - inner.x, row - inner.y)
        {
            effects.push(Effect::SendToSession {
                id,
                input: SessionInput::Mouse(ev),
            });
        } else if self.derive_mode() == Mode::Copy
            && inner.contains((col, row).into())
            && let Some(id) = session
            && let Some(ev) = mouse_input(mouse, col - inner.x, row - inner.y)
        {
            // M3-04: in copy mode the mouse belongs to sverb (never sent to the remote).
            self.copy_on_mouse(id, ev, effects);
        }
        true
    }

    // ------------------------------------------------------------------ drawing

    /// The tab bar's items (the tabs, or the open sessions before they are placed).
    pub(crate) fn tab_items(&self) -> Vec<TabItem> {
        let use_osc = self.config.terminal.use_osc_title;
        if self.tabs.list.is_empty() {
            return self
                .tabs
                .sessions
                .iter()
                .map(|id| TabItem {
                    label: self.pane(*id).label,
                    active: self.focus == Focus::Session(*id),
                    markers: String::new(),
                })
                .collect();
        }
        self.tabs
            .list
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let info = self.pane(tab.focused_session());
                let label = tabbar::title(
                    tab.title_override.as_deref(),
                    &info.label,
                    info.osc_title.as_deref(),
                    use_osc,
                );
                let lives = tab.panes.values();
                let markers = MarkerSet {
                    activity: tab.markers.activity,
                    bell: tab.markers.bell,
                    disconnected: lives
                        .clone()
                        .any(|p| p.life == PaneLife::Down || self.is_exited(p.session)),
                    auth: lives.clone().any(|p| p.life == PaneLife::AuthPending),
                    zoomed: tab.zoomed.is_some(),
                };
                TabItem {
                    label,
                    active: i == self.tabs.active && self.sessions_shown(),
                    // M3-02: `≋` while the tab broadcasts.
                    markers: markers.text(false) + &Self::broadcast_tab_marker(tab),
                }
            })
            .collect()
    }

    /// Draw the active tab's panes into `area`; returns the focused pane's cursor.
    /// `None` when there is nothing to draw (the caller shows "No open sessions").
    pub(crate) fn render_session_area(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        panes: &dyn PaneSource,
    ) -> Option<Option<PaneCursor>> {
        let tab = self
            .active_tab()
            .filter(|t| match self.focus {
                Focus::Session(id) => t.has_session(id),
                Focus::Hosts => true,
            })
            .cloned();
        let Some(tab) = tab else {
            // Not placed yet (a session focused outside an event): just that session.
            return match self.focus {
                Focus::Session(id) => Some(self.render_session_pane(frame, area, id, panes)),
                Focus::Hosts => None,
            };
        };
        let mut cursor = None;
        for (p, rect) in pane_rects(&tab.layout, tab.zoomed, area) {
            if rect.width == 0 || rect.height == 0 {
                continue;
            }
            let s = tab
                .panes
                .get(&p)
                .map_or(super::SessionId(p.0), |x| x.session);
            if let Some(c) = self.render_session_pane(frame, rect, s, panes) {
                cursor = Some(c);
            }
        }
        Some(cursor)
    }
}

/// "Close pane?" / "Close tab?". Danger: `Enter` cancels.
fn close_confirm(title: &str, body: &str) -> Modal {
    Modal::confirm(
        title,
        body,
        vec![
            Button::new(CLOSE, "Close", 'c').danger(),
            Button::new("keep", "Keep", 'k').safe(),
        ],
        0,
        true,
    )
}

/// A local tab's label: the shell's name (`zsh`), else `local`.
fn local_label(spec: &sverb_conn::LocalSpec) -> String {
    spec.shell
        .as_deref()
        .and_then(|s| std::path::Path::new(s).file_name())
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("local")
        .to_owned()
}

/// A crossterm mouse event at pane-relative `(col, row)` for the session.
fn mouse_input(ev: MouseEvent, col: u16, row: u16) -> Option<MouseInput> {
    let button = |b: MouseButton| match b {
        MouseButton::Left => TermButton::Left,
        MouseButton::Right => TermButton::Right,
        MouseButton::Middle => TermButton::Middle,
    };
    let action = match ev.kind {
        MouseEventKind::Down(b) => MouseAction::Press(button(b)),
        MouseEventKind::Up(b) => MouseAction::Release(button(b)),
        MouseEventKind::Drag(b) => MouseAction::Drag(button(b)),
        MouseEventKind::Moved => MouseAction::Move,
        MouseEventKind::ScrollUp => MouseAction::WheelUp,
        MouseEventKind::ScrollDown => MouseAction::WheelDown,
        MouseEventKind::ScrollLeft => MouseAction::WheelLeft,
        MouseEventKind::ScrollRight => MouseAction::WheelRight,
    };
    let mut mods = KeyMods::NONE;
    for (ct, ours) in [
        (KeyModifiers::SHIFT, KeyMods::SHIFT),
        (KeyModifiers::ALT, KeyMods::ALT),
        (KeyModifiers::CONTROL, KeyMods::CTRL),
    ] {
        if ev.modifiers.contains(ct) {
            mods = mods | ours;
        }
    }
    Some(MouseInput {
        action,
        col,
        row,
        mods,
    })
}

#[cfg(test)]
#[path = "tabs_tests.rs"]
mod tests;
