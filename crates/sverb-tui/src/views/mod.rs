//! Views: the successors of the template's `Component` trait.
//!
//! A [`View`] is plain data plus two functions:
//! - [`View::handle`] reacts to input synchronously and may request effects through
//!   [`ViewCx`]. It returns [`Outcome::Ignored`] for keys it does not handle, so they
//!   bubble to the global keymap.
//! - [`View::render`] draws into a frame and is **infallible**: a view that cannot
//!   render (area too small, missing data) draws an inline message instead.
//!
//! # No senders, no ping-pong
//! Views get no channel, no `register_action_handler` and no way to enqueue events,
//! not even to themselves. Everything a view can do happens inside one `handle` call
//! through [`ViewCx`]: push effects (bounded by what one call pushes), request a
//! redraw, or close itself if it is a dialog. Effect results come back later as new
//! `UiEvent`s, from services, never re-entrantly. That makes the old template's
//! action ping-pong impossible by construction.
//!
//! # Adding a view
//! See `docs/architecture.md` ("How to add a view").

pub mod dialogs;
pub mod hosts;
// M2-02: the Keychain section (Identities sub-tab; M2-03 adds Keys and Certificates).
pub mod keychain;
// M0-11
pub mod shell;
pub mod sidebar;
// M1-04: first run, unlock prompt / change password, lock overlay.
pub mod first_run;
pub mod lock_overlay;
pub mod unlock;
// M3-05: the recording replay player (M3-06 adds the Logs list around it).
pub mod logs;
// M1-17: tabs, panes and the tab bar's geometry.
pub mod sessions;
// M1-15: the Known Hosts section (list, edit, import / export prompts).
pub mod known_hosts;
// M2-08: the Forwards section (rules, live status, add / edit form).
pub mod forwards;
// M2-11: the import / export wizard (dry-run preview, target, conflict policy).
pub mod import_wizard;
// M2-09: the Snippets section, the `leader e` picker, the variable form, the editor
// and the exec results.
pub mod snippets;
// M2-12: the command palette overlay (`leader p`, `ctrl-k`).
pub mod palette;
// M3-03: the workspaces dialog (list, fuzzy picker, preview, save / rename prompts).
pub mod workspaces;
// M5-03: Settings → Team: safety numbers, ✓ verification, key-change warnings.
pub mod settings;

use std::collections::BTreeMap;

use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::{Frame, layout::Rect};

use crate::{
    app::{
        Config, Effect, EffectId, Mode,
        state::{Focus, IdGen, PendingKind},
    },
    theme::Theme,
};

pub use dialogs::{Dialog, DialogId, DialogKind};
pub use hosts::HostsView;
// M0-11
pub use shell::{MainView, Region, Section, ShellRects, ShellState};
pub use sidebar::SidebarView;

/// The subset of input that reaches a focused view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewEvent {
    /// A key press or repeat.
    Key(KeyEvent),
    /// A mouse event.
    Mouse(MouseEvent),
    /// A bracketed paste.
    Paste(String),
}

/// Whether a view handled an event. The first `Consumed` in the dispatch chain
/// (dialog → focused view → global keymap) wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Handled; stop dispatching.
    Consumed,
    /// Not handled; try the next handler.
    Ignored,
}

/// What a view may touch while handling an event.
#[derive(Debug)]
pub struct ViewCx<'a> {
    config: &'a Config,
    effects: &'a mut Vec<Effect>,
    pending: &'a mut BTreeMap<EffectId, PendingKind>,
    ids: &'a mut IdGen,
    redraw: bool,
    close: bool,
}

impl<'a> ViewCx<'a> {
    pub(crate) fn new(
        config: &'a Config,
        effects: &'a mut Vec<Effect>,
        pending: &'a mut BTreeMap<EffectId, PendingKind>,
        ids: &'a mut IdGen,
    ) -> Self {
        Self {
            config,
            effects,
            pending,
            ids,
            redraw: false,
            close: false,
        }
    }

    /// Read-only configuration.
    pub fn config(&self) -> &Config {
        self.config
    }

    /// Request a side effect that has no result to correlate.
    pub fn push(&mut self, effect: Effect) {
        self.effects.push(effect);
    }

    /// Request a side effect whose result comes back as `UiEvent::EffectDone`.
    /// `make` builds the effect from the freshly assigned id; `kind` says how to
    /// route the result.
    pub fn issue(&mut self, make: impl FnOnce(EffectId) -> Effect, kind: PendingKind) -> EffectId {
        let id = self.ids.effect();
        self.pending.insert(id, kind);
        self.effects.push(make(id));
        id
    }

    /// Ask for the screen to be redrawn.
    pub fn request_redraw(&mut self) {
        self.redraw = true;
    }

    /// Close this view. Only meaningful for dialogs, which are popped from the stack.
    pub fn close(&mut self) {
        self.close = true;
        self.redraw = true;
    }

    pub(crate) fn redraw_requested(&self) -> bool {
        self.redraw
    }

    pub(crate) fn close_requested(&self) -> bool {
        self.close
    }
}

/// What a view may read while rendering.
#[derive(Debug, Clone, Copy)]
pub struct RenderCx<'a> {
    /// Read-only configuration.
    pub config: &'a Config,
    /// Current input mode.
    pub mode: Mode,
    /// Whether this view has keyboard focus.
    pub focused: bool,
    // M0-11
    /// The resolved UI theme (styles already account for `NO_COLOR` and color depth).
    pub theme: &'a Theme,
    /// `--debug` is on (the log pane and its binding exist).
    pub debug: bool,
}

/// A screen region with input handling and infallible rendering.
pub trait View {
    /// React to input. Must be synchronous, deterministic and I/O-free.
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome;

    /// Draw into `area`. Must not panic for any area size, including 0×0 and 1×1.
    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>);

    // M1-06
    /// The view is editing text (a list's filter line, a form field). The mode is then
    /// Insert (M0-10): keys go to the view, Normal-mode bindings (`q`, `?`) do not
    /// fire, and the leader still works.
    fn insert_mode(&self) -> bool {
        false
    }
}

/// All views, one field per view (no `Vec<Box<dyn …>>`).
///
/// Append new views at the end, one block per task with a `// <task-id>` comment.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Views {
    // M0-08
    /// Hosts section (M1-07).
    pub hosts: HostsView,
    // M0-11
    /// The sidebar (section switcher).
    pub sidebar: SidebarView,
    // M3-06
    /// The Logs section (connection logs, recordings).
    pub logs: logs::LogsView,
    // M2-02
    /// The Keychain section.
    pub keychain: keychain::KeychainView,
    // M1-15
    /// The Known Hosts section.
    pub known_hosts: known_hosts::KnownHostsView,
    // M2-08
    /// The Forwards section.
    pub forwards: forwards::ForwardsView,
    // M2-09
    /// The Snippets section.
    pub snippets: snippets::SnippetsView,
}

impl Views {
    /// The view that has focus. `None` for a session pane (M0-10: its keys are routed
    /// by the reducer; M1-10 adds the pane widget).
    pub fn focused_mut(&mut self, focus: Focus) -> Option<&mut dyn View> {
        match focus {
            Focus::Hosts => Some(&mut self.hosts),
            // M0-10
            Focus::Session(_) => None,
        }
    }
}
