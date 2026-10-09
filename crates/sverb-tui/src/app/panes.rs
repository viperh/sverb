//! M1-10: per-pane state in the reducer (color scheme, title, overlay) and drawing the
//! focused session's [`TerminalPane`].
//!
//! The scheme of a pane is its host's `color_scheme` ([`PaneInfo::scheme`], set when the
//! session is opened or when the host form changes it) or else `terminal.color_scheme`.
//! Changing it only redraws when that pane is visible.

use std::sync::Arc;

use ratatui::{Frame, layout::Rect};
use sverb_term::ColorDepth;
use sverb_term::scheme::{ColorScheme, SchemeCatalog};

use super::{App, SessionId};
use crate::widgets::terminal_pane::{
    PaneCursor, PaneInfo, PaneOverlay, PaneSource, TerminalPane, pane_depth, resolve_scheme,
};

impl App {
    /// Use these terminal color schemes (built-ins plus `themes/*.toml`).
    #[must_use]
    pub fn with_schemes(mut self, schemes: Arc<SchemeCatalog>) -> Self {
        self.schemes = schemes;
        self
    }

    /// Replace the schemes (a `themes/` change); panes redraw.
    pub fn set_schemes(&mut self, schemes: Arc<SchemeCatalog>) {
        if *self.schemes != *schemes {
            self.schemes = schemes;
            self.needs_redraw = true;
        }
    }

    /// The terminal color schemes.
    pub fn schemes(&self) -> &SchemeCatalog {
        &self.schemes
    }

    /// A pane's state (default for panes nothing was set for).
    pub fn pane(&self, id: SessionId) -> PaneInfo {
        self.panes.get(&id).cloned().unwrap_or_else(|| PaneInfo {
            label: format!("session {}", id.0),
            ..PaneInfo::default()
        })
    }

    fn update_pane(&mut self, id: SessionId, f: impl FnOnce(&mut PaneInfo)) -> bool {
        let mut info = self.pane(id);
        let before = info.clone();
        f(&mut info);
        if info == before {
            return false;
        }
        self.panes.insert(id, info);
        // Forget panes of sessions that are gone.
        let open = &self.tabs.sessions;
        self.panes.retain(|id, _| open.contains(id));
        let visible = self.visible_sessions().contains(&id);
        self.needs_redraw |= visible;
        visible
    }

    /// Set the pane's label (host label; the title when there is no OSC title).
    pub fn set_pane_label(&mut self, id: SessionId, label: impl Into<String>) {
        let label = label.into();
        self.update_pane(id, |p| p.label = label);
    }

    /// Set the pane's host item id (so host edits find its panes).
    pub fn set_pane_host(&mut self, id: SessionId, host: Option<String>) {
        self.update_pane(id, |p| p.host = host);
    }

    /// The OSC title (shown with `terminal.use_osc_title`).
    pub fn set_pane_title(&mut self, id: SessionId, title: Option<String>) {
        self.update_pane(id, |p| p.osc_title = title);
    }

    /// The pane-state overlay (M1-04, M1-12, M1-16 drive it).
    pub fn set_pane_overlay(&mut self, id: SessionId, overlay: PaneOverlay) {
        self.update_pane(id, |p| p.overlay = overlay);
    }

    /// A session's color scheme override (`None` = `terminal.color_scheme`). Returns
    /// whether the pane is visible (and so redraws).
    pub fn set_session_scheme(&mut self, id: SessionId, scheme: Option<String>) -> bool {
        self.update_pane(id, |p| p.scheme = scheme)
    }

    /// A host's `color_scheme` changed (host form): every pane of that host takes it, and
    /// only visible ones redraw. Returns the sessions that changed.
    pub fn set_host_scheme(&mut self, host: &str, scheme: Option<String>) -> Vec<SessionId> {
        let ids: Vec<SessionId> = self
            .panes
            .iter()
            .filter(|(_, p)| p.host.as_deref() == Some(host) && p.scheme != scheme)
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            self.update_pane(*id, |p| p.scheme = scheme.clone());
        }
        ids
    }

    /// The palette a pane's content uses (`None` = `terminal`, pass-through).
    pub fn pane_scheme(&self, id: SessionId) -> Option<Arc<ColorScheme>> {
        let pane = self.panes.get(&id);
        let name = pane
            .and_then(|p| p.scheme.as_deref())
            .unwrap_or(&self.config.terminal.color_scheme);
        resolve_scheme(&self.schemes, name)
    }

    /// The color depth of pane content (`Mono` under `NO_COLOR`).
    pub fn pane_depth(&self) -> ColorDepth {
        pane_depth(
            self.theme_env.depth(self.config.ui.truecolor),
            self.theme_env.no_color,
        )
    }

    /// Draw session `id` into `area`; sets the frame cursor for a focused live pane.
    pub(crate) fn render_session_pane(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        id: SessionId,
        panes: &dyn PaneSource,
    ) -> Option<PaneCursor> {
        // M6-03: a viewer pane draws the host-sized screen letterboxed.
        if let Some(cursor) = self.render_share_viewer(frame, area, id, panes) {
            return cursor;
        }
        let emulator = panes.emulator(id);
        let mut info = self.pane(id);
        // M3-02: broadcast members get the broadcast border.
        info.broadcast = self.broadcast_highlight(id);
        if emulator.is_none() && info.overlay == PaneOverlay::None {
            // No emulator (reducer tests, a session that is gone): the M0-10 placeholder.
            self.render_session_placeholder(frame, area, id);
            return None;
        }
        let pane = TerminalPane {
            info: &info,
            theme: &self.theme,
            focused: self.dialogs.is_empty() && self.focused_session() == Some(id),
            scheme: self.pane_scheme(id),
            depth: self.pane_depth(),
            use_osc_title: self.config.terminal.use_osc_title,
            leader: self.keymap.leader().hint(),
        };
        // M3-04: copy mode, mouse selection and link overlays.
        let cursor = pane.render_with(area, frame.buffer_mut(), emulator.as_ref(), &|emu, view| {
            self.pane_decor(id, emu, view)
        });
        if let Some(c) = cursor {
            frame.set_cursor_position(c.position);
        }
        // M6-03: `⚠ shared · view|control` on a pane this device shares.
        self.render_share_badge(frame, area, id);
        // M7-01: the ghost-text suggestion after the cursor (`history.ghost_text`).
        self.render_ghost_text(frame, area, id, emulator.as_ref(), cursor.as_ref());
        cursor
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ratatui::{Terminal, backend::TestBackend, style::Color};
    use sverb_conn::SharedEmulator;

    use super::*;
    use crate::app::Config;
    use crate::widgets::terminal_pane::tests::new_emulator;

    fn app_with(scheme: &str) -> App {
        let mut config = Config::default();
        config.terminal.color_scheme = scheme.to_owned();
        App::new(Arc::new(config)).with_theme_env(crate::theme::ThemeEnv {
            no_color: false,
            colorterm_truecolor: true,
        })
    }

    fn draw(app: &App, emu: &SharedEmulator) -> (Terminal<TestBackend>, Option<PaneCursor>) {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut cursor = None;
        let source = |_: SessionId| Some(Arc::clone(emu));
        terminal
            .draw(|f| cursor = app.render_with_panes(f, &source))
            .unwrap();
        (terminal, cursor)
    }

    fn find(terminal: &Terminal<TestBackend>, needle: char) -> ratatui::buffer::Cell {
        let buf = terminal.backend().buffer();
        buf.content()
            .iter()
            .find(|c| c.symbol() == needle.to_string())
            .cloned()
            .unwrap()
    }

    #[test]
    fn focused_pane_renders_content_and_cursor() {
        let mut app = app_with("terminal");
        app.focus_session(SessionId(1));
        app.set_pane_label(SessionId(1), "web-1");
        let emu = new_emulator(40, 10, b"\x1b[31mR");
        let (terminal, cursor) = draw(&app, &emu);
        assert_eq!(find(&terminal, 'R').fg, Color::Indexed(1));
        let cursor = cursor.unwrap();
        assert_eq!(terminal.backend().cursor_position(), cursor.position);
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().to_owned())
            .collect();
        assert!(text.contains("web-1"));
    }

    #[test]
    fn config_scheme_and_host_override() {
        let mut app = app_with("dracula");
        app.focus_session(SessionId(1));
        let emu = new_emulator(40, 10, b"\x1b[31mR");
        let (terminal, _) = draw(&app, &emu);
        assert_eq!(find(&terminal, 'R').fg, Color::Rgb(0xff, 0x55, 0x55));
        app.set_session_scheme(SessionId(1), Some("nord".to_owned()));
        let (terminal, _) = draw(&app, &emu);
        assert_eq!(find(&terminal, 'R').fg, Color::Rgb(0xbf, 0x61, 0x6a));
        // Without truecolor the scheme's RGB is downsampled.
        let app256 = app
            .clone()
            .with_theme_env(crate::theme::ThemeEnv::default());
        let (terminal, _) = draw(&app256, &emu);
        assert!(matches!(find(&terminal, 'R').fg, Color::Indexed(16..)));
        // The chrome keeps the UI theme.
        assert_eq!(app.theme.name, "default-dark");
    }

    #[test]
    fn no_color_is_mono() {
        let app = app_with("dracula").with_theme_env(crate::theme::ThemeEnv {
            no_color: true,
            colorterm_truecolor: true,
        });
        assert_eq!(app.pane_depth(), ColorDepth::Mono);
    }

    // T-14: changing a host's scheme re-renders that pane only.
    #[test]
    fn host_scheme_change_redraws_only_visible_panes() {
        let mut app = app_with("terminal");
        let (a, b, c) = (SessionId(1), SessionId(2), SessionId(3));
        for id in [a, b, c] {
            app.focus_session(id);
        }
        app.set_pane_host(a, Some("host-a".to_owned()));
        app.set_pane_host(b, Some("host-b".to_owned()));
        app.set_pane_host(c, Some("host-a".to_owned()));
        app.focus_session(a);
        app.mark_drawn();

        // A hidden pane of another host: state changes, no redraw.
        assert_eq!(app.set_host_scheme("host-b", Some("nord".to_owned())), [b]);
        assert!(!app.needs_redraw());
        assert_eq!(app.pane_scheme(b).unwrap().name, "nord");
        assert!(app.pane_scheme(a).is_none());

        // The visible pane's host: both of its panes change, and the frame redraws.
        let changed = app.set_host_scheme("host-a", Some("dracula".to_owned()));
        assert_eq!(changed, [a, c]);
        assert!(app.needs_redraw());
        assert_eq!(app.pane_scheme(a).unwrap().name, "dracula");
        assert_eq!(
            app.pane_scheme(b).unwrap().name,
            "nord",
            "other host untouched"
        );

        // Setting the same value again changes nothing.
        app.mark_drawn();
        assert!(
            app.set_host_scheme("host-a", Some("dracula".to_owned()))
                .is_empty()
        );
        assert!(!app.needs_redraw());
    }

    #[test]
    fn overlay_without_emulator_and_locked() {
        let mut app = app_with("terminal");
        app.focus_session(SessionId(1));
        app.set_pane_overlay(
            SessionId(1),
            PaneOverlay::Disconnected {
                reason: "reset".to_owned(),
                gave_up: None,
            },
        );
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|f| {
                app.render_with_panes(f, &crate::widgets::terminal_pane::NoPanes);
            })
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().to_owned())
            .collect();
        assert!(text.contains("[Enter] reconnect"), "{text}");
    }
}
