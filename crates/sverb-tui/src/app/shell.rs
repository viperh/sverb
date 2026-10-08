//! The shell in the reducer (M0-11): sidebar, sections, regions, the session-area
//! toggle, the debug log pane, theme state and drawing the whole frame.
//!
//! Layout math lives in [`crate::views::shell`]; widgets in [`crate::widgets`].

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::logging::{DEBUG_WARNING, LogRing};

use super::{App, Effect, Focus, Mode, ToastLevel};
// M1-10
use crate::widgets::terminal_pane::{PaneCursor, PaneSource};
use crate::{
    keymap::{
        Table,
        action::ActionName,
        chord::{KeyChord, Mods},
    },
    theme::{Theme, ThemeEnv},
    views::{
        MainView, Region, RenderCx, Section, ShellRects, View,
        dialogs::HelpState,
        hosts::leader_hint,
        shell::{self, layout, next_region},
    },
    widgets::{
        log_pane,
        statusbar::{self, StatusInfo},
        tabbar, toast,
        topbar::{self, TopBarInfo},
        which_key,
    },
};

/// Assumed terminal size before the first `Resize` event.
const DEFAULT_SIZE: (u16, u16) = (80, 24);

/// Log lines per `PageUp`/`PageDown`.
const LOG_PAGE: usize = 10;

/// A handle to the `--debug` log ring. An external data source, not state: two
/// handles always compare equal so `App` stays comparable in reducer tests.
#[derive(Clone)]
pub struct DebugRing(pub LogRing);

impl PartialEq for DebugRing {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for DebugRing {}

impl std::fmt::Debug for DebugRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugRing")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl App {
    /// Use this terminal environment (`NO_COLOR`, `COLORTERM`) for the theme.
    #[must_use]
    pub fn with_theme_env(mut self, env: ThemeEnv) -> Self {
        self.theme_env = env;
        self.resolve_theme();
        self
    }

    /// `--debug`: the log pane reads this ring, and `toggle_log_pane` is bound.
    #[must_use]
    pub fn with_debug_ring(mut self, ring: Option<LogRing>) -> Self {
        self.debug_ring = ring.map(DebugRing);
        self
    }

    /// Whether `--debug` is on.
    pub fn debug(&self) -> bool {
        self.debug_ring.is_some()
    }

    /// The resolved theme.
    pub fn theme(&self) -> &Theme {
        &self.theme
    }

    /// Shell state (sections, sidebar, regions).
    pub fn shell(&self) -> &shell::ShellState {
        &self.shell
    }

    pub(crate) fn resolve_theme(&mut self) {
        self.theme = Theme::resolve(
            &self.config.ui.theme,
            self.config.ui.truecolor,
            self.theme_env,
        );
        self.needs_redraw = true;
    }

    /// The layout for the last known terminal size.
    pub fn shell_rects(&self) -> ShellRects {
        let (w, h) = self.layout.size.unwrap_or(DEFAULT_SIZE);
        layout(Rect::new(0, 0, w, h), &self.shell, &self.config)
    }

    /// Whether the log ring has lines the last frame didn't show.
    pub(crate) fn log_dirty(&self) -> bool {
        self.shell.log_pane
            && self
                .debug_ring
                .as_ref()
                .is_some_and(|r| r.0.total_pushed() != self.log_drawn)
    }

    pub(crate) fn note_log_drawn(&mut self) {
        if let Some(r) = &self.debug_ring {
            self.log_drawn = r.0.total_pushed();
        }
    }

    /// The first event: show the one-time `--debug` warning (M0-04).
    pub(crate) fn on_launch_shell(&mut self, effects: &mut Vec<Effect>) {
        if self.debug() && !self.debug_warning_shown {
            self.debug_warning_shown = true;
            self.push_toast(ToastLevel::Warning, DEBUG_WARNING.to_owned(), effects);
        }
    }

    /// The shell's actions. Returns `false` for actions it doesn't own.
    pub(crate) fn apply_shell_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        match action {
            ActionName::Help => {
                self.push_dialog(crate::views::DialogKind::Help(HelpState::default()));
            }
            ActionName::ToggleSidebar => self.toggle_sidebar(),
            ActionName::ToggleViews => self.toggle_views(),
            ActionName::NotificationHistory => self.open_notification_history(effects),
            // M1-13: the session info panel (SSH sessions).
            ActionName::SessionInfo => self.open_session_info(effects),
            ActionName::ToggleLogPane => {
                if self.debug() {
                    self.shell.log_pane = !self.shell.log_pane;
                    self.shell.log_scroll = 0;
                    if !self.shell.log_pane && self.shell.region == Region::Log {
                        self.shell.region = Region::Main;
                    }
                    self.needs_redraw = true;
                } else {
                    // Unbound without `--debug` (the leader path reports the chord).
                    self.push_toast(
                        ToastLevel::Info,
                        "The log pane needs `sverb --debug`".to_owned(),
                        effects,
                    );
                }
            }
            _ => return false,
        }
        true
    }

    // M1-13
    /// `session_info`: negotiated algorithms, server version, connected time, latency.
    fn open_session_info(&mut self, effects: &mut Vec<Effect>) {
        use crate::views::dialogs::ModalDialog;
        use crate::widgets::dialog::Modal;
        let Some(id) = self.focused_session() else {
            self.push_toast(
                ToastLevel::Info,
                "No session is focused".to_owned(),
                effects,
            );
            return;
        };
        let Some(ssh) = self.tabs.ssh.get(&id) else {
            self.push_toast(
                ToastLevel::Info,
                "Session info is available for connected SSH sessions".to_owned(),
                effects,
            );
            return;
        };
        let label = self.pane(id).label;
        let body = crate::widgets::session_info::panel_body(
            &label,
            ssh,
            &self.config.ui.date_format,
            None,
        );
        self.push_dialog(crate::views::DialogKind::Modal(ModalDialog::new(
            Modal::info("Session info", &body),
        )));
    }

    fn toggle_sidebar(&mut self) {
        self.shell.sidebar_toggled = !self.shell.sidebar_toggled;
        let rects = self.shell_rects();
        if rects.sidebar.is_some() {
            // Showing it focuses it (in the section views); hiding it gives focus back.
            if self.focus == Focus::Hosts {
                self.shell.region = Region::Sidebar;
            }
        } else if self.shell.region == Region::Sidebar {
            self.shell.region = Region::Main;
        }
        self.needs_redraw = true;
    }

    /// `leader v`: the section views ↔ the session area.
    pub(crate) fn toggle_views(&mut self) {
        match self.shell.main_view {
            MainView::Sections => {
                self.shell.main_view = MainView::Sessions;
                if let Some(id) = self.shell_last_session() {
                    self.focus = Focus::Session(id);
                    self.input.copy_mode = false;
                }
                self.shell.region = Region::Main;
            }
            MainView::Sessions => {
                if let Focus::Session(id) = self.focus {
                    self.last_session = Some(id);
                }
                self.shell.main_view = MainView::Sections;
                self.focus = Focus::Hosts;
            }
        }
        self.needs_redraw = true;
    }

    fn shell_last_session(&self) -> Option<super::SessionId> {
        self.last_session
            .filter(|id| self.tabs.sessions.contains(id))
            .or_else(|| self.tabs.sessions.last().copied())
    }

    /// Open `section` in the main area (from the sidebar).
    pub(crate) fn open_section(&mut self, section: Section) {
        self.shell.section = section;
        self.views.sidebar.select(section);
        if self.shell.main_view == MainView::Sessions {
            if let Focus::Session(id) = self.focus {
                self.last_session = Some(id);
            }
            self.shell.main_view = MainView::Sections;
            self.focus = Focus::Hosts;
        }
        self.shell.region = Region::Main;
        self.needs_redraw = true;
    }

    /// The view that gets keys in the section views, by region.
    pub(crate) fn focused_view_mut(&mut self) -> Option<&mut dyn View> {
        if self.focus != Focus::Hosts {
            return self.views.focused_mut(self.focus);
        }
        match (self.shell.region, self.shell.main_view) {
            (Region::Sidebar, _) if self.shell_rects().sidebar.is_some() => {
                Some(&mut self.views.sidebar)
            }
            (Region::Main, MainView::Sections) if self.shell.section == Section::Hosts => {
                Some(&mut self.views.hosts)
            }
            // M3-06
            (Region::Main, MainView::Sections) if self.shell.section == Section::Logs => {
                Some(&mut self.views.logs)
            }
            // M2-02
            (Region::Main, MainView::Sections) if self.shell.section == Section::Keychain => {
                Some(&mut self.views.keychain)
            }
            // M1-15
            (Region::Main, MainView::Sections) if self.shell.section == Section::Known => {
                Some(&mut self.views.known_hosts)
            }
            // M2-08
            (Region::Main, MainView::Sections) if self.shell.section == Section::Forwards => {
                Some(&mut self.views.forwards)
            }
            // M2-09
            (Region::Main, MainView::Sections) if self.shell.section == Section::Snippets => {
                Some(&mut self.views.snippets)
            }
            _ => None,
        }
    }

    /// After a dispatch: a section chosen in the sidebar opens.
    pub(crate) fn after_dispatch(&mut self) {
        if let Some(section) = self.views.sidebar.chosen.take() {
            self.open_section(section);
        }
    }

    /// Normal-mode keys no view or binding took: `tab` cycles focus, `Esc` dismisses
    /// sticky toasts, `PageUp`/`PageDown`/`End` scroll a focused log pane.
    pub(crate) fn on_shell_key(&mut self, chord: KeyChord, effects: &mut Vec<Effect>) {
        if self.derive_mode() != Mode::Normal {
            return;
        }
        match (chord.code, chord.mods) {
            (KeyCode::Tab, Mods::NONE) => {
                let rects = self.shell_rects();
                self.shell.region = next_region(self.shell.region, &rects);
                self.needs_redraw = true;
            }
            (KeyCode::Tab, Mods::SHIFT) => {
                // Backwards: three steps forward in a cycle of (at most) four.
                let rects = self.shell_rects();
                let start = self.shell.region;
                let mut prev = start;
                let mut r = next_region(start, &rects);
                while r != start {
                    prev = r;
                    r = next_region(r, &rects);
                }
                self.shell.region = prev;
                self.needs_redraw = true;
            }
            (KeyCode::Esc, Mods::NONE) => {
                self.dismiss_sticky_toasts(effects);
            }
            (KeyCode::PageUp, _) if self.shell.region == Region::Log => {
                self.shell.log_scroll = self.shell.log_scroll.saturating_add(LOG_PAGE);
                self.needs_redraw = true;
            }
            (KeyCode::PageDown, _) if self.shell.region == Region::Log => {
                self.shell.log_scroll = self.shell.log_scroll.saturating_sub(LOG_PAGE);
                self.needs_redraw = true;
            }
            (KeyCode::End, _) if self.shell.region == Region::Log => {
                self.shell.log_scroll = 0;
                self.needs_redraw = true;
            }
            _ => {}
        }
    }

    /// Whether `action` is usable here (`toggle_log_pane` only with `--debug`).
    pub(crate) fn action_available(&self, action: ActionName) -> bool {
        match action {
            ActionName::ToggleLogPane => self.debug(),
            _ => true,
        }
    }

    /// Status-bar data.
    fn status_info(&self) -> StatusInfo {
        // M1-08/M1-13 (session), M2-08 (forwards), M3-05 (REC), M3-02 (broadcast),
        // M4-09 (sync) fill in the other segments.
        let mut info = StatusInfo::new(self.derive_mode(), self.status_hint());
        // M3-05: `REC ●` while the focused session is recorded.
        info.recording = self
            .focused_session()
            .is_some_and(|id| self.tabs.recording.contains_key(&id));
        // M1-13: `label · ssh · 23ms` for a focused SSH session.
        // M2-08: `⇄ L:5432→db:5432` / `⇄ 3 forwards`.
        info.forwards = crate::views::forwards::status_segment(&self.views.forwards.statuses());
        info.session = self.focused_session().and_then(|id| {
            let ssh = self.tabs.ssh.get(&id)?;
            Some(crate::widgets::session_info::status_segment(
                &self.pane(id).label,
                ssh,
            ))
        });
        // M3-02: `BROADCAST ×N` while the focused pane's input is broadcast.
        if let Some(b) = self.broadcast_status() {
            info.broadcast = Some(b.count);
            info.broadcast_note = b.note;
        }
        // M3-01: `RESIZE` (the mode segment is drawn in the accent color).
        if self.resize_mode_shown() {
            info.mode = "RESIZE".to_owned();
            info.hint = super::resize::RESIZE_HINT.to_owned();
        }
        info
    }

    // ---- drawing ------------------------------------------------------------------

    /// Draw the whole UI. Infallible: tiny areas degrade, they never panic.
    /// M1-10: session content comes from `panes`; returns the focused pane's cursor.
    pub(crate) fn render_shell(
        &self,
        frame: &mut Frame<'_>,
        panes: &dyn PaneSource,
    ) -> Option<PaneCursor> {
        let mut cursor = None;
        let area = frame.area();
        let theme = &self.theme;
        frame.render_widget(Block::default().style(theme.base), area);
        let rects = layout(area, &self.shell, &self.config);
        if rects.too_small {
            render_too_small(frame, area, theme);
            return None;
        }
        let no_dialog = self.dialogs.is_empty();
        let in_sections = self.focus == Focus::Hosts;
        let rcx = |focused: bool| RenderCx {
            config: &self.config,
            mode: self.derive_mode(),
            focused,
            theme,
            debug: self.debug(),
        };

        topbar::render(frame, rects.top_bar, &TopBarInfo::default(), theme);

        // Tab bar (with the status segments on its right when merged).
        let info = self.status_info();
        // M1-17: the same area mouse clicks are tested against.
        let tab_area = self.tab_bar_area(&rects);
        if tab_area.width < rects.tab_bar.width {
            let status = Rect {
                x: tab_area.x + tab_area.width,
                width: rects.tab_bar.width - tab_area.width,
                ..rects.tab_bar
            };
            statusbar::render(frame, status, &info, theme);
        }
        tabbar::render(
            frame,
            tab_area,
            &self.tab_items(),
            &self.empty_tabs_hint(),
            theme,
        );

        // Main area.
        match self.shell.main_view {
            MainView::Sections => {
                let focused = no_dialog && in_sections && self.shell.region == Region::Main;
                if self.shell.section == Section::Hosts {
                    self.views.hosts.render(frame, rects.main, &rcx(focused));
                } else if self.shell.section == Section::Logs {
                    // M3-06
                    self.views.logs.render(frame, rects.main, &rcx(focused));
                } else if self.shell.section == Section::Known {
                    // M1-15
                    self.views
                        .known_hosts
                        .render(frame, rects.main, &rcx(focused));
                } else if self.shell.section == Section::Keychain {
                    // M2-02
                    self.views.keychain.render(frame, rects.main, &rcx(focused));
                } else if self.shell.section == Section::Forwards {
                    // M2-08
                    self.views.forwards.render(frame, rects.main, &rcx(focused));
                } else if self.shell.section == Section::Snippets {
                    // M2-09
                    self.views.snippets.render(frame, rects.main, &rcx(focused));
                } else {
                    render_placeholder(frame, rects.main, self.shell.section, &rcx(focused));
                }
                if let Some(detail) = rects.detail {
                    let focused = no_dialog && in_sections && self.shell.region == Region::Detail;
                    if self.shell.section == Section::Logs {
                        // M3-06: the highlighted entry.
                        crate::views::logs::detail::render_detail_pane(
                            self.views.logs.selected_entry(),
                            self.views.logs.utc_offset_secs,
                            frame,
                            detail,
                            &rcx(focused),
                        );
                    } else if self.shell.section == Section::Hosts {
                        // M1-07: the selected host.
                        self.views.hosts.render_detail(frame, detail, &rcx(focused));
                    } else if self.shell.section == Section::Known {
                        // M1-15: fingerprint and randomart of the selected entry.
                        self.views
                            .known_hosts
                            .render_detail(frame, detail, &rcx(focused));
                    } else if self.shell.section == Section::Keychain {
                        // M2-02: the selected identity.
                        self.views
                            .keychain
                            .render_detail(frame, detail, &rcx(focused));
                    } else if self.shell.section == Section::Forwards {
                        // M2-08: the selected rule.
                        self.views
                            .forwards
                            .render_detail(frame, detail, &rcx(focused));
                    } else if self.shell.section == Section::Snippets {
                        // M2-09: the selected snippet, variables highlighted.
                        self.views
                            .snippets
                            .render_detail(frame, detail, &rcx(focused));
                    } else {
                        render_detail(frame, detail, &rcx(focused));
                    }
                }
            }
            // M1-10: terminal panes; M1-17: the active tab's layout.
            MainView::Sessions => match self.render_session_area(frame, rects.main, panes) {
                Some(c) => cursor = c,
                None => {
                    let focused = no_dialog && self.shell.region == Region::Main;
                    render_no_sessions(frame, rects.main, &rcx(focused));
                }
            },
        }

        if let Some(sidebar) = rects.sidebar {
            let focused = no_dialog && in_sections && self.shell.region == Region::Sidebar;
            self.views.sidebar.render(frame, sidebar, &rcx(focused));
        }

        if let Some(log) = rects.log {
            let focused = no_dialog && self.shell.region == Region::Log;
            log_pane::render(
                frame,
                log,
                self.debug_ring.as_ref().map(|r| &r.0),
                self.shell.log_scroll,
                focused,
                theme,
            );
        }

        if let Some(status) = rects.status {
            statusbar::render(frame, status, &info, theme);
        }

        toast::render(frame, rects.body, &self.toasts, theme);

        let top = self.dialogs.len().saturating_sub(1);
        for (i, dialog) in self.dialogs.iter().enumerate() {
            dialog.render(frame, area, &rcx(i == top));
        }
        // Which-key sits above everything (it also shows over forms).
        if self.which_key_visible() {
            which_key::render(frame, rects.body, &self.keymap, theme, self.debug());
        }
        cursor
    }

    // M1-17
    /// The tab bar's area: the tab-bar row, minus the status segments on its right
    /// when the status bar is merged into it (under 24 rows).
    pub(crate) fn tab_bar_area(&self, rects: &ShellRects) -> Rect {
        let mut tab_area = rects.tab_bar;
        if rects.status_merged() {
            let info = self.status_info();
            let max = usize::from(rects.tab_bar.width) * 2 / 3;
            let w = statusbar::needed_width(&info, max);
            tab_area.width = tab_area.width.saturating_sub(w);
        }
        tab_area
    }

    fn empty_tabs_hint(&self) -> String {
        let leader = self.keymap.leader().hint();
        let key = |a: ActionName| {
            self.keymap
                .bindings(Table::Leader)
                .into_iter()
                .find(|(_, x)| *x == a)
                .map(|(k, _)| KeyChord::display_sequence(&k))
        };
        let mut parts = vec![" no sessions".to_owned()];
        if let Some(k) = key(ActionName::QuickConnect) {
            parts.push(format!("{leader} {k} quick connect"));
        }
        if let Some(k) = key(ActionName::ToggleViews) {
            parts.push(format!("{leader} {k} views/sessions"));
        }
        parts.join(" · ")
    }
}

/// "Terminal too small (W×H)", centered.
fn render_too_small(frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let text = format!("Terminal too small ({}×{})", area.width, area.height);
    let y = area.y + area.height / 2;
    let row = Rect {
        y,
        height: 1,
        ..area
    };
    frame.render_widget(
        Paragraph::new(Line::styled(text, theme.warn))
            .alignment(ratatui::layout::Alignment::Center),
        row,
    );
}

/// A section whose task hasn't landed yet.
fn render_placeholder(frame: &mut Frame<'_>, area: Rect, section: Section, cx: &RenderCx<'_>) {
    let block = Block::bordered()
        .title(Span::styled(
            format!(" {} ", section.title()),
            cx.theme.title_for(cx.focused),
        ))
        .border_style(cx.theme.border_for(cx.focused));
    frame.render_widget(
        Paragraph::new(Line::styled(section.placeholder(), cx.theme.dim))
            .wrap(Wrap { trim: true })
            .block(block),
        area,
    );
}

/// The detail pane (filled by each section's list view, M1-06).
fn render_detail(frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    let block = Block::bordered()
        .title(Span::styled(" Details ", cx.theme.title_for(cx.focused)))
        .border_style(cx.theme.border_for(cx.focused));
    frame.render_widget(
        Paragraph::new(Line::styled("Nothing selected.", cx.theme.dim)).block(block),
        area,
    );
}

/// The session area with no session open.
fn render_no_sessions(frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    let leader = leader_hint(cx);
    let block = Block::bordered()
        .title(Span::styled(" Sessions ", cx.theme.title_for(cx.focused)))
        .border_style(cx.theme.border_for(cx.focused));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("No open sessions.", cx.theme.accent),
            Line::styled(format!("{leader} o  quick connect"), cx.theme.dim),
            Line::styled(format!("{leader} t  local shell"), cx.theme.dim),
            Line::styled(format!("{leader} v  back to the views"), cx.theme.dim),
        ])
        .wrap(Wrap { trim: true })
        .block(block),
        area,
    );
}
