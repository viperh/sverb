//! The shell (SPEC §8.1): top bar, sidebar, tab bar, main area, optional
//! detail and log panes, status bar.
//!
//! ```text
//! sverb ─ Personal ▾ ──────────────────────────── ⟳ synced · 🔒   top bar (1 row)
//! ┌ sidebar ┐ 1 web ┬ 2 db ┬ + ───────────────────────────────   tab bar (1 row)
//! │ ▸ Hosts │ ┌ main area ───────────────────┐┌ detail ───────┐
//! │   …     │ │ section view / session area  ││               │
//! └─────────┘ └──────────────────────────────┘└───────────────┘
//! ┌ log (--debug, leader D, 30% height) ─────────────────────────┐
//!  NORMAL │ session │ forwards │ REC ● │ sync │ ^\ ? help        status bar (1 row)
//! ```
//!
//! [`layout`] is a pure function from the frame size, [`ShellState`] and the config
//! to the [`ShellRects`] every widget draws into, so the responsive rules are unit
//! tested without rendering:
//! - width < [`SIDEBAR_AUTO_MIN_WIDTH`] and `ui.sidebar = auto` → sidebar hidden,
//! - width < [`OVERLAY_MAX_WIDTH`] → a visible sidebar is drawn **over** the main area,
//! - height < [`STATUS_MERGE_HEIGHT`] → the status segments move into the tab-bar row,
//! - below [`MIN_WIDTH`]×[`MIN_HEIGHT`] → only "Terminal too small (W×H)".

use ratatui::layout::Rect;
use sverb_core::config::SidebarMode;

use crate::app::Config;

/// Below this width (`ui.sidebar = auto`) the sidebar is hidden.
pub const SIDEBAR_AUTO_MIN_WIDTH: u16 = 100;
/// Below this width a visible sidebar is an overlay.
pub const OVERLAY_MAX_WIDTH: u16 = 80;
/// Below this height the status bar merges into the tab bar.
pub const STATUS_MERGE_HEIGHT: u16 = 24;
/// Minimum supported width.
pub const MIN_WIDTH: u16 = 40;
/// Minimum supported height.
pub const MIN_HEIGHT: u16 = 10;
/// Sidebar width including its border.
pub const SIDEBAR_WIDTH: u16 = 16;
/// The detail pane is shown when the main area is at least this wide.
pub const DETAIL_MIN_MAIN_WIDTH: u16 = 100;
/// Log pane height, in percent of the body.
pub const LOG_PANE_PERCENT: u16 = 30;

/// Sidebar sections (SPEC §8.5), in sidebar order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    /// Hosts.
    #[default]
    Hosts,
    /// Keys, certificates, identities.
    Keychain,
    /// Port forwards.
    Forwards,
    /// Snippets.
    Snippets,
    /// Known hosts.
    Known,
    /// Connection logs and recordings.
    Logs,
    /// Settings.
    Settings,
}

impl Section {
    /// Every section, in sidebar order.
    pub const ALL: [Self; 7] = [
        Self::Hosts,
        Self::Keychain,
        Self::Forwards,
        Self::Snippets,
        Self::Known,
        Self::Logs,
        Self::Settings,
    ];

    /// Sidebar label and main-area title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Keychain => "Keychain",
            Self::Forwards => "Forwards",
            Self::Snippets => "Snippets",
            Self::Known => "Known",
            Self::Logs => "Logs",
            Self::Settings => "Settings",
        }
    }

    /// Placeholder text until the section's own task lands.
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Hosts => "No hosts yet.",
            Self::Keychain => "Keys, certificates and identities arrive with M2-02/M2-03.",
            Self::Forwards => "Port forwards arrive with M2-08.",
            Self::Snippets => "Snippets arrive with M2-09.",
            Self::Known => "Known hosts arrive with M1-15.",
            Self::Logs => "Connection logs and recordings arrive with M3-06.",
            Self::Settings => "Settings arrive with a later task.",
        }
    }

    /// Position in [`Section::ALL`].
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// `app::Focus` already names the view/session focus). Cycled with `tab`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    /// The sidebar.
    Sidebar,
    /// The main area (the active section).
    #[default]
    Main,
    /// The detail pane next to the main area.
    Detail,
    /// The debug log pane (`--debug`).
    Log,
}

/// What the main area shows (`leader v` toggles).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MainView {
    /// The active section's view.
    #[default]
    Sections,
    /// The session area: tab bar and panes.
    Sessions,
}

/// Shell state owned by the reducer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShellState {
    /// The active section.
    pub section: Section,
    /// The focused region (in the section views).
    pub region: Region,
    /// Section views or the session area.
    pub main_view: MainView,
    /// `leader s` flips the configured/automatic sidebar visibility.
    pub sidebar_toggled: bool,
    /// The debug log pane is open (only ever true with `--debug`).
    pub log_pane: bool,
    /// Lines scrolled up from the bottom of the log; 0 follows new lines.
    pub log_scroll: usize,
}

/// The rectangles of one frame. Hidden parts are `None`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShellRects {
    /// Below the minimum size: draw only the "too small" message.
    pub too_small: bool,
    /// Top bar row.
    pub top_bar: Rect,
    /// The sidebar, if visible.
    pub sidebar: Option<Rect>,
    /// The sidebar is drawn over the main area (narrow terminals).
    pub sidebar_overlay: bool,
    /// Tab bar row (also holds the status segments when merged).
    pub tab_bar: Rect,
    /// The main area below the tab bar.
    pub main: Rect,
    /// The detail pane, if shown.
    pub detail: Option<Rect>,
    /// The debug log pane, if open.
    pub log: Option<Rect>,
    /// The status bar row; `None` when merged into the tab bar.
    pub status: Option<Rect>,
    /// Everything between the top bar and the status bar (toasts and which-key anchor here).
    pub body: Rect,
}

impl ShellRects {
    /// The status segments share the tab-bar row.
    pub fn status_merged(&self) -> bool {
        !self.too_small && self.status.is_none()
    }

    /// Whether `region` is on screen.
    pub fn shows(&self, region: Region) -> bool {
        match region {
            Region::Sidebar => self.sidebar.is_some(),
            Region::Main => !self.too_small,
            Region::Detail => self.detail.is_some(),
            Region::Log => self.log.is_some(),
        }
    }
}

/// Whether the sidebar is visible at `width`.
pub fn sidebar_visible(width: u16, state: &ShellState, config: &Config) -> bool {
    let base = match config.ui.sidebar {
        SidebarMode::Auto => width >= SIDEBAR_AUTO_MIN_WIDTH,
        SidebarMode::Always => true,
        SidebarMode::Never => false,
    };
    base != state.sidebar_toggled
}

/// Compute the shell's rectangles for a frame of `area`.
pub fn layout(area: Rect, state: &ShellState, config: &Config) -> ShellRects {
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        return ShellRects {
            too_small: true,
            ..ShellRects::default()
        };
    }
    let row = |y: u16| Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    let top_bar = row(area.y);
    let merged = area.height < STATUS_MERGE_HEIGHT;
    let bottom = area.y + area.height;
    let status = (!merged).then(|| row(bottom - 1));
    let body_bottom = if merged { bottom } else { bottom - 1 };
    let body = Rect {
        x: area.x,
        y: area.y + 1,
        width: area.width,
        height: body_bottom - (area.y + 1),
    };

    // Log pane: the bottom 30% of the body, at least 3 rows.
    let (upper, log) = if state.log_pane {
        let h = (body.height * LOG_PANE_PERCENT / 100)
            .max(3)
            .min(body.height / 2);
        let upper = Rect {
            height: body.height - h,
            ..body
        };
        let log = Rect {
            y: body.y + upper.height,
            height: h,
            ..body
        };
        (upper, Some(log))
    } else {
        (body, None)
    };

    let show_sidebar = sidebar_visible(area.width, state, config);
    let overlay = show_sidebar && area.width < OVERLAY_MAX_WIDTH;
    let (sidebar, right) = if show_sidebar {
        let w = SIDEBAR_WIDTH.min(upper.width / 2);
        let sidebar = Rect { width: w, ..upper };
        let right = if overlay {
            upper
        } else {
            Rect {
                x: upper.x + w,
                width: upper.width - w,
                ..upper
            }
        };
        (Some(sidebar), right)
    } else {
        (None, upper)
    };

    let tab_bar = Rect { height: 1, ..right };
    let content = Rect {
        y: right.y + 1,
        height: right.height.saturating_sub(1),
        ..right
    };
    let (main, detail) =
        if state.main_view == MainView::Sections && content.width >= DETAIL_MIN_MAIN_WIDTH {
            let dw = content.width / 3;
            let main = Rect {
                width: content.width - dw,
                ..content
            };
            let detail = Rect {
                x: content.x + main.width,
                width: dw,
                ..content
            };
            (main, Some(detail))
        } else {
            (content, None)
        };

    ShellRects {
        too_small: false,
        top_bar,
        sidebar,
        sidebar_overlay: overlay,
        tab_bar,
        main,
        detail,
        log,
        status,
        body,
    }
}

/// The region after `from` in the `tab` cycle Sidebar → Main → Detail → Log, skipping
/// regions that are not on screen.
pub fn next_region(from: Region, rects: &ShellRects) -> Region {
    const CYCLE: [Region; 4] = [Region::Sidebar, Region::Main, Region::Detail, Region::Log];
    let start = CYCLE.iter().position(|r| *r == from).unwrap_or(1);
    (1..=CYCLE.len())
        .map(|i| CYCLE[(start + i) % CYCLE.len()])
        .find(|r| rects.shows(*r))
        .unwrap_or(Region::Main)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn cfg(mode: SidebarMode) -> Config {
        let mut c = Config::default();
        c.ui.sidebar = mode;
        c
    }

    fn at(w: u16, h: u16, mode: SidebarMode) -> ShellRects {
        layout(Rect::new(0, 0, w, h), &ShellState::default(), &cfg(mode))
    }

    #[test]
    fn t01_auto_layout_table() {
        // (w, h, sidebar visible, overlay, status merged)
        let table = [
            (40, 10, false, false, true),
            (79, 24, false, false, false),
            (80, 24, false, false, false),
            (99, 30, false, false, false),
            (100, 30, true, false, false),
            (160, 48, true, false, false),
            (300, 100, true, false, false),
            (120, 23, true, false, true),
            (120, 24, true, false, false),
        ];
        for (w, h, sidebar, overlay, merged) in table {
            let r = at(w, h, SidebarMode::Auto);
            assert!(!r.too_small, "{w}×{h}");
            assert_eq!(
                (r.sidebar.is_some(), r.sidebar_overlay, r.status_merged()),
                (sidebar, overlay, merged),
                "{w}×{h}"
            );
            // Every rect fits in the frame and the rows add up.
            let area = Rect::new(0, 0, w, h);
            for rect in [
                Some(r.top_bar),
                r.sidebar,
                Some(r.tab_bar),
                Some(r.main),
                r.detail,
                r.status,
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(area.intersection(rect), rect, "{w}×{h}: {rect:?}");
            }
            let status_rows = u16::from(!merged);
            assert_eq!(1 + r.body.height + status_rows, h, "{w}×{h}");
        }
    }

    #[test]
    fn t02_always_and_never() {
        let r = at(60, 24, SidebarMode::Always);
        assert!(r.sidebar.is_some());
        assert!(r.sidebar_overlay);
        assert_eq!(r.main.x, 0, "the overlay doesn't shrink the main area");
        let r = at(200, 50, SidebarMode::Never);
        assert!(r.sidebar.is_none());
        let r = at(90, 30, SidebarMode::Always);
        assert!(r.sidebar.is_some() && !r.sidebar_overlay);
        assert_eq!(r.main.x, SIDEBAR_WIDTH);
    }

    #[test]
    fn toggle_flips_the_rule() {
        let state = ShellState {
            sidebar_toggled: true,
            ..ShellState::default()
        };
        let c = cfg(SidebarMode::Auto);
        assert!(layout(Rect::new(0, 0, 60, 24), &state, &c).sidebar_overlay);
        assert!(
            layout(Rect::new(0, 0, 160, 48), &state, &c)
                .sidebar
                .is_none()
        );
    }

    #[test]
    fn t03_too_small() {
        for (w, h) in [(39, 10), (40, 9), (0, 0), (1, 1), (39, 100)] {
            assert!(at(w, h, SidebarMode::Auto).too_small, "{w}×{h}");
        }
        assert!(!at(40, 10, SidebarMode::Auto).too_small);
    }

    #[test]
    fn log_pane_takes_thirty_percent() {
        let state = ShellState {
            log_pane: true,
            ..ShellState::default()
        };
        let r = layout(Rect::new(0, 0, 160, 48), &state, &cfg(SidebarMode::Auto));
        let log = r.log.unwrap();
        assert_eq!(log.height, 46 * 30 / 100);
        assert_eq!(log.y + log.height, 47);
        assert!(r.main.y + r.main.height <= log.y);
    }

    #[test]
    fn region_cycle_skips_hidden_regions() {
        let wide = at(160, 48, SidebarMode::Auto);
        assert_eq!(next_region(Region::Sidebar, &wide), Region::Main);
        assert_eq!(next_region(Region::Main, &wide), Region::Detail);
        assert_eq!(next_region(Region::Detail, &wide), Region::Sidebar);
        let narrow = at(80, 24, SidebarMode::Auto);
        assert_eq!(next_region(Region::Main, &narrow), Region::Main);
    }
}
