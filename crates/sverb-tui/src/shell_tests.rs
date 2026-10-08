//! M0-11 tests: shell snapshots (T-04..T-11), shell behavior (T-12..T-16), toasts,
//! notification history and the debug log pane. Layout (T-01..T-03) is unit tested in
//! `views/shell.rs`, the status priorities (T-10) in `widgets/statusbar.rs`, color
//! downsampling (T-17/T-18) in `sverb_term::color` and `theme`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::UNIX_EPOCH};

use pretty_assertions::assert_eq;
use ratatui::{
    buffer::Buffer,
    style::{Color, Modifier},
};
use sverb_core::{
    config::{ConfigEvent, SidebarMode, TruecolorMode},
    error_report::ErrorReport,
    logging::{DEBUG_WARNING, LogLine, LogRing},
};
use tracing::Level;

use crate::{
    app::{Config, Mode, SessionId, ToastLevel, UiEvent},
    keymap::action::ActionName,
    testing::{AppHarness, buffer_to_string},
    theme::ThemeEnv,
    views::{DialogKind, MainView, Region, Section},
};

fn truecolor() -> ThemeEnv {
    ThemeEnv {
        no_color: false,
        colorterm_truecolor: true,
    }
}

fn no_color() -> ThemeEnv {
    ThemeEnv {
        no_color: true,
        colorterm_truecolor: true,
    }
}

fn themed(theme: &str) -> Config {
    let mut c = Config::default();
    c.ui.theme = theme.to_owned();
    c
}

fn harness(config: Config, w: u16, h: u16) -> AppHarness {
    let mut h_ = AppHarness::new(config).with_theme_env(truecolor());
    h_.resize(w, h);
    h_.take_effects();
    h_
}

/// Text plus one line per style run, compact enough to review.
fn styled(buf: &Buffer) -> String {
    let mut out = buffer_to_string(buf);
    out.push_str("--- styles (x,y fg bg modifiers) ---\n");
    let area = buf.area;
    for y in area.top()..area.bottom() {
        let mut last = None;
        for x in area.left()..area.right() {
            let c = &buf[(x, y)];
            let key = (c.fg, c.bg, c.modifier);
            if last != Some(key) {
                out.push_str(&format!("{x},{y} {:?} {:?} {:?}\n", c.fg, c.bg, c.modifier));
                last = Some(key);
            }
        }
    }
    out
}

fn row(buf: &Buffer, y: u16) -> String {
    (buf.area.left()..buf.area.right())
        .map(|x| buf[(x, y)].symbol())
        .collect()
}

// ---- T-04 / T-05 / T-06 Themes ----------------------------------------------------------

#[test]
fn t04_initial_screen_default_dark() {
    for (w, h) in [(80, 24), (160, 48)] {
        let hs = harness(Config::default(), w, h);
        let buf = hs.render_buffer(w, h);
        insta::assert_snapshot!(format!("t04_default_dark_{w}x{h}"), styled(&buf));
        let text = buffer_to_string(&buf);
        assert!(text.contains("Hosts"), "{text}");
        assert!(text.contains("NORMAL"));
        assert!(text.contains("sverb"));
    }
    // At 160 columns the sidebar lists all seven sections.
    let text = harness(Config::default(), 160, 48).render(160, 48);
    for s in Section::ALL {
        assert!(text.contains(s.title()), "{} missing", s.title());
    }
    assert!(text.contains("▸ Hosts"));
}

#[test]
fn t05_no_color_is_monochrome_with_reverse_bold_selection() {
    for (w, h) in [(80, 24), (160, 48)] {
        let mut hs = AppHarness::new(Config::default()).with_theme_env(no_color());
        hs.resize(w, h);
        // M1-07: the Hosts list with hosts (the cursor row is the selection).
        hs.app_mut().seed_three_hosts();
        let buf = hs.render_buffer(w, h);
        insta::assert_snapshot!(format!("t05_no_color_{w}x{h}"), buffer_to_string(&buf));
        for y in 0..h {
            for x in 0..w {
                let c = &buf[(x, y)];
                assert_eq!(
                    (c.fg, c.bg),
                    (Color::Reset, Color::Reset),
                    "color at {x},{y}"
                );
            }
        }
        // The selected Hosts row ("alpha") is reverse + bold.
        let y = (0..h)
            .find(|y| row(&buf, *y).contains("alpha  10.0.0.1"))
            .unwrap();
        let r = row(&buf, y);
        let at = r.find("alpha  10.0.0.1").unwrap();
        let x = u16::try_from(r[..at].chars().count()).unwrap();
        let m = buf[(x, y)].modifier;
        assert!(m.contains(Modifier::REVERSED | Modifier::BOLD), "{m:?}");
    }

    // The focused sidebar's cursor row too.
    let mut hs = AppHarness::new(Config::default()).with_theme_env(no_color());
    hs.resize(160, 48);
    hs.keys("tab tab");
    assert_eq!(hs.app().shell().region, Region::Sidebar);
    let buf = hs.render_buffer(160, 48);
    let y = (0..48).find(|y| row(&buf, *y).contains("▸ Hosts")).unwrap();
    let x = u16::try_from(row(&buf, y).chars().position(|c| c == 'H').unwrap()).unwrap();
    assert!(
        buf[(x, y)]
            .modifier
            .contains(Modifier::REVERSED | Modifier::BOLD)
    );
}

#[test]
fn t06_light_and_high_contrast() {
    let dark = styled(&harness(Config::default(), 80, 24).render_buffer(80, 24));
    for theme in ["default-light", "high-contrast"] {
        let buf = harness(themed(theme), 80, 24).render_buffer(80, 24);
        let s = styled(&buf);
        assert_ne!(s, dark, "{theme} looks like default-dark");
        insta::assert_snapshot!(format!("t06_{theme}_80x24"), s);
    }
}

#[test]
fn truecolor_off_downsamples_the_theme() {
    let mut c = Config::default();
    c.ui.truecolor = TruecolorMode::Off;
    let buf = harness(c, 80, 24).render_buffer(80, 24);
    let any_rgb = buf
        .content()
        .iter()
        .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..)));
    assert!(!any_rgb, "RGB colors left with ui.truecolor = off");
    assert!(
        buf.content()
            .iter()
            .any(|c| matches!(c.fg, Color::Indexed(_)))
    );
}

// ---- T-07 / T-08 Which-key and help ------------------------------------------------------

#[test]
fn t07_which_key_popup() {
    for (w, h) in [(80, 24), (160, 48)] {
        let mut hs = harness(Config::default(), w, h);
        hs.keys("ctrl-\\");
        hs.advance(400);
        assert!(hs.app().which_key_visible());
        let text = hs.render(w, h);
        insta::assert_snapshot!(format!("t07_which_key_{w}x{h}"), text);
        // Above the status bar: the last row is still the status bar.
        assert!(text.lines().last().unwrap().contains("NORMAL"));
        assert!(
            !text.contains("Toggle log pane"),
            "no --debug, no log pane binding"
        );
    }
}

#[test]
fn t08_help_overlay_and_search() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.keys("?");
    assert!(matches!(hs.app().dialogs()[0].kind, DialogKind::Help(_)));
    insta::assert_snapshot!("t08_help_80x24", hs.render(80, 24));
    hs.keys("/ s i d e b a r");
    let text = hs.render(80, 24);
    assert!(text.contains("Toggle sidebar"), "{text}");
    assert!(!text.contains("Split horizontal"), "{text}");
    // `q` while searching types, it doesn't close.
    hs.keys("q");
    assert_eq!(hs.app().dialogs().len(), 1);
    hs.keys("esc esc");
    assert!(hs.app().dialogs().is_empty());
    assert!(hs.effects().is_empty(), "nothing quit");
}

// ---- T-09 Toasts --------------------------------------------------------------------------

#[test]
fn t09_toasts_fade_except_errors() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.toast(ToastLevel::Info, "Connected to prod-web-1");
    hs.toast(ToastLevel::Warning, "Host key will expire soon");
    hs.toast(
        ToastLevel::Error,
        "Authentication failed for deploy@db-primary: no more methods to try after publickey and password",
    );
    insta::assert_snapshot!("t09_three_toasts_80x24", hs.render(80, 24));
    hs.advance(4_000);
    let levels: Vec<_> = hs.app().toasts().iter().map(|t| t.level).collect();
    assert_eq!(levels, [ToastLevel::Error]);
    let text = hs.render(80, 24);
    assert!(text.contains("Authentication"));
    assert!(!text.contains("Connected"));
}

#[test]
fn at_most_three_toasts_and_width_limits() {
    let mut hs = harness(Config::default(), 80, 24);
    for i in 0..5 {
        hs.toast(ToastLevel::Error, &format!("error number {i}"));
    }
    assert_eq!(hs.app().toasts().len(), 3);
    assert_eq!(hs.app().notifications().len(), 5);
    hs.toast(ToastLevel::Info, &"word ".repeat(60));
    let buf = hs.render_buffer(80, 24);
    // Every toast fits in 50 columns at the right edge.
    for y in 0..24 {
        let r = row(&buf, y);
        for title in ["┌ info ", "┌ error "] {
            if let Some(i) = r.find(title) {
                let x = r[..i].chars().count();
                assert!(80 - x <= 50, "row {y}: {r}");
            }
        }
    }
}

// ---- T-10 / T-11 Status bar ----------------------------------------------------------------

#[test]
fn t10_status_bar_at_60_columns() {
    let hs = harness(Config::default(), 60, 24);
    let text = hs.render(60, 24);
    let last = text.lines().last().unwrap();
    assert!(last.contains("NORMAL") && last.contains("? help"), "{last}");
}

#[test]
fn t11_status_merges_into_the_tab_bar_below_24_rows() {
    let hs = harness(Config::default(), 80, 20);
    let text = hs.render(80, 20);
    insta::assert_snapshot!("t11_merged_80x20", text);
    let lines: Vec<_> = text.lines().collect();
    assert!(lines[1].contains("NORMAL"), "tab-bar row: {}", lines[1]);
    assert!(lines[1].contains("? help"), "tab-bar row: {}", lines[1]);
    assert!(!lines[19].contains("NORMAL"), "no separate status row");
}

#[test]
fn too_small_terminal() {
    let hs = harness(Config::default(), 30, 8);
    let text = hs.render(30, 8);
    assert!(text.contains("Terminal too small (30×8)"), "{text}");
    assert!(!text.contains("NORMAL"));
}

// ---- T-12 / T-13 Sidebar and focus --------------------------------------------------------

#[test]
fn t12_sidebar_toggle_and_focus_cycle() {
    let mut hs = harness(Config::default(), 160, 48);
    assert!(hs.app().shell_rects().sidebar.is_some());
    hs.keys("ctrl-\\ s");
    assert!(hs.app().shell_rects().sidebar.is_none());
    assert!(!hs.render(160, 48).contains("Keychain"));
    hs.keys("ctrl-\\ s");
    assert!(hs.app().shell_rects().sidebar.is_some());
    assert_eq!(
        hs.app().shell().region,
        Region::Sidebar,
        "showing it focuses it"
    );

    let mut seen = vec![hs.app().shell().region];
    for _ in 0..3 {
        hs.keys("tab");
        seen.push(hs.app().shell().region);
    }
    assert_eq!(
        seen,
        [
            Region::Sidebar,
            Region::Main,
            Region::Detail,
            Region::Sidebar
        ]
    );
    hs.keys("shift-tab");
    assert_eq!(hs.app().shell().region, Region::Detail);
    assert_eq!(hs.app().mode(), Mode::Normal);

    // Narrow: `leader s` shows the sidebar as an overlay.
    let mut hs = harness(Config::default(), 70, 24);
    hs.keys("ctrl-\\ s");
    let rects = hs.app().shell_rects();
    assert!(rects.sidebar.is_some() && rects.sidebar_overlay);
    assert!(hs.render(70, 24).contains("Keychain"));
}

#[test]
fn t13_sidebar_selects_sections() {
    let mut hs = harness(Config::default(), 160, 48);
    hs.keys("tab tab");
    assert_eq!(hs.app().shell().region, Region::Sidebar);
    hs.keys("j j enter");
    assert_eq!(hs.app().shell().section, Section::Forwards);
    assert_eq!(hs.app().shell().region, Region::Main);
    let text = hs.render(160, 48);
    assert!(text.contains("┌ Forwards"), "{text}");
    assert!(text.contains("▸ Forwards"));
    assert!(!text.contains("No hosts yet"));

    hs.keys("tab tab down down down enter");
    assert_eq!(hs.app().shell().section, Section::Logs);
    hs.keys("tab tab up up up up up up enter");
    assert_eq!(hs.app().shell().section, Section::Hosts);
    assert!(hs.render(160, 48).contains("No hosts yet"));
}

#[test]
fn leader_v_toggles_views_and_sessions() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.keys("ctrl-\\ v");
    assert_eq!(hs.app().shell().main_view, MainView::Sessions);
    assert!(hs.render(80, 24).contains("No open sessions"));
    hs.keys("ctrl-\\ v");
    assert_eq!(hs.app().shell().main_view, MainView::Sections);

    let mut hs = harness(Config::default(), 80, 24).with_live_session();
    assert_eq!(hs.app().mode(), Mode::Terminal);
    hs.keys("ctrl-\\ v");
    assert_eq!(hs.app().mode(), Mode::Normal);
    assert!(hs.render(80, 24).contains("No hosts yet"));
    hs.keys("ctrl-\\ v");
    assert_eq!(hs.app().mode(), Mode::Terminal, "back to the same session");
    assert_eq!(hs.app().visible_sessions(), [SessionId(1)]);
}

// ---- T-14 Coalescing ----------------------------------------------------------------------

#[test]
fn t14_duplicate_toasts_coalesce() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.toast(ToastLevel::Warning, "Reconnecting");
    hs.advance(1_500);
    hs.toast(ToastLevel::Warning, "Reconnecting");
    assert_eq!(hs.app().toasts().len(), 1);
    assert_eq!(hs.app().toasts()[0].count, 2);
    assert!(hs.render(80, 24).contains("Reconnecting (×2)"));
    // A different level doesn't coalesce.
    hs.toast(ToastLevel::Info, "Reconnecting");
    assert_eq!(hs.app().toasts().len(), 2);
    // After the 2 s window a repeat is a new toast.
    hs.advance(2_001);
    hs.toast(ToastLevel::Warning, "Reconnecting");
    assert_eq!(
        hs.app()
            .toasts()
            .iter()
            .filter(|t| t.level == ToastLevel::Warning)
            .count(),
        2
    );
    assert_eq!(hs.app().notifications().len(), 3);
}

// ---- Notification history ------------------------------------------------------------------

#[test]
fn notification_history_lists_and_expands() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.toast(ToastLevel::Info, "first");
    let report = ErrorReport {
        short: "database is locked".into(),
        chain: vec!["sqlite busy".into(), "another sverb is running".into()],
    };
    let mut effects = Vec::new();
    hs.app_mut().push_error(&report, &mut effects);
    let at = chrono::DateTime::parse_from_rfc3339("2026-10-07T12:34:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Local);
    hs.app_mut().stamp_notifications(at);
    assert_eq!(hs.app().toasts().len(), 2);

    hs.keys("ctrl-\\ !");
    assert!(
        hs.app()
            .toasts()
            .iter()
            .all(|t| t.level != ToastLevel::Error),
        "opening the history dismisses sticky toasts"
    );
    let DialogKind::Notifications(list) = &hs.app().dialogs()[0].kind else {
        panic!("history not open");
    };
    assert_eq!(list.entries.len(), 2);
    assert_eq!(
        list.entries[0].message, "database is locked",
        "newest first"
    );
    let text = hs.render(80, 24);
    assert!(
        text.contains(&at.format("%Y-%m-%d %H:%M").to_string()),
        "{text}"
    );
    assert!(!text.contains("sqlite busy"));
    hs.keys("enter");
    let text = hs.render(80, 24);
    assert!(text.contains("↳ sqlite busy"), "{text}");
    assert!(text.contains("↳ another sverb is running"));
    hs.keys("esc");
    assert!(hs.app().dialogs().is_empty());
}

#[test]
fn esc_dismisses_sticky_toasts() {
    let mut hs = harness(Config::default(), 80, 24);
    hs.toast(ToastLevel::Error, "boom");
    hs.toast(ToastLevel::Info, "fyi");
    hs.keys("esc");
    let levels: Vec<_> = hs.app().toasts().iter().map(|t| t.level).collect();
    assert_eq!(levels, [ToastLevel::Info]);
}

// ---- T-15 Debug log pane -------------------------------------------------------------------

fn ring_with_lines() -> LogRing {
    let ring = LogRing::new(100);
    for (i, level) in [Level::INFO, Level::WARN, Level::ERROR, Level::DEBUG]
        .into_iter()
        .enumerate()
    {
        ring.push(LogLine {
            at: UNIX_EPOCH,
            level,
            target: "sverb_tui::test".into(),
            message: format!("ring line {i}"),
        });
    }
    ring
}

#[test]
fn t15_log_pane_with_debug() {
    let ring = ring_with_lines();
    let mut hs = AppHarness::new(Config::default())
        .with_theme_env(truecolor())
        .with_debug_ring(ring.clone());
    hs.resize(100, 30);
    hs.send(UiEvent::Launch(crate::app::LaunchIntent::Plain));
    assert!(
        hs.app().toasts().iter().any(|t| t.message == DEBUG_WARNING),
        "one-time --debug warning toast"
    );
    hs.keys("ctrl-\\ D");
    assert!(hs.app().shell().log_pane);
    let rects = hs.app().shell_rects();
    let log = rects.log.unwrap();
    assert_eq!(log.height, rects.body.height * 30 / 100);
    let text = hs.render(100, 30);
    for i in 0..4 {
        assert!(text.contains(&format!("ring line {i}")), "{text}");
    }
    // New lines make the app dirty; drawing clears it.
    hs.app_mut().mark_drawn();
    assert!(!hs.app().needs_redraw());
    ring.push(LogLine {
        at: UNIX_EPOCH,
        level: Level::INFO,
        target: "t".into(),
        message: "late line".into(),
    });
    assert!(hs.app().needs_redraw());
    assert!(hs.render(100, 30).contains("late line"), "auto-scrolls");

    // Focus it with tab, scroll up a page.
    while hs.app().shell().region != Region::Log {
        hs.keys("tab");
    }
    hs.keys("pageup");
    assert_eq!(hs.app().shell().log_scroll, 10);
    hs.keys("end");
    assert_eq!(hs.app().shell().log_scroll, 0);

    // Which-key lists it with --debug.
    hs.keys("ctrl-\\ D ctrl-\\");
    hs.advance(400);
    assert!(hs.render(100, 30).contains("Toggle log pane"));
}

#[test]
fn t15_log_pane_unbound_without_debug() {
    let mut hs = harness(Config::default(), 100, 30);
    hs.send(UiEvent::Launch(crate::app::LaunchIntent::Plain));
    assert!(hs.app().toasts().is_empty(), "no debug warning");
    hs.keys("ctrl-\\ D");
    assert!(!hs.app().shell().log_pane);
    assert_ne!(hs.app().last_action(), Some(ActionName::ToggleLogPane));
    assert!(
        hs.app().toasts()[0]
            .message
            .contains("No binding for ctrl-\\ D"),
        "{:?}",
        hs.app().toasts()
    );
}

// ---- T-16 Live theme change ----------------------------------------------------------------

#[test]
fn t16_config_reload_changes_the_theme() {
    let mut hs = harness(Config::default(), 80, 24);
    let before = styled(&hs.render_buffer(80, 24));
    let mut cfg = Config::default();
    cfg.ui.theme = "high-contrast".into();
    hs.send(UiEvent::Config(ConfigEvent::Reloaded {
        config: Arc::new(cfg),
        warnings: Vec::new(),
    }));
    assert!(hs.app().needs_redraw());
    assert_eq!(hs.app().theme().name, "high-contrast");
    let after = styled(&hs.render_buffer(80, 24));
    assert_ne!(before, after);
}

#[test]
fn sidebar_config_never_and_always() {
    let mut c = Config::default();
    c.ui.sidebar = SidebarMode::Never;
    assert!(!harness(c, 200, 50).render(200, 50).contains("Keychain"));
    let mut c = Config::default();
    c.ui.sidebar = SidebarMode::Always;
    assert!(harness(c, 60, 24).render(60, 24).contains("Keychain"));
}

#[test]
fn shell_renders_at_every_size() {
    let mut hs = AppHarness::new(Config::default()).with_debug_ring(ring_with_lines());
    hs.keys("ctrl-\\ D ctrl-\\ s");
    hs.toast(ToastLevel::Error, "an error that is rather long to fit");
    for (w, h) in [
        (0, 0),
        (1, 1),
        (39, 9),
        (40, 10),
        (41, 23),
        (60, 15),
        (79, 24),
        (300, 100),
    ] {
        hs.resize(w, h);
        assert_eq!(hs.render(w, h).lines().count(), usize::from(h));
    }
}
