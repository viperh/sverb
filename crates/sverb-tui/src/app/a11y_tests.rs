//! The accessibility pass (SPEC §8.8, §21 M7).
//!
//! - Every registry action is keyboard-reachable: it has a default binding, or the
//!   command palette lists it (in the state where it applies).
//! - Status indicators carry text, not only color: rendered with `NO_COLOR` and
//!   `ui.ascii = "on"`, the screen still says what is going on, and every cell is ASCII.
//!   The rendered screens are snapshots (the review list is in `docs/accessibility.md`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use ratatui::style::Color;
use strum::IntoEnumIterator;
use sverb_core::config::AsciiMode;

use crate::{
    app::{Config, Focus, SessionId, ToastLevel},
    keymap::{
        Keymap,
        action::{ActionName, registry},
        keymap::Table,
    },
    testing::{AppHarness, buffer_to_string},
    theme::ThemeEnv,
    views::palette::PaletteTarget,
};

const LEADER: &str = "ctrl-\\";

/// Actions the palette lists only while connected to a sync server (§1.1: no sync UI in
const CONNECTED_ONLY: &[ActionName] = &[
    ActionName::SharePane,
    ActionName::SyncStatus,
    ActionName::SyncNow,
    ActionName::Devices,
    ActionName::TeamKeys,
];

fn palette_actions(h: &AppHarness) -> BTreeSet<ActionName> {
    h.app()
        .palette_entries("", false)
        .into_iter()
        .filter_map(|e| match e.target {
            PaletteTarget::Action(a) => Some(a),
            _ => None,
        })
        .collect()
}

fn focused(h: &AppHarness) -> SessionId {
    match h.app().focus {
        Focus::Session(id) => id,
        Focus::Hosts => panic!("no session focused"),
    }
}

/// T-06 (keyboard-complete): every action has a default key or a palette entry.
#[test]
fn t06_every_action_is_bound_or_in_the_palette() {
    let config = Config::default();
    let keymap = Keymap::from_config(&config);
    let normal: BTreeSet<ActionName> = keymap
        .bindings(Table::Normal)
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    let bound = |a: ActionName| !keymap.after_leader_keys(a).is_empty() || normal.contains(&a);

    // The palette in a fresh app, and with two tabs of two local panes (tab and pane
    // actions only apply then).
    let mut h = AppHarness::new(config.clone());
    let mut listed = palette_actions(&h);
    h.keys(&format!("{LEADER} t"));
    h.keys(&format!("{LEADER} |"));
    h.keys(&format!("{LEADER} t"));
    h.keys(&format!("{LEADER} -"));
    let _ = focused(&h);
    h.take_effects();
    listed.extend(palette_actions(&h));

    let mut missing = Vec::new();
    for info in registry() {
        let a = info.name;
        if bound(a) || listed.contains(&a) {
            continue;
        }
        if CONNECTED_ONLY.contains(&a) {
            // Reachable once connected: the palette rule names the condition.
            continue;
        }
        missing.push(a);
    }
    assert!(
        missing.is_empty(),
        "actions with neither a default key nor a palette entry: {missing:?}"
    );
    // The list above is exact: every connected-only action is really unbound.
    for a in CONNECTED_ONLY {
        assert!(!listed.contains(a), "{a} is listed while local-only");
    }
    // And the registry is the whole enum.
    assert_eq!(registry().len(), ActionName::iter().count());
}

fn render_screen(h: &AppHarness, w: u16, rows: u16) -> (String, ratatui::buffer::Buffer) {
    let buf = h.render_buffer(w, rows);
    (buffer_to_string(&buf), buf)
}

fn mono_ascii() -> Config {
    let mut c = Config::default();
    c.ui.ascii = AsciiMode::On;
    c
}

fn no_color() -> ThemeEnv {
    ThemeEnv {
        no_color: true,
        colorterm_truecolor: false,
    }
}

/// T-06 (monochrome): status indicators read as text with `NO_COLOR`, and
/// `ui.ascii = "on"` leaves no non-ASCII cell.
#[test]
fn t06_status_indicators_have_text_in_no_color_and_ascii() {
    // Hosts list, toasts of every level.
    let mut h = AppHarness::new(mono_ascii()).with_theme_env(no_color());
    h.resize(100, 30);
    h.app_mut().seed_three_hosts();
    h.toast(ToastLevel::Info, "info toast");
    h.toast(ToastLevel::Warning, "warning toast");
    h.toast(ToastLevel::Error, "error toast");
    let (screen, buf) = render_screen(&h, 100, 30);
    insta::assert_snapshot!("t06_hosts_toasts_no_color_ascii", screen);
    for level in [ToastLevel::Info, ToastLevel::Warning, ToastLevel::Error] {
        assert!(
            screen.contains(level.label()),
            "toast level {level:?} has no text label:\n{screen}"
        );
    }
    assert!(screen.contains("NORMAL"), "mode segment:\n{screen}");
    assert_all_ascii_mono(&buf);

    // Broadcast to three panes, a connecting pane (spinner).
    let mut h = AppHarness::new(mono_ascii()).with_theme_env(no_color());
    h.resize(120, 30);
    h.keys(&format!("{LEADER} t"));
    h.keys(&format!("{LEADER} |"));
    h.keys(&format!("{LEADER} |"));
    h.keys(&format!("{LEADER} b"));
    h.take_effects();
    let (screen, buf) = render_screen(&h, 120, 30);
    insta::assert_snapshot!("t06_broadcast_no_color_ascii", screen);
    assert!(screen.contains("BROADCAST x3"), "{screen}");
    assert_all_ascii_mono(&buf);
}

/// `ui.ascii = "auto"` follows the environment; `off` never rewrites.
#[test]
fn ascii_auto_follows_the_environment() {
    let unicode = |config: Config, env: bool| {
        let mut h = AppHarness::new(config);
        h.app_mut().ascii_env = env;
        h.app_mut().resolve_theme();
        h.resize(80, 24);
        let (_, buf) = render_screen(&h, 80, 24);
        buf.content.iter().any(|c| !c.symbol().is_ascii())
    };
    assert!(unicode(Config::default(), false));
    assert!(!unicode(Config::default(), true));
    let mut off = Config::default();
    off.ui.ascii = AsciiMode::Off;
    assert!(unicode(off, true));
    assert!(!unicode(mono_ascii(), false));
}

/// `ui.reduce_motion` freezes the spinner.
#[test]
fn reduce_motion_freezes_the_spinner() {
    let mut c = Config::default();
    c.ui.reduce_motion = true;
    let h = AppHarness::new(c);
    assert!(h.app().theme().reduce_motion);
    assert_eq!(h.app().theme().spinner(0), h.app().theme().spinner(7));
    let h = AppHarness::new(Config::default());
    assert_ne!(h.app().theme().spinner(0), h.app().theme().spinner(7));
}

fn assert_all_ascii_mono(buf: &ratatui::buffer::Buffer) {
    for c in &buf.content {
        assert!(c.symbol().is_ascii(), "non-ASCII cell {:?}", c.symbol());
        assert!(
            matches!(c.fg, Color::Reset) && matches!(c.bg, Color::Reset),
            "color in NO_COLOR: {c:?}"
        );
    }
}
