//! , reorder, border drags and the snapshot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use sverb_core::layout::Layout;

use super::*;
use crate::app::{Config, InputEvent, SessionId, UiEvent, effect::SessionInput};
use crate::keymap::chord::KeyChord;
use crate::testing::AppHarness;
use crate::views::sessions::{
    pane_of,
    panes::{content_size, pane_rects},
};

const LEADER: &str = "ctrl-\\";

fn harness_with(config: Config, w: u16, h: u16) -> AppHarness {
    let mut h_ = AppHarness::new(config);
    h_.resize(w, h);
    h_.take_effects();
    h_
}

fn harness(w: u16, h: u16) -> AppHarness {
    harness_with(Config::default(), w, h)
}

fn leader(h: &mut AppHarness, key: &str) {
    h.keys(&format!("{LEADER} {key}"));
}

fn focused(h: &AppHarness) -> SessionId {
    match h.app().focus {
        Focus::Session(id) => id,
        Focus::Hosts => panic!("no session focused"),
    }
}

fn local_tab(h: &mut AppHarness) -> SessionId {
    leader(h, "t");
    focused(h)
}

/// `a | b` in one tab, `b` focused; effects and timers settled.
fn side_by_side(h: &mut AppHarness) -> (SessionId, SessionId) {
    let a = local_tab(h);
    leader(h, "|");
    let b = focused(h);
    h.advance(100);
    h.take_effects();
    (a, b)
}

fn resizes(effects: &[Effect]) -> Vec<(SessionId, u16, u16)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::ResizeSession { id, cols, rows } => Some((*id, *cols, *rows)),
            _ => None,
        })
        .collect()
}

fn sent(effects: &[Effect]) -> Vec<(SessionId, SessionInput)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::SendToSession { id, input } => Some((*id, input.clone())),
            _ => None,
        })
        .collect()
}

fn layout(h: &AppHarness) -> Layout {
    h.app().active_tab().unwrap().layout.clone()
}

fn main_area(h: &AppHarness) -> sverb_core::layout::Rect {
    to_core(h.app().shell_rects().main)
}

#[test]
fn t06_single_steps_and_resize_mode() {
    let mut h = harness(160, 48);
    let (_a, b) = side_by_side(&mut h);
    let main = main_area(&h);
    let start = layout(&h);
    // `leader L`: exactly one step.
    leader(&mut h, "L");
    let one = start.resize(pane_of(b), Direction::Right, main, 1);
    assert_ne!(one, start);
    assert_eq!(layout(&h), one);
    // The next plain `L` goes to the session (no timed repeat, A6).
    h.take_effects();
    h.keys("L");
    assert_eq!(layout(&h), one);
    assert_eq!(
        sent(&h.take_effects()),
        [(b, SessionInput::Key(KeyChord::char('L')))]
    );
    // `leader r`, then `l l =`: two steps, then equalize; nothing reaches the session.
    leader(&mut h, "r");
    assert!(h.app().tabs().pane_ops.resize_mode);
    assert!(h.render(160, 48).contains("RESIZE"));
    h.keys("l");
    let two = one.resize(pane_of(b), Direction::Right, main, 1);
    assert_eq!(layout(&h), two);
    h.keys("l");
    assert_eq!(
        layout(&h),
        two.resize(pane_of(b), Direction::Right, main, 1)
    );
    // `H` is three steps.
    let before = layout(&h);
    h.keys("H");
    assert_eq!(
        layout(&h),
        before.resize(pane_of(b), Direction::Left, main, 3)
    );
    h.keys("=");
    assert_eq!(layout(&h), start.equalize());
    // Anything else is swallowed (K-06), even keys a shell would want.
    h.keys("x ctrl-c up");
    assert!(sent(h.effects()).is_empty(), "{:?}", h.effects());
    // `Esc` leaves; keys reach the session again.
    h.keys("esc");
    assert!(!h.app().tabs().pane_ops.resize_mode);
    assert!(!h.render(160, 48).contains("RESIZE"));
    assert!(sent(&h.take_effects()).is_empty());
    h.keys("x");
    assert_eq!(sent(&h.take_effects()).len(), 1);
    // `Enter` leaves too.
    leader(&mut h, "r");
    h.keys("enter");
    assert!(!h.app().tabs().pane_ops.resize_mode);
    assert!(sent(&h.take_effects()).is_empty());
    // 10 s idle leaves; a key restarts the idle time.
    leader(&mut h, "r");
    h.advance(9_000);
    h.keys("k");
    h.advance(9_000);
    assert!(h.app().tabs().pane_ops.resize_mode);
    h.advance(1_000);
    assert!(!h.app().tabs().pane_ops.resize_mode);
    h.take_effects();
    h.keys("x");
    assert_eq!(sent(&h.take_effects()).len(), 1);
}

#[test]
fn resize_mode_needs_a_pane_and_single_pane_is_a_noop() {
    let mut h = harness(160, 48);
    leader(&mut h, "r");
    assert!(!h.app().tabs().pane_ops.resize_mode);
    let _a = local_tab(&mut h);
    let start = layout(&h);
    leader(&mut h, "L");
    assert_eq!(layout(&h), start);
    leader(&mut h, "r");
    h.keys("l j");
    assert_eq!(layout(&h), start);
}

#[test]
fn t07_zoom_toggle() {
    let mut h = harness(160, 48);
    let (a, b) = side_by_side(&mut h);
    let main = h.app().shell_rects().main;
    let before: Vec<_> = pane_rects(&layout(&h), None, main);
    leader(&mut h, "z");
    let tab = h.app().active_tab().unwrap();
    assert_eq!(tab.zoomed, Some(pane_of(b)));
    assert_eq!(
        pane_rects(&tab.layout, tab.zoomed, main),
        [(pane_of(b), main)]
    );
    assert!(h.app().tab_items()[0].markers.contains('Z'));
    assert_eq!(h.app().visible_sessions(), [b]);
    h.advance(60);
    // Only the zoomed pane is resized; the hidden one keeps its size.
    assert_eq!(
        resizes(&h.take_effects()),
        [(b, main.width - 2, main.height - 2)]
    );
    leader(&mut h, "z");
    assert_eq!(h.app().active_tab().unwrap().zoomed, None);
    assert!(!h.app().tab_items()[0].markers.contains('Z'));
    h.advance(60);
    let (cols, rows) = content_size(before[1].1);
    assert_eq!(resizes(&h.take_effects()), [(b, cols, rows)]);
    assert_eq!(h.app().visible_sessions(), [a, b]);
}

#[test]
fn t08_focus_move_while_zoomed_unzooms() {
    let mut h = harness(160, 48);
    let (a, _b) = side_by_side(&mut h);
    leader(&mut h, "z");
    assert!(h.app().active_tab().unwrap().zoomed.is_some());
    leader(&mut h, "h");
    assert_eq!(h.app().active_tab().unwrap().zoomed, None);
    assert_eq!(focused(&h), a);
    // Closing the zoomed pane unzooms too.
    leader(&mut h, "z");
    h.send(UiEvent::Session(
        a,
        sverb_conn::SessionEvent::State(sverb_conn::SessionState::Closed),
    ));
    assert_eq!(h.app().active_tab().unwrap().zoomed, None);
    // One pane: nothing to zoom.
    leader(&mut h, "z");
    assert_eq!(h.app().active_tab().unwrap().zoomed, None);
}

#[test]
fn t09_rename_tab() {
    let mut h = harness(160, 48);
    let _a = local_tab(&mut h);
    assert_eq!(h.app().tab_items()[0].label, "local");
    leader(&mut h, ",");
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Modal(_))
    ));
    // Prefilled with the current title.
    h.keys("backspace backspace backspace backspace backspace d b enter");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(h.app().tab_items()[0].label, "db");
    assert_eq!(
        h.app().active_tab().unwrap().title_override.as_deref(),
        Some("db")
    );
    // `Esc` keeps it.
    leader(&mut h, ",");
    h.keys("x esc");
    assert_eq!(h.app().tab_items()[0].label, "db");
    // An empty name reverts to the default title.
    leader(&mut h, ",");
    h.keys("backspace backspace enter");
    assert_eq!(h.app().active_tab().unwrap().title_override, None);
    assert_eq!(h.app().tab_items()[0].label, "local");
    assert!(
        sent(h.effects()).is_empty(),
        "typing in the prompt never reaches the session"
    );
}

#[test]
fn t10_reorder_tabs() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    let c = local_tab(&mut h);
    let order = |h: &AppHarness| -> Vec<SessionId> {
        h.app()
            .tabs()
            .list
            .iter()
            .map(|t| t.focused_session())
            .collect()
    };
    leader(&mut h, "2");
    assert_eq!(focused(&h), b);
    leader(&mut h, ">");
    assert_eq!(order(&h), [a, c, b]);
    assert_eq!(h.app().tabs().active, 2);
    assert_eq!(focused(&h), b);
    // No wrap.
    leader(&mut h, ">");
    assert_eq!(order(&h), [a, c, b]);
    leader(&mut h, "1");
    leader(&mut h, "<");
    assert_eq!(order(&h), [a, c, b]);
    // Tab numbers follow the order.
    leader(&mut h, "3");
    assert_eq!(focused(&h), b);
    leader(&mut h, "2");
    assert_eq!(focused(&h), c);
    leader(&mut h, "<");
    assert_eq!(order(&h), [c, a, b]);
    leader(&mut h, "1");
    assert_eq!(focused(&h), c);
}

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> UiEvent {
    UiEvent::Input(InputEvent::Mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }))
}

#[test]
fn t11_mouse_border_drag() {
    let mut h = harness(160, 48);
    let (a, b) = side_by_side(&mut h);
    let main = h.app().shell_rects().main;
    let rects = pane_rects(&layout(&h), None, main);
    let border = rects[1].1.x; // first column of the right pane
    let row = main.y + 5;
    h.send(mouse(
        MouseEventKind::Down(MouseButton::Left),
        border - 1,
        row,
    ));
    assert!(h.app().tabs().pane_ops.drag.is_some());
    for dx in 1..=10u16 {
        h.send(mouse(
            MouseEventKind::Drag(MouseButton::Left),
            border - 1 + dx,
            row,
        ));
        h.advance(10);
    }
    h.send(mouse(
        MouseEventKind::Up(MouseButton::Left),
        border + 9,
        row,
    ));
    assert!(h.app().tabs().pane_ops.drag.is_none());
    let after = pane_rects(&layout(&h), None, main);
    assert_eq!(after[1].1.x, border + 10, "{after:?}");
    let Layout::Split { ratio, .. } = layout(&h) else {
        panic!()
    };
    assert!(ratio[0] > 0.5, "{ratio:?}");
    // The drag never reached the sessions.
    assert!(sent(h.effects()).is_empty());
    assert!(resizes(h.effects()).is_empty(), "debounced while dragging");
    h.advance(60);
    let r = resizes(&h.take_effects());
    assert_eq!(
        r,
        [
            (a, content_size(after[0].1).0, content_size(after[0].1).1),
            (b, content_size(after[1].1).0, content_size(after[1].1).1),
        ]
    );
    // A press inside a pane is not a drag.
    h.send(mouse(
        MouseEventKind::Down(MouseButton::Left),
        main.x + 5,
        row,
    ));
    assert!(h.app().tabs().pane_ops.drag.is_none());
}

#[test]
fn border_drag_needs_mouse_enabled() {
    let mut config = Config::default();
    config.ui.mouse = false;
    let mut h = harness_with(config, 160, 48);
    side_by_side(&mut h);
    let main = h.app().shell_rects().main;
    let border = pane_rects(&layout(&h), None, main)[1].1.x;
    let start = layout(&h);
    h.send(mouse(
        MouseEventKind::Down(MouseButton::Left),
        border,
        main.y + 5,
    ));
    h.send(mouse(
        MouseEventKind::Drag(MouseButton::Left),
        border + 10,
        main.y + 5,
    ));
    assert_eq!(layout(&h), start);
}

#[test]
fn equalize_action_and_palette_entry() {
    let mut h = harness(160, 48);
    let (_a, _b) = side_by_side(&mut h);
    let start = layout(&h);
    leader(&mut h, "L");
    leader(&mut h, "L");
    assert_ne!(layout(&h), start);
    let mut effects = Vec::new();
    h.app_mut()
        .run_action(ActionName::EqualizePanes, &mut effects);
    assert_eq!(layout(&h), start.equalize());
    assert!(ActionName::EqualizePanes.info().is_some());
}

/// Draw with an emulator per live session (so panes show their label and border).
fn render_panes(h: &AppHarness, w: u16, hgt: u16) -> String {
    use crate::widgets::terminal_pane::tests::new_emulator;
    let source = |id: SessionId| {
        h.app()
            .tabs()
            .sessions
            .contains(&id)
            .then(|| new_emulator(20, 5, format!("$ echo {}", id.0).as_bytes()))
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, hgt)).unwrap();
    terminal
        .draw(|f| {
            h.app().render_with_panes(f, &source);
        })
        .unwrap();
    crate::testing::buffer_to_string(terminal.backend().buffer())
}

#[test]
fn t12_zoom_marker_and_resize_status_snapshot() {
    let mut h = harness(80, 24);
    side_by_side(&mut h);
    leader(&mut h, "z");
    leader(&mut h, "r");
    let screen = render_panes(&h, 80, 24);
    assert!(screen.contains("RESIZE"), "{screen}");
    assert!(
        screen.lines().nth(1).unwrap_or_default().contains(" Z"),
        "{screen}"
    );
    insta::assert_snapshot!("m3_01_t12_zoom_resize_80x24", screen);
}
