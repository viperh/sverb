//! Copy mode, mouse selection and links through the reducer.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, style::Modifier};
use sverb_conn::{SessionEvent, SharedEmulator};
use sverb_term::modes::input::{KeyMods, MouseAction, MouseButton, MouseInput};

use super::*;
use crate::{
    app::{Effect, Mode, UiEvent},
    testing::{AppHarness, buffer_to_string},
    views::DialogKind,
    widgets::terminal_pane::tests::new_emulator,
};

const S: SessionId = SessionId(1);

/// A focused live session 1 whose emulator is `emu`.
fn harness(emu: &SharedEmulator) -> AppHarness {
    let mut h = AppHarness::new(Config::default()).with_live_session();
    let e = Arc::clone(emu);
    h.app_mut().copy.terms = TermAccess(Some(Arc::new(move |id: SessionId| {
        (id == S).then(|| Arc::clone(&e))
    })));
    h
}

fn feed(emu: &SharedEmulator, bytes: &[u8]) {
    emu.lock().feed(bytes);
}

fn copies(h: &AppHarness) -> Vec<String> {
    h.effects()
        .iter()
        .filter_map(|e| match e {
            Effect::CopyToClipboard(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

fn mouse(action: MouseAction, col: u16, row: u16, mods: KeyMods) -> UiEvent {
    UiEvent::Session(
        S,
        SessionEvent::Mouse(MouseInput {
            action,
            col,
            row,
            mods,
        }),
    )
}

fn draw(h: &AppHarness, emu: &SharedEmulator, w: u16, h_: u16) -> Buffer {
    let e = Arc::clone(emu);
    let source = move |id: SessionId| (id == S).then(|| Arc::clone(&e));
    let mut terminal = Terminal::new(TestBackend::new(w, h_)).unwrap();
    terminal
        .draw(|f| {
            h.app().render_with_panes(f, &source);
        })
        .unwrap();
    terminal.backend().buffer().clone()
}

/// `leader [` → copy mode; `v` + motions + `y` → `CopyToClipboard`, back to Terminal.
#[test]
fn t06_select_and_yank() {
    let emu = new_emulator(40, 5, b"$ ssh web-1:22\r\nhello world\r\n$ ");
    let mut h = harness(&emu);
    h.keys("ctrl-\\ [");
    assert_eq!(h.app().mode(), Mode::Copy);
    let state = h.app().copy.state.clone().unwrap();
    assert_eq!(
        state.cursor,
        GridPoint::new(2, 2),
        "starts at the terminal cursor"
    );
    // Up to `hello`, select two words.
    h.keys("k 0 v e w e y");
    assert_eq!(copies(&h), ["hello world"]);
    assert_eq!(h.app().mode(), Mode::Terminal);
    assert!(h.app().copy.state.is_none());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message == "Copied 11 chars"),
        "{:?}",
        h.app().toasts()
    );
    // Nothing went to the session while in copy mode.
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. }))
    );
    // `Y` yanks the current line; `3 Y` three lines; `q` just leaves.
    h.take_effects();
    h.keys("ctrl-\\ [ k k Y");
    assert_eq!(copies(&h), ["$ ssh web-1:22"]);
    h.take_effects();
    h.keys("ctrl-\\ [ g g 2 Y");
    assert_eq!(copies(&h), ["$ ssh web-1:22\nhello world"]);
    h.keys("ctrl-\\ [ q");
    assert_eq!(h.app().mode(), Mode::Terminal);
}

/// New output while in copy mode doesn't move the view; the badge counts lines.
#[test]
fn t07_frozen_view_counts_new_lines() {
    let emu = new_emulator(30, 4, b"line 1\r\nline 2\r\nline 3\r\nline 4");
    let mut h = harness(&emu);
    h.resize(60, 14);
    h.keys("ctrl-\\ [");
    let before = buffer_to_string(&draw(&h, &emu, 60, 14));
    assert!(before.contains("line 1"), "{before}");
    assert!(before.contains("COPY"), "{before}");
    feed(&emu, b"\r\nnew a\r\nnew b\r\nnew c");
    let after = buffer_to_string(&draw(&h, &emu, 60, 14));
    assert!(after.contains("COPY · +3 lines"), "{after}");
    assert!(
        after.contains("line 1") && !after.contains("new a"),
        "{after}"
    );
    // Motions still work on the frozen content.
    h.keys("g g");
    assert_eq!(h.app().copy.state.as_ref().unwrap().cursor.line, -3);
    // Leaving returns to the live view.
    h.keys("q");
    let live = buffer_to_string(&draw(&h, &emu, 60, 14));
    assert!(live.contains("new c") && !live.contains("COPY"), "{live}");
}

/// Drag + release copies; Shift-drag works even when the remote captures the mouse.
#[test]
fn t08_mouse_selection() {
    let emu = new_emulator(40, 4, b"alpha beta gamma\r\nsecond row");
    let mut h = harness(&emu);
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        6,
        0,
        KeyMods::NONE,
    ));
    h.send(mouse(
        MouseAction::Drag(MouseButton::Left),
        8,
        0,
        KeyMods::NONE,
    ));
    h.send(mouse(
        MouseAction::Drag(MouseButton::Left),
        9,
        0,
        KeyMods::NONE,
    ));
    assert!(copies(&h).is_empty(), "nothing before the release");
    h.send(mouse(
        MouseAction::Release(MouseButton::Left),
        9,
        0,
        KeyMods::NONE,
    ));
    assert_eq!(copies(&h), ["beta"]);
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message == "Copied 4 chars")
    );
    // A plain click copies nothing.
    h.take_effects();
    h.advance(1000);
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    h.send(mouse(
        MouseAction::Release(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    assert!(copies(&h).is_empty());
    // Double click: the word; triple click: the line.
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    h.send(mouse(
        MouseAction::Release(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    assert_eq!(copies(&h), ["second"]);
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    h.send(mouse(
        MouseAction::Release(MouseButton::Left),
        2,
        1,
        KeyMods::NONE,
    ));
    assert_eq!(copies(&h), ["second", "second row"]);
    // After the multi-click window a click starts over.
    h.advance(500);
    assert!(h.app().copy.last_press.is_none());

    // The remote enables mouse reporting: the session only hands sverb Shift events
    // (sverb-conn routes them); sverb selects with them as usual.
    feed(&emu, b"\x1b[?1000h\x1b[?1006h");
    h.take_effects();
    for (action, col) in [
        (MouseAction::Press(MouseButton::Left), 0),
        (MouseAction::Drag(MouseButton::Left), 4),
        (MouseAction::Release(MouseButton::Left), 4),
    ] {
        h.send(mouse(action, col, 0, KeyMods::SHIFT));
    }
    assert_eq!(copies(&h), ["alpha"]);
    // Events the session handed back to sverb are never sent to it again.
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. }))
    );
    // Typing drops the selection.
    h.keys("x");
    assert!(h.app().copy.mouse.is_none());
}

#[test]
fn wheel_scrolls_scrollback_in_terminal_mode() {
    let lines: String = (0..30).map(|i| format!("l{i}\r\n")).collect();
    let emu = new_emulator(20, 5, lines.as_bytes());
    let mut h = harness(&emu);
    h.send(mouse(MouseAction::WheelUp, 0, 0, KeyMods::NONE));
    assert_eq!(h.app().pane(S).scroll_offset, WHEEL_LINES);
    assert_eq!(h.app().mode(), Mode::Terminal, "no copy mode");
    h.send(mouse(MouseAction::WheelDown, 0, 0, KeyMods::NONE));
    assert_eq!(h.app().pane(S).scroll_offset, 0);
    h.send(mouse(MouseAction::WheelUp, 0, 0, KeyMods::NONE));
    // Copy mode starts on the scrolled view; leaving goes back to the live one.
    h.keys("ctrl-\\ [");
    let s = h.app().copy.state.clone().unwrap();
    assert_eq!(s.scroll_offset(), WHEEL_LINES);
    h.keys("esc");
    assert_eq!(h.app().pane(S).scroll_offset, 0);
    // A key typed into the session snaps back to the live view.
    h.send(mouse(MouseAction::WheelUp, 0, 0, KeyMods::NONE));
    h.keys("a");
    assert_eq!(h.app().pane(S).scroll_offset, 0);
}

const LINK: &[u8] = b"see \x1b]8;;https://example.com/docs\x1b\\the docs\x1b]8;;\x1b\\ now";

fn open_urls(h: &AppHarness) -> Vec<String> {
    h.effects()
        .iter()
        .filter_map(|e| match e {
            Effect::OpenUrl(u) => Some(u.clone()),
            _ => None,
        })
        .collect()
}

/// `o` on a hyperlink → a confirm dialog with the URL; only "Open" opens it.
#[test]
fn t09_open_link_needs_confirmation() {
    let emu = new_emulator(40, 3, LINK);
    let mut h = harness(&emu);
    h.keys("ctrl-\\ [ 0 w");
    assert_eq!(
        h.app().link_hint().as_deref(),
        Some("https://example.com/docs")
    );
    assert!(h.app().status_hint().contains("https://example.com/docs"));
    h.keys("o");
    let Some(DialogKind::Modal(m)) = h.app().dialogs().last().map(|d| &d.kind) else {
        panic!("no dialog");
    };
    assert!(m.modal.body.contains("https://example.com/docs"));
    assert!(open_urls(&h).is_empty(), "nothing opens before the answer");
    // Enter is on Cancel (danger dialog); Esc too: no open.
    h.keys("enter");
    assert!(open_urls(&h).is_empty());
    h.keys("o");
    h.keys("esc");
    assert!(open_urls(&h).is_empty());
    assert_eq!(
        h.app().mode(),
        Mode::Copy,
        "back in copy mode after the dialog"
    );
    // "Open".
    h.keys("o o");
    assert_eq!(open_urls(&h), ["https://example.com/docs"]);
    // `o` off a link says so; no dialog.
    h.keys("0");
    let dialogs = h.app().dialogs().len();
    h.keys("o");
    assert_eq!(h.app().dialogs().len(), dialogs);
}

#[test]
fn ctrl_click_and_hover_on_auto_detected_urls() {
    let emu = new_emulator(50, 3, b"docs at https://example.org/x. ok");
    let mut h = harness(&emu);
    h.send(mouse(MouseAction::Move, 10, 0, KeyMods::NONE));
    assert_eq!(
        h.app().link_hint().as_deref(),
        Some("https://example.org/x")
    );
    assert!(h.app().status_hint().contains("ctrl-click"));
    h.send(mouse(MouseAction::Move, 1, 0, KeyMods::NONE));
    assert!(h.app().link_hint().is_none());
    // A plain click doesn't open; ctrl-click asks.
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        10,
        0,
        KeyMods::NONE,
    ));
    assert!(h.app().dialogs().is_empty());
    h.send(mouse(
        MouseAction::Press(MouseButton::Left),
        10,
        0,
        KeyMods::CTRL,
    ));
    assert_eq!(h.app().dialogs().len(), 1);
    h.keys("o");
    assert_eq!(open_urls(&h), ["https://example.org/x"]);
    // Unsupported schemes are refused before any dialog.
    let mut effects = Vec::new();
    h.app_mut()
        .confirm_open_link("file:///etc/passwd".to_owned(), &mut effects);
    assert!(h.app().dialogs().is_empty());
}

/// Marks overlay styles per cell: `S` selection (reversed), `C` current match, `m` match.
fn overlay_map(
    buf: &Buffer,
    current: ratatui::style::Color,
    matched: ratatui::style::Color,
) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        let mut row = String::new();
        for x in area.left()..area.right() {
            let c = &buf[(x, y)];
            row.push(
                if c.modifier.contains(Modifier::REVERSED) && c.bg != current && c.bg != matched {
                    'S'
                } else if c.bg == current {
                    'C'
                } else if c.bg == matched {
                    'm'
                } else {
                    '.'
                },
            );
        }
        out.push_str(row.trim_end_matches('.'));
        out.push('\n');
    }
    out
}

/// Copy mode with a selection and search highlights at 80×24.
#[test]
fn t10_snapshot_selection_and_search() {
    let mut text = Vec::new();
    for i in 0..30 {
        text.extend_from_slice(format!("{i:02} error: disk full on host-{i}\r\n").as_bytes());
    }
    text.extend_from_slice(b"$ ");
    let emu = new_emulator(78, 18, &text);
    let mut h = harness(&emu);
    h.resize(80, 24);
    h.keys("ctrl-\\ [ ? h o s t - 2 enter");
    h.keys("0 v j $");
    let buf = draw(&h, &emu, 80, 24);
    let theme = &h.app().theme;
    let current = theme.accent.fg.unwrap();
    let matched = theme.warn.fg.unwrap();
    assert_ne!(current, matched);
    let snap = format!(
        "{}\n--- overlays (S selection, C current match, m match) ---\n{}",
        buffer_to_string(&buf),
        overlay_map(&buf, current, matched)
    );
    insta::assert_snapshot!("m3_04_t10_copy_mode_80x24", snap);
}

/// Regression (crash 2026-10-09, "control character passed to cell_width without
/// filtering"): remote output with tabs left a literal `\t` in the emulator grid, and the
/// pane copied it into the frame; ratatui's flush then panicked. Drawing through a real
/// `Terminal` (draw → flush → diff) must not panic, the tab must show as blanks, and later
/// frames (diffed against the previous one) must stay clean too.
#[test]
fn tab_output_draws_without_control_cells() {
    let emu = new_emulator(40, 5, b"$ ls\r\nCargo.toml\tsrc\ttarget\r\n$ ");
    let h = harness(&emu);
    let e = Arc::clone(&emu);
    let source = move |id: SessionId| (id == S).then(|| Arc::clone(&e));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|f| {
            h.app().render_with_panes(f, &source);
        })
        .unwrap();
    feed(&emu, b"printf 'a\\tb'\r\na\tb\r\n\t\tdeep\r\n$ ");
    terminal
        .draw(|f| {
            h.app().render_with_panes(f, &source);
        })
        .unwrap();
    let buf = terminal.backend().buffer().clone();
    for cell in buf.content() {
        assert!(
            !cell.symbol().chars().any(char::is_control),
            "control character {:?} in a rendered cell",
            cell.symbol()
        );
    }
    let text = buffer_to_string(&buf);
    assert!(text.contains("Cargo.toml      src     target"), "{text}");
    assert!(text.contains("a       b"), "{text}");
}
