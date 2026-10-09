//!  and the session-area snapshots.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use sverb_conn::{DisconnectReason, SessionEvent, SessionSpec, SessionState};
use sverb_core::layout::{Layout, SplitDir};

use super::*;
use crate::app::{Config, InputEvent, UiEvent};
use crate::testing::AppHarness;
use crate::views::DialogKind;

const LEADER: &str = "ctrl-\\";

fn harness(w: u16, h: u16) -> AppHarness {
    let mut h_ = AppHarness::new(Config::default());
    h_.resize(w, h);
    h_.take_effects();
    h_
}

fn leader(h: &mut AppHarness, key: &str) {
    h.keys(&format!("{LEADER} {key}"));
}

fn opened(effects: &[Effect]) -> Vec<(SessionId, SessionSpec, u16, u16)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::OpenSession {
                id,
                spec,
                cols,
                rows,
            } => Some((*id, spec.clone(), *cols, *rows)),
            _ => None,
        })
        .collect()
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

fn state(h: &mut AppHarness, id: SessionId, s: SessionState) {
    h.send(UiEvent::Session(id, SessionEvent::State(s)));
}

fn connected(h: &mut AppHarness, id: SessionId) {
    let now = h.now();
    state(h, id, SessionState::Connected { since: now });
}

fn focused(h: &AppHarness) -> SessionId {
    match h.app().focus {
        Focus::Session(id) => id,
        Focus::Hosts => panic!("no session focused"),
    }
}

/// A local tab; returns its session.
fn local_tab(h: &mut AppHarness) -> SessionId {
    leader(h, "t");
    focused(h)
}

#[test]
fn t06_leader_c_picks_a_host_into_a_new_tab() {
    let mut h = harness(160, 48);
    let (index, ids) =
        crate::views::hosts::sample_index(&[("alpha", "10.0.0.1"), ("bravo", "10.0.0.2")]);
    h.send(UiEvent::IndexUpdated(index));
    let first = local_tab(&mut h);
    h.take_effects();
    leader(&mut h, "c");
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::QuickConnect(_))
    ));
    h.keys("b r a v o");
    // The typed target is the first row; the saved host follows it.
    h.keys("down enter");
    let effects = h.take_effects();
    let open = opened(&effects);
    assert_eq!(open.len(), 1, "{effects:?}");
    let (sid, spec, cols, rows) = open[0].clone();
    let SessionSpec::Ssh(spec) = spec else {
        panic!("{spec:?}")
    };
    assert_eq!(spec.host_id, Some(ids[1]));
    let app = h.app();
    assert_eq!(app.tabs().list.len(), 2);
    assert_eq!(app.tabs().active, 1);
    assert_eq!(focused(&h), sid);
    assert!(app.tabs().list[0].has_session(first));
    let items = app.tab_items();
    assert_eq!(items[1].label, "bravo");
    assert!(items[1].active && !items[0].active);
    // Opened at its pane's size.
    let main = app.shell_rects().main;
    assert_eq!((cols, rows), (main.width - 2, main.height - 2));
}

#[test]
fn t07_split_opens_the_same_target_and_focuses_it() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    h.take_effects();
    leader(&mut h, "-");
    let effects = h.take_effects();
    let open = opened(&effects);
    assert_eq!(open.len(), 1, "{effects:?}");
    let (b, spec, cols, rows) = open[0].clone();
    assert!(matches!(spec, SessionSpec::Local(_)));
    let tab = h.app().active_tab().unwrap().clone();
    assert_eq!(h.app().tabs().list.len(), 1, "no new tab");
    let Layout::Split { dir, children, .. } = &tab.layout else {
        panic!("{:?}", tab.layout)
    };
    assert_eq!(*dir, SplitDir::Horizontal);
    assert_eq!(children.len(), 2);
    assert_eq!(tab.sessions(), [a, b], "inserted after the target");
    assert_eq!(focused(&h), b);
    let main = h.app().shell_rects().main;
    // Stacked: the lower half's content size.
    assert_eq!(cols, main.width - 2);
    assert!(rows < main.height / 2, "{rows}");
    // The upper pane shrank: one debounced resize for it.
    h.advance(60);
    let r = resizes(&h.take_effects());
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].0, a);
}

#[test]
fn split_of_a_saved_host_connects_to_that_host() {
    let mut h = harness(160, 48);
    let ids = h.app_mut().seed_three_hosts();
    h.keys("enter");
    let first = opened(&h.take_effects());
    assert_eq!(first.len(), 1);
    leader(&mut h, "|");
    let open = opened(&h.take_effects());
    assert_eq!(open.len(), 1);
    let SessionSpec::Ssh(spec) = &open[0].1 else {
        panic!()
    };
    assert_eq!(spec.host_id, Some(ids[0]));
    assert_eq!(h.app().active_tab().unwrap().panes.len(), 2);
    assert_eq!(h.app().pane(open[0].0).label, "alpha");
}

#[test]
fn hosts_connect_in_split_splits_the_current_tab() {
    let mut h = harness(160, 48);
    h.app_mut().seed_three_hosts();
    h.keys("enter");
    leader(&mut h, "v");
    assert_eq!(h.app().focus, Focus::Hosts);
    h.keys("j v");
    let tabs = &h.app().tabs().list;
    assert_eq!(tabs.len(), 1, "{tabs:?}");
    assert_eq!(tabs[0].panes.len(), 2);
    assert!(matches!(
        tabs[0].layout,
        Layout::Split {
            dir: SplitDir::Vertical,
            ..
        }
    ));
    assert_eq!(h.app().shell().main_view, crate::views::MainView::Sessions);
    assert!(
        !h.app().toasts().iter().any(|t| t.message.contains("M1-17")),
        "no more interim toast"
    );
}

#[test]
fn t08_focus_moves_by_geometry() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    leader(&mut h, "|");
    let b = focused(&h);
    assert_ne!(a, b);
    leader(&mut h, "h");
    assert_eq!(focused(&h), a);
    leader(&mut h, "h");
    assert_eq!(focused(&h), a, "edge: no-op");
    leader(&mut h, "l");
    assert_eq!(focused(&h), b);
    leader(&mut h, "j");
    assert_eq!(focused(&h), b);
    // Split b below: c. Up from c → b; left from c → a.
    leader(&mut h, "-");
    let c = focused(&h);
    leader(&mut h, "left");
    assert_eq!(focused(&h), a);
    // Ties go to the most recent: from a, right overlaps b and c equally → c (more
    // recent than b).
    leader(&mut h, "right");
    assert_eq!(focused(&h), c);
    leader(&mut h, "k");
    assert_eq!(focused(&h), b);
    assert_eq!(h.app().mode(), Mode::Terminal);
}

#[test]
fn t09_close_pane_confirms_while_alive_and_collapses() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    leader(&mut h, "|");
    let b = focused(&h);
    connected(&mut h, b);
    h.take_effects();
    leader(&mut h, "x");
    let Some(DialogKind::Modal(m)) = h.app().dialogs().last().map(|d| &d.kind) else {
        panic!("no confirm: {:?}", h.app().dialogs())
    };
    assert_eq!(m.modal.title, "Close pane?");
    assert!(!h.effects().contains(&Effect::CloseSession(b)));
    // Enter keeps it (danger dialog).
    h.keys("enter");
    assert!(!h.take_effects().contains(&Effect::CloseSession(b)));
    assert_eq!(h.app().active_tab().unwrap().panes.len(), 2);
    leader(&mut h, "x");
    h.keys("c");
    let effects = h.take_effects();
    assert!(effects.contains(&Effect::CloseSession(b)), "{effects:?}");
    assert_eq!(
        h.app().active_tab().unwrap().layout,
        Layout::leaf(pane_of(a))
    );
    assert_eq!(focused(&h), a);
    assert!(!h.app().tabs().sessions.contains(&b));
    // The session's own Closed later changes nothing.
    state(&mut h, b, SessionState::Closed);
    assert_eq!(h.app().tabs().list.len(), 1);

    // A connecting session is alive too; the last pane closes the tab.
    leader(&mut h, "x");
    assert!(!h.app().dialogs().is_empty());
    h.keys("c");
    assert!(h.app().tabs().list.is_empty());
    assert_eq!(h.app().focus, Focus::Hosts);
    assert_eq!(h.app().shell().main_view, crate::views::MainView::Sections);
}

#[test]
fn close_pane_without_live_session_needs_no_confirm() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let at = h.now();
    state(
        &mut h,
        a,
        SessionState::Disconnected {
            reason: DisconnectReason::Exited(0),
            at,
        },
    );
    h.take_effects();
    leader(&mut h, "x");
    assert!(h.app().dialogs().is_empty());
    assert!(h.effects().contains(&Effect::CloseSession(a)));
    assert!(h.app().tabs().list.is_empty());
}

#[test]
fn close_tab_confirms_and_closes_every_pane() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    leader(&mut h, "-");
    let c = focused(&h);
    connected(&mut h, c);
    h.take_effects();
    leader(&mut h, "X");
    let Some(DialogKind::Modal(m)) = h.app().dialogs().last().map(|d| &d.kind) else {
        panic!()
    };
    assert_eq!(m.modal.title, "Close tab?");
    assert!(m.modal.body.contains("2 sessions"), "{}", m.modal.body);
    h.keys("c");
    let effects = h.take_effects();
    assert!(effects.contains(&Effect::CloseSession(b)));
    assert!(effects.contains(&Effect::CloseSession(c)));
    assert_eq!(h.app().tabs().list.len(), 1);
    assert_eq!(focused(&h), a);
}

#[test]
fn t10_tab_numbers_and_wrapping() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    assert_eq!(h.app().tabs().active, 1);
    leader(&mut h, "3");
    assert_eq!(h.app().tabs().active, 1, "no tab 3: no-op");
    assert_eq!(focused(&h), b);
    leader(&mut h, "1");
    assert_eq!(focused(&h), a);
    leader(&mut h, "N");
    assert_eq!(focused(&h), b, "wraps to the last");
    leader(&mut h, "n");
    assert_eq!(focused(&h), a, "wraps to the first");
    leader(&mut h, "2");
    assert_eq!(h.app().tabs().active, 1);
}

#[test]
fn t11_activity_and_bell_markers() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    // Output in the active tab: no marker.
    h.send(UiEvent::Session(b, SessionEvent::Dirty));
    assert_eq!(h.app().tab_items()[1].markers, "");
    h.send(UiEvent::Session(a, SessionEvent::Dirty));
    assert_eq!(h.app().tab_items()[0].markers, " ●");
    assert!(h.render(160, 48).contains("1 local ●"));
    leader(&mut h, "1");
    assert_eq!(h.app().tab_items()[0].markers, "", "cleared on focus");
    h.send(UiEvent::Session(b, SessionEvent::Bell));
    assert_eq!(h.app().tab_items()[1].markers, " 🔔");
    // Disconnected and auth markers.
    let at = h.now();
    state(
        &mut h,
        b,
        SessionState::Disconnected {
            reason: DisconnectReason::Timeout,
            at,
        },
    );
    assert!(h.app().tab_items()[1].markers.contains('✕'));
    connected(&mut h, b);
    assert!(!h.app().tab_items()[1].markers.contains('✕'));
    // Background output while the section views are shown marks the active tab too.
    leader(&mut h, "v");
    h.send(UiEvent::Session(a, SessionEvent::Dirty));
    assert!(h.app().tab_items()[0].markers.contains('●'));
}

#[test]
fn t12_osc_title_in_the_tab_bar() {
    let mut config = Config::default();
    config.terminal.use_osc_title = true;
    let mut h = AppHarness::new(config);
    h.resize(160, 48);
    let a = local_tab(&mut h);
    let long = "t".repeat(300);
    h.send(UiEvent::Session(a, SessionEvent::Title(long)));
    let label = &h.app().tab_items()[0].label;
    assert_eq!(label.chars().count(), 256);
    let screen = h.render(160, 48);
    assert!(
        screen.contains(&format!(" 1 {}… ┬ + ", "t".repeat(23))),
        "{screen}"
    );
    h.send(UiEvent::Session(a, SessionEvent::Title("vim".into())));
    assert_eq!(h.app().tab_items()[0].label, "vim");
    // Off: the label.
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    h.send(UiEvent::Session(a, SessionEvent::Title("vim".into())));
    assert_eq!(h.app().tab_items()[0].label, "local");
}

#[test]
fn t13_resize_is_debounced_per_pane() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    leader(&mut h, "|");
    let b = focused(&h);
    h.advance(100);
    h.take_effects();
    for i in 0..10u16 {
        h.resize(150 + i, 40 + i);
        h.advance(4);
    }
    assert!(resizes(h.effects()).is_empty(), "nothing before 50 ms");
    h.advance(50);
    let r = resizes(&h.take_effects());
    assert_eq!(r.len(), 2, "{r:?}");
    let sizes: std::collections::BTreeMap<_, _> =
        r.iter().map(|(id, c, w)| (*id, (*c, *w))).collect();
    let main = h.app().shell_rects().main;
    let tab = h.app().active_tab().unwrap();
    for (p, rect) in pane_rects(&tab.layout, None, main) {
        assert_eq!(sizes[&tab.panes[&p].session], content_size(rect));
    }
    assert!(sizes.contains_key(&a) && sizes.contains_key(&b));
    // Nothing changed since: no more resizes.
    h.resize(159, 49);
    h.advance(100);
    assert!(resizes(&h.take_effects()).is_empty());
}

#[test]
fn background_tabs_are_resized_and_hidden_ones_not_visible() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    assert_eq!(h.app().visible_sessions(), [b]);
    h.advance(100);
    h.take_effects();
    h.resize(120, 40);
    h.advance(60);
    let ids: Vec<SessionId> = resizes(&h.take_effects()).iter().map(|r| r.0).collect();
    assert_eq!(ids, [a, b]);
}

#[test]
fn mouse_clicks_switch_tabs_focus_panes_and_reach_the_session() {
    let mut h = harness(160, 48);
    let a = local_tab(&mut h);
    let b = local_tab(&mut h);
    leader(&mut h, "|");
    let c = focused(&h);
    let click = |col, row| {
        UiEvent::Input(InputEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        }))
    };
    let rects = h.app().shell_rects();
    let bar = h.app().tab_bar_area(&rects);
    // " 1 local ┬ 2 local ┬ + ": tab 1 at offset 1.
    h.send(click(bar.x + 1, bar.y));
    assert_eq!(focused(&h), a);
    h.send(click(bar.x + 12, bar.y));
    assert_eq!(focused(&h), c, "tab 2 keeps its focused pane");
    // Click the left pane: focus, nothing sent.
    let main = rects.main;
    h.take_effects();
    h.send(click(main.x + 3, main.y + 3));
    assert_eq!(focused(&h), b);
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. }))
    );
    // A click inside the focused pane goes to its session, pane-relative.
    h.send(click(main.x + 5, main.y + 4));
    let sent: Vec<_> = h
        .take_effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::SendToSession {
                id,
                input: SessionInput::Mouse(m),
            } => Some((id, m.col, m.row)),
            _ => None,
        })
        .collect();
    assert_eq!(sent, [(b, 4, 3)]);
    // `+` opens the host picker.
    let segs = tabbar::bar_segments(&h.app().tab_items(), bar.width);
    let plus = segs.last().unwrap();
    h.send(click(bar.x + plus.x + 2, bar.y));
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::QuickConnect(_))
    ));
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

fn three_tabs(w: u16, hgt: u16) -> AppHarness {
    let mut h = harness(w, hgt);
    // Tab 1: 2×2.
    let a = local_tab(&mut h);
    leader(&mut h, "|");
    leader(&mut h, "-");
    leader(&mut h, "h");
    leader(&mut h, "-");
    // Tab 2: disconnected.
    let d = local_tab(&mut h);
    let at = h.now();
    state(
        &mut h,
        d,
        SessionState::Disconnected {
            reason: DisconnectReason::Closed,
            at,
        },
    );
    // Tab 3: active; then tab 1 gets output in the background… and tab 2 shows.
    let _c = local_tab(&mut h);
    h.send(UiEvent::Session(a, SessionEvent::Dirty));
    leader(&mut h, "3");
    h.app_mut().set_pane_label(d, "db-primary");
    h
}

#[test]
fn t14_snapshots() {
    for (w, hgt) in [(160, 48), (80, 24)] {
        let mut h = three_tabs(w, hgt);
        leader(&mut h, "1");
        let tab = h.app().active_tab().unwrap();
        assert_eq!(tab.panes.len(), 4);
        // Tab 1 is shown (2×2); give tab 3 activity for the bar.
        let c = h.app().tabs().list[2].focused_session();
        h.send(UiEvent::Session(c, SessionEvent::Dirty));
        insta::assert_snapshot!(
            format!("t14_three_tabs_{w}x{hgt}"),
            render_panes(&h, w, hgt)
        );
    }
    // Tab overflow at 40 columns, with many tabs.
    let mut h = three_tabs(40, 12);
    for _ in 0..5 {
        local_tab(&mut h);
    }
    leader(&mut h, "4");
    let screen = render_panes(&h, 40, 12);
    let bar = screen.lines().nth(1).unwrap_or_default().to_owned();
    assert!(bar.contains('‹') && bar.contains('›'), "{screen}");
    insta::assert_snapshot!("t14_tab_overflow_40x12", screen);
}
