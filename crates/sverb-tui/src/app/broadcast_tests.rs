#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use sverb_conn::{DisconnectReason, SessionEvent, SessionState};
use sverb_core::model::{ItemId, RunMode, Snippet};
use sverb_term::{TermModes, input::EncodeOpts, input::encode_key};

use crate::app::{
    Config, Effect, Focus, InputEvent, SessionId, SessionInput, SnippetsEvent, UiEvent,
};
use crate::keymap::chord::KeyChord;
use crate::testing::{AppHarness, buffer_to_string};
use crate::theme::ThemeEnv;
use crate::views::{DialogKind, sessions::panes::pane_rects};

const LEADER: &str = "ctrl-\\";

fn harness(env: Option<ThemeEnv>) -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    if let Some(env) = env {
        h = h.with_theme_env(env);
    }
    h.resize(160, 48);
    h.take_effects();
    h
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

/// One tab of `n` local panes side by side; returns them in layout order, the last
/// one focused.
fn panes(h: &mut AppHarness, n: usize) -> Vec<SessionId> {
    leader(h, "t");
    let mut out = vec![focused(h)];
    for _ in 1..n {
        leader(h, "|");
        out.push(focused(h));
    }
    assert_eq!(h.app().active_tab().unwrap().sessions(), out);
    h.take_effects();
    out
}

fn focus(h: &mut AppHarness, id: SessionId) {
    h.app_mut().focus_session(id);
    // Let the tab follow the focus.
    h.send(UiEvent::Input(InputEvent::FocusGained));
    h.take_effects();
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

fn key(s: &str) -> SessionInput {
    SessionInput::Key(KeyChord::parse_sequence(s).unwrap()[0])
}

/// What each session received, in order.
fn by_session(effects: &[Effect]) -> BTreeMap<SessionId, Vec<SessionInput>> {
    let mut out: BTreeMap<SessionId, Vec<SessionInput>> = BTreeMap::new();
    for (id, input) in sent(effects) {
        out.entry(id).or_default().push(input);
    }
    out
}

fn status_line(h: &AppHarness) -> String {
    h.render(160, 48)
        .lines()
        .last()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn t01_all_panes_receive_every_key() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    leader(&mut h, "b");
    assert!(sent(h.effects()).is_empty(), "the leader is not broadcast");
    h.take_effects();
    h.keys("l s enter");
    let got = by_session(&h.take_effects());
    assert_eq!(got.len(), 3, "{got:?}");
    for id in &ids {
        assert_eq!(got[id], [key("l"), key("s"), key("enter")], "{id:?}");
    }
    assert!(status_line(&h).contains("BROADCAST ×3"));
    // The focused pane is sent first (no copy of its bytes: every target gets the key).
    let order: Vec<SessionId> = {
        h.keys("x");
        sent(&h.take_effects())
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    };
    assert_eq!(order[0], ids[2]);
    // `leader b` again turns it off.
    leader(&mut h, "b");
    h.take_effects();
    h.keys("y");
    assert_eq!(sent(&h.take_effects()), [(ids[2], key("y"))]);
    assert!(!status_line(&h).contains("BROADCAST"));
}

#[test]
fn t02_each_pane_encodes_with_its_own_modes() {
    let mut h = harness(None);
    let ids = panes(&mut h, 2);
    leader(&mut h, "b");
    h.take_effects();
    h.keys("up");
    // Mock sessions: A has DECCKM on, B off. Each encodes the chord it received.
    let modes: BTreeMap<SessionId, TermModes> = BTreeMap::from([
        (
            ids[0],
            TermModes {
                app_cursor: true,
                ..TermModes::default()
            },
        ),
        (ids[1], TermModes::default()),
    ]);
    let mut bytes = BTreeMap::new();
    for (id, input) in sent(&h.take_effects()) {
        let SessionInput::Key(chord) = input else {
            panic!("{input:?}")
        };
        let out = encode_key(
            chord.to_key_input().unwrap(),
            &modes[&id],
            &EncodeOpts::default(),
        );
        bytes.insert(id, out.unwrap().to_vec());
    }
    assert_eq!(bytes[&ids[0]], b"\x1bOA");
    assert_eq!(bytes[&ids[1]], b"\x1b[A");
}

#[test]
fn t03_custom_set() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    focus(&mut h, ids[0]);
    leader(&mut h, "B");
    focus(&mut h, ids[2]);
    leader(&mut h, "B");
    focus(&mut h, ids[0]);
    h.keys("a");
    let got = by_session(&h.take_effects());
    assert_eq!(got.keys().copied().collect::<Vec<_>>(), [ids[0], ids[2]]);
    // A pane outside the set types alone.
    focus(&mut h, ids[1]);
    h.keys("b");
    assert_eq!(sent(&h.take_effects()), [(ids[1], key("b"))]);
    assert!(!status_line(&h).contains("BROADCAST"));
    // A new pane does not join a custom set; a closed member leaves it.
    leader(&mut h, "|");
    let new = focused(&h);
    assert!(!h.app().broadcast_highlight(new));
    h.take_effects();
    focus(&mut h, ids[2]);
    leader(&mut h, "x");
    h.keys("c"); // "Close" in the confirmation
    assert!(!h.app().tabs().sessions.contains(&ids[2]));
    focus(&mut h, ids[0]);
    h.keys("z");
    assert_eq!(sent(&h.take_effects()), [(ids[0], key("z"))], "pending now");
}

#[test]
fn t04_single_member_is_pending_and_highlighted() {
    let mut h = harness(None);
    let ids = panes(&mut h, 2);
    focus(&mut h, ids[0]);
    leader(&mut h, "B");
    h.take_effects();
    h.keys("q");
    assert_eq!(sent(&h.take_effects()), [(ids[0], key("q"))]);
    assert!(h.app().broadcast_highlight(ids[0]));
    assert!(!h.app().broadcast_highlight(ids[1]));
    assert!(status_line(&h).contains("BROADCAST ×1 (pending)"));
    // The member's border uses the broadcast style.
    let buf = render_buffer(&h);
    let (r0, r1) = rects(&h);
    let theme = h.app().theme.clone();
    assert_eq!(buf[(r0.x, r0.y)].fg, theme.broadcast_border.fg.unwrap());
    assert_ne!(buf[(r1.x, r1.y)].fg, theme.broadcast_border.fg.unwrap());
    assert!(h.render(160, 48).contains("≋"));
}

#[test]
fn t05_resize_is_never_broadcast() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    leader(&mut h, "b");
    h.advance(100);
    h.take_effects();
    h.resize(120, 40);
    h.advance(100);
    let effects = h.take_effects();
    assert!(sent(&effects).is_empty(), "{effects:?}");
    let mut resized: Vec<SessionId> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::ResizeSession { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    resized.sort();
    assert_eq!(resized, ids, "one geometric resize per pane");
}

#[test]
fn t06_paste_is_broadcast() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    leader(&mut h, "b");
    h.take_effects();
    h.send(UiEvent::Input(InputEvent::Paste(
        "echo hi\necho there".into(),
    )));
    let got = by_session(&h.take_effects());
    for id in &ids {
        // Each session applies its own bracketed-paste / confirmation rule.
        assert_eq!(
            got[id],
            [SessionInput::Paste("echo hi\necho there".into())],
            "{id:?}"
        );
    }
}

#[test]
fn t07_snippet_runs_are_broadcast() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    let uptime = ItemId::from_bytes([2; 16]);
    h.send(UiEvent::Snippets(SnippetsEvent::Loaded {
        snippets: vec![(
            uptime,
            Snippet {
                name: "uptime".into(),
                script: "uptime".into(),
                description: None,
                tags: Vec::new(),
                variables: Vec::new(),
                run_mode: RunMode::Paste,
                read_only: false,
            },
        )],
        tags: BTreeMap::new(),
    }));
    leader(&mut h, "b");
    leader(&mut h, "e");
    for c in "upt".chars() {
        h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::NONE,
        ))));
    }
    h.keys("enter");
    h.take_effects();
    h.keys("enter");
    let got = by_session(&h.take_effects());
    assert_eq!(got.len(), 3, "{got:?}");
    for id in &ids {
        assert_eq!(got[id], [SessionInput::PasteUnchecked("uptime".into())]);
    }
}

#[test]
fn t08_unavailable_members_are_skipped() {
    let mut h = harness(None);
    let ids = panes(&mut h, 3);
    leader(&mut h, "b");
    let at = h.now();
    h.send(UiEvent::Session(
        ids[1],
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::Closed,
            at,
        }),
    ));
    h.take_effects();
    h.keys("k");
    let got = by_session(&h.take_effects());
    assert_eq!(got.keys().copied().collect::<Vec<_>>(), [ids[0], ids[2]]);
    assert!(
        status_line(&h).contains("BROADCAST ×2 (1 skipped)"),
        "{}",
        status_line(&h)
    );
}

#[test]
fn t09_leader_and_actions_are_not_broadcast() {
    let mut h = harness(None);
    panes(&mut h, 2);
    leader(&mut h, "b");
    h.take_effects();
    leader(&mut h, "-");
    let effects = h.take_effects();
    assert!(sent(&effects).is_empty(), "{effects:?}");
    let opened = effects
        .iter()
        .filter(|e| matches!(e, Effect::OpenSession { .. }))
        .count();
    assert_eq!(opened, 1);
    // The new pane joins `AllPanes` at once.
    let new = focused(&h);
    assert!(h.app().broadcast_highlight(new));
    h.keys("w");
    assert_eq!(sent(&h.take_effects()).len(), 3);
}

#[test]
fn t10_large_broadcast_asks_once_per_run() {
    let mut h = harness(None);
    let ids = panes(&mut h, 5);
    let modal_open = |h: &AppHarness| {
        matches!(
            h.app().dialogs().last().map(|d| &d.kind),
            Some(DialogKind::Modal(_))
        )
    };
    leader(&mut h, "b");
    assert!(modal_open(&h));
    assert!(h.render(160, 48).contains("Broadcast input to 5 panes?"));
    // Cancel: still off, nothing typed anywhere.
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());
    assert!(!h.app().broadcast_highlight(ids[0]));
    leader(&mut h, "b");
    assert!(modal_open(&h), "asked again after a cancel");
    h.take_effects();
    h.keys("b");
    assert!(h.app().dialogs().is_empty());
    assert!(sent(&h.take_effects()).is_empty());
    h.keys("v");
    assert_eq!(sent(&h.take_effects()).len(), 5);
    // Off and on again: no second confirmation in this run.
    leader(&mut h, "b");
    leader(&mut h, "b");
    assert!(h.app().dialogs().is_empty());
    assert!(h.app().broadcast_highlight(ids[4]));
}

fn render_buffer(h: &AppHarness) -> ratatui::buffer::Buffer {
    use crate::widgets::terminal_pane::tests::new_emulator;
    let source = |id: SessionId| {
        h.app()
            .tabs()
            .sessions
            .contains(&id)
            .then(|| new_emulator(20, 5, format!("$ echo {}", id.0).as_bytes()))
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 48)).unwrap();
    terminal
        .draw(|f| {
            h.app().render_with_panes(f, &source);
        })
        .unwrap();
    terminal.backend().buffer().clone()
}

/// The first two panes' rects.
fn rects(h: &AppHarness) -> (Rect, Rect) {
    let tab = h.app().active_tab().unwrap();
    let r = pane_rects(&tab.layout, tab.zoomed, h.app().shell_rects().main);
    (r[0].1, r[1].1)
}

#[test]
fn t11_snapshots() {
    for (name, env) in [
        (
            "color",
            ThemeEnv {
                no_color: false,
                colorterm_truecolor: true,
            },
        ),
        (
            "no_color",
            ThemeEnv {
                no_color: true,
                colorterm_truecolor: false,
            },
        ),
    ] {
        let mut h = harness(Some(env));
        panes(&mut h, 3);
        leader(&mut h, "b");
        let buf = render_buffer(&h);
        let screen = buffer_to_string(&buf);
        assert!(screen.contains("BROADCAST ×3"), "{screen}");
        assert_eq!(
            screen.matches('≋').count(),
            4,
            "3 panes + the tab: {screen}"
        );
        let (r0, _) = rects(&h);
        let border = buf[(r0.x, r0.y)].clone();
        if env.no_color {
            assert!(border.modifier.contains(ratatui::style::Modifier::BOLD));
        } else {
            assert_eq!(border.fg, h.app().theme.broadcast_border.fg.unwrap());
        }
        insta::assert_snapshot!(format!("m3_02_t11_broadcast_{name}_160x48"), screen);
    }
}
