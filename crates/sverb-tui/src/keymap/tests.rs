//! M0-10 reducer-level tests: modes, leader, which-key, overrides, pass-through (K-01…K-04).
//! Chord parsing tests (T-01…T-04) live in `chord.rs`.

use std::sync::Arc;

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MediaKeyCode, ModifierKeyCode,
};
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use sverb_core::config::{Config, ConfigEvent, KeyChordSpec, LeaderCheck, Severity};
// M1-11
use sverb_term::{
    TermModes,
    modes::input::{EncodeOpts, encode_key},
};

use super::{
    Keymap, Table,
    action::{ActionName, registry},
    chord::KeyChord,
    dump, validate, validators, whichkey,
};
use crate::{
    app::{Effect, InputEvent, MetaFlag, MetaFlags, Mode, SessionId, SessionInput, UiEvent},
    keymap::leader::KeyState,
    testing::AppHarness,
    views::{DialogKind, hosts::form::HostFormDialog},
};

fn c(s: &str) -> KeyChord {
    s.parse().unwrap_or_else(|e| panic!("{e}"))
}

fn with_leader(leader: &str) -> Config {
    let mut cfg = Config::default();
    cfg.general.leader = KeyChordSpec::from(leader);
    cfg
}

fn from_toml(src: &str) -> Config {
    let out = Config::from_toml_str(src, &validators());
    assert!(out.is_ok(), "{:?}", out.errors);
    out.config
}

fn terminal(cfg: Config) -> AppHarness {
    AppHarness::new(cfg).with_live_session()
}

/// What went to the session.
fn sent(effects: &[Effect]) -> Vec<SessionInput> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::SendToSession { input, .. } => Some(input.clone()),
            _ => None,
        })
        .collect()
}

// M1-11: the real encoder (`sverb_term` input encoding) replaces the legacy oracle.
/// The bytes the session actor sends for `chord` in a pane with default modes (normal
/// cursor keys, no keypad, modifyOtherKeys or kitty flags) and `backspace = del`.
fn encoded(chord: &KeyChord) -> Vec<u8> {
    let input = chord
        .to_key_input()
        .unwrap_or_else(|| panic!("no key input for {chord}"));
    encode_key(input, &TermModes::default(), &EncodeOpts::default())
        .unwrap_or_else(|| panic!("no bytes for {chord}"))
        .to_vec()
}

fn sent_bytes(effects: &[Effect]) -> Vec<u8> {
    sent(effects)
        .iter()
        .flat_map(|i| match i {
            SessionInput::Key(k) => encoded(k),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

fn toasts(h: &AppHarness) -> Vec<String> {
    h.app().toasts().iter().map(|t| t.message.clone()).collect()
}

// ---- Modes ----------------------------------------------------------------------------

#[test]
fn modes_follow_focus() {
    let mut h = AppHarness::new(Config::default());
    assert_eq!(h.app().mode(), Mode::Normal);
    h.app_mut().focus_session(SessionId(3));
    assert_eq!(h.app().mode(), Mode::Terminal);
    h.keys("ctrl-\\ [");
    assert_eq!(h.app().mode(), Mode::Copy);
    assert!(
        sent(h.effects()).is_empty(),
        "copy mode keys never reach the session"
    );
    h.keys("j q");
    assert_eq!(h.app().mode(), Mode::Terminal);
    h.app_mut()
        .push_dialog(DialogKind::HostForm(HostFormDialog::blank()));
    assert_eq!(h.app().mode(), Mode::Insert);
}

// ---- T-05 … T-15 Leader state machine ----------------------------------------------------

#[test]
fn t05_terminal_keys_go_to_the_session_and_the_leader_does_not() {
    let mut h = terminal(Config::default());
    h.keys("a");
    assert_eq!(
        h.take_effects(),
        vec![Effect::SendToSession {
            id: SessionId(1),
            input: SessionInput::Key(c("a")),
        }]
    );
    assert_eq!(
        sent_bytes(&[Effect::SendToSession {
            id: SessionId(1),
            input: SessionInput::Key(c("a")),
        }]),
        b"a"
    );
    h.keys("ctrl-\\");
    assert!(sent(h.effects()).is_empty());
    assert!(matches!(h.app().key_state(), KeyState::Pending(_)));
}

// T-06 / K-04
#[test]
fn t06_double_leader_sends_the_literal_leader() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\ ctrl-\\");
    assert_eq!(sent_bytes(&h.take_effects()), vec![0x1C]);
    assert_eq!(h.app().key_state(), &KeyState::Idle);

    let mut h = terminal(with_leader("ctrl-g"));
    h.keys("ctrl-g ctrl-g");
    assert_eq!(sent_bytes(&h.take_effects()), vec![0x07]);

    // In Normal mode there is no session: nothing happens.
    let mut h = AppHarness::new(Config::default());
    h.keys("ctrl-\\ ctrl-\\");
    assert!(sent(h.effects()).is_empty());
    assert_eq!(h.app().key_state(), &KeyState::Idle);
}

#[test]
fn t07_leader_dash_splits_without_sending_bytes() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\ -");
    assert_eq!(h.app().last_action(), Some(ActionName::SplitHorizontal));
    assert!(sent(h.effects()).is_empty());
}

#[test]
fn t08_leader_times_out() {
    // The timeout is suspended while which-key shows (T-09), so test it without the popup
    // and with a popup delay longer than the timeout.
    let mut no_popup = Config::default();
    no_popup.ui.show_which_key = false;
    let mut slow_popup = Config::default();
    slow_popup.ui.which_key_delay_ms = 2_000;
    for cfg in [no_popup, slow_popup] {
        let mut h = terminal(cfg);
        h.keys("ctrl-\\");
        h.advance(1_499);
        assert!(matches!(h.app().key_state(), KeyState::Pending(_)));
        h.advance(1);
        assert_eq!(h.app().key_state(), &KeyState::Idle);
        assert!(!h.app().which_key_visible());
        h.take_effects();
        h.keys("a");
        assert_eq!(sent(h.effects()), vec![SessionInput::Key(c("a"))]);
        h.advance(5_000);
        assert!(
            !h.app().which_key_visible(),
            "stale timer must not show the popup"
        );
    }
}

#[test]
fn t09_which_key_popup() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\");
    h.advance(399);
    assert!(!h.app().which_key_visible());
    h.advance(1);
    assert!(h.app().which_key_visible());
    insta::assert_snapshot!("which_key_80x24", h.render(80, 24));
    h.advance(5_000);
    assert!(
        h.app().which_key_visible(),
        "timeout suspended while visible"
    );
    h.keys("p");
    assert_eq!(h.app().last_action(), Some(ActionName::Palette));
    assert!(!h.app().which_key_visible());
    assert_eq!(h.app().key_state(), &KeyState::Idle);
    assert!(sent(h.effects()).is_empty());
}

#[test]
fn which_key_renders_at_every_size() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\");
    h.advance(400);
    for (w, ht) in [
        (0, 0),
        (1, 1),
        (5, 3),
        (20, 6),
        (40, 12),
        (120, 40),
        (300, 100),
    ] {
        assert_eq!(h.render(w, ht).lines().count(), usize::from(ht));
    }
}

#[test]
fn t10_no_popup_when_disabled() {
    let mut cfg = Config::default();
    cfg.ui.show_which_key = false;
    let mut h = terminal(cfg);
    h.keys("ctrl-\\");
    h.advance(10_000);
    assert!(!h.app().which_key_visible());
    assert!(!h.effects().iter().any(|e| matches!(
        e,
        Effect::ScheduleTimer {
            kind: crate::app::TimerKind::WhichKey,
            ..
        }
    )));
}

#[test]
fn t11_unbound_after_leader_toasts_and_discards() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\ y");
    assert!(sent(h.effects()).is_empty());
    assert_eq!(toasts(&h), vec!["No binding for ctrl-\\ y".to_owned()]);
    assert_eq!(h.app().key_state(), &KeyState::Idle);
}

#[test]
fn t12_escape_cancels() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-\\ esc");
    assert_eq!(h.app().key_state(), &KeyState::Idle);
    assert_eq!(h.app().last_action(), None);
    assert!(sent(h.effects()).is_empty());
    assert!(toasts(&h).is_empty());
}

#[test]
fn t13_q_quits_only_in_normal_mode() {
    let mut h = AppHarness::new(Config::default());
    h.keys("q");
    assert_eq!(h.effects(), &[Effect::Quit { code: 0 }]);

    let mut h = terminal(Config::default());
    h.keys("q");
    assert_eq!(sent_bytes(h.effects()), b"q");
    // The leader's `q` still quits (with confirmation: a session is open).
    h.take_effects();
    h.keys("ctrl-\\ q");
    assert_eq!(h.app().dialogs()[0].kind, DialogKind::ConfirmQuit);
}

#[test]
fn t14_ctrl_c_reaches_the_session() {
    let mut h = terminal(Config::default());
    h.keys("ctrl-c ctrl-d ctrl-z ctrl-h");
    assert_eq!(sent_bytes(h.effects()), vec![0x03, 0x04, 0x1A, 0x08]);
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::Quit { .. } | Effect::Suspend))
    );
}

#[test]
fn t15_leader_works_in_insert_mode() {
    let mut h = AppHarness::new(Config::default());
    h.app_mut()
        .push_dialog(DialogKind::HostForm(HostFormDialog::blank()));
    assert_eq!(h.app().mode(), Mode::Insert);
    h.keys("ctrl-\\");
    h.advance(400);
    assert!(h.app().which_key_visible());
    h.keys("esc w e b");
    let DialogKind::HostForm(d) = &h.app().dialogs()[0].kind else {
        panic!("form closed");
    };
    assert_eq!(
        d.form
            .field("label")
            .map(crate::widgets::form::Field::value),
        Some(crate::widgets::form::FieldValue::Text("web".into()))
    );
    // Esc without a pending leader leaves the form (after "Discard changes?").
    h.keys("esc d");
    assert!(h.app().dialogs().is_empty());
}

#[test]
fn modal_dialogs_get_every_key_including_the_leader() {
    let mut h = AppHarness::new(Config::default()).with_sessions(1);
    h.keys("q");
    assert_eq!(h.app().dialogs()[0].kind, DialogKind::ConfirmQuit);
    h.keys("ctrl-\\");
    assert_eq!(h.app().key_state(), &KeyState::Idle);
    h.keys("n");
    assert!(h.app().dialogs().is_empty());
}

#[test]
fn normal_multi_key_sequences() {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().seed_three_hosts();
    h.app_mut()
        .keymap
        .bind_seq(Table::Normal, vec![c("g"), c("g")], ActionName::Help);
    h.keys("g");
    assert!(matches!(h.app().key_state(), KeyState::Pending(_)));
    h.keys("g");
    assert_eq!(h.app().last_action(), Some(ActionName::Help));
    h.keys("esc");
    // A broken sequence hands the new key to normal handling (`j` moves the list).
    h.keys("g j");
    assert_eq!(h.app().views().hosts.list.cursor(), 1);
    // Timeout with nothing bound to `g` alone: back to Idle.
    h.keys("g");
    h.advance(1_000);
    assert_eq!(h.app().key_state(), &KeyState::Idle);
}

// ---- T-16 … T-19 Config overrides --------------------------------------------------------

#[test]
fn t16_overrides_merge() {
    let cfg = from_toml("[keys.terminal]\nv = \"split_vertical\"\n");
    let mut h = terminal(cfg);
    h.keys("ctrl-\\ v");
    assert_eq!(h.app().last_action(), Some(ActionName::SplitVertical));
    h.keys("ctrl-\\ -");
    assert_eq!(h.app().last_action(), Some(ActionName::SplitHorizontal));
    h.keys("ctrl-\\ b");
    assert_eq!(h.app().last_action(), Some(ActionName::ToggleBroadcast));
    h.keys("ctrl-\\ |");
    assert_eq!(h.app().last_action(), Some(ActionName::SplitVertical));
    assert!(sent(h.effects()).is_empty());
}

#[test]
fn t17_none_unbinds() {
    let cfg = from_toml("[keys.terminal]\n\"-\" = \"none\"\n");
    let mut h = terminal(cfg);
    h.keys("ctrl-\\ -");
    assert_eq!(h.app().last_action(), None);
    assert_eq!(toasts(&h), vec!["No binding for ctrl-\\ -".to_owned()]);
}

#[test]
fn t18_leader_hot_reload() {
    let mut h = terminal(Config::default());
    h.send(UiEvent::Config(ConfigEvent::Reloaded {
        config: Arc::new(with_leader("ctrl-g")),
        warnings: Vec::new(),
    }));
    h.take_effects();
    h.keys("ctrl-g ctrl-g");
    assert_eq!(sent_bytes(&h.take_effects()), vec![0x07]);
    h.keys("ctrl-\\");
    assert_eq!(sent_bytes(&h.take_effects()), vec![0x1C]);
    h.keys("ctrl-g -");
    assert_eq!(h.app().last_action(), Some(ActionName::SplitHorizontal));
}

#[test]
fn t19_binding_the_leader_after_the_leader_is_an_error() {
    let out = Config::from_toml_str(
        "[keys.terminal]\n\"ctrl-\\\\\" = \"palette\"\n",
        &validators(),
    );
    assert!(!out.is_ok());
    assert!(
        out.errors
            .iter()
            .any(|e| e.path.starts_with("keys.terminal") && e.message.contains("leader")),
        "{:?}",
        out.errors
    );
    // Legacy spelling of the same chord is caught too.
    let out = Config::from_toml_str("[keys.terminal]\n\"ctrl-4\" = \"palette\"\n", &validators());
    assert!(!out.is_ok(), "ctrl-4 is ctrl-\\");
    // Other problems: unknown action, bad chord.
    let out = Config::from_toml_str("[keys.normal]\n\"ctrl-\" = \"nope\"\n", &validators());
    assert_eq!(out.errors.len(), 2, "{:?}", out.errors);
}

// ---- T-23 … T-27 Pass-through audit -----------------------------------------------------

fn raw_code() -> impl Strategy<Value = KeyCode> {
    prop_oneof![
        any::<char>().prop_map(KeyCode::Char),
        (0u8..0x80).prop_map(|b| KeyCode::Char(char::from(b))),
        (0u8..=30).prop_map(KeyCode::F),
        prop::sample::select(vec![
            KeyCode::Backspace,
            KeyCode::Enter,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Delete,
            KeyCode::Insert,
            KeyCode::Null,
            KeyCode::Esc,
            KeyCode::CapsLock,
            KeyCode::ScrollLock,
            KeyCode::NumLock,
            KeyCode::PrintScreen,
            KeyCode::Pause,
            KeyCode::Menu,
            KeyCode::KeypadBegin,
            KeyCode::Media(MediaKeyCode::PlayPause),
            KeyCode::Modifier(ModifierKeyCode::LeftShift),
        ]),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // T-23 / K-01: every chord except the leader → exactly one SendToSession(Key(chord)).
    #[test]
    fn t23_k01_pass_through(code in raw_code(), bits in 0u8..64, repeat in any::<bool>()) {
        let modifiers = KeyModifiers::from_bits_truncate(bits);
        let ev = KeyEvent {
            code,
            modifiers,
            kind: if repeat { KeyEventKind::Repeat } else { KeyEventKind::Press },
            state: KeyEventState::NONE,
        };
        let chord = KeyChord::from_key_event(&ev);
        for leader in ["ctrl-\\", "ctrl-g", "ctrl-a", "ctrl-]"] {
            if chord == c(leader) {
                continue;
            }
            let mut h = terminal(with_leader(leader));
            h.send(UiEvent::Input(InputEvent::Key(ev)));
            prop_assert_eq!(
                h.effects(),
                &[Effect::SendToSession { id: SessionId(1), input: SessionInput::Key(chord) }],
                "leader {}, key {:?}", leader, ev
            );
        }
    }
}

// T-24 / K-02: the explicit must-pass list.
#[test]
fn t24_k02_must_pass_list() {
    let mut list: Vec<String> = ('a'..='z').map(|l| format!("ctrl-{l}")).collect();
    list.extend(
        [
            "ctrl-space",
            "ctrl-[",
            "ctrl-]",
            "ctrl-^",
            "ctrl-_",
            "esc",
            "alt-b",
            "alt-f",
            "alt-d",
            "alt-.",
            "tab",
            "shift-tab",
            "home",
            "end",
            "pageup",
            "pagedown",
            "insert",
            "delete",
            "enter",
            "backspace",
            "q",
        ]
        .map(str::to_owned),
    );
    list.extend((1..=12).map(|n| format!("f{n}")));
    for arrow in ["up", "down", "left", "right"] {
        for m in ["", "ctrl-", "alt-", "shift-"] {
            list.push(format!("{m}{arrow}"));
        }
    }
    let mut h = terminal(Config::default());
    for s in &list {
        let chord = c(s);
        h.keys(s);
        let effects = h.take_effects();
        assert_eq!(sent(&effects), vec![SessionInput::Key(chord)], "{s}");
        assert_eq!(effects.len(), 1, "{s}");
        // M1-11: byte-exact through the real encoder.
        assert_eq!(sent_bytes(&effects), k02_bytes(s), "{s}");
    }
    // Also the legacy report of ctrl-] (`Char('5')+CONTROL`) reaches the session as ctrl-].
    h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
        KeyCode::Char('5'),
        KeyModifiers::CONTROL,
    ))));
    assert_eq!(sent_bytes(&h.take_effects()), vec![0x1D]);
}

// M1-11
/// K-02's expected bytes (the M1-11 table, default modes).
fn k02_bytes(s: &str) -> Vec<u8> {
    if let Some(l) = s.strip_prefix("ctrl-")
        && let [b @ b'a'..=b'z'] = l.as_bytes()
    {
        return vec![b - b'a' + 1];
    }
    for (name, fin) in [("up", 'A'), ("down", 'B'), ("right", 'C'), ("left", 'D')] {
        for (m, param) in [
            ("", ""),
            ("ctrl-", "1;5"),
            ("alt-", "1;3"),
            ("shift-", "1;2"),
        ] {
            if s == format!("{m}{name}") {
                return format!("\x1b[{param}{fin}").into_bytes();
            }
        }
    }
    if let Some(n) = s.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
        return match n {
            1..=4 => vec![0x1b, b'O', b'P' + n - 1],
            5 => b"\x1b[15~".to_vec(),
            6..=10 => format!("\x1b[{}~", n + 11).into_bytes(),
            _ => format!("\x1b[{}~", n + 12).into_bytes(),
        };
    }
    let bytes: &[u8] = match s {
        "ctrl-space" => b"\x00",
        "ctrl-[" | "esc" => b"\x1b",
        "ctrl-]" => b"\x1d",
        "ctrl-^" => b"\x1e",
        "ctrl-_" => b"\x1f",
        "alt-b" => b"\x1bb",
        "alt-f" => b"\x1bf",
        "alt-d" => b"\x1bd",
        "alt-." => b"\x1b.",
        "tab" => b"\t",
        "shift-tab" => b"\x1b[Z",
        "home" => b"\x1b[H",
        "end" => b"\x1b[F",
        "pageup" => b"\x1b[5~",
        "pagedown" => b"\x1b[6~",
        "insert" => b"\x1b[2~",
        "delete" => b"\x1b[3~",
        "enter" => b"\r",
        "backspace" => b"\x7f",
        "q" => b"q",
        other => panic!("not in K-02: {other}"),
    };
    bytes.to_vec()
}

// K-05: crossterm's report of ctrl-\ is the leader.
#[test]
fn k05_legacy_leader_report_is_the_leader() {
    for code in [KeyCode::Char('4'), KeyCode::Char('\\')] {
        let mut h = terminal(Config::default());
        h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
            code,
            KeyModifiers::CONTROL,
        ))));
        assert!(matches!(h.app().key_state(), KeyState::Pending(_)));
    }
    let mut h = terminal(Config::default());
    h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
        KeyCode::Char('\x1c'),
        KeyModifiers::NONE,
    ))));
    assert!(matches!(h.app().key_state(), KeyState::Pending(_)));
}

// K-06 (partial): a pane whose session is gone swallows plain keys; M1-16 adds Enter.
#[test]
fn k06_dead_pane_swallows_keys() {
    let mut h = AppHarness::new(Config::default()).with_live_session();
    h.app_mut().tabs.sessions.clear();
    h.keys("c d enter q");
    assert_eq!(h.effects(), &[]);
}

// T-25 / K-03: no key twice in a table.
#[test]
fn t25_k03_no_duplicate_bindings() {
    for table in [
        super::keymap::AFTER_LEADER_DEFAULTS,
        super::keymap::NORMAL_DEFAULTS,
    ] {
        let mut seen = std::collections::HashSet::new();
        for (keys, action) in table {
            let seq = KeyChord::parse_sequence(keys).unwrap_or_else(|e| panic!("{e}"));
            assert!(seen.insert(seq), "{keys} → {action} is bound twice");
        }
    }
    // The leader itself is never in the after-leader table.
    let km = Keymap::default();
    assert_eq!(km.lookup_after_leader(&km.leader()), None);
    // Two spellings of one key in a config table are an error.
    let out = Config::from_toml_str(
        "[keys.terminal]\n\"L\" = \"zoom_pane\"\n\"shift-l\" = \"palette\"\n",
        &validators(),
    );
    assert!(
        out.errors.iter().any(|e| e.message.contains("same key")),
        "{:?}",
        out.errors
    );
}

#[test]
fn t26_leader_validation() {
    let check = |s: &str| validate::check_leader(&c(s));
    for bad in [
        "ctrl-c", "ctrl-d", "ctrl-z", "ctrl-m", "enter", "ctrl-i", "tab", "ctrl-[", "esc", "g",
        "f5",
    ] {
        assert!(matches!(check(bad), LeaderCheck::Reject(_)), "{bad}");
    }
    let LeaderCheck::Warn(msg) = check("ctrl-b") else {
        panic!("ctrl-b must warn");
    };
    assert!(msg.contains("tmux"), "{msg}");
    for warn in [
        "ctrl-a", "ctrl-e", "ctrl-k", "ctrl-r", "ctrl-u", "ctrl-w", "ctrl-l",
    ] {
        assert!(matches!(check(warn), LeaderCheck::Warn(_)), "{warn}");
    }
    for ok in [
        "ctrl-\\",
        "ctrl-g",
        "ctrl-]",
        "ctrl-q",
        "alt-space",
        "ctrl-alt-c",
    ] {
        assert_eq!(check(ok), LeaderCheck::Ok, "{ok}");
    }
    // Through config validation: rejected → error; warning → accepted with a warning.
    let out = Config::from_toml_str("[general]\nleader = \"ctrl-c\"\n", &validators());
    assert!(!out.is_ok());
    let out = Config::from_toml_str("[general]\nleader = \"ctrl-b\"\n", &validators());
    assert!(out.is_ok());
    assert!(
        out.warnings
            .iter()
            .any(|w| w.severity == Severity::Warning && w.message.contains("tmux"))
    );
}

#[test]
fn t27_first_run_leader_notice_once() {
    let mut h = AppHarness::new(Config::default());
    h.send(UiEvent::Meta(MetaFlags {
        seen_leader_notice: false,
    }));
    assert_eq!(h.app().dialogs()[0].kind, DialogKind::LeaderNotice);
    assert_eq!(
        h.take_effects(),
        vec![Effect::SetMetaFlag(MetaFlag::SeenLeaderNotice)]
    );
    insta::assert_snapshot!("leader_notice_80x24", h.render(80, 24));
    h.keys("enter");
    assert!(h.app().dialogs().is_empty());
    h.send(UiEvent::Meta(MetaFlags {
        seen_leader_notice: false,
    }));
    assert!(h.app().dialogs().is_empty(), "never twice in one run");

    let mut h = AppHarness::new(Config::default());
    h.send(UiEvent::Meta(MetaFlags {
        seen_leader_notice: true,
    }));
    assert!(h.app().dialogs().is_empty());
    assert_eq!(h.effects(), &[]);
}

// ---- T-20 … T-22 Dump, docs, registry ---------------------------------------------------

#[test]
fn t20_dump_snapshots() {
    insta::assert_snapshot!("dump_text_default", dump::dump(&Config::default(), false));
    insta::assert_snapshot!("dump_json_default", dump::dump(&Config::default(), true));
    let cfg = from_toml(
        "[general]\nleader = \"ctrl-g\"\n[keys.terminal]\nv = \"split_vertical\"\n\"-\" = \"none\"\n[keys.normal]\n\"ctrl-p\" = \"palette\"\n",
    );
    insta::assert_snapshot!("dump_text_overrides", dump::dump(&cfg, false));
}

#[test]
fn effective_rows_mark_sources() {
    let cfg = from_toml("[keys.terminal]\nv = \"split_vertical\"\n");
    let rows = Keymap::effective(&cfg);
    let v = rows
        .iter()
        .find(|r| r.keys == "ctrl-\\ v")
        .unwrap_or_else(|| panic!("no v"));
    assert_eq!(v.action, ActionName::SplitVertical);
    assert_eq!(v.source, super::Source::Config);
    let p = rows
        .iter()
        .find(|r| r.keys == "ctrl-\\ p")
        .unwrap_or_else(|| panic!("no p"));
    assert_eq!(p.source, super::Source::Default);
}

#[test]
fn t22_every_action_is_described_and_in_which_key() {
    let groups = whichkey::entries(&Keymap::default());
    for info in registry() {
        assert!(!info.description.trim().is_empty(), "{}", info.name);
        // M3-01: unbound by default (palette only), so not in which-key.
        if crate::keymap::action::UNBOUND_BY_DEFAULT.contains(&info.name) {
            assert!(
                !groups
                    .iter()
                    .any(|(_, es)| es.iter().any(|e| e.actions.contains(&info.name))),
                "{} is bound by default",
                info.name
            );
            continue;
        }
        assert!(
            groups.iter().any(
                |(g, es)| *g == info.group && es.iter().any(|e| e.actions.contains(&info.name))
            ),
            "{} is missing from which-key",
            info.name
        );
    }
}

#[test]
fn validator_accepts_none_and_known_actions_only() {
    use sverb_core::config::KeymapValidator;
    let v = validate::TuiKeymapValidator;
    assert!(v.action_exists("terminal", "none"));
    assert!(v.action_exists("normal", "go_to_tab_3"));
    assert!(!v.action_exists("terminal", "render"));
    assert_eq!(v.parse_chord("shift-l"), Ok("L".to_owned()));
    assert_eq!(v.parse_chord("g  g"), Ok("g g".to_owned()));
    assert!(v.parse_chord("ctrl-").is_err());
    // M3-04: `[keys.copy]` takes copy-mode actions only.
    assert_eq!(
        v.modes(),
        vec![
            "terminal".to_owned(),
            "normal".to_owned(),
            "copy".to_owned()
        ]
    );
    assert!(v.action_exists("copy", "yank"));
    assert!(v.action_exists("copy", "none"));
    assert!(!v.action_exists("copy", "quit"));
}
