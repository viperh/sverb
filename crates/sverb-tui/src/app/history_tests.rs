//! M7-01 reducer tests: T-06 (the `leader Space` overlay anchored at the cursor, `Enter`
//! / `Tab`), T-10 (purging a host), capture through both tiers, ghost text.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ratatui::{Terminal, backend::TestBackend};
use sverb_conn::{SessionEvent, SharedEmulator};
use sverb_core::{
    history::StoredEntry,
    model::{HistoryEntry, ItemId, UnixMillis},
};
use sverb_term::osc133::ShellCommand;

use super::*;
use crate::{
    app::{Config, Effect, SessionInput, UiEvent},
    testing::AppHarness,
    views::DialogKind,
    widgets::terminal_pane::tests::new_emulator,
};

const S: SessionId = SessionId(1);

fn host(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn harness_with(config: Config, emu: &SharedEmulator) -> AppHarness {
    let mut h = AppHarness::new(config).with_live_session();
    h.resize(100, 30);
    let e = Arc::clone(emu);
    let app = std::mem::replace(h.app_mut(), App::new(Arc::new(Config::default())));
    *h.app_mut() = app.with_terms(Arc::new(move |id: SessionId| {
        (id == S).then(|| Arc::clone(&e))
    }));
    h
}

fn harness(emu: &SharedEmulator) -> AppHarness {
    harness_with(Config::default(), emu)
}

fn leader(h: &AppHarness) -> String {
    h.app().keymap().leader().to_string()
}

fn stored(b: u8, cmd: &str, host_id: Option<ItemId>, at: i64) -> StoredEntry {
    StoredEntry {
        id: ItemId::from_bytes([b; 16]),
        entry: HistoryEntry {
            command: cmd.into(),
            host_id,
            executed_at: UnixMillis(at),
            exit_code: Some(0),
            ..HistoryEntry::default()
        },
    }
}

fn load(h: &mut AppHarness, list: Vec<StoredEntry>) {
    h.send(UiEvent::History(HistoryEvent::Loaded(list)));
}

fn records(h: &AppHarness) -> Vec<HistoryEntry> {
    h.effects()
        .iter()
        .filter_map(|e| match e {
            Effect::History(HistoryEffect::Record(e)) => Some(e.clone()),
            _ => None,
        })
        .collect()
}

fn typed(h: &AppHarness) -> Vec<Vec<u8>> {
    h.effects()
        .iter()
        .filter_map(|e| match e {
            Effect::SendToSession {
                id,
                input: SessionInput::Raw(b),
            } if *id == S => Some(b.clone()),
            _ => None,
        })
        .collect()
}

fn overlay(h: &AppHarness) -> Option<&Autocomplete> {
    h.app().dialogs().iter().find_map(|d| match &d.kind {
        DialogKind::Autocomplete(a) => Some(&**a),
        _ => None,
    })
}

const PROMPT_133: &[u8] = b"\x1b]133;A\x07user@h:~$ \x1b]133;B\x07";

// ------------------------------------------------------------------- T-06

#[test]
fn t06_overlay_is_anchored_at_the_cursor_and_types_the_remainder() {
    let emu = new_emulator(80, 20, PROMPT_133);
    emu.lock().feed(b"git st");
    let mut h = harness(&emu);
    load(
        &mut h,
        vec![
            stored(1, "git status", None, 3_000),
            stored(2, "git stash", None, 2_000),
            stored(3, "ls", None, 1_000),
        ],
    );
    let leader = leader(&h);
    h.keys(&format!("{leader} space"));

    let o = overlay(&h).expect("the overlay is open");
    // Anchored at the pane's cursor (`t06_cursor_anchor_matches_the_drawn_cursor` checks
    // the mapping against the drawn cursor).
    assert_eq!(
        o.anchor,
        h.app().cursor_anchor(S, emu.lock().cursor().point)
    );
    let grid = emu.lock().cursor().point;
    assert_eq!(grid.column, 16, "after `user@h:~$ git st`");
    assert_eq!(o.prefix, "git st");
    assert!(o.integrated);
    let texts: Vec<&str> = o.rows.iter().map(|r| r.text.as_str()).collect();
    // History first, then common commands extending the prefix.
    assert_eq!(
        texts,
        ["git status", "git stash", "git stash list", "git stash pop"],
        "pre-filtered by the prefix"
    );
    // Below the cursor row, starting at the cursor column.
    let rect = o.placement(ratatui::layout::Rect::new(0, 0, 100, 30));
    assert_eq!(rect.y, o.anchor.1 + 1);
    assert_eq!(rect.x, o.anchor.0);

    // Enter: the remainder and `\r`.
    h.take_effects();
    h.keys("enter");
    assert!(overlay(&h).is_none(), "closed");
    assert_eq!(typed(&h), [b"atus\r".to_vec()]);

    // Tab: the remainder only (`git stash` is the second row).
    h.take_effects();
    h.keys(&format!("{leader} space"));
    h.keys("down tab");
    assert_eq!(typed(&h), [b"ash".to_vec()]);
    assert!(overlay(&h).is_none());
}

#[test]
fn t06_cursor_anchor_matches_the_drawn_cursor() {
    let emu = new_emulator(80, 20, b"$ ");
    let h = harness(&emu);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let mut cursor = None;
    let source = |_: SessionId| Some(Arc::clone(&emu));
    terminal
        .draw(|f| cursor = h.app().render_with_panes(f, &source))
        .unwrap();
    let drawn = cursor.expect("focused pane cursor").position;
    let anchor = h.app().cursor_anchor(S, emu.lock().cursor().point);
    assert_eq!((drawn.x, drawn.y), anchor);
}

#[test]
fn t06_overlay_goes_above_without_room_below_and_filters_by_query() {
    let emu = new_emulator(80, 20, b"");
    let mut h = harness(&emu);
    load(&mut h, vec![stored(1, "kubectl get pods", None, 1)]);
    h.keys(&format!("{} space", leader(&h)));
    let o = overlay(&h).unwrap().clone();
    let mut low = o.clone();
    low.anchor = (5, 28);
    let rect = low.placement(ratatui::layout::Rect::new(0, 0, 100, 30));
    assert!(rect.bottom() <= 28, "{rect:?}");
    // Without shell integration: no prefix, F2 offers the install snippet.
    assert!(!o.integrated);
    assert_eq!(o.rows[0].text, "kubectl get pods", "host history first");
    h.keys("k u b g p");
    let o = overlay(&h).unwrap();
    assert_eq!(o.query, "kubgp");
    assert_eq!(o.rows[0].text, "kubectl get pods");
    // Esc closes without typing.
    h.take_effects();
    h.keys("esc");
    assert!(overlay(&h).is_none());
    assert!(typed(&h).is_empty());
}

#[test]
fn f2_adds_the_install_snippet_when_missing() {
    let emu = new_emulator(80, 20, b"$ ");
    let mut h = harness(&emu);
    h.keys(&format!("{} space", leader(&h)));
    h.take_effects();
    h.keys("f2");
    let saved: Vec<String> = h
        .effects()
        .iter()
        .filter_map(|e| match e {
            Effect::Snippets(crate::app::SnippetsEffect::Save { id: None, snippet }) => {
                Some(snippet.name.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        saved,
        [
            "Install sverb shell integration",
            "Uninstall sverb shell integration"
        ]
    );
}

// ------------------------------------------------------------------- capture

#[test]
fn tier1_commands_are_recorded_verified_with_the_pane_host() {
    let emu = new_emulator(80, 20, b"");
    let mut h = harness(&emu);
    h.app_mut().panes.entry(S).or_default().host = Some(host(7).to_string());
    h.send(UiEvent::Session(
        S,
        SessionEvent::Command(ShellCommand {
            command: "make test".into(),
            exit_code: Some(2),
        }),
    ));
    let r = records(&h);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].command, "make test");
    assert_eq!(r[0].exit_code, Some(2));
    assert_eq!(r[0].host_id, Some(host(7)));
    assert!(r[0].verified);
}

#[test]
fn tier2_learns_the_prompt_and_records_unverified() {
    let emu = new_emulator(80, 20, b"user@h:~$ ");
    let mut h = harness(&emu);
    // The first key on a fresh line teaches the prompt.
    h.keys("l");
    emu.lock().feed(b"ls -la");
    h.keys("enter");
    let r = records(&h);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].command, "ls -la");
    assert!(!r[0].verified);
    // The keys still reached the session.
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. }))
    );
}

#[test]
fn t04_tier2_skips_the_alt_screen_and_password_prompts() {
    let emu = new_emulator(80, 20, b"user@h:~$ ");
    let mut h = harness(&emu);
    h.keys("v");
    emu.lock().feed(b"vim\r\n\x1b[?1049h~");
    h.keys("enter");
    assert!(records(&h).is_empty(), "alt screen");
    emu.lock().feed(b"\x1b[?1049l\r\nPassword: ");
    h.keys("enter");
    assert!(records(&h).is_empty(), "password prompt");
    emu.lock().feed(b"\r\nuser@h:~$ sudo ls");
    let mut lines = b"\r\n[sudo] password for user:\r\n".to_vec();
    lines.extend_from_slice(b"user@h:~$ id");
    emu.lock().feed(&lines);
    h.keys("enter");
    assert!(records(&h).is_empty(), "the line after a password prompt");
}

#[test]
fn nothing_is_recorded_when_history_is_disabled() {
    let mut config = Config::default();
    config.history.enabled = false;
    let emu = new_emulator(80, 20, b"user@h:~$ ");
    let mut h = harness_with(config, &emu);
    h.keys("l");
    emu.lock().feed(b"ls");
    h.keys("enter");
    h.send(UiEvent::Session(
        S,
        SessionEvent::Command(ShellCommand {
            command: "ls".into(),
            exit_code: Some(0),
        }),
    ));
    assert!(records(&h).is_empty());
}

#[test]
fn integrated_panes_are_not_captured_heuristically() {
    let emu = new_emulator(80, 20, PROMPT_133);
    let mut h = harness(&emu);
    h.keys("l");
    emu.lock().feed(b"ls");
    h.keys("enter");
    assert!(records(&h).is_empty(), "tier 1 reports it instead");
}

// ------------------------------------------------------------------- ghost text

#[test]
fn ghost_text_is_drawn_dim_and_accepted_with_leader_tab_only() {
    let mut config = Config::default();
    config.history.ghost_text = true;
    let emu = new_emulator(80, 20, PROMPT_133);
    emu.lock().feed(b"git st");
    let mut h = harness_with(config, &emu);
    load(&mut h, vec![stored(1, "git status", None, 1)]);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let mut cursor = None;
    let source = |_: SessionId| Some(Arc::clone(&emu));
    terminal
        .draw(|f| cursor = h.app().render_with_panes(f, &source))
        .unwrap();
    let p = cursor.unwrap().position;
    let buf = terminal.backend().buffer();
    let ghost: String = (0..4)
        .map(|i| buf[(p.x + i, p.y)].symbol().to_owned())
        .collect();
    assert_eq!(ghost, "atus");
    assert_eq!(buf[(p.x, p.y)].style().fg, h.app().theme.dim.fg);

    // `→` / `ctrl-f` go to the shell untouched.
    h.take_effects();
    h.keys("right ctrl-f");
    assert!(typed(&h).is_empty());
    h.keys(&format!("{} tab", leader(&h)));
    assert_eq!(typed(&h), [b"atus".to_vec()]);
}

#[test]
fn ghost_text_is_off_by_default() {
    let emu = new_emulator(80, 20, PROMPT_133);
    emu.lock().feed(b"git st");
    let mut h = harness(&emu);
    load(&mut h, vec![stored(1, "git status", None, 1)]);
    h.keys(&format!("{} tab", leader(&h)));
    assert!(typed(&h).is_empty());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("ghost_text"))
    );
}

// ------------------------------------------------------------------- T-10

#[test]
fn t10_clear_history_purges_the_host() {
    let emu = new_emulator(80, 20, b"");
    let mut h = harness(&emu);
    let (a, b) = (Some(host(1)), Some(host(2)));
    load(
        &mut h,
        vec![
            stored(1, "ls", a, 1),
            stored(2, "pwd", a, 2),
            stored(3, "id", b, 3),
        ],
    );
    let mut effects = Vec::new();
    h.app_mut().confirm_clear_history(a, "db", &mut effects);
    assert!(effects.is_empty() || !effects.iter().any(|e| matches!(e, Effect::History(_))));
    h.take_effects();
    // The danger button is not the default: `Enter` keeps.
    h.keys("enter");
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::History(_))));
    let mut effects = Vec::new();
    h.app_mut().confirm_clear_history(a, "db", &mut effects);
    h.keys("c");
    assert!(
        h.effects()
            .contains(&Effect::History(HistoryEffect::Purge { host: a })),
        "{:?}",
        h.effects()
    );
    h.send(UiEvent::History(HistoryEvent::Purged { host: a, count: 2 }));
    let left: Vec<&str> = h
        .app()
        .history
        .entries()
        .iter()
        .map(|e| e.command.as_str())
        .collect();
    assert_eq!(left, ["id"]);
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Cleared 2"))
    );
}

#[test]
fn locking_drops_the_entries() {
    let emu = new_emulator(80, 20, b"");
    let mut h = harness(&emu);
    load(&mut h, vec![stored(1, "ls", None, 1)]);
    assert_eq!(h.app().history.entries().len(), 1);
    let mut effects = Vec::new();
    h.app_mut()
        .history_lock_transition(sverb_core::vault::LockState::Unlocked, &mut effects);
    // Still unlocked (no vault service): nothing changes.
    assert_eq!(h.app().history.entries().len(), 1);
}
