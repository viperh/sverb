//! M2-12 reducer tests: opening (T-01), actions with key hints run like their binding
//! (T-02), availability (T-03), prefixes and hosts (T-04), snippets (T-05), quick
//! connect (T-06), share links (T-07), the recency boost (T-08), snapshots (T-09) and
//! device-local recents (T-10, reducer half; the store half is in `services/palette.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_conn::SessionSpec;
use sverb_core::{
    model::{
        DeviceId, HlcClock, Host, ItemBody, ItemId, ItemKind, RunMode, Snippet, VarDef, VaultId,
    },
    search::{IndexSnapshot, ItemIndex},
};

use super::{SnippetsEvent, palette::recency_boost};
use crate::app::{Config, Effect, InputEvent, Mode, UiEvent};
use crate::keymap::action::ActionName;
use crate::testing::AppHarness;
use crate::views::{
    DialogKind,
    palette::{
        PaletteEffect, PaletteEntry, PaletteEvent, PaletteGroup, PaletteState, PaletteTarget,
    },
    snippets::{RunWhere, SnippetDialogKind},
};

const WEB1: ItemId = ItemId::from_bytes([0x11; 16]);
const WEB2: ItemId = ItemId::from_bytes([0x12; 16]);
const DB: ItemId = ItemId::from_bytes([0x13; 16]);
const DEPLOY: ItemId = ItemId::from_bytes([0x21; 16]);
const UPTIME: ItemId = ItemId::from_bytes([0x22; 16]);

fn deploy_snippet() -> Snippet {
    Snippet {
        name: "deploy web".into(),
        script: "./deploy.sh {{env}}".into(),
        description: None,
        tags: Vec::new(),
        variables: vec![VarDef {
            name: "env".into(),
            default: None,
            secret: false,
        }],
        run_mode: RunMode::PasteAndExecute,
        read_only: false,
    }
}

fn uptime_snippet() -> Snippet {
    Snippet {
        name: "uptime".into(),
        script: "uptime".into(),
        description: None,
        tags: Vec::new(),
        variables: Vec::new(),
        run_mode: RunMode::Paste,
        read_only: false,
    }
}

/// Hosts web-1, web-2, db-1 and the snippets "deploy web", "uptime".
fn index() -> Arc<IndexSnapshot> {
    let mut clock = HlcClock::default();
    let device = DeviceId::from_bytes([1; 16]);
    let vault = VaultId::from_bytes([2; 16]);
    let mut bodies = Vec::new();
    for (id, label, address, user) in [
        (WEB1, "web-1", "10.0.0.1", "deploy"),
        (WEB2, "web-2", "10.0.0.2", ""),
        (DB, "db-1", "10.0.0.3", ""),
    ] {
        let mut body = ItemBody::new(ItemKind::Host, 1);
        Host {
            label: label.into(),
            address: address.into(),
            username: (!user.is_empty()).then(|| user.to_owned()),
            ..Host::default()
        }
        .apply_to(&mut body, &mut clock, device);
        bodies.push((id, body));
    }
    for (id, snippet) in [(DEPLOY, deploy_snippet()), (UPTIME, uptime_snippet())] {
        let mut body = ItemBody::new(ItemKind::Snippet, 1);
        snippet.apply_to(&mut body, &mut clock, device);
        bodies.push((id, body));
    }
    ItemIndex::build(bodies.iter().map(|(id, b)| (*id, vault, b))).snapshot()
}

fn with_items(mut h: AppHarness) -> AppHarness {
    h.send(UiEvent::IndexUpdated(index()));
    h.send(UiEvent::Snippets(SnippetsEvent::Loaded {
        snippets: vec![(DEPLOY, deploy_snippet()), (UPTIME, uptime_snippet())],
        tags: BTreeMap::new(),
    }));
    // No store in these tests: the recents load answers "none".
    h.send(UiEvent::Palette(PaletteEvent::Recents(Vec::new())));
    h.take_effects();
    h
}

fn palette(h: &AppHarness) -> Option<&PaletteState> {
    match h.app().dialogs().last().map(|d| &d.kind) {
        Some(DialogKind::Palette(p)) => Some(p),
        _ => None,
    }
}

fn entries(h: &AppHarness) -> Vec<PaletteEntry> {
    palette(h).expect("palette open").entries.clone()
}

fn key(h: &mut AppHarness, code: KeyCode, mods: KeyModifiers) {
    h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(code, mods))));
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        key(h, KeyCode::Char(c), KeyModifiers::NONE);
    }
}

/// Move the highlight to the first entry whose target is `target`, then `Enter`.
fn pick(h: &mut AppHarness, target: &PaletteTarget, mods: KeyModifiers) {
    let at = entries(h)
        .iter()
        .position(|e| &e.target == target)
        .unwrap_or_else(|| panic!("{target:?} not listed: {:#?}", entries(h)));
    let from = palette(h).unwrap().selected;
    for _ in from..at {
        key(h, KeyCode::Down, KeyModifiers::NONE);
    }
    assert_eq!(
        palette(h).unwrap().current().map(|e| &e.target),
        Some(target)
    );
    key(h, KeyCode::Enter, mods);
}

fn open(h: &mut AppHarness) {
    h.keys("ctrl-\\ p");
    assert!(palette(h).is_some(), "{:?}", h.app().dialogs());
}

/// Effects that matter for "same as the key binding": no timers, no recents.
fn behavior(effects: &[Effect]) -> Vec<Effect> {
    effects
        .iter()
        .filter(|e| {
            !matches!(
                e,
                Effect::ScheduleTimer { .. } | Effect::CancelTimer(_) | Effect::Palette(_)
            )
        })
        .cloned()
        .collect()
}

/// A harness with a local tab (its splits open more local panes).
fn with_local_tab() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.keys("ctrl-\\ t");
    h.send(UiEvent::Palette(PaletteEvent::Recents(Vec::new())));
    h.take_effects();
    assert_eq!(h.app().tabs().list.len(), 1);
    h
}

// T-01
#[test]
fn t01_ctrl_k_in_normal_and_leader_p_in_terminal_open_the_palette() {
    let mut h = AppHarness::new(Config::default());
    assert_eq!(h.app().mode(), Mode::Normal);
    h.keys("ctrl-k");
    assert!(palette(&h).is_some(), "{:?}", h.app().dialogs());
    assert!(
        h.effects()
            .contains(&Effect::Palette(PaletteEffect::LoadRecents))
    );
    // The palette edits text: Insert mode, so `q` types instead of quitting.
    assert_eq!(h.app().mode(), Mode::Insert);
    type_text(&mut h, "q");
    assert_eq!(palette(&h).unwrap().input, "q");
    key(&mut h, KeyCode::Esc, KeyModifiers::NONE);
    assert!(palette(&h).is_none());

    let mut h = AppHarness::new(Config::default()).with_live_session();
    h.send(UiEvent::Palette(PaletteEvent::Recents(Vec::new())));
    assert_eq!(h.app().mode(), Mode::Terminal);
    h.take_effects();
    h.keys("ctrl-\\ p");
    assert!(palette(&h).is_some());
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. })),
        "{:?}",
        h.effects()
    );
    // Recents were loaded already: not asked again.
    assert!(
        !h.effects()
            .contains(&Effect::Palette(PaletteEffect::LoadRecents))
    );
}

// T-01: `ctrl-k` in Terminal mode still belongs to the session.
#[test]
fn t01_ctrl_k_in_terminal_mode_is_passed_through() {
    let mut h = AppHarness::new(Config::default()).with_live_session();
    h.keys("ctrl-k");
    assert!(palette(&h).is_none());
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. }))
    );
}

// T-02
#[test]
fn t02_split_lists_both_splits_with_hints_and_runs_like_the_binding() {
    let mut by_key = with_local_tab();
    by_key.keys("ctrl-\\ -");
    let key_effects = behavior(&by_key.take_effects());
    assert!(
        key_effects
            .iter()
            .any(|e| matches!(e, Effect::OpenSession { .. })),
        "{key_effects:?}"
    );

    let mut h = with_local_tab();
    open(&mut h);
    type_text(&mut h, "split");
    let list = entries(&h);
    let hint = |a: ActionName| {
        list.iter()
            .find(|e| e.target == PaletteTarget::Action(a))
            .and_then(|e| e.hint.clone())
    };
    assert_eq!(hint(ActionName::SplitHorizontal).as_deref(), Some("^\\ -"));
    assert_eq!(hint(ActionName::SplitVertical).as_deref(), Some("^\\ |"));
    assert!(list.iter().take(2).all(|e| matches!(
        e.target,
        PaletteTarget::Action(ActionName::SplitHorizontal | ActionName::SplitVertical)
    )));
    h.take_effects();
    pick(
        &mut h,
        &PaletteTarget::Action(ActionName::SplitHorizontal),
        KeyModifiers::NONE,
    );
    assert!(palette(&h).is_none());
    assert_eq!(behavior(h.effects()), key_effects);
    assert_eq!(h.app().tabs().list, by_key.app().tabs().list);
    assert_eq!(h.app().last_action(), Some(ActionName::SplitHorizontal));
}

// T-03
#[test]
fn t03_unavailable_actions_are_hidden() {
    let h = AppHarness::new(Config::default());
    let app = h.app();
    assert!(!app.action_enabled(ActionName::ZoomPane));
    assert!(
        !app.action_enabled(ActionName::ToggleLogPane),
        "needs --debug"
    );
    assert!(!app.action_enabled(ActionName::GoToTab1));
    assert!(app.action_enabled(ActionName::Help));
    let listed = |app: &crate::app::App, q: &str, a: ActionName| {
        app.palette_entries(q, false)
            .iter()
            .any(|e| e.target == PaletteTarget::Action(a))
    };
    assert!(!listed(app, "zoom", ActionName::ZoomPane));
    assert!(!listed(app, "", ActionName::ZoomPane));
    assert!(listed(app, "", ActionName::Help));

    let mut h = with_local_tab();
    assert!(!h.app().action_enabled(ActionName::ZoomPane), "one pane");
    h.keys("ctrl-\\ -");
    assert_eq!(h.app().active_tab().unwrap().panes.len(), 2);
    assert!(h.app().action_enabled(ActionName::ZoomPane));
    assert!(listed(h.app(), "zoom", ActionName::ZoomPane));
}

// T-04
#[test]
fn t04_at_prefix_lists_hosts_enter_opens_a_tab_ctrl_enter_a_split() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    type_text(&mut h, "@web");
    let list = entries(&h);
    assert_eq!(list.len(), 2, "{list:#?}");
    assert!(list.iter().all(|e| e.group == PaletteGroup::Hosts));
    assert_eq!(list[0].title, "web-1");
    assert_eq!(list[0].detail, "deploy@10.0.0.1");
    h.take_effects();
    pick(&mut h, &PaletteTarget::Host(WEB1), KeyModifiers::NONE);
    let opened: Vec<_> = h
        .effects()
        .iter()
        .filter_map(|e| match e {
            Effect::OpenSession {
                spec: SessionSpec::Ssh(s),
                ..
            } => Some(s.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(opened.len(), 1, "{:?}", h.effects());
    assert_eq!(opened[0].host_id, Some(WEB1));
    assert_eq!(opened[0].host, "10.0.0.1");
    assert_eq!(h.app().tabs().list.len(), 1);

    open(&mut h);
    type_text(&mut h, "@web");
    pick(&mut h, &PaletteTarget::Host(WEB2), KeyModifiers::CONTROL);
    assert_eq!(h.app().tabs().list.len(), 1, "a split, not a tab");
    assert_eq!(h.app().active_tab().unwrap().panes.len(), 2);
}

// T-04: `tab` opens the host's menu; "Run snippet on it" lists snippets for that host.
#[test]
fn host_menu_edit_and_run_snippet_on_host() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    type_text(&mut h, "@db");
    key(&mut h, KeyCode::Tab, KeyModifiers::NONE);
    assert!(palette(&h).unwrap().menu.is_some());
    // Edit: the host form loads the host.
    key(&mut h, KeyCode::Down, KeyModifiers::NONE);
    key(&mut h, KeyCode::Down, KeyModifiers::NONE);
    h.take_effects();
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    assert!(palette(&h).is_none());
    assert!(h.effects().iter().any(|e| matches!(
        e,
        Effect::Vault(crate::app::VaultEffect::Items(
            crate::app::hosts::ItemEffect::LoadHost { item, .. }
        )) if *item == DB
    )));

    open(&mut h);
    type_text(&mut h, "@db");
    key(&mut h, KeyCode::Tab, KeyModifiers::NONE);
    for _ in 0..4 {
        key(&mut h, KeyCode::Down, KeyModifiers::NONE);
    }
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    let p = palette(&h).expect("snippet palette for the host");
    assert_eq!(p.on_host.as_ref().map(|(id, _)| *id), Some(DB));
    assert!(p.entries.iter().all(|e| e.group == PaletteGroup::Snippets));
    type_text(&mut h, "deploy");
    pick(&mut h, &PaletteTarget::Snippet(DEPLOY), KeyModifiers::NONE);
    match h.app().dialogs().last().map(|d| &d.kind) {
        Some(DialogKind::Snippet(d)) => match &d.kind {
            SnippetDialogKind::Vars(form) => {
                assert!(matches!(&form.target, RunWhere::Hosts(hosts) if hosts[0].0 == DB));
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

// T-05
#[test]
fn t05_bang_prefix_lists_snippets_enter_opens_the_variable_form() {
    let mut h = with_items(AppHarness::new(Config::default()).with_live_session());
    open(&mut h);
    type_text(&mut h, "!deploy");
    let list = entries(&h);
    assert_eq!(list.len(), 1, "{list:#?}");
    assert_eq!(list[0].target, PaletteTarget::Snippet(DEPLOY));
    assert_eq!(list[0].group, PaletteGroup::Snippets);
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        matches!(
            h.app().dialogs().last().map(|d| &d.kind),
            Some(DialogKind::Snippet(d)) if matches!(d.kind, SnippetDialogKind::Vars(_))
        ),
        "{:?}",
        h.app().dialogs()
    );
}

// T-04/T-05: `#tag` keeps only hosts and snippets.
#[test]
fn tag_filter_hides_actions_tabs_and_settings() {
    let h = with_items(AppHarness::new(Config::default()));
    let list = h.app().palette_entries("#nope", false);
    assert!(list.is_empty(), "{list:#?}");
    let list = h.app().palette_entries(">help", false);
    assert!(list.iter().all(|e| e.group == PaletteGroup::Actions));
    assert!(!list.is_empty());
}

// T-06
#[test]
fn t06_user_at_host_port_offers_quick_connect_first() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    type_text(&mut h, "root@10.0.0.9:2200");
    let list = entries(&h);
    assert_eq!(list[0].title, "Connect to root@10.0.0.9:2200");
    assert_eq!(list[0].group, PaletteGroup::Special);
    h.take_effects();
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    let spec = h
        .effects()
        .iter()
        .find_map(|e| match e {
            Effect::OpenSession {
                spec: SessionSpec::Ssh(s),
                ..
            } => Some(s.clone()),
            _ => None,
        })
        .expect("a session opens");
    assert_eq!(
        (spec.host.as_str(), spec.port, spec.user.as_deref()),
        ("10.0.0.9", 2200, Some("root"))
    );
    // Plain words are not targets.
    assert!(
        h.app()
            .palette_entries("split", false)
            .iter()
            .all(|e| e.group != PaletteGroup::Special)
    );
}

// T-07
#[test]
fn t07_pasted_share_link_offers_join_first() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    h.send(UiEvent::Input(InputEvent::Paste(
        "sverb://join/abcdef#secret-key\n".into(),
    )));
    let list = entries(&h);
    assert_eq!(list[0].title, "Join shared terminal");
    assert!(
        matches!(&list[0].target, PaletteTarget::Join(l) if l == "sverb://join/abcdef#secret-key")
    );
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    assert!(palette(&h).is_none());
    // M6-03: the pick joins; this link has no valid share id, so it is refused.
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Not a usable share link"))
    );
    let app = h.app();
    let https = app.palette_entries("https://share.example.com/s/x1#k", false);
    assert_eq!(https[0].title, "Join shared terminal");
}

// T-08
#[test]
fn t08_recent_picks_rank_above_equal_scores() {
    let mut h = with_items(AppHarness::new(Config::default()));
    let base = h.app().palette_entries("toggle", false);
    let actions: Vec<&PaletteEntry> = base
        .iter()
        .filter(|e| e.group == PaletteGroup::Actions)
        .collect();
    let (y, x) = actions
        .windows(2)
        .find(|w| w[0].score == w[1].score)
        .map(|w| (w[0].target.clone(), w[1].target.clone()))
        .expect("two equally scored actions");
    let pos = |list: &[PaletteEntry], t: &PaletteTarget| list.iter().position(|e| &e.target == t);
    assert!(pos(&base, &y) < pos(&base, &x));
    for _ in 0..2 {
        open(&mut h);
        type_text(&mut h, "toggle");
        pick(&mut h, &x, KeyModifiers::NONE);
        // Some toggles open a dialog; close it.
        while !h.app().dialogs().is_empty() {
            key(&mut h, KeyCode::Esc, KeyModifiers::NONE);
        }
    }
    let after = h.app().palette_entries("toggle", false);
    assert!(pos(&after, &x) < pos(&after, &y), "{after:#?}");
    // With no query, the picks are listed first, under Recent.
    let empty = h.app().palette_entries("", false);
    assert_eq!(empty[0].target, x);
    assert_eq!(empty[0].group, PaletteGroup::Recent);
    let key = x.recent_key().unwrap();
    assert!(recency_boost(&h.app().palette.recents, &key) > 0);
}

// T-08: the stored recents arrive after picks of this run: both are kept.
#[test]
fn stored_recents_merge_after_this_runs_picks() {
    let mut h = AppHarness::new(Config::default());
    h.keys("ctrl-k");
    type_text(&mut h, ">help");
    key(&mut h, KeyCode::Enter, KeyModifiers::NONE);
    h.take_effects();
    h.send(UiEvent::Palette(PaletteEvent::Recents(vec![
        "action:toggle_sidebar".into(),
    ])));
    assert_eq!(
        h.app().palette.recents,
        ["action:help", "action:toggle_sidebar"]
    );
    assert_eq!(
        h.effects(),
        [Effect::Palette(PaletteEffect::SaveRecents(vec![
            "action:help".into(),
            "action:toggle_sidebar".into()
        ]))]
    );
}

// T-09
#[test]
fn t09_palette_snapshots() {
    let mut h = with_items(AppHarness::new(Config::default()).with_live_session());
    open(&mut h);
    type_text(&mut h, "de");
    let groups: std::collections::BTreeSet<_> = entries(&h).iter().map(|e| e.group).collect();
    assert!(groups.len() >= 3, "mixed results: {groups:?}");
    insta::assert_snapshot!("palette_mixed_80x24", h.render(80, 24));
    insta::assert_snapshot!("palette_mixed_160x48", h.render(160, 48));
}

// T-10 (reducer half)
#[test]
fn t10_picks_go_to_meta_not_to_items() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    type_text(&mut h, "@web-2");
    h.take_effects();
    pick(&mut h, &PaletteTarget::Host(WEB2), KeyModifiers::NONE);
    let saves: Vec<_> = h
        .effects()
        .iter()
        .filter_map(|e| match e {
            Effect::Palette(PaletteEffect::SaveRecents(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(saves, [vec![format!("host:{WEB2}")]]);
    assert!(
        !h.effects().iter().any(|e| matches!(e, Effect::Vault(_))),
        "no item write: {:?}",
        h.effects()
    );
}

// Panes of other tabs are listed and switched to.
#[test]
fn tabs_and_panes_are_listed_and_focused() {
    let mut h = with_local_tab();
    h.keys("ctrl-\\ t");
    assert_eq!(h.app().tabs().list.len(), 2);
    assert_eq!(h.app().tabs().active, 1);
    let first = h.app().tabs().list[0].focused_session();
    open(&mut h);
    type_text(&mut h, "tab 1");
    pick(&mut h, &PaletteTarget::Pane(first), KeyModifiers::NONE);
    assert_eq!(h.app().tabs().active, 0);
    assert_eq!(h.app().focused_session(), Some(first));
}

// Locking closes the palette (it shows host and snippet names).
#[test]
fn lock_closes_the_palette() {
    let mut h = with_items(AppHarness::new(Config::default()));
    open(&mut h);
    let was = h.app().lock_state();
    h.app_mut().vault.lock = sverb_core::vault::LockState::Locked;
    h.app_mut().palette_lock_transition(was);
    assert!(palette(&h).is_none());
}
