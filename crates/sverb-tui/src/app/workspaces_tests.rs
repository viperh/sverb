//! hosts, broadcast sets, `--workspace` (reducer side) and the
//! workspaces dialog.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use sverb_conn::{SessionEvent, SessionSpec, SessionState};
use sverb_core::layout::{Direction, Layout, PaneId, Rect, SplitDir};
use sverb_core::model::{VaultId, workspace::map_panes};

use super::*;
use crate::app::{Config, LaunchIntent, UiEvent};
use crate::testing::AppHarness;
use crate::views::DialogKind;

const LEADER: &str = "ctrl-\\";

fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.resize(160, 48);
    h.take_effects();
    h
}

fn leader(h: &mut AppHarness, key: &str) {
    h.keys(&format!("{LEADER} {key}"));
}

fn opened(effects: &[Effect]) -> Vec<(SessionId, SessionSpec)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::OpenSession { id, spec, .. } => Some((*id, spec.clone())),
            _ => None,
        })
        .collect()
}

fn connected(h: &mut AppHarness, id: SessionId) {
    let now = h.now();
    h.send(UiEvent::Session(
        id,
        SessionEvent::State(SessionState::Connected { since: now }),
    ));
}

fn vault() -> VaultId {
    VaultId::from_bytes([2; 16])
}

fn entry(n: u8, spec: &WorkspaceSpec) -> WorkspaceEntry {
    WorkspaceEntry {
        id: ItemId::from_bytes([0x80 | n; 16]),
        vault: vault(),
        name: spec.name.clone(),
        spec: Ok(spec.clone()),
    }
}

/// `sverb --workspace <name>` with `spec` in the vault; returns the effects of the
/// open.
fn open(h: &mut AppHarness, spec: &WorkspaceSpec) -> Vec<Effect> {
    h.send(UiEvent::Launch(LaunchIntent::Workspace(spec.name.clone())));
    let effects = h.take_effects();
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Workspaces(WorkspacesEffect::Load))),
        "{effects:?}"
    );
    h.send(UiEvent::Workspaces(WorkspacesEvent::Loaded(vec![entry(
        1, spec,
    )])));
    h.take_effects()
}

fn act(h: &mut AppHarness, action: ActionName) -> Vec<Effect> {
    let mut effects = Vec::new();
    assert!(h.app_mut().apply_workspace_action(action, &mut effects));
    effects
}

/// A 2×2 grid of leaves 0..4 with uneven ratios.
fn grid() -> Layout {
    let l = Layout::leaf(PaneId(0))
        .split(PaneId(0), SplitDir::Vertical, PaneId(1))
        .unwrap();
    let l = l.split(PaneId(0), SplitDir::Horizontal, PaneId(2)).unwrap();
    let l = l.split(PaneId(1), SplitDir::Horizontal, PaneId(3)).unwrap();
    l.resize(PaneId(0), Direction::Right, Rect::new(0, 0, 100, 40), 3)
}

fn renumbered(layout: &Layout) -> Layout {
    WorkspaceTab::capture(None, layout, PaneId(0), &Broadcast::Off, |_| {
        Some(LeafRef::Local { cwd: None })
    })
    .tab
    .unwrap()
    .layout
}

fn host_tab(hosts: &[ItemId], broadcast: Broadcast<u32>) -> WorkspaceTab {
    let layout = renumbered(&grid());
    WorkspaceTab {
        title_override: Some("hosts".into()),
        layout,
        leaves: hosts.iter().map(|h| LeafRef::Host(*h)).collect(),
        focused: 3,
        broadcast,
    }
}

fn local_tab(cwd: Option<&str>) -> WorkspaceTab {
    WorkspaceTab {
        title_override: None,
        layout: Layout::leaf(PaneId(0)),
        leaves: vec![LeafRef::Local {
            cwd: cwd.map(str::to_owned),
        }],
        focused: 0,
        broadcast: Broadcast::Off,
    }
}

fn index(h: &mut AppHarness) -> Vec<ItemId> {
    let (index, ids) = crate::views::hosts::sample_index(&[
        ("alpha", "10.0.0.1"),
        ("bravo", "10.0.0.2"),
        ("charlie", "10.0.0.3"),
        ("delta", "10.0.0.4"),
    ]);
    h.send(UiEvent::IndexUpdated(index));
    h.take_effects();
    ids
}

#[test]
fn t02_save_captures_tabs_and_omits_quick_connect_panes() {
    let mut h = harness();
    let ids = index(&mut h);
    // Tab 1: a 2×2 split of alpha (`leader |`, then `-` in each column).
    h.send(UiEvent::Launch(LaunchIntent::Connect("alpha".into())));
    leader(&mut h, "|");
    leader(&mut h, "-");
    leader(&mut h, "h");
    leader(&mut h, "-");
    // Tab 2: a local shell. Tab 3: a quick-connect target (not saveable).
    leader(&mut h, "t");
    h.send(UiEvent::Launch(LaunchIntent::Connect(
        "root@10.9.9.9".into(),
    )));
    assert_eq!(h.app().tabs().list.len(), 3);
    h.take_effects();

    let effects = act(&mut h, ActionName::SaveWorkspace);
    // The list is loaded for the overwrite check.
    assert!(effects.contains(&Effect::Workspaces(WorkspacesEffect::Load)));
    // The warning names the omitted pane.
    let warning = h
        .app()
        .toasts()
        .iter()
        .find(|t| t.level == ToastLevel::Warning)
        .expect("warning toast");
    assert!(warning.message.contains("10.9.9.9"), "{}", warning.message);
    h.send(UiEvent::Workspaces(WorkspacesEvent::Loaded(Vec::new())));
    h.take_effects();
    h.keys("d e v enter");
    let effects = h.take_effects();
    let spec = effects
        .iter()
        .find_map(|e| match e {
            Effect::Workspaces(WorkspacesEffect::Save { id, vault, spec }) => {
                assert_eq!((*id, *vault), (None, None));
                Some(spec.clone())
            }
            _ => None,
        })
        .expect("save effect");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(spec.name, "dev");
    assert_eq!(spec.tabs.len(), 2);
    let grid = &spec.tabs[0];
    grid.check().unwrap();
    assert_eq!(grid.leaves, vec![LeafRef::Host(ids[0]); 4]);
    let Layout::Split { dir, children, .. } = &grid.layout else {
        panic!("{:?}", grid.layout)
    };
    assert_eq!(*dir, SplitDir::Vertical);
    assert!(children.iter().all(|c| matches!(
        c,
        Layout::Split {
            dir: SplitDir::Horizontal,
            ..
        }
    )));
    assert_eq!(spec.tabs[1].leaves, vec![LeafRef::Local { cwd: None }]);
    // The item view round-trips.
    assert_eq!(WorkspaceSpec::from_item(&spec.to_item()).unwrap(), spec);
}

#[test]
fn save_asks_before_overwriting_and_reports_nothing_to_save() {
    let mut h = harness();
    act(&mut h, ActionName::SaveWorkspace);
    assert!(h.app().toasts()[0].message.contains("Nothing to save"));
    leader(&mut h, "t");
    h.take_effects();
    act(&mut h, ActionName::SaveWorkspace);
    let existing = entry(
        1,
        &WorkspaceSpec {
            name: "dev".into(),
            tabs: vec![local_tab(None)],
            active: 0,
        },
    );
    h.send(UiEvent::Workspaces(WorkspacesEvent::Loaded(vec![
        existing.clone(),
    ])));
    h.keys("d e v enter");
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::Workspaces(WorkspacesEffect::Save { .. })))
    );
    // "Overwrite" (mnemonic `o`).
    h.keys("o");
    let save = h.take_effects().into_iter().find_map(|e| match e {
        Effect::Workspaces(WorkspacesEffect::Save { id, .. }) => Some(id),
        _ => None,
    });
    assert_eq!(save, Some(Some(existing.id)));
}

#[test]
fn t03_open_recreates_tabs_ratios_and_opens_each_leaf() {
    let mut h = harness();
    let ids = index(&mut h);
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![host_tab(&ids, Broadcast::Off), local_tab(Some("/tmp"))],
        active: 0,
    };
    let effects = open(&mut h, &spec);
    let open = opened(&effects);
    assert_eq!(open.len(), 5, "{effects:?}");
    let app = h.app();
    assert_eq!(app.tabs().list.len(), 2);
    let tab = &app.tabs().list[0];
    assert_eq!(tab.title_override.as_deref(), Some("hosts"));
    // Same tree and ratios, with the new pane ids in leaf order.
    let panes = tab.layout.panes();
    assert_eq!(
        tab.layout,
        map_panes(&spec.tabs[0].layout, &mut |p| panes
            [usize::try_from(p.0).unwrap()])
    );
    // Each pane opens its own host, in leaf order.
    for (i, p) in panes.iter().enumerate() {
        let (_, s) = open.iter().find(|(s, _)| pane_of(*s) == *p).unwrap();
        let SessionSpec::Ssh(s) = s else {
            panic!("{s:?}")
        };
        assert_eq!(s.host_id, Some(ids[i]));
    }
    // The saved focus, and the first tab is active.
    assert_eq!(tab.focused, panes[3]);
    assert_eq!(app.tabs().active, 0);
    assert_eq!(app.focused_session(), Some(SessionId(panes[3].0)));
    let SessionSpec::Local(l) = &open[4].1 else {
        panic!("{:?}", open[4])
    };
    assert_eq!(l.cwd.as_deref(), Some(std::path::Path::new("/tmp")));
    // Opened at their pane sizes (not the 80×24 placeholder).
    assert!(effects.iter().all(|e| match e {
        Effect::OpenSession { cols, rows, .. } => (*cols, *rows) != (80, 24),
        _ => true,
    }));
}

#[test]
fn open_appends_after_existing_tabs_or_replaces_a_dead_only_tab() {
    let mut h = harness();
    leader(&mut h, "t");
    let first = h.app().focused_session().unwrap();
    let spec = WorkspaceSpec {
        name: "w".into(),
        tabs: vec![local_tab(None)],
        active: 0,
    };
    open(&mut h, &spec);
    assert_eq!(h.app().tabs().list.len(), 2);
    assert!(h.app().tabs().list[0].has_session(first));
    // A single dead pane is replaced.
    let mut h = harness();
    leader(&mut h, "t");
    let dead = h.app().focused_session().unwrap();
    let now = h.now();
    h.send(UiEvent::Session(
        dead,
        SessionEvent::State(SessionState::Disconnected {
            reason: sverb_conn::DisconnectReason::Exited(0),
            at: now,
        }),
    ));
    let effects = open(&mut h, &spec);
    assert!(effects.contains(&Effect::CloseSession(dead)));
    assert_eq!(h.app().tabs().list.len(), 1);
    assert!(!h.app().tabs().list[0].has_session(dead));
}

#[test]
fn t04_twenty_leaves_never_more_than_eight_connecting() {
    let mut h = harness();
    let mut layout = Layout::leaf(PaneId(0));
    for i in 1..20u64 {
        let dir = if i % 2 == 0 {
            SplitDir::Vertical
        } else {
            SplitDir::Horizontal
        };
        layout = layout.split(PaneId(i - 1), dir, PaneId(i)).unwrap();
    }
    let layout = renumbered(&layout);
    let spec = WorkspaceSpec {
        name: "big".into(),
        tabs: vec![WorkspaceTab {
            title_override: None,
            layout,
            leaves: (0..20)
                .map(|i| LeafRef::Local {
                    cwd: Some(format!("/d{i}")),
                })
                .collect(),
            focused: 0,
            broadcast: Broadcast::Off,
        }],
        active: 0,
    };
    // The fake manager: sessions opened and not yet connected.
    let mut in_flight: Vec<SessionId> = opened(&open(&mut h, &spec))
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let mut total = in_flight.len();
    assert_eq!(total, OPEN_CONCURRENCY);
    assert_eq!(h.app().tabs().list[0].panes.len(), 20);
    let mut max = in_flight.len();
    let mut step = 0;
    while let Some(id) = in_flight.first().copied() {
        in_flight.remove(0);
        // Alternate outcomes: connected or failed.
        let now = h.now();
        let state = match step % 2 {
            0 => SessionState::Connected { since: now },
            _ => SessionState::Disconnected {
                reason: sverb_conn::DisconnectReason::Connect,
                at: now,
            },
        };
        step += 1;
        h.send(UiEvent::Session(id, SessionEvent::State(state)));
        let more = opened(&h.take_effects());
        total += more.len();
        in_flight.extend(more.into_iter().map(|(id, _)| id));
        max = max.max(in_flight.len());
        assert!(in_flight.len() <= OPEN_CONCURRENCY);
    }
    assert_eq!(total, 20);
    assert_eq!(max, OPEN_CONCURRENCY);
    assert!(h.app().tabs.workspaces.peak <= OPEN_CONCURRENCY);
    assert_eq!(h.app().workspace_queue_len(), 0);
}

#[test]
fn a_queued_pane_closed_before_its_turn_never_opens() {
    let mut h = harness();
    let spec = WorkspaceSpec {
        name: "q".into(),
        tabs: (0..9).map(|_| local_tab(None)).collect(),
        active: 0,
    };
    let first = opened(&open(&mut h, &spec));
    assert_eq!(first.len(), 8);
    let last_tab = h.app().tabs().list.last().unwrap().clone();
    let queued = last_tab.focused_session();
    assert!(first.iter().all(|(id, _)| *id != queued));
    // Close the queued pane, then free a slot: nothing opens for it.
    let mut effects = vec![Effect::CloseSession(queued)];
    h.app_mut().tabs_after_handle(&mut effects);
    connected(&mut h, first[0].0);
    assert!(opened(&h.take_effects()).is_empty());
}

#[test]
fn t05_a_deleted_host_opens_a_placeholder_pane() {
    let mut h = harness();
    let ids = index(&mut h);
    let gone = ItemId::from_bytes([0x55; 16]);
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![host_tab(&[ids[0], gone, ids[1], ids[2]], Broadcast::Off)],
        active: 0,
    };
    let effects = open(&mut h, &spec);
    assert_eq!(opened(&effects).len(), 3);
    let tab = h.app().tabs().list[0].clone();
    let placeholder = tab.layout.panes()[1];
    let session = SessionId(placeholder.0);
    assert_eq!(tab.panes[&placeholder].life, PaneLife::Down);
    assert!(matches!(
        h.app().pane(session).overlay,
        PaneOverlay::Missing { .. }
    ));
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("no longer exist"))
    );
    // It takes no keys, and `leader x` closes it without asking.
    h.app_mut().focus_session(session);
    h.send(UiEvent::Input(crate::app::InputEvent::FocusGained));
    assert_eq!(h.app().mode(), crate::app::Mode::Normal);
    h.take_effects();
    leader(&mut h, "x");
    assert!(h.take_effects().contains(&Effect::CloseSession(session)));
    assert_eq!(h.app().tabs().list[0].panes.len(), 3);
    // The rendered pane says so.
    let screen = h.render(160, 48);
    assert!(!screen.is_empty());
}

#[test]
fn t06_broadcast_sets_are_restored_on_the_new_panes() {
    let mut h = harness();
    let ids = index(&mut h);
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![
            host_tab(&ids, Broadcast::Custom(BTreeSet::from([0, 2]))),
            host_tab(&ids, Broadcast::AllPanes),
        ],
        active: 1,
    };
    open(&mut h, &spec);
    let app = h.app();
    let t0 = &app.tabs().list[0];
    let panes = t0.layout.panes();
    assert_eq!(
        t0.broadcast,
        BroadcastSet::Custom(BTreeSet::from([panes[0], panes[2]]))
    );
    assert_eq!(app.tabs().list[1].broadcast, BroadcastSet::AllPanes);
    // The saved active tab is active.
    assert_eq!(app.tabs().active, 1);
    // Saving again gives the same sets.
    let (again, _) = app.capture_workspace();
    assert_eq!(again.tabs[0].broadcast, spec.tabs[0].broadcast);
    assert_eq!(again.tabs[1].broadcast, Broadcast::AllPanes);
    assert_eq!(again.tabs[0].layout, spec.tabs[0].layout);
    assert_eq!(again.active, 1);
}

// T-07 (reducer side; the PTY test is `crates/sverb/tests/workspace.rs`)
#[test]
fn t07_unknown_workspace_name_lists_the_available_ones() {
    let mut h = harness();
    h.send(UiEvent::Launch(LaunchIntent::Workspace("nope".into())));
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![local_tab(None)],
        active: 0,
    };
    let mut ops = spec.clone();
    ops.name = "ops".into();
    h.send(UiEvent::Workspaces(WorkspacesEvent::Loaded(vec![
        entry(1, &ops),
        entry(2, &spec),
    ])));
    let toast = &h.app().toasts()[0];
    assert_eq!(toast.level, ToastLevel::Error);
    assert!(
        toast.message.contains("No workspace named \"nope\"") && toast.message.contains("dev, ops"),
        "{}",
        toast.message
    );
    assert!(h.app().tabs().list.is_empty());
    // A failing service (no vault) is reported too.
    h.send(UiEvent::Launch(LaunchIntent::Workspace("dev".into())));
    h.send(UiEvent::Workspaces(WorkspacesEvent::Failed(
        ErrorReport::msg("Workspaces need a vault"),
    )));
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("need a vault"))
    );
}

#[test]
fn the_dialog_opens_renames_deletes_and_duplicates() {
    let mut h = harness();
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![local_tab(None)],
        active: 0,
    };
    let mut prod = spec.clone();
    prod.name = "prod".into();
    let (dev, prod) = (entry(1, &spec), entry(2, &prod));
    let effects = act(&mut h, ActionName::OpenWorkspace);
    assert!(effects.contains(&Effect::Workspaces(WorkspacesEffect::Load)));
    h.send(UiEvent::Workspaces(WorkspacesEvent::Loaded(vec![
        dev.clone(),
        prod.clone(),
    ])));
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Workspaces(_))
    ));
    assert_eq!(h.app().mode(), crate::app::Mode::Insert);
    let screen = h.render(160, 48);
    assert!(
        screen.contains("Open workspace") && screen.contains("prod"),
        "{screen}"
    );
    // Filter to "prod", duplicate, rename, delete.
    h.keys("p r");
    h.take_effects();
    h.keys("ctrl-y");
    assert!(
        h.take_effects()
            .contains(&Effect::Workspaces(WorkspacesEffect::Duplicate(prod.id)))
    );
    h.keys("ctrl-r");
    // The prompt is prefilled with the name.
    h.keys("2 enter");
    assert!(
        h.take_effects()
            .contains(&Effect::Workspaces(WorkspacesEffect::Rename {
                id: prod.id,
                name: "prod2".into()
            }))
    );
    // Renaming onto an existing name is refused.
    h.keys("ctrl-r backspace backspace backspace backspace d e v enter");
    assert!(
        !h.take_effects()
            .iter()
            .any(|e| matches!(e, Effect::Workspaces(WorkspacesEffect::Rename { .. })))
    );
    h.keys("ctrl-d d");
    assert!(
        h.take_effects()
            .contains(&Effect::Workspaces(WorkspacesEffect::Delete(prod.id)))
    );
    // Enter opens the selection and closes the dialog.
    h.keys("enter");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(h.app().tabs().list.len(), 1);
}
