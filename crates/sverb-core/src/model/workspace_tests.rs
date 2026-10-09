#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use ciborium::Value;
use proptest::prelude::*;

use super::*;
use crate::layout::Direction;
use crate::model::{HlcClock, ItemBody, ItemKind, ManualClock};

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn host(b: u8) -> LeafRef {
    LeafRef::Host(id(b))
}

fn local(cwd: Option<&str>) -> LeafRef {
    LeafRef::Local {
        cwd: cwd.map(str::to_owned),
    }
}

/// Spec → item view → stamped body → CBOR bytes → body → item view → spec.
fn through_cbor(spec: &WorkspaceSpec) -> WorkspaceSpec {
    let mut clock = HlcClock::new(ManualClock::new(std::time::Duration::from_secs(
        1_700_000_000,
    )));
    let device = crate::model::DeviceId::from_bytes([9; 16]);
    let mut body = ItemBody::new(ItemKind::Workspace, 1);
    spec.to_item().apply_to(&mut body, &mut clock, device);
    let bytes = body.to_cbor().expect("encode");
    let back = ItemBody::from_cbor(&bytes).expect("decode");
    let item = Workspace::try_from(&back).expect("view");
    WorkspaceSpec::from_item(&item).expect("spec")
}

/// A 2×2 grid of panes 1..=4 (left column 1 over 3, right column 2 over 4).
fn grid() -> Layout {
    let l = Layout::leaf(PaneId(1))
        .split(PaneId(1), SplitDir::Vertical, PaneId(2))
        .unwrap();
    let l = l.split(PaneId(1), SplitDir::Horizontal, PaneId(3)).unwrap();
    l.split(PaneId(2), SplitDir::Horizontal, PaneId(4)).unwrap()
}

#[test]
fn capture_renumbers_and_keeps_ratios_focus_and_broadcast() {
    let area = Rect::new(0, 0, 100, 40);
    let layout = grid().resize(PaneId(1), Direction::Right, area, 3);
    let custom = Broadcast::Custom(BTreeSet::from([PaneId(2), PaneId(4)]));
    let c = WorkspaceTab::capture(Some("ops".into()), &layout, PaneId(4), &custom, |p| {
        Some(host(u8::try_from(p.0).unwrap()))
    });
    assert!(c.omitted.is_empty());
    let tab = c.tab.unwrap();
    tab.check().unwrap();
    // Layout order: 1, 3 (left column), 2, 4 (right column).
    assert_eq!(tab.leaves, vec![host(1), host(3), host(2), host(4)]);
    assert_eq!(tab.focused, 3);
    assert_eq!(tab.broadcast, Broadcast::Custom(BTreeSet::from([2, 3])));
    // Same geometry with the new ids.
    let (back, focused, bc) = tab
        .instantiate(&[PaneId(11), PaneId(13), PaneId(12), PaneId(14)])
        .unwrap();
    assert_eq!(back, map_panes(&layout, &mut |p| PaneId(p.0 + 10)));
    assert_eq!(focused, PaneId(14));
    assert_eq!(
        bc,
        Broadcast::Custom(BTreeSet::from([PaneId(12), PaneId(14)]))
    );
}

#[test]
fn capture_omits_unsaveable_panes() {
    let layout = grid();
    let custom = Broadcast::Custom(BTreeSet::from([PaneId(2)]));
    let c = WorkspaceTab::capture(None, &layout, PaneId(2), &custom, |p| {
        (p.0 != 2).then(|| local(None))
    });
    assert_eq!(c.omitted, vec![PaneId(2)]);
    let tab = c.tab.unwrap();
    tab.check().unwrap();
    assert_eq!(tab.leaves.len(), 3);
    // The focused pane was omitted: the first pane takes the focus; the set emptied.
    assert_eq!(tab.focused, 0);
    assert_eq!(tab.broadcast, Broadcast::Off);
    // Nothing saveable: no tab.
    let none = WorkspaceTab::capture(None, &layout, PaneId(1), &Broadcast::Off, |_| None);
    assert_eq!(none.tab, None);
    assert_eq!(none.omitted.len(), 4);
}

#[test]
fn round_trip_of_a_known_workspace() {
    let c = WorkspaceTab::capture(None, &grid(), PaneId(3), &Broadcast::AllPanes, |p| {
        Some(host(u8::try_from(p.0).unwrap()))
    });
    let spec = WorkspaceSpec {
        name: "dev".into(),
        tabs: vec![
            c.tab.unwrap(),
            WorkspaceTab {
                title_override: Some("logs".into()),
                layout: Layout::leaf(PaneId(0)),
                leaves: vec![local(Some("/var/log"))],
                focused: 0,
                broadcast: Broadcast::Off,
            },
        ],
        active: 1,
    };
    assert_eq!(through_cbor(&spec), spec);
    assert_eq!(
        spec.host_ids(),
        BTreeSet::from([id(1), id(2), id(3), id(4)])
    );
    assert_eq!(spec.pane_count(), 5);
    let item = spec.to_item();
    // One broadcast group (the first tab broadcasts to all panes).
    assert_eq!(item.broadcast_groups.len(), 1);
}

#[test]
fn malformed_items_are_errors() {
    let mut item = Workspace {
        name: "x".into(),
        ..Workspace::default()
    };
    assert_eq!(
        WorkspaceSpec::from_item(&item),
        Err(WorkspaceError::NoLayout)
    );
    item.layout = Some(Value::Map(vec![(Value::from("v"), Value::from(99))]));
    assert_eq!(
        WorkspaceSpec::from_item(&item),
        Err(WorkspaceError::Newer(99))
    );
    // A leaf index without a leaf.
    let spec = WorkspaceSpec {
        name: "x".into(),
        tabs: vec![WorkspaceTab {
            title_override: None,
            layout: Layout::leaf(PaneId(1)),
            leaves: vec![local(None)],
            focused: 0,
            broadcast: Broadcast::Off,
        }],
        active: 0,
    };
    assert!(matches!(
        WorkspaceSpec::from_item(&spec.to_item()),
        Err(WorkspaceError::Invalid(_))
    ));
    // Garbage never panics.
    for v in [
        Value::Null,
        Value::from(3),
        Value::Map(vec![(Value::from("tabs"), Value::from("no"))]),
        Value::Map(vec![(
            Value::from("tabs"),
            Value::Array(vec![Value::Map(vec![(
                Value::from("tree"),
                Value::from(-1),
            )])]),
        )]),
    ] {
        item.layout = Some(v);
        assert!(WorkspaceSpec::from_item(&item).is_err());
    }
}

#[test]
fn preview_draws_boxes_and_labels() {
    let tab = WorkspaceTab::capture(None, &grid(), PaneId(1), &Broadcast::Off, |p| {
        Some(host(u8::try_from(p.0).unwrap()))
    })
    .tab
    .unwrap();
    let lines = tab.preview(20, 8, |l| match l {
        LeafRef::Host(h) => format!("h{}", h.as_bytes()[0]),
        LeafRef::Local { .. } => "local".into(),
    });
    assert_eq!(lines.len(), 8);
    assert!(lines.iter().all(|l| l.chars().count() == 20));
    let all = lines.join("\n");
    assert!(all.contains("*h1"), "{all}");
    for label in ["h2", "h3", "h4"] {
        assert!(all.contains(label), "{all}");
    }
    assert!(lines[0].starts_with('+'));
    // Tiny areas don't panic.
    let _ = tab.preview(0, 0, |_| String::new());
    let _ = tab.preview(1, 1, |_| String::new());
}

// ---------------------------------------------------------------- T-01

/// A random layout of `n` panes built by splits and resizes (the way users build one).
fn layout_strategy() -> impl Strategy<Value = Layout> {
    (
        1usize..10,
        prop::collection::vec((any::<u8>(), any::<bool>()), 9),
        prop::collection::vec((any::<u8>(), 0u8..4, 1u16..6), 0..8),
    )
        .prop_map(|(n, splits, resizes)| {
            let mut layout = Layout::leaf(PaneId(0));
            for (i, (target, vertical)) in splits.iter().take(n - 1).enumerate() {
                let panes = layout.panes();
                let target = panes[usize::from(*target) % panes.len()];
                let dir = if *vertical {
                    SplitDir::Vertical
                } else {
                    SplitDir::Horizontal
                };
                if let Some(l) = layout.split(target, dir, PaneId(i as u64 + 1)) {
                    layout = l;
                }
            }
            let area = Rect::new(0, 0, 200, 60);
            for (pane, dir, steps) in resizes {
                let panes = layout.panes();
                let pane = panes[usize::from(pane) % panes.len()];
                let dir = [
                    Direction::Left,
                    Direction::Right,
                    Direction::Up,
                    Direction::Down,
                ][usize::from(dir)];
                layout = layout.resize(pane, dir, area, steps);
            }
            layout
        })
}

fn leaf_strategy() -> impl Strategy<Value = LeafRef> {
    prop_oneof![
        any::<[u8; 16]>().prop_map(|b| LeafRef::Host(ItemId::from_bytes(b))),
        proptest::option::of("[a-z/ ._-]{0,12}").prop_map(|cwd| LeafRef::Local { cwd }),
    ]
}

fn tab_strategy() -> impl Strategy<Value = WorkspaceTab> {
    (
        layout_strategy(),
        prop::collection::vec(leaf_strategy(), 10),
        proptest::option::of("[ -~]{0,10}"),
        any::<u8>(),
        0u8..3,
        prop::collection::vec(any::<u8>(), 0..5),
    )
        .prop_map(|(layout, leaves, title, focus, bc, members)| {
            let panes = layout.panes();
            let focused = panes[usize::from(focus) % panes.len()];
            let broadcast = match bc {
                0 => Broadcast::Off,
                1 => Broadcast::AllPanes,
                _ => Broadcast::Custom(
                    members
                        .iter()
                        .map(|m| panes[usize::from(*m) % panes.len()])
                        .collect(),
                ),
            };
            WorkspaceTab::capture(title, &layout, focused, &broadcast, |p| {
                Some(leaves[usize::try_from(p.0).unwrap()].clone())
            })
            .tab
            .unwrap()
        })
}

proptest! {
    // Layout + leaves serialize to CBOR and back identically.
    #[test]
    fn t01_workspace_cbor_round_trip(
        tabs in prop::collection::vec(tab_strategy(), 1..4),
        name in "[a-z]{1,8}",
        active in any::<u8>(),
    ) {
        let active = u32::from(active) % tabs.len() as u32;
        let spec = WorkspaceSpec { name, tabs, active };
        for t in &spec.tabs {
            prop_assert!(t.check().is_ok());
        }
        prop_assert_eq!(through_cbor(&spec), spec);
    }
}
