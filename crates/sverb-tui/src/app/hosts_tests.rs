//! M1-07 reducer tests: bulk delete (T-08), address validation in the form (T-09),
//! quick connect and "Save as host" (T-10), connect / copy / launch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sverb_conn::{SessionEvent, SessionSpec, SessionState, SshSpec};
use sverb_core::model::ItemKind;

use super::hosts::ItemEffect;
use super::{Config, Effect, UiEvent, VaultEffect};
use crate::testing::AppHarness;
use crate::views::DialogKind;
use crate::widgets::form::FieldValue;

fn item_effects(effects: &[Effect]) -> Vec<ItemEffect> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Vault(VaultEffect::Items(op)) => Some(op.clone()),
            _ => None,
        })
        .collect()
}

fn opened(effects: &[Effect]) -> Vec<SshSpec> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::OpenSession {
                spec: SessionSpec::Ssh(s),
                ..
            } => Some(s.clone()),
            _ => None,
        })
        .collect()
}

// T-08
#[test]
fn t08_bulk_delete_confirms_then_deletes_each() {
    let mut h = AppHarness::new(Config::default());
    let ids = h.app_mut().seed_three_hosts();
    h.keys("space space space d");
    let DialogKind::Modal(m) = &h.app().dialogs().last().unwrap().kind else {
        panic!("no confirm: {:?}", h.app().dialogs());
    };
    assert_eq!(m.modal.title, "Delete 3 hosts?");
    assert!(
        item_effects(h.effects()).is_empty(),
        "nothing deleted before the answer"
    );
    // Enter is safe in a danger dialog: it cancels.
    h.keys("enter");
    assert!(h.app().dialogs().is_empty());
    assert!(item_effects(&h.take_effects()).is_empty());

    h.keys("d d");
    let deletes = item_effects(&h.take_effects());
    assert_eq!(
        deletes,
        ids.iter()
            .map(|id| ItemEffect::Delete(*id))
            .collect::<Vec<_>>()
    );
}

// T-09
#[test]
fn t09_invalid_address_blocks_the_save() {
    let mut h = AppHarness::new(Config::default());
    h.keys("a");
    assert!(matches!(h.app().dialogs()[0].kind, DialogKind::HostForm(_)));
    h.keys("tab r o o t @ x tab");
    let DialogKind::HostForm(d) = &h.app().dialogs()[0].kind else {
        panic!()
    };
    let err = d.form.field("address").unwrap().error.clone();
    assert!(
        err.is_some_and(|e| e.contains("user name")),
        "{:?}",
        d.form.field("address")
    );
    h.keys("ctrl-s");
    assert!(
        item_effects(&h.take_effects()).is_empty(),
        "save is blocked"
    );
    assert_eq!(h.app().dialogs().len(), 1);

    // Fixing it saves every field of the new host.
    h.keys("backspace backspace backspace backspace backspace backspace x . o r g ctrl-s");
    let ops = item_effects(&h.take_effects());
    let [
        ItemEffect::Save {
            item: None,
            kind: ItemKind::Host,
            changes,
            ..
        },
    ] = ops.as_slice()
    else {
        panic!("{ops:?}");
    };
    assert_eq!(
        changes.get("address"),
        Some(&FieldValue::Text("x.org".into()))
    );
}

// T-10
#[test]
fn t10_quick_connect_and_save_as_host() {
    let mut h = AppHarness::new(Config::default());
    h.keys("ctrl-\\ o");
    assert!(matches!(
        h.app().dialogs()[0].kind,
        DialogKind::QuickConnect(_)
    ));
    for c in "deploy@10.0.0.5:2222".chars() {
        let chord = if c == '@' {
            "@".to_owned()
        } else {
            c.to_string()
        };
        h.keys(&chord);
    }
    h.keys("enter");
    assert!(h.app().dialogs().is_empty());
    let effects = h.take_effects();
    assert_eq!(
        opened(&effects),
        [SshSpec {
            host: "10.0.0.5".into(),
            port: 2222,
            user: Some("deploy".into()),
            ..SshSpec::default()
        }]
    );
    let sid = h.app().tabs().sessions[0];
    h.send(UiEvent::Session(
        sid,
        SessionEvent::State(SessionState::Connected { since: h.now() }),
    ));
    let DialogKind::SaveHostOffer(offer) = &h.app().dialogs()[0].kind else {
        panic!("no offer");
    };
    assert_eq!(offer.target.display(), "deploy@10.0.0.5:2222");
    let screen = h.render(80, 24);
    assert!(screen.contains("Save as host?"), "{screen}");
    h.keys("s");
    let DialogKind::HostForm(d) = &h.app().dialogs()[0].kind else {
        panic!("no form");
    };
    let value = |k: &str| d.form.field(k).unwrap().value();
    assert_eq!(value("address"), FieldValue::Text("10.0.0.5".into()));
    assert_eq!(value("username"), FieldValue::Text("deploy".into()));
    assert_eq!(value("port"), FieldValue::Number(Some(2222)));
}

#[test]
fn quick_connect_inline_error_and_saved_hosts() {
    let mut h = AppHarness::new(Config::default());
    h.keys("ctrl-\\ o");
    h.keys("h : 0 enter");
    let DialogKind::QuickConnect(q) = &h.app().dialogs()[0].kind else {
        panic!()
    };
    assert!(q.error().is_some());
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());
    assert!(opened(h.effects()).is_empty());
}

#[test]
fn offer_dismissed_by_another_key_which_goes_on() {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().connect_ephemeral(
        sverb_core::quick_connect::parse("h").unwrap(),
        &mut Vec::new(),
    );
    let sid = h.app().tabs().sessions[0];
    h.send(UiEvent::Session(
        sid,
        SessionEvent::State(SessionState::Connected { since: h.now() }),
    ));
    h.take_effects();
    h.keys("x");
    assert!(h.app().dialogs().is_empty());
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. })),
        "the key reached the session: {:?}",
        h.effects()
    );
}

#[test]
fn enter_connects_and_connected_touches_the_host() {
    let mut h = AppHarness::new(Config::default());
    let ids = h.app_mut().seed_three_hosts();
    h.keys("j enter");
    let effects = h.take_effects();
    assert_eq!(opened(&effects)[0].host, "10.0.0.2");
    let sid = h.app().tabs().sessions[0];
    h.send(UiEvent::Session(
        sid,
        SessionEvent::State(SessionState::Connected { since: h.now() }),
    ));
    assert_eq!(
        item_effects(h.effects()),
        [ItemEffect::TouchConnected(ids[1])]
    );
}

#[test]
fn pin_duplicate_edit_and_copy() {
    let mut h = AppHarness::new(Config::default());
    let ids = h.app_mut().seed_three_hosts();
    h.keys("p y e");
    let ops = item_effects(&h.take_effects());
    assert_eq!(
        ops[0],
        ItemEffect::SetPinned {
            item: ids[0],
            pinned: true
        }
    );
    assert_eq!(ops[1], ItemEffect::Duplicate(ids[0]));
    assert!(matches!(ops[2], ItemEffect::LoadHost { item, .. } if item == ids[0]));
    // Copy needs the catalog: without it, a hint.
    h.keys("c");
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("loading"))
    );
    let mut catalog = crate::views::hosts::catalog::HostCatalog::default();
    catalog.hosts.insert(
        ids[0],
        crate::views::hosts::catalog::HostSummary {
            id: ids[0],
            address: "10.0.0.1".into(),
            port: Some(2222),
            username: Some("root".into()),
            ..Default::default()
        },
    );
    h.app_mut().views.hosts.set_catalog(Arc::new(catalog));
    h.keys("c");
    assert!(
        h.effects()
            .contains(&Effect::CopyToClipboard("ssh -p 2222 root@10.0.0.1".into())),
        "{:?}",
        h.effects()
    );
}

#[test]
fn launch_connect_resolves_saved_hosts_then_parses() {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().seed_three_hosts();
    // No vault service in this harness: resolution uses the reducer's index (none
    // here), so the target is parsed.
    h.send(UiEvent::Launch(super::LaunchIntent::Connect(
        "u@db:2200".into(),
    )));
    assert_eq!(
        opened(h.effects()),
        [SshSpec {
            host: "db".into(),
            port: 2200,
            user: Some("u".into()),
            ..SshSpec::default()
        }]
    );
    h.take_effects();
    h.send(UiEvent::Launch(super::LaunchIntent::Connect(
        "bad host".into(),
    )));
    assert!(opened(h.effects()).is_empty());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Cannot connect"))
    );
}

// ---------------------------------------------------------------------- M2-01

mod m2_01 {
    use std::sync::Arc;

    use sverb_core::model::{ItemId, group::DeleteGroupMode};
    use sverb_core::resolve::{GroupNode, Settings};

    use super::{item_effects, opened};
    use crate::app::hosts::{ItemEffect, group_delete_plan};
    use crate::app::{Config, Effect};
    use crate::testing::AppHarness;
    use crate::views::DialogKind;
    use crate::views::hosts::catalog::{HostCatalog, HostSummary, TagInfo};
    use crate::views::hosts::organize::OrganizeDialog;

    fn gid(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    const ROOT: u8 = 201;
    const PROD: u8 = 202;
    const SUB: u8 = 203;

    fn group(name: &str, parent: Option<u8>, port: Option<u16>) -> GroupNode {
        GroupNode {
            name: name.into(),
            parent_id: parent.map(gid),
            icon: None,
            defaults: Settings {
                port,
                ..Settings::default()
            },
        }
    }

    /// `n` hosts (`h1` … `hn`); `in_prod` of them (the first ones) are in `prod`
    /// (under `root`, with an empty subgroup `sub`).
    fn seeded(n: usize, in_prod: usize, prod_port: Option<u16>) -> (AppHarness, Vec<ItemId>) {
        let mut h = AppHarness::new(Config::default());
        let names: Vec<(String, String)> = (1..=n)
            .map(|i| (format!("h{i}"), format!("10.0.0.{i}")))
            .collect();
        let refs: Vec<(&str, &str)> = names
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let ids = h.app_mut().seed_hosts(&refs);
        let mut c = HostCatalog::default();
        c.lookup.groups.insert(gid(ROOT), group("root", None, None));
        c.lookup
            .groups
            .insert(gid(PROD), group("prod", Some(ROOT), prod_port));
        c.lookup
            .groups
            .insert(gid(SUB), group("sub", Some(PROD), None));
        for (i, id) in ids.iter().enumerate() {
            c.hosts.insert(
                *id,
                HostSummary {
                    id: *id,
                    label: names[i].0.clone(),
                    address: names[i].1.clone(),
                    group_id: (i < in_prod).then(|| gid(PROD)),
                    ..HostSummary::default()
                },
            );
        }
        h.app_mut().views.hosts.set_catalog(Arc::new(c));
        (h, ids)
    }

    fn top_dialog(h: &AppHarness) -> &OrganizeDialog {
        match &h.app().dialogs().last().expect("a dialog").kind {
            DialogKind::Organize(o) => o,
            other => panic!("{other:?}"),
        }
    }

    // M2-01 T-05
    #[test]
    fn t05_tree_collapses_and_bulk_moves_to_a_group() {
        let (mut h, ids) = seeded(4, 1, None);
        let visible = |h: &AppHarness| h.app().views.hosts.list.visible_len();
        // root > prod > (sub, h1); h2 h3 h4 at the top level.
        assert_eq!(visible(&h), 7);
        h.app_mut()
            .views
            .hosts
            .list
            .select_key(&crate::views::hosts::HostRowKey::Group(gid(ROOT)));
        h.keys("h"); // collapse root
        assert_eq!(visible(&h), 4);
        h.keys("l");
        assert_eq!(visible(&h), 7);
        h.keys("j h"); // collapse prod
        assert_eq!(visible(&h), 5);
        h.keys("l");

        // Mark h2, h3, h4 and move them to prod.
        assert!(h.app_mut().views.hosts.select(ids[1]));
        h.keys("space space space m");
        let OrganizeDialog::GroupPicker(p) = top_dialog(&h) else {
            panic!()
        };
        let labels: Vec<&str> = p.options.iter().map(|(_, l)| l.as_str()).collect();
        assert_eq!(labels, ["(no group)", "root", "  prod", "    sub"]);
        h.keys("j j enter");
        assert!(h.app().dialogs().is_empty());
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::MoveToGroup {
                items: ids[1..].to_vec(),
                group: Some(gid(PROD)),
            }]
        );
    }

    // M2-01 T-06
    #[test]
    fn t06_delete_group_moves_contents_to_the_parent() {
        let (mut h, ids) = seeded(3, 2, None);
        let catalog = h.app().views.hosts.catalog().cloned().expect("catalog");
        let plan = group_delete_plan(&catalog, gid(PROD), DeleteGroupMode::MoveToParent);
        assert_eq!(plan.move_hosts, ids[..2].to_vec());
        assert_eq!(plan.move_groups, vec![gid(SUB)]);
        assert_eq!(plan.new_parent, Some(gid(ROOT)));
        assert_eq!(plan.delete_groups, vec![gid(PROD)]);

        h.app_mut()
            .views
            .hosts
            .list
            .select_key(&crate::views::hosts::HostRowKey::Group(gid(PROD)));
        h.keys("d");
        let OrganizeDialog::DeleteGroup(d) = top_dialog(&h) else {
            panic!()
        };
        assert_eq!((d.hosts, d.subgroups, d.delete_count), (2, 1, 3));
        // The default answer moves the contents.
        h.keys("enter");
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::DeleteGroup {
                group: gid(PROD),
                mode: DeleteGroupMode::MoveToParent,
            }]
        );
    }

    // M2-01 T-07
    #[test]
    fn t07_delete_all_types_the_count_above_ten() {
        let (mut h, _) = seeded(12, 12, None);
        let select = |h: &mut AppHarness| {
            h.app_mut()
                .views
                .hosts
                .list
                .select_key(&crate::views::hosts::HostRowKey::Group(gid(PROD)));
        };
        select(&mut h);
        h.keys("d j enter");
        let OrganizeDialog::DeleteGroup(d) = top_dialog(&h) else {
            panic!()
        };
        assert_eq!(d.delete_count, 13, "12 hosts and the subgroup");
        assert!(d.typing.is_some(), "a typed confirmation");
        assert!(item_effects(h.effects()).is_empty());
        h.keys("1 2 enter");
        let OrganizeDialog::DeleteGroup(d) = top_dialog(&h) else {
            panic!()
        };
        assert!(d.error.is_some(), "a wrong count is refused");
        h.keys("backspace backspace 1 3 enter");
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::DeleteGroup {
                group: gid(PROD),
                mode: DeleteGroupMode::DeleteAll,
            }]
        );

        // Ten items or fewer: no typing.
        let (mut h, _) = seeded(3, 3, None);
        select(&mut h);
        h.keys("d j enter");
        assert!(h.app().dialogs().is_empty());
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::DeleteGroup {
                group: gid(PROD),
                mode: DeleteGroupMode::DeleteAll,
            }]
        );
    }

    // M2-01 T-10 (reducer half; tests/groups.rs checks the writes)
    #[test]
    fn t10_bulk_tags_add_and_remove() {
        let (mut h, ids) = seeded(5, 0, None);
        let mut c = (**h.app().views.hosts.catalog().expect("catalog")).clone();
        let (web, db) = (gid(150), gid(151));
        c.tags.insert(
            web,
            TagInfo {
                name: "web".into(),
                color: None,
            },
        );
        c.tags.insert(
            db,
            TagInfo {
                name: "db".into(),
                color: None,
            },
        );
        for id in &ids {
            c.hosts.get_mut(id).expect("host").tags = vec![web];
        }
        h.app_mut().views.hosts.set_catalog(Arc::new(c));
        assert!(h.app_mut().views.hosts.select(ids[0]));
        h.keys("V t");
        let OrganizeDialog::TagPicker(p) = top_dialog(&h) else {
            panic!()
        };
        // Sorted by name: db (none), web (all).
        assert_eq!(p.tags[0].name, "db");
        h.keys("space j space enter");
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::SetTags {
                items: ids.clone(),
                add: vec![db],
                remove: vec![web],
                create: None,
            }]
        );
        // A new tag inline; a duplicate name is refused in place.
        h.take_effects();
        h.keys("t j j W E B enter");
        let OrganizeDialog::TagPicker(p) = top_dialog(&h) else {
            panic!()
        };
        assert!(
            p.error
                .as_deref()
                .is_some_and(|e| e.contains("already exists"))
        );
        h.keys("backspace backspace backspace o p s enter");
        assert_eq!(
            item_effects(h.effects()),
            [ItemEffect::SetTags {
                items: ids,
                add: vec![],
                remove: vec![],
                create: Some("ops".into()),
            }]
        );
    }

    fn ssh_ports(effects: &[Effect]) -> Vec<u16> {
        opened(effects).iter().map(|s| s.port).collect()
    }

    // M2-01 T-12
    #[test]
    fn t12_group_default_port_applies_to_the_next_connection_only() {
        let (mut h, ids) = seeded(1, 1, Some(2222));
        assert!(h.app_mut().views.hosts.select(ids[0]));
        h.keys("enter");
        let first = h.take_effects();
        assert_eq!(ssh_ports(&first), [2222]);
        let sessions = h.app().tabs().sessions.clone();

        // The group's default changes (a new catalog after the save).
        let mut c = (**h.app().views.hosts.catalog().expect("catalog")).clone();
        c.lookup
            .groups
            .get_mut(&gid(PROD))
            .expect("prod")
            .defaults
            .port = Some(3333);
        h.app_mut().views.hosts.set_catalog(Arc::new(c));
        // The open session is left alone: nothing is sent to it.
        assert!(
            !h.effects()
                .iter()
                .any(|e| matches!(e, Effect::OpenSession { .. })),
            "{:?}",
            h.effects()
        );
        assert_eq!(h.app().tabs().sessions, sessions);

        // The next connection resolves anew.
        let mut effects = Vec::new();
        h.app_mut().connect_host(ids[0], &mut effects);
        assert_eq!(ssh_ports(&effects), [3333]);
        assert_eq!(ssh_ports(&first), [2222], "the first spec is what it was");
    }
}
