//! The host form's jump chain editor (ordering, effective-route preview,
//! inline cycle check) and copy-as-command from the effective chain.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use sverb_core::{model::ItemId, resolve::GlobalDefaults, ssh_command};

use super::super::catalog::{HostCatalog, HostSummary};
use super::{
    HOST_FORM_FEATURES, HostFormDialog, HostFormInit, InheritCx, JUMP_CHAIN, apply_changes,
    host_form,
};
use crate::widgets::{
    form::{FieldChanges, FieldValue, FieldWidget},
    test_util::{draw, key, text},
};

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

const BASTION: u8 = 10;
const INNER: u8 = 11;
const OTHER: u8 = 12;
const TARGET: u8 = 20;

fn summary(b: u8, label: &str, user: Option<&str>, chain: &[u8]) -> HostSummary {
    HostSummary {
        id: id(b),
        label: label.into(),
        address: format!("{label}.example"),
        username: user.map(str::to_owned),
        jump_chain: chain.iter().map(|b| id(*b)).collect(),
        ..HostSummary::default()
    }
}

/// bastion; inner-bastion jumps through bastion; other; the edited target.
fn catalog(bastion_chain: &[u8]) -> HostCatalog {
    let mut c = HostCatalog::default();
    for h in [
        summary(BASTION, "bastion", Some("ops"), bastion_chain),
        summary(INNER, "inner-bastion", None, &[BASTION]),
        summary(OTHER, "other", None, &[]),
        summary(TARGET, "target", Some("deploy"), &[INNER]),
    ] {
        c.hosts.insert(h.id, h);
    }
    c
}

fn dialog(c: HostCatalog, chain: &[u8]) -> HostFormDialog {
    let c = Arc::new(c);
    let mut init = HostFormInit {
        item: Some(id(TARGET)),
        summary: c.hosts.get(&id(TARGET)).cloned().unwrap(),
        password: None,
    };
    init.summary.jump_chain = chain.iter().map(|b| id(*b)).collect();
    let form = host_form(&init, Some(&c), None, &[], 30, HOST_FORM_FEATURES);
    let mut d = HostFormDialog {
        item: Some(id(TARGET)),
        form,
        inherit: Some(Box::new(InheritCx {
            catalog: c,
            globals: GlobalDefaults::default(),
            vault: None,
        })),
    };
    d.sync_inherited();
    d
}

fn list(d: &HostFormDialog) -> &crate::widgets::form::RefListInput {
    match &d.form.field(JUMP_CHAIN).expect("jump chain field").widget {
        FieldWidget::RefList(l) => l,
        other => panic!("not a list: {other:?}"),
    }
}

fn focus_chain(d: &mut HostFormDialog) {
    for _ in 0..60 {
        if d.form.focused_key() == Some(JUMP_CHAIN) {
            return;
        }
        key(&mut d.form, KeyCode::Tab, KeyModifiers::NONE);
    }
    panic!("the jump chain field is not reachable");
}

/// The list keeps its order, `K`/`J` reorder it, the preview follows the
/// recursive expansion, and the saved chain is the list in order.
#[test]
fn t09_form_ordering_and_effective_route() {
    let mut d = dialog(catalog(&[]), &[OTHER, INNER]);
    assert!(!d.form.field(JUMP_CHAIN).unwrap().hidden);
    let labels: Vec<&str> = list(&d).rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["other", "inner-bastion"]);
    assert_eq!(
        list(&d).note.as_deref(),
        Some("Effective route: you → other → bastion → inner-bastion → target")
    );

    // Move inner-bastion up.
    focus_chain(&mut d);
    key(&mut d.form, KeyCode::Down, KeyModifiers::NONE);
    key(&mut d.form, KeyCode::Char('K'), KeyModifiers::NONE);
    d.sync_inherited();
    assert_eq!(list(&d).ids(), [id(INNER), id(OTHER)]);
    assert_eq!(
        list(&d).note.as_deref(),
        Some("Effective route: you → bastion → inner-bastion → other → target")
    );
    let screen = text(&draw(&d.form, 120, 60, true));
    assert!(
        screen.contains("Effective route: you → bastion → inner-bastion → other → target"),
        "{screen}"
    );
    assert!(screen.contains("1. inner-bastion"), "{screen}");

    // The save writes the list in order.
    let value = d.form.field(JUMP_CHAIN).unwrap().value();
    assert_eq!(value, FieldValue::References(vec![id(INNER), id(OTHER)]));
    let mut host = sverb_core::model::Host::default();
    apply_changes(&mut host, &FieldChanges(vec![(JUMP_CHAIN.into(), value)])).unwrap();
    assert_eq!(host.jump_chain, [id(INNER), id(OTHER)]);

    // Remove one.
    key(&mut d.form, KeyCode::Char('d'), KeyModifiers::NONE);
    d.sync_inherited();
    assert_eq!(list(&d).ids(), [id(OTHER)]);
    assert_eq!(
        list(&d).note.as_deref(),
        Some("Effective route: you → other → target")
    );
}

/// Inline cycle validation: bastion jumping back through the edited host.
#[test]
fn t09_cycle_is_an_inline_error() {
    let d = dialog(catalog(&[TARGET]), &[INNER]);
    assert_eq!(
        list(&d).error.as_deref(),
        Some("Jump chain cycle: target → inner-bastion → bastion → target")
    );
    assert!(list(&d).note.is_none());
    assert_eq!(
        d.form.field(JUMP_CHAIN).unwrap().check(),
        Err("Jump chain cycle: target → inner-bastion → bastion → target".to_owned())
    );
    // Without the cycle the field is fine.
    let d = dialog(catalog(&[]), &[INNER]);
    assert_eq!(d.form.field(JUMP_CHAIN).unwrap().check(), Ok(()));
}

/// Copy as command: `-J` lists the effective chain (bastion before inner-bastion).
#[test]
fn copy_as_command_uses_the_effective_chain() {
    let c = catalog(&[]);
    let target = c.hosts.get(&id(TARGET)).unwrap();
    let cmd = ssh_command::render(&c.ssh_target(target));
    assert!(
        cmd.contains("-J ops@bastion.example,inner-bastion.example"),
        "{cmd}"
    );
    assert!(cmd.ends_with("deploy@target.example"), "{cmd}");
    let hops = c
        .effective_chain(target, &GlobalDefaults::default())
        .unwrap();
    assert_eq!(hops.len(), 2);
    // A cycle: the chain as configured.
    let c = catalog(&[TARGET]);
    let target = c.hosts.get(&id(TARGET)).unwrap();
    assert!(
        c.effective_chain(target, &GlobalDefaults::default())
            .is_err()
    );
    let cmd = ssh_command::render(&c.ssh_target(target));
    assert!(cmd.contains("-J inner-bastion.example"), "{cmd}");
}
