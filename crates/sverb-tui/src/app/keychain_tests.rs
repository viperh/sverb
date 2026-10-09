//! "Use identity" / "Inline" toggle, identity CRUD requests, "Used by" and
//! "+ new identity".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::hosts::ItemEffect;
use super::{Config, Effect, EffectOutput, UiEvent, VaultEffect};
use crate::testing::AppHarness;
use crate::views::keychain::identity_form::IdentityDialog;
use crate::views::keychain::tests::{CACHE, DB1, OPS, WEB1, id, sample};
use crate::views::{DialogKind, Section};
use crate::widgets::form::{Field, FieldValue, FieldWidget};

fn item_effects(effects: &[Effect]) -> Vec<ItemEffect> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Vault(VaultEffect::Items(op)) => Some(op.clone()),
            _ => None,
        })
        .collect()
}

/// An app on the Keychain section with the sample identities and hosts.
fn keychain() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    let (index, cat) = sample();
    let cat = Arc::new(cat);
    // The index reaches both views (and the forms' pickers) the normal way.
    h.send(UiEvent::IndexUpdated(index));
    h.take_effects();
    let app = h.app_mut();
    app.views.keychain.set_catalog(Arc::clone(&cat));
    app.views.hosts.set_catalog(cat);
    app.open_section(Section::Keychain);
    // Keys is the default sub-tab; these tests are about Identities.
    app.views.keychain.tab = crate::views::keychain::KeychainTab::Identities;
    h
}

fn top(h: &AppHarness) -> &DialogKind {
    &h.app().dialogs().last().expect("a dialog").kind
}

#[test]
fn t03_delete_dialog_shows_direct_and_inherited_usage() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.identities.select(id(OPS)));
    h.keys("d");
    let DialogKind::Identity(IdentityDialog::Delete(d)) = top(&h) else {
        panic!("no delete dialog: {:?}", h.app().dialogs());
    };
    assert_eq!(d.usage.total(), 3);
    assert_eq!(d.usage.direct.len(), 2);
    assert_eq!(d.usage.inherited.len(), 1);
    assert_eq!(
        d.warning(),
        "This identity is used by 3 hosts (2 direct, 1 via group). They will fall back to \
         inherited or inline credentials."
    );
    let screen = h.render(120, 40);
    assert!(screen.contains("used by 3 hosts (2 direct,"), "{screen}");
    assert!(
        screen.contains("[ ] Convert to inline credentials"),
        "{screen}"
    );
    assert!(item_effects(h.effects()).is_empty());

    // Space toggles "convert"; Enter deletes.
    h.keys("space enter");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(
        item_effects(&h.take_effects()),
        [ItemEffect::DeleteIdentity {
            item: id(OPS),
            convert: true
        }]
    );
    // Esc cancels.
    h.keys("d esc");
    assert!(h.app().dialogs().is_empty());
    assert!(item_effects(&h.take_effects()).is_empty());
}

#[test]
fn add_edit_duplicate_requests() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.identities.select(id(OPS)));
    h.keys("y");
    assert_eq!(
        item_effects(&h.take_effects()),
        [ItemEffect::Duplicate(id(OPS))]
    );
    h.keys("e");
    let ops = item_effects(&h.take_effects());
    let [ItemEffect::LoadIdentity { id: eid, item }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_eq!(*item, id(OPS));
    let record = crate::views::keychain::identity_form::IdentityRecord {
        id: Some(id(OPS)),
        label: "ops".into(),
        username: "deploy".into(),
        ..Default::default()
    };
    h.send(UiEvent::EffectDone {
        id: *eid,
        result: Ok(EffectOutput::Identity(Box::new(record))),
    });
    let DialogKind::Identity(IdentityDialog::Form(f)) = top(&h) else {
        panic!("no form");
    };
    assert_eq!(f.item, Some(id(OPS)));
    assert_eq!(f.form.title, "Edit identity · ops");
    // Change the user and save: only `username` is sent.
    h.keys("tab ctrl-u r o o t ctrl-s");
    let ops = item_effects(&h.take_effects());
    let [ItemEffect::SaveIdentity { item, changes, .. }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_eq!(*item, Some(id(OPS)));
    assert_eq!(changes.keys(), ["username"]);
}

#[test]
fn used_by_jumps_to_the_host() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.identities.select(id(OPS)));
    h.keys("enter");
    let DialogKind::Identity(IdentityDialog::UsedBy(d)) = top(&h) else {
        panic!("no used-by dialog");
    };
    assert_eq!(d.hosts.len(), 3);
    assert_eq!(d.hosts[2].0, id(DB1));
    assert_eq!(d.hosts[2].2.as_deref(), Some("prod"));
    h.keys("j j enter");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(h.app().shell.section, Section::Hosts);
    assert_eq!(
        h.app()
            .views
            .hosts
            .list
            .selected_key()
            .and_then(|k| k.item()),
        Some(id(DB1))
    );
    let _ = (CACHE, WEB1);
}

fn field<'a>(h: &'a AppHarness, key: &str) -> &'a Field {
    let DialogKind::HostForm(d) = top(h) else {
        panic!("no host form");
    };
    d.form.field(key).unwrap()
}

fn focused(h: &AppHarness) -> String {
    let DialogKind::HostForm(d) = top(h) else {
        panic!("no host form");
    };
    d.form.focused_key().unwrap_or_default().to_owned()
}

#[test]
fn t06_use_identity_vs_inline_toggles_fields_and_keeps_the_override() {
    let mut h = keychain();
    h.app_mut().open_section(Section::Hosts);
    h.keys("a");
    // General has six fields; the credentials choice comes next.
    h.keys("tab tab tab tab tab tab");
    assert_eq!(focused(&h), "credentials");
    // A new host starts inline.
    assert!(field(&h, "identity_id").hidden);
    assert!(!field(&h, "password").hidden);
    assert!(!field(&h, "key_id").hidden);
    assert_eq!(field(&h, "username").label, "Username");

    // Type a user, then switch to "Use identity".
    h.keys("tab");
    assert_eq!(focused(&h), "username");
    h.keys("r o o t shift-tab left");
    assert_eq!(focused(&h), "credentials");
    assert!(!field(&h, "identity_id").hidden);
    assert!(field(&h, "password").hidden);
    assert!(field(&h, "key_id").hidden);
    assert_eq!(field(&h, "username").label, "Username override");
    assert_eq!(
        field(&h, "username").value(),
        FieldValue::Text("root".into())
    );
    // Tab goes to the identity picker, then the override.
    h.keys("tab");
    assert_eq!(focused(&h), "identity_id");
    h.keys("tab");
    assert_eq!(focused(&h), "username");

    // Back to inline: the username is still there.
    h.keys("shift-tab shift-tab right");
    assert!(field(&h, "identity_id").hidden);
    assert!(!field(&h, "password").hidden);
    assert_eq!(
        field(&h, "username").value(),
        FieldValue::Text("root".into())
    );
}

#[test]
fn identity_picker_is_limited_to_the_vault_and_offers_new_identity() {
    let mut h = keychain();
    h.app_mut().open_section(Section::Hosts);
    h.keys("a tab tab tab tab tab tab left tab enter");
    let DialogKind::HostForm(d) = top(&h) else {
        panic!("no host form");
    };
    let FieldWidget::Reference(r) = &d.form.field("identity_id").unwrap().widget else {
        panic!()
    };
    assert!(r.is_open());
    assert_eq!(r.vault(), Some(crate::views::keychain::tests::vault()));
    let labels: Vec<&str> = r.candidates().iter().map(|c| c.label.as_str()).collect();
    assert_eq!(labels, ["backup", "ops"]);
    // The last entry is "+ new identity": it opens the identity form on top.
    h.keys("down down enter");
    let host_form = h.app().dialogs()[0].id;
    let DialogKind::Identity(IdentityDialog::Form(f)) = top(&h) else {
        panic!("no identity form: {:?}", h.app().dialogs());
    };
    assert_eq!(f.for_host, Some(host_form));
    assert_eq!(f.item, None);
    h.keys("n e w ctrl-s");
    let ops = item_effects(&h.take_effects());
    let [ItemEffect::SaveIdentity { id: eid, vault, .. }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_eq!(*vault, Some(crate::views::keychain::tests::vault()));
    // Saved: the form closes and the host form references the new identity.
    h.send(UiEvent::EffectDone {
        id: *eid,
        result: Ok(EffectOutput::Item(id(77))),
    });
    assert_eq!(h.app().dialogs().len(), 1);
    assert_eq!(
        field(&h, "identity_id").value(),
        FieldValue::Reference(Some(id(77)))
    );
}

#[test]
fn switching_to_inline_clears_the_identity_on_save() {
    let mut h = keychain();
    h.app_mut().open_section(Section::Hosts);
    // Edit web-1 (direct identity): prefilled in "Use identity" mode.
    assert!(h.app_mut().views.hosts.select(id(WEB1)));
    h.keys("e");
    let ops = item_effects(&h.take_effects());
    let [ItemEffect::LoadHost { id: eid, .. }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    let record = crate::views::hosts::catalog::HostRecord {
        summary: h.app().views.hosts.host(id(WEB1)).unwrap().clone(),
        password: None,
    };
    h.send(UiEvent::EffectDone {
        id: *eid,
        result: Ok(EffectOutput::Host(Box::new(record))),
    });
    assert!(!field(&h, "identity_id").hidden);
    assert!(field(&h, "password").hidden);
    h.keys("tab tab tab tab tab tab right ctrl-s");
    let ops = item_effects(&h.take_effects());
    let [ItemEffect::Save { changes, .. }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_eq!(
        changes.get("identity_id"),
        Some(&FieldValue::Reference(None))
    );
}
