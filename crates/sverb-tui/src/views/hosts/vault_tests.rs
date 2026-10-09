//! , read-only forms for `read` members, "(your override)" in the
//! detail pane.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use sverb_core::model::{
    CredentialOverride, DeviceId, HlcClock, Host, ItemBody, ItemId, ItemKind, VaultId,
};
use sverb_core::resolve::overrides::OverrideLayer;
use sverb_core::search::ItemIndex;

use super::catalog::{HostCatalog, HostSummary};
use super::form::{HostFormFeatures, HostFormInit, host_form};
use super::*;
use crate::widgets::form::ReadOnly;

fn id(n: u8) -> ItemId {
    let mut b = [0u8; 16];
    b[15] = n;
    ItemId::from_bytes(b)
}

const PERSONAL: VaultId = VaultId::from_bytes([1; 16]);
const OPS: VaultId = VaultId::from_bytes([2; 16]);

/// `laptop` (personal), `prod-db` and `prod-web` (shared "Ops").
fn fixture() -> (Arc<sverb_core::search::IndexSnapshot>, HostCatalog) {
    let mut clock = HlcClock::default();
    let device = DeviceId::from_bytes([1; 16]);
    let mut cat = HostCatalog {
        personal_vault: Some(PERSONAL),
        ..HostCatalog::default()
    };
    cat.vault_names.insert(PERSONAL, "Personal".into());
    cat.vault_names.insert(OPS, "Ops".into());
    cat.shared_vaults.insert(OPS);
    let mut bodies = Vec::new();
    for (n, label, vault) in [
        (1, "laptop", PERSONAL),
        (2, "prod-db", OPS),
        (3, "prod-web", OPS),
    ] {
        let host = Host {
            label: label.into(),
            address: format!("{label}.example"),
            username: Some("deploy".into()),
            ..Host::default()
        };
        let mut b = ItemBody::new(ItemKind::Host, 1);
        host.apply_to(&mut b, &mut clock, device);
        cat.hosts
            .insert(id(n), HostSummary::from_host(id(n), vault, &host, None));
        bodies.push((id(n), vault, b));
    }
    let mut ix = ItemIndex::build(bodies.iter().map(|(i, v, b)| (*i, *v, b)));
    ix.set_vault_name(PERSONAL, "Personal");
    ix.set_vault_name(OPS, "Ops");
    (ix.snapshot(), cat)
}

fn labels(rows: &[HostRow]) -> Vec<(String, Option<String>)> {
    rows.iter()
        .filter(|r| matches!(r.key, HostRowKey::Host(_)))
        .map(|r| (r.label.clone(), r.vault.clone()))
        .collect()
}

// "All vaults" shows every host with a badge on shared ones; selecting a
// vault filters; the top bar label follows.
#[test]
fn t05_badges_and_selector() {
    let (index, cat) = fixture();
    let all = labels(&HostsView::rows(Some(&index), Some(&cat)));
    assert_eq!(all.len(), 3);
    assert!(all.contains(&("laptop".into(), None)));
    assert!(all.contains(&("prod-db".into(), Some("Ops".into()))));

    let mut view = HostsView::default();
    view.set_index(index);
    view.set_catalog(Arc::new(cat));
    assert_eq!(view.vault_label(), "All vaults");
    let press = |v: &mut HostsView| v.on_action_key(KeyCode::Char('V'), KeyModifiers::NONE);
    assert_eq!(
        press(&mut view),
        Some(HostsRequest::VaultSelected(Some(PERSONAL)))
    );
    assert_eq!(view.vault_label(), "Personal");
    assert_eq!(labels(view.list.rows()), vec![("laptop".to_owned(), None)]);
    assert_eq!(
        press(&mut view),
        Some(HostsRequest::VaultSelected(Some(OPS)))
    );
    assert_eq!(view.vault_label(), "Ops");
    let ops: Vec<String> = labels(view.list.rows())
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(ops.len(), 2);
    assert!(ops.iter().all(|l| l.starts_with("prod-")));
    // Filtered to one vault: no badges.
    assert!(labels(view.list.rows()).iter().all(|(_, b)| b.is_none()));
    assert_eq!(press(&mut view), Some(HostsRequest::VaultSelected(None)));
    assert_eq!(view.vault_label(), "All vaults");
    assert_eq!(labels(view.list.rows()).len(), 3);
}

#[test]
fn selector_needs_a_shared_vault() {
    let (index, mut cat) = fixture();
    cat.vault_names.remove(&OPS);
    let mut view = HostsView::default();
    view.set_index(index);
    view.set_catalog(Arc::new(cat));
    assert_eq!(view.vault_label(), "Personal");
    assert_eq!(
        view.on_action_key(KeyCode::Char('V'), KeyModifiers::NONE),
        None
    );
}

// A `read` member's host form is read-only with the "Read-only vault" badge.
#[test]
fn t04_read_only_form() {
    let (_, mut cat) = fixture();
    let summary = cat.hosts[&id(2)].clone();
    let init = HostFormInit {
        item: Some(id(2)),
        summary,
        password: None,
    };
    let form = host_form(&init, Some(&cat), None, &[], 30, HostFormFeatures::ALL);
    assert_eq!(form.read_only_reason(), None);
    cat.read_only_vaults.insert(OPS);
    let form = host_form(&init, Some(&cat), None, &[], 30, HostFormFeatures::ALL);
    assert_eq!(form.read_only_reason(), Some(ReadOnly::Vault));
    assert_eq!(ReadOnly::Vault.banner(), "Read-only vault");
    // `O` is offered on shared hosts only.
    let (index, cat) = fixture();
    let mut view = HostsView::default();
    view.set_index(index);
    view.set_catalog(Arc::new(cat));
    assert!(view.select(id(1)));
    assert_eq!(
        view.on_action_key(KeyCode::Char('O'), KeyModifiers::NONE),
        None
    );
    assert!(view.select(id(2)));
    assert_eq!(
        view.on_action_key(KeyCode::Char('O'), KeyModifiers::NONE),
        Some(HostsRequest::Override(id(2)))
    );
}

// The detail pane shows the override's user with "(your override)".
#[test]
fn t07_detail_shows_your_override() {
    let (index, mut cat) = fixture();
    let mut o = CredentialOverride::new(id(2));
    o.username = Some("bob".into());
    cat.overrides.insert(id(2), OverrideLayer::new(id(50), &o));
    let r = cat.resolve(
        &cat.hosts[&id(2)],
        &sverb_core::resolve::GlobalDefaults::default(),
    );
    assert_eq!(r.username.as_deref(), Some("bob"));
    let mut view = HostsView::default();
    view.set_index(index);
    view.set_catalog(Arc::new(cat));
    assert!(view.select(id(2)));
    let row = view.list.selected().unwrap().clone();
    let theme = crate::theme::Theme::default();
    let lines = HostDetail {
        catalog: view.catalog().map(|c| &**c),
    }
    .lines(&row, &theme, 80);
    let text: Vec<String> = lines
        .iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
        .collect();
    assert!(
        text.iter().any(|l| l.contains("bob (your override)")),
        "{text:#?}"
    );
    assert!(
        text.iter()
            .any(|l| l.contains("your override (personal vault)"))
    );
    // Another host keeps the shared user.
    assert!(view.select(id(3)));
    let row = view.list.selected().unwrap().clone();
    let lines = HostDetail {
        catalog: view.catalog().map(|c| &**c),
    }
    .lines(&row, &theme, 80);
    let text: String = lines
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
        .collect();
    assert!(text.contains("deploy") && !text.contains("your override"));
}
