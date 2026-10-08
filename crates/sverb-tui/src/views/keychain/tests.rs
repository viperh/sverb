//! M2-02 view tests: the Identities sub-tab (rows, usage, detail) and its snapshot
//! (T-09). [`sample`] is shared with the reducer tests (`app/keychain_tests.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ratatui::layout::Rect;
use sverb_core::model::{
    DeviceId, Group, HlcClock, Host, HostDefaults, Identity, ItemBody, ItemId, ItemKind, VaultId,
};
use sverb_core::search::{IndexSnapshot, ItemIndex};
use sverb_core::secret::SecretString;

use super::KeychainView;
use crate::views::View as _;
use crate::views::hosts::catalog::{HostCatalog, HostSummary, IdentityInfo};
use crate::views::shell::{ShellState, layout};
use crate::widgets::test_util::{draw_with, keys, text};

pub(crate) fn id(n: u8) -> ItemId {
    let mut b = [0u8; 16];
    b[15] = n;
    ItemId::from_bytes(b)
}

pub(crate) fn vault() -> VaultId {
    VaultId::from_bytes([9; 16])
}

/// Ids in [`sample`].
pub(crate) const OPS: u8 = 1;
pub(crate) const BACKUP: u8 = 2;
pub(crate) const KEY: u8 = 3;
pub(crate) const PROD: u8 = 4;
pub(crate) const WEB1: u8 = 11;
pub(crate) const WEB2: u8 = 12;
pub(crate) const DB1: u8 = 13;
pub(crate) const CACHE: u8 = 14;

/// Identities "ops" (deploy, password + key "laptop") and "backup" (no auth); group
/// "prod" defaults to "ops"; hosts web-1 and web-2 use "ops" directly, db-1 through
/// "prod", cache uses none.
pub(crate) fn sample() -> (Arc<IndexSnapshot>, HostCatalog) {
    let mut clock = HlcClock::default();
    let device = DeviceId::from_bytes([1; 16]);
    let mut bodies: Vec<(ItemId, ItemBody)> = Vec::new();
    let mut cat = HostCatalog {
        personal_vault: Some(vault()),
        ..HostCatalog::default()
    };
    cat.vault_names.insert(vault(), "Personal".into());
    cat.keys.insert(id(KEY), "laptop".into());
    cat.lookup.mark_live(id(KEY));
    for (n, label, user, pw, key) in [
        (OPS, "ops", "deploy", Some("s3cret"), Some(id(KEY))),
        (BACKUP, "backup", "bk", None, None),
    ] {
        let i = Identity {
            label: label.into(),
            username: user.into(),
            password: pw.map(SecretString::from),
            key_id: key,
            read_only: false,
        };
        let mut b = ItemBody::new(ItemKind::Identity, 1);
        i.apply_to(&mut b, &mut clock, device);
        bodies.push((id(n), b));
        cat.lookup.insert_identity(id(n), &i);
        cat.lookup.mark_live(id(n));
        cat.identities.insert(
            id(n),
            IdentityInfo {
                label: label.into(),
                username: user.into(),
                key_id: key,
            },
        );
    }
    let g = Group {
        name: "prod".into(),
        defaults: HostDefaults {
            identity_id: Some(id(OPS)),
            ..HostDefaults::default()
        },
        ..Group::default()
    };
    cat.lookup.insert_group(id(PROD), vault(), &g);
    cat.lookup.mark_live(id(PROD));
    cat.groups.insert(id(PROD), "prod".into());
    cat.group_vaults.insert(id(PROD), vault());
    for (n, label, identity, group) in [
        (WEB1, "web-1", Some(OPS), None),
        (WEB2, "web-2", Some(OPS), None),
        (DB1, "db-1", None, Some(PROD)),
        (CACHE, "cache", None, None),
    ] {
        let h = Host {
            label: label.into(),
            address: format!("{label}.example"),
            identity_id: identity.map(id),
            group_id: group.map(id),
            ..Host::default()
        };
        let mut b = ItemBody::new(ItemKind::Host, 1);
        h.apply_to(&mut b, &mut clock, device);
        bodies.push((id(n), b));
        cat.lookup.mark_live(id(n));
        cat.hosts
            .insert(id(n), HostSummary::from_host(id(n), vault(), &h, None));
    }
    let mut ix = ItemIndex::build(bodies.iter().map(|(i, b)| (*i, vault(), b)));
    (ix.snapshot(), cat)
}

pub(crate) fn view() -> KeychainView {
    let (index, cat) = sample();
    let mut v = KeychainView::default();
    v.set_index(index);
    v.set_catalog(Arc::new(cat));
    // M2-03: Keys is the default sub-tab; these tests are about Identities.
    v.tab = super::KeychainTab::Identities;
    v
}

fn draw_view(v: &KeychainView, w: u16, h: u16) -> String {
    let rects = layout(
        Rect::new(0, 0, w, h),
        &ShellState::default(),
        &crate::app::Config::default(),
    );
    text(&draw_with(w, h, true, |frame, cx| {
        v.render(frame, rects.main, cx);
        if let Some(d) = rects.detail {
            v.render_detail(frame, d, cx);
        }
    }))
}

#[test]
fn rows_show_user_auth_and_usage() {
    let v = view();
    let rows = v.identities.list.rows();
    assert_eq!(rows.len(), 2);
    // Alphabetical: backup, ops.
    assert_eq!(rows[0].label, "backup");
    assert_eq!(rows[0].auth, "none");
    assert_eq!(rows[0].used, 0);
    assert_eq!(rows[1].label, "ops");
    assert_eq!(rows[1].username, "deploy");
    assert_eq!(rows[1].auth, "password + key");
    assert_eq!(rows[1].used, 3);
    let usage = v.identities.usage(id(OPS));
    assert_eq!(usage.direct, [id(WEB1), id(WEB2)]);
    assert_eq!(usage.inherited, [id(DB1)]);
}

#[test]
fn filter_searches_label_and_user_and_tabs_switch() {
    let mut v = view();
    keys(&mut v, "/ d e p l o y enter");
    let shown: Vec<String> = v
        .identities
        .list
        .visible_rows()
        .map(|r| r.label.clone())
        .collect();
    assert_eq!(shown, ["ops"]);
    keys(&mut v, "]");
    assert_eq!(v.tab, super::KeychainTab::Keys);
    keys(&mut v, "[");
    assert_eq!(v.tab, super::KeychainTab::Identities);
}

#[test]
fn action_keys_become_requests() {
    use super::KeychainRequest::Identity as R;
    use super::identities::IdentityRequest as I;
    let mut v = view();
    v.identities.select(id(OPS));
    for (k, want) in [
        ("a", I::Add),
        ("e", I::Edit(id(OPS))),
        ("y", I::Duplicate(vec![id(OPS)])),
        ("d", I::Delete(id(OPS))),
        ("enter", I::UsedBy(id(OPS))),
    ] {
        keys(&mut v, k);
        assert_eq!(v.take_request(), Some(R(want)), "{k}");
    }
}

#[test]
fn identities_view_never_panics_on_tiny_areas() {
    let v = view();
    for (w, h) in [(0, 0), (1, 1), (3, 2), (10, 4), (40, 10)] {
        let _ = text(&draw_with(w, h, true, |frame, cx| {
            v.render(frame, Rect::new(0, 0, w, h), cx);
            v.render_detail(frame, Rect::new(0, 0, w, h), cx);
        }));
    }
}

// M2-02 T-09
#[test]
fn t09_identities_sub_tab_160x48() {
    let mut v = view();
    assert!(v.identities.select(id(OPS)));
    let screen = draw_view(&v, 160, 48);
    for needle in [
        "Identities",
        "deploy",
        "password + key",
        "3 hosts",
        "Used by 3 hosts",
        "(2 direct, 1 via group)",
        "web-1",
        "db-1 (via prod)",
    ] {
        assert!(screen.contains(needle), "{needle}: {screen}");
    }
    assert!(!screen.contains("s3cret"));
    insta::assert_snapshot!("t09_identities_160x48", screen);
}

// ---------------------------------------------------------------- M2-03

pub(crate) const CERT: u8 = 20;
pub(crate) const YUBI: u8 = 21;
pub(crate) const CI: u8 = 22;

/// The fixture certificate's `valid_before` (2036-01-01T00:00:00Z).
pub(crate) const CERT_END: i64 = 2_082_758_400;

const ID_CERT_PUB: &str = include_str!("../../../../../tests/fixtures/keys/id_cert.pub");
const ID_CERT: &str = include_str!("../../../../../tests/fixtures/keys/id_cert-cert.pub");
const AGENT_PUB: &str = include_str!("../../../../../tests/fixtures/keys/agent_ref.pub");
const ECDSA_PUB_KEY: &str = include_str!("../../../../../tests/fixtures/keys/user_ca.pub");

/// Keys "laptop" (Ed25519, the fixture certificate attached, used by identity "ops"),
/// "yubikey" (an agent reference) and "ci" (encrypted, forwardable); the catalog was
/// built 3 days before the certificate expires.
pub(crate) fn add_sample_keys(cat: &mut HostCatalog) {
    use super::keys::{CertSummary, KeyInfo};
    use sverb_core::keychain::{cert::parse_cert, fingerprint};
    use sverb_core::model::KeyAlgorithm;
    cat.loaded_at = (CERT_END - 3 * 86_400) * 1000;
    let info = |label: &str, public: &str| KeyInfo {
        vault: vault(),
        label: label.into(),
        algorithm: KeyAlgorithm::Ed25519,
        public_key: public.trim().into(),
        fingerprint: fingerprint(public).unwrap(),
        agent_ref: false,
        encrypted: false,
        has_passphrase: false,
        agent_forwardable: false,
        confirm_on_use: false,
        certificate_ids: Vec::new(),
    };
    let mut laptop = info("laptop", ID_CERT_PUB);
    laptop.certificate_ids = vec![id(CERT)];
    cat.key_details.insert(id(KEY), laptop);
    let mut yubi = info("yubikey", AGENT_PUB);
    yubi.agent_ref = true;
    cat.key_details.insert(id(YUBI), yubi);
    cat.keys.insert(id(YUBI), "yubikey".into());
    let mut ci = info("ci", ECDSA_PUB_KEY);
    ci.encrypted = true;
    ci.has_passphrase = true;
    ci.agent_forwardable = true;
    cat.key_details.insert(id(CI), ci);
    cat.keys.insert(id(CI), "ci".into());
    cat.certs.insert(
        id(CERT),
        CertSummary {
            vault: vault(),
            label: "alice@sverb".into(),
            key_id: Some(id(KEY)),
            cert: ID_CERT.trim().into(),
            info: Some(parse_cert(ID_CERT).unwrap()),
        },
    );
}

pub(crate) fn keys_view() -> KeychainView {
    let (index, mut cat) = sample();
    add_sample_keys(&mut cat);
    let mut v = KeychainView::default();
    v.set_index(index);
    v.set_catalog(Arc::new(cat));
    v.keys.utc_offset_secs = Some(0);
    v.certs.utc_offset_secs = Some(0);
    v
}

#[test]
fn m2_03_key_rows_flags_badges_usage() {
    use sverb_core::keychain::cert::ExpiryBadge;
    let v = keys_view();
    assert_eq!(v.tab, super::KeychainTab::Keys);
    let rows = v.keys.list.rows();
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["ci", "laptop", "yubikey"]);
    assert_eq!(rows[0].flags, ["enc", "fwd"]);
    assert_eq!(rows[1].badge, ExpiryBadge::Expiring);
    assert_eq!(rows[1].certs, 1);
    // Identity "ops" uses "laptop" (its hosts resolve to it through the identity too).
    assert_eq!(v.keys.usage(id(KEY)).identities, [id(OPS)]);
    assert!(rows[1].used >= 1);
    assert_eq!(rows[2].flags, ["agent"]);
    // Certificates tab.
    let certs = v.certs.list.rows();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].key, "laptop");
    assert_eq!(certs[0].principals, "alice,bob");
    assert_eq!(certs[0].badge, ExpiryBadge::Expiring);
}

#[test]
fn m2_03_key_action_keys_become_requests() {
    use super::KeychainRequest::{Cert as C, Key as R};
    use super::certs::CertRequest;
    use super::keys::KeyRequest as K;
    let mut v = keys_view();
    assert!(v.keys.select(id(KEY)));
    for (k, want) in [
        ("a", K::Generate),
        ("I", K::ImportFile),
        ("p", K::ImportPaste),
        ("c", K::CopyPublic(id(KEY))),
        ("x", K::ExportPublic(id(KEY))),
        ("X", K::ExportPrivate(id(KEY))),
        ("P", K::ChangePassphrase(id(KEY))),
        ("t", K::AttachCert(id(KEY))),
        ("f", K::ToggleForwardable(id(KEY))),
        ("o", K::ToggleConfirm(id(KEY))),
        ("H", K::Install(id(KEY))),
        ("d", K::Delete(id(KEY))),
    ] {
        keys(&mut v, k);
        assert_eq!(v.take_request(), Some(R(want)), "{k}");
    }
    keys(&mut v, "]");
    assert_eq!(v.tab, super::KeychainTab::Certificates);
    for (k, want) in [
        ("a", CertRequest::Import),
        ("c", CertRequest::Copy(id(CERT))),
        ("d", CertRequest::Delete(id(CERT))),
    ] {
        keys(&mut v, k);
        assert_eq!(v.take_request(), Some(C(want)), "{k}");
    }
}

#[test]
fn m2_03_views_never_panic_on_tiny_areas() {
    let mut v = keys_view();
    for tab in super::KeychainTab::ALL {
        v.tab = tab;
        for (w, h) in [(0, 0), (1, 1), (3, 2), (10, 4), (40, 10)] {
            let _ = text(&draw_with(w, h, true, |frame, cx| {
                v.render(frame, Rect::new(0, 0, w, h), cx);
                v.render_detail(frame, Rect::new(0, 0, w, h), cx);
            }));
        }
    }
}

// M2-03 T-14
#[test]
fn t14_keys_tab_with_expiring_cert_badge_160x48() {
    let mut v = keys_view();
    assert!(v.keys.select(id(KEY)));
    let screen = draw_view(&v, 160, 48);
    for needle in [
        "[Keys]",
        "laptop [expiring]",
        "yubikey",
        "agent",
        "SHA256:",
        "1 certificate",
        "alice@sverb [expiring]",
        "until 2036-01-01 00:00",
    ] {
        assert!(screen.contains(needle), "{needle}: {screen}");
    }
    assert!(!screen.contains("PRIVATE KEY"));
    insta::assert_snapshot!("t14_keys_160x48", screen);
}

#[test]
fn m2_03_certificates_detail_shows_derived_fields() {
    let mut v = keys_view();
    v.tab = super::KeychainTab::Certificates;
    let screen = draw_view(&v, 160, 48);
    for needle in [
        "alice@sverb",
        "Principals  alice,bob",
        "Serial      42",
        "Valid from  2026-01-01 00:00",
        "Valid until 2036-01-01 00:00 [expiring]",
        "SHA256:bvVu7QD3xxOu",
    ] {
        assert!(screen.contains(needle), "{needle}: {screen}");
    }
}
