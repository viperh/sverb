//! M2-01 integration tests: groups, tags and vault defaults through the item service
//! (the writes behind T-06, T-07, T-09, T-10 and T-12). Small Argon2 parameters,
//! in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::model::{Group, Host, ItemId, Tag, group::DeleteGroupMode};
use sverb_core::resolve::{GlobalDefaults, SettingKey, Source};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::vault::items::{ItemError, ItemOps};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::widgets::form::{FieldChanges, FieldValue};

const PW: &str = "correct horse battery staple violin";
const T0: i64 = 1_800_000_000_000;

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m2-01-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            clock: Arc::new(ManualClock::new(T0)),
            keyring: MemKeyring::new(),
        }
    }

    fn engine(&self) -> VaultEngine {
        let store = Store::open_at(self.dir.join("sverb.db"), self.clock.clone()).unwrap();
        VaultEngine::new(store, Arc::new(self.keyring.clone()), Argon2Cost::TEST)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn ops(fx: &Fixture) -> (VaultService, ItemOps) {
    fx.engine().initialize(PW, false).await.unwrap();
    let service = VaultService::new(fx.engine());
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    service.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &tx,
    );
    while let Some(ev) = rx.recv().await {
        if matches!(ev, UiEvent::IndexUpdated(_)) {
            break;
        }
    }
    let ops = service.item_ops().unwrap();
    (service, ops)
}

fn changes(pairs: &[(&str, FieldValue)]) -> FieldChanges {
    FieldChanges(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.to_owned())
}

async fn group(ops: &ItemOps, name: &str, parent: Option<ItemId>, port: Option<u64>) -> ItemId {
    ops.save_group(
        None,
        changes(&[
            ("name", text(name)),
            ("parent_id", FieldValue::Reference(parent)),
            ("port", FieldValue::Number(port)),
        ]),
    )
    .await
    .unwrap()
    .id
}

async fn host(ops: &ItemOps, label: &str, group: Option<ItemId>) -> ItemId {
    ops.save_host(
        None,
        changes(&[
            ("label", text(label)),
            ("address", text(&format!("{label}.example"))),
            ("group_id", FieldValue::Reference(group)),
        ]),
    )
    .await
    .unwrap()
    .id
}

async fn host_view(ops: &ItemOps, id: ItemId) -> Option<Host> {
    let l = ops.load(id).await.unwrap()?;
    Some(Host::try_from(&l.body).unwrap())
}

async fn group_view(ops: &ItemOps, id: ItemId) -> Option<Group> {
    let l = ops.load(id).await.unwrap()?;
    Some(Group::try_from(&l.body).unwrap())
}

// M2-01 T-06 (the writes)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_delete_group_moves_hosts_and_subgroups_to_the_parent() {
    let fx = Fixture::new("t06");
    let (_s, ops) = ops(&fx).await;
    let root = group(&ops, "root", None, None).await;
    let prod = group(&ops, "prod", Some(root), Some(2222)).await;
    let sub = group(&ops, "sub", Some(prod), None).await;
    let a = host(&ops, "a", Some(prod)).await;
    let b = host(&ops, "b", Some(sub)).await;
    let c = host(&ops, "c", None).await;

    ops.delete_group(prod, DeleteGroupMode::MoveToParent)
        .await
        .unwrap();
    assert!(group_view(&ops, prod).await.is_none(), "deleted");
    assert_eq!(host_view(&ops, a).await.unwrap().group_id, Some(root));
    assert_eq!(group_view(&ops, sub).await.unwrap().parent_id, Some(root));
    assert_eq!(host_view(&ops, b).await.unwrap().group_id, Some(sub));
    assert_eq!(host_view(&ops, c).await.unwrap().group_id, None);
}

// M2-01 T-07 (the writes)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_delete_group_and_everything_below() {
    let fx = Fixture::new("t07");
    let (_s, ops) = ops(&fx).await;
    let prod = group(&ops, "prod", None, None).await;
    let sub = group(&ops, "sub", Some(prod), None).await;
    let a = host(&ops, "a", Some(prod)).await;
    let b = host(&ops, "b", Some(sub)).await;
    let c = host(&ops, "c", None).await;
    let plan = ops
        .plan_group_delete(prod, DeleteGroupMode::DeleteAll)
        .await
        .unwrap();
    assert_eq!(plan.deleted_contents(), 3);
    ops.delete_group(prod, DeleteGroupMode::DeleteAll)
        .await
        .unwrap();
    for id in [a, b] {
        assert!(host_view(&ops, id).await.is_none());
    }
    assert!(group_view(&ops, sub).await.is_none());
    assert!(host_view(&ops, c).await.is_some());
}

// M2-01 T-10 (the writes)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_bulk_tags_change_only_the_tags_field() {
    let fx = Fixture::new("t10");
    let (_s, ops) = ops(&fx).await;
    let web = ops
        .save_tag(None, "web".into(), Some("green".into()))
        .await
        .unwrap()
        .id;
    let mut hosts = Vec::new();
    for i in 0..5 {
        let id = host(&ops, &format!("h{i}"), None).await;
        if i % 2 == 0 {
            ops.set_tags(&[id], &[web], &[], None).await.unwrap();
        }
        hosts.push(id);
    }
    let mut before = Vec::new();
    for id in &hosts {
        before.push(ops.load(*id).await.unwrap().unwrap().body);
    }
    let ws = ops
        .set_tags(&hosts, &[], &[web], Some("DB".into()))
        .await
        .unwrap();
    let db = ws[0].id;
    assert_eq!(
        Tag::try_from(&ws[0].body).unwrap().name,
        "DB",
        "the new tag is written first"
    );
    for (id, old) in hosts.iter().zip(before) {
        let now = ops.load(*id).await.unwrap().unwrap().body;
        assert_eq!(Host::try_from(&now).unwrap().tags, vec![db]);
        for (k, v) in &now.fields {
            if k != "tags" {
                assert_eq!(Some(v), old.get_stamped(k), "{k} changed");
            }
        }
    }
    // An inline "db" reuses the existing tag (case-insensitive).
    let ws = ops
        .set_tags(&hosts[..1], &[], &[], Some("db".into()))
        .await
        .unwrap();
    assert_eq!(ws.len(), 1, "no new tag");
}

// M2-01 T-09 (the service refuses duplicates too)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_tag_names_are_unique_per_vault() {
    let fx = Fixture::new("t09");
    let (_s, ops) = ops(&fx).await;
    let prod = ops.save_tag(None, "prod".into(), None).await.unwrap().id;
    let dup = ops.save_tag(None, "PROD".into(), None).await;
    assert!(matches!(dup, Err(ItemError::Invalid(_))), "{dup:?}");
    // Renaming in place (another case) and recoloring are fine.
    ops.save_tag(Some(prod), "Prod".into(), Some("red".into()))
        .await
        .unwrap();
    let bad = ops
        .save_tag(None, "x".into(), Some("chartreuse".into()))
        .await;
    assert!(matches!(bad, Err(ItemError::Invalid(_))));
    // Deleting a tag leaves the stale id on hosts; the catalog ignores it.
    let h = host(&ops, "a", None).await;
    ops.set_tags(&[h], &[prod], &[], None).await.unwrap();
    ops.delete(prod).await.unwrap();
    let cat = ops.catalog().await.unwrap();
    assert!(cat.tags_of(&cat.hosts[&h]).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_cycles_are_rejected_on_save() {
    let fx = Fixture::new("cycle");
    let (_s, ops) = ops(&fx).await;
    let a = group(&ops, "a", None, None).await;
    let b = group(&ops, "b", Some(a), None).await;
    let r = ops
        .save_group(
            Some(a),
            changes(&[("parent_id", FieldValue::Reference(Some(b)))]),
        )
        .await;
    assert!(matches!(r, Err(ItemError::Invalid(_))), "{r:?}");
    let r = ops
        .save_group(Some(a), changes(&[("name", text(" "))]))
        .await;
    assert!(matches!(r, Err(ItemError::Invalid(_))));
}

// M2-01 T-12 (the catalog side): resolution follows the stored group defaults, and
// vault defaults (a reserved group item) sit below the groups.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_resolves_groups_and_vault_defaults() {
    let fx = Fixture::new("resolve");
    let (_s, ops) = ops(&fx).await;
    let prod = group(&ops, "prod", None, Some(2222)).await;
    let a = host(&ops, "a", Some(prod)).await;
    let b = host(&ops, "b", None).await;
    ops.save_group(
        None,
        changes(&[
            ("is_vault_defaults", FieldValue::Bool(true)),
            ("name", text("Vault defaults")),
            ("keepalive_secs", FieldValue::Number(Some(77))),
            ("port", FieldValue::Number(Some(2022))),
        ]),
    )
    .await
    .unwrap();
    let cat = ops.catalog().await.unwrap();
    assert!(
        !cat.groups.values().any(|g| g == "Vault defaults"),
        "not a tree node"
    );
    let g = GlobalDefaults::default();
    let ra = cat.resolve(&cat.hosts[&a], &g);
    assert_eq!(ra.port, 2222);
    assert_eq!(ra.keepalive_secs, 77);
    assert_eq!(ra.source(SettingKey::KeepaliveSecs), &Source::VaultDefaults);
    let rb = cat.resolve(&cat.hosts[&b], &g);
    assert_eq!(rb.port, 2022);

    // The group's default changes: the next resolution sees it.
    ops.save_group(
        Some(prod),
        changes(&[("port", FieldValue::Number(Some(3333)))]),
    )
    .await
    .unwrap();
    let cat2 = ops.catalog().await.unwrap();
    assert_eq!(cat2.resolve(&cat2.hosts[&a], &g).port, 3333);
    assert_eq!(ra.port, 2222, "an earlier resolution is a snapshot");

    // Moving the host out of the group: the vault default applies.
    ops.move_to_group(&[a], None).await.unwrap();
    let cat3 = ops.catalog().await.unwrap();
    assert_eq!(cat3.resolve(&cat3.hosts[&a], &g).port, 2022);
    // A deleted group reads as none (§12.4).
    ops.move_to_group(&[a], Some(prod)).await.unwrap();
    ops.delete(prod).await.unwrap();
    let cat4 = ops.catalog().await.unwrap();
    let r = cat4.resolve(&cat4.hosts[&a], &g);
    assert!(r.missing_group());
    assert_eq!(r.port, 2022);
}
