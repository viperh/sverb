//! M2-10 integration tests (SPEC §17.1): values typed on this device are approved at
//! save (T-03); a synced value needs approval, Allow stores it (T-04); a remote change
//! asks again (T-05). Small Argon2 parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sverb_conn::proxy::{Approval, COMMAND_FIELD, LocalApprovals, ValueOrigin};
use sverb_core::model::{
    DeviceId, HlcClock, Host, ItemBody, ItemId, ItemKind, Proxy, current_schema,
};
use sverb_core::resolve::approval::{ApprovalStatus, Decision, value_sha256};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, RemoteItem, Store};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::vault::items::ItemOps;
use sverb_tui::services::vault::{VaultEngine, VaultService};

const PW: &str = "correct horse battery staple violin";
const T0: i64 = 1_800_000_000_000;
const CMD: &str = "ssh -W %h:%p bastion";

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m2-10-{tag}-{}-{}",
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

fn host_with(cmd: &str) -> Host {
    Host {
        label: "db".into(),
        address: "db.example".into(),
        proxy: Some(Proxy::Command(cmd.into())),
        ..Host::default()
    }
}

/// The connector's check for the host's ProxyCommand (as `services::ssh` builds it).
fn check(service: &VaultService, item: ItemId, cmd: &str, here: DeviceId) -> Approval {
    let origin = ValueOrigin {
        item_id: Some(item),
        written_by: Some(here),
        this_device: Some(here),
    };
    service
        .store()
        .device_approvals()
        .check(COMMAND_FIELD, cmd, &origin)
}

/// Store `host` as if it arrived through sync from another device (`apply_remote`).
async fn apply_from_other_device(
    store: &Store,
    ops: &ItemOps,
    id: ItemId,
    host: &Host,
    revision: i64,
) {
    let vault = ops.vault().personal_vault().unwrap();
    let other = DeviceId::from_bytes([0xee; 16]);
    let mut body = match ops.load(id).await.unwrap() {
        Some(l) => l.body,
        None => ItemBody::new(ItemKind::Host, current_schema(ItemKind::Host)),
    };
    let mut clock = HlcClock::default();
    host.apply_to(&mut body, &mut clock, other);
    let (key_version, envelope) = ops.vault().seal(vault, id, &body).unwrap();
    store
        .apply_remote(
            vault,
            vec![RemoteItem {
                id,
                revision,
                key_version,
                envelope,
                deleted: false,
                local_pending: false,
            }],
            revision,
        )
        .await
        .unwrap();
}

// T-03
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_typed_on_this_device_is_approved_at_save() {
    let fx = Fixture::new("t03");
    let (service, ops) = ops(&fx).await;
    let here = ops.vault().device_id();
    let host = host_with(CMD);
    let written = ops
        .save(ItemKind::Host, None, None, move |body, clock, device| {
            host.apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();
    let rows = service.store().list_local_approvals().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].item_id, written.id);
    assert_eq!(rows[0].field, "proxy.command");
    assert_eq!(rows[0].value_sha256, value_sha256(CMD));
    // The connect proceeds without a prompt.
    assert_eq!(check(&service, written.id, CMD, here), Approval::Approved);
}

// T-04 + T-05
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_t05_synced_value_needs_approval_and_change_asks_again() {
    let fx = Fixture::new("t04");
    let (service, ops) = ops(&fx).await;
    let here = ops.vault().device_id();
    let id = ItemId::new();
    apply_from_other_device(service.store(), &ops, id, &host_with(CMD), 1).await;
    assert!(matches!(
        Host::try_from(&ops.load(id).await.unwrap().unwrap().body).unwrap().proxy,
        Some(Proxy::Command(c)) if c == CMD
    ));
    // Pauses: no row.
    assert_eq!(check(&service, id, CMD, here), Approval::NeedsApproval);
    let live = service.store().device_approvals();
    assert_eq!(
        live.decide(id, COMMAND_FIELD, CMD),
        Decision::Ask(ApprovalStatus::NeedsApproval)
    );
    // Editing an unrelated field on this device does not approve the synced value.
    ops.save(ItemKind::Host, Some(id), None, |body, clock, device| {
        let mut h = Host::try_from(&*body).unwrap();
        h.port = Some(2222);
        h.apply_to(body, clock, device);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(check(&service, id, CMD, here), Approval::NeedsApproval);

    // Allow → stored; the next connect has no prompt.
    live.approve(id, COMMAND_FIELD, CMD);
    assert_eq!(check(&service, id, CMD, here), Approval::Approved);
    let mut stored = false;
    for _ in 0..200 {
        let rows = service.store().list_local_approvals().await.unwrap();
        if rows.iter().any(|r| r.item_id == id) {
            stored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stored, "the approval row was not stored");

    // T-05: changed remotely → asks again.
    let changed = "ssh -W %h:%p evil-bastion";
    apply_from_other_device(service.store(), &ops, id, &host_with(changed), 2).await;
    assert_eq!(check(&service, id, changed, here), Approval::NeedsApproval);
    assert_eq!(
        live.decide(id, COMMAND_FIELD, changed),
        Decision::Ask(ApprovalStatus::ChangedSinceApproval)
    );
}
