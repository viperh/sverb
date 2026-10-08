//! M4-07 T-05 (unit, mock server): a server that answers every push with
//! `conflict` → after 5 rounds the status is `error` and the item stays
//! dirty.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use common::{Device, seal};
use parking_lot::Mutex;
use sverb_core::model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::random::{os_rng, random_key32};
use sverb_proto::auth::TokenPair;
use sverb_proto::sync::{
    Permission, PullResponse, PushRequest, PushResponse, PushResult, PushStatus, RemoteItem,
    VaultKind, VaultView,
};
use sverb_sync::{MAX_CONFLICT_ROUNDS, SyncStatus, TokenManager};

#[derive(Clone)]
struct Mock {
    vault: VaultId,
    vk: Key32,
    pushes: Arc<AtomicU64>,
    hlc: Arc<Mutex<HlcClock>>,
    device: DeviceId,
}

async fn vaults(State(m): State<Mock>) -> Json<Vec<VaultView>> {
    Json(vec![VaultView {
        id: m.vault.uuid(),
        kind: VaultKind::Personal,
        org_id: None,
        name_enc: vec![1],
        key_version: 1,
        head_revision: 0,
        permission: Permission::Manage,
        grants: vec![],
        rotation: None,
    }])
}

async fn pull() -> Json<PullResponse> {
    Json(PullResponse {
        items: vec![],
        head_revision: 0,
        more: false,
    })
}

/// Always a conflict, with a server copy newer than anything before.
async fn push(State(m): State<Mock>, Json(req): Json<PushRequest>) -> Json<PushResponse> {
    let n = m.pushes.fetch_add(1, Ordering::SeqCst) + 1;
    let results = req
        .changes
        .iter()
        .map(|c| {
            let id = ItemId::from_uuid(c.id);
            let mut body = ItemBody::new(ItemKind::Host, 1);
            {
                let mut clock = m.hlc.lock();
                body.set("label", "server", &mut clock, m.device);
                body.set(
                    "port",
                    format!("{}", 1000 + n).as_str(),
                    &mut clock,
                    m.device,
                );
            }
            PushResult {
                id: c.id,
                status: PushStatus::Conflict,
                revision: None,
                current: Some(RemoteItem {
                    id: c.id,
                    revision: n,
                    key_version: 1,
                    envelope: seal(&m.vk, m.vault, id, 1, &body),
                    deleted: false,
                }),
                message: None,
            }
        })
        .collect();
    Json(PushResponse { results })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_persistent_conflicts_surface_after_five_rounds() {
    let vault = VaultId::new();
    let vk = random_key32(&mut os_rng());
    let dev = Device::new(vault, &vk).await;
    let mock = Mock {
        vault,
        vk: vk.clone(),
        pushes: Arc::new(AtomicU64::new(0)),
        hlc: Arc::new(Mutex::new(HlcClock::default())),
        device: DeviceId::new(),
    };
    let app = Router::new()
        .route("/v1/vaults", get(vaults))
        .route("/v1/vaults/{id}/changes", get(pull).post(push))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let pair = TokenPair {
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        access_expires_in_s: 900,
        refresh_expires_in_s: 86_400,
    };
    TokenManager::save_login(&dev.store, &dev.lmk, &format!("http://{addr}"), None, &pair)
        .await
        .unwrap();

    let id = ItemId::new();
    dev.edit(id, &[("label", "mine"), ("user", "me")]).await;
    let mut e = dev.engine(dev.config()).await;
    let status = e.sync_once().await;
    assert_eq!(
        mock.pushes.load(Ordering::SeqCst),
        u64::from(MAX_CONFLICT_ROUNDS),
        "five rounds, then it gives up"
    );
    match &status {
        SyncStatus::Error { message } => assert!(message.contains("kept conflicting"), "{message}"),
        other => panic!("expected error, got {other:?}"),
    }
    let row = dev.store.get_item(id).await.unwrap().unwrap();
    assert!(row.dirty, "the item stays dirty");
    assert_eq!(dev.pending().await, 1);
    // The local edit survived every merge.
    let body = dev.body(id).await.unwrap();
    assert_eq!(body.get("user").and_then(|v| v.as_text()), Some("me"));
    server.abort();
}
