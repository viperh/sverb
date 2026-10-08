//! M5-03 integration tests: TOFU pinning against the in-process server
//! (in-memory backend, loopback HTTP). The server's
//! `GET /v1/users/{id}/public-keys` is the harness hook
//! (`TestServer::user_keys`), so a test can substitute a user's keys.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::HashMap;

use common::{TestServer, first_device};
use sverb_core::model::ItemId;
use sverb_crypto::account::{AccountKeys, generate_account_keys};
use sverb_crypto::grant::grant_vault_key;
use sverb_crypto::random::{os_rng, random_key32};
use sverb_proto::b64;
use sverb_proto::sync::{Permission, VaultGrant, VaultKind, VaultView};
use sverb_proto::users::UserPublicKeys;
use sverb_store::{PinObservation, PinState};
use sverb_sync::SyncStatus;
use sverb_sync::VaultKeySource;
use sverb_sync::trust::{
    OrgRole, TokenDirectory, Trust, TrustError, TrustedKeySource, VaultMembership,
};
use uuid::Uuid;

fn publish(server: &TestServer, user: Uuid, email: &str, keys: &AccountKeys) {
    let p = keys.public();
    server.user_keys.lock().insert(
        user,
        UserPublicKeys {
            user_id: user,
            email: Some(email.to_owned()),
            x25519_pub: p.x25519.to_vec(),
            ed25519_pub: p.ed25519.to_vec(),
        },
    );
}

/// Bob grants key v1 of shared `vault` to `me`.
fn bobs_grant(
    bob: &AccountKeys,
    bob_id: Uuid,
    me: Uuid,
    me_keys: &AccountKeys,
    vault: Uuid,
) -> VaultView {
    let vk = random_key32(&mut os_rng());
    let g = grant_vault_key(
        &vk,
        vault.as_bytes(),
        1,
        me.as_bytes(),
        &me_keys.public().x25519,
        bob.ed25519_signing_key(),
        &mut os_rng(),
    )
    .unwrap();
    VaultView {
        id: vault,
        kind: VaultKind::Shared,
        org_id: Some(Uuid::now_v7()),
        name_enc: Vec::new(),
        key_version: 1,
        head_revision: 0,
        permission: Permission::Write,
        grants: vec![VaultGrant {
            key_version: 1,
            wrapped_vault_key: g.wrapped,
            wrapped_by: bob_id,
            signature: g.signature.to_vec(),
        }],
        rotation: None,
    }
}

fn bob_manages(bob: Uuid, me: Uuid) -> VaultMembership {
    VaultMembership {
        org_roles: HashMap::from([(bob, OrgRole::Admin), (me, OrgRole::Member)]),
        permissions: HashMap::from([(bob, Permission::Manage), (me, Permission::Write)]),
        creator: Some(bob),
    }
}

/// T-01: the first fetch pins Bob's key; a second fetch with the same key
/// gives no warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_first_fetch_pins() {
    let server = TestServer::start().await;
    let (alice, dev) = first_device(&server, "alice-t01@example.com").await;
    let engine = dev.engine(dev.config()).await;
    let dir = TokenDirectory(engine.tokens().clone());
    let trust = Trust::new(dev.store.clone(), alice.user_id);

    let bob = generate_account_keys(&mut os_rng());
    let bob_id = Uuid::now_v7();
    publish(&server, bob_id, "bob@example.com", &bob);

    let (keys, obs) = trust.fetch(&dir, bob_id).await.unwrap();
    assert_eq!(obs, PinObservation::FirstSeen);
    assert_eq!(keys, bob.public());
    let pin = dev
        .store
        .get_pin(*bob_id.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pin.fingerprint, bob.public().fingerprint());
    assert_eq!(pin.label.as_deref(), Some("bob@example.com"));

    let (_, obs) = trust.fetch(&dir, bob_id).await.unwrap();
    assert_eq!(obs, PinObservation::Unchanged);
    assert_eq!(
        trust.find("bob").await.unwrap().state(),
        PinState::Pinned,
        "no warning for an unchanged key"
    );
    // Granting to Bob is allowed with the pinned key.
    assert_eq!(
        trust.keys_for_grant(&dir, bob_id).await.unwrap(),
        bob.public()
    );
    // The fetch went to the server (requests are recorded).
    assert!(
        server
            .requests
            .lock()
            .iter()
            .any(|r| r.method == "GET" && r.path == format!("/v1/users/{bob_id}/public-keys"))
    );
}

/// T-02: the server returns a different key for Bob → warning, the grant to
/// Bob is blocked, and Bob's grants to me are not trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_key_substitution_blocks_grants() {
    let server = TestServer::start().await;
    let (alice, dev) = first_device(&server, "alice-t02@example.com").await;
    let engine = dev.engine(dev.config()).await;
    let dir = TokenDirectory(engine.tokens().clone());
    let trust = Trust::new(dev.store.clone(), alice.user_id);

    let bob = generate_account_keys(&mut os_rng());
    let bob_id = Uuid::now_v7();
    publish(&server, bob_id, "bob@example.com", &bob);
    trust.fetch(&dir, bob_id).await.unwrap();
    trust.mark_verified(bob_id).await.unwrap();

    // A vault key granted by the real Bob is trusted before the substitution.
    let vault = Uuid::now_v7();
    let view = bobs_grant(&bob, bob_id, alice.user_id, &alice.keys, vault);
    let source = TrustedKeySource::new(
        alice.user_id,
        alice.keys.clone(),
        trust.pins().await.unwrap(),
    );
    source.set_membership(vault, bob_manages(bob_id, alice.user_id));
    assert!(source.open_grant(&view, 1).is_some());

    // The server substitutes Bob's keys.
    let mallory = generate_account_keys(&mut os_rng());
    publish(&server, bob_id, "bob@example.com", &mallory);
    let (_, obs) = trust.fetch(&dir, bob_id).await.unwrap();
    assert_eq!(
        obs,
        PinObservation::Changed {
            pinned: bob.public().fingerprint(),
            seen: mallory.public().fingerprint(),
        }
    );
    let pin = trust.find("bob@example.com").await.unwrap();
    assert_eq!(pin.state(), PinState::KeyChanged, "warning state");
    assert!(!pin.verified, "✓ cleared");
    assert_eq!(
        pin.x25519_pub,
        bob.public().x25519,
        "the pin is not replaced"
    );

    // The grant to Bob is blocked.
    assert_eq!(
        trust.keys_for_grant(&dir, bob_id).await.unwrap_err(),
        TrustError::KeyChanged(bob_id)
    );
    // Bob's grants to me are not trusted (neither the old-key one nor one
    // signed with the substituted key).
    source.set_pins(trust.pins().await.unwrap());
    assert_eq!(
        source.open_checked(&view, 1).unwrap_err(),
        TrustError::KeyChanged(bob_id)
    );
    assert!(source.open_grant(&view, 1).is_none());
    let forged = bobs_grant(&mallory, bob_id, alice.user_id, &alice.keys, vault);
    assert_eq!(
        source.open_checked(&forged, 1).unwrap_err(),
        TrustError::KeyChanged(bob_id)
    );
    // Marking verified is refused until the new key is accepted.
    assert_eq!(
        trust.mark_verified(bob_id).await.unwrap_err(),
        TrustError::KeyChanged(bob_id)
    );
    // After comparing safety numbers (computed from the new key) and
    // accepting it, Bob's new grants verify again.
    let sn_before = trust.safety_number(bob_id).await.unwrap_err();
    assert_eq!(
        sn_before,
        TrustError::NotPinned(alice.user_id),
        "self not pinned yet"
    );
    trust
        .pin_self(&alice.keys.public(), Some(alice.email.clone()))
        .await
        .unwrap();
    assert_eq!(
        trust.safety_number(bob_id).await.unwrap(),
        sverb_sync::trust::keys_safety_number(&alice.keys.public(), &mallory.public())
    );
    assert!(trust.accept_new_key(bob_id, true).await.unwrap());
    source.set_pins(trust.pins().await.unwrap());
    assert!(source.open_grant(&forged, 1).is_some());
    assert!(source.open_grant(&view, 1).is_none());
}

/// T-07: pins are never pushed to the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_pins_never_pushed() {
    let server = TestServer::start().await;
    let (alice, dev) = first_device(&server, "alice-t07@example.com").await;
    let mut engine = dev.engine(dev.config()).await;
    let dir = TokenDirectory(engine.tokens().clone());
    let trust = Trust::new(dev.store.clone(), alice.user_id);

    trust
        .pin_self(&alice.keys.public(), Some(alice.email.clone()))
        .await
        .unwrap();
    let bob = generate_account_keys(&mut os_rng());
    let bob_id = Uuid::now_v7();
    publish(&server, bob_id, "bob@example.com", &bob);
    trust.fetch(&dir, bob_id).await.unwrap();
    trust.mark_verified(bob_id).await.unwrap();
    // A changed key for a third user too (pending change columns).
    let carol_id = Uuid::now_v7();
    publish(
        &server,
        carol_id,
        "carol@example.com",
        &generate_account_keys(&mut os_rng()),
    );
    trust.fetch(&dir, carol_id).await.unwrap();
    publish(
        &server,
        carol_id,
        "carol@example.com",
        &generate_account_keys(&mut os_rng()),
    );
    trust.fetch(&dir, carol_id).await.unwrap();
    let pins = trust.members().await.unwrap();
    assert_eq!(pins.len(), 3);

    // A local edit, then a full sync cycle.
    dev.edit(
        ItemId::new(),
        &[("label", "web"), ("hostname", "web.example")],
    )
    .await;
    assert_eq!(engine.sync_once().await, SyncStatus::Synced);
    assert_eq!(server.head(dev.vault), 1, "the item was pushed");

    // Nothing the client sent contains pin material, and no request is about
    // pins. The only key-related requests are the GETs of the public keys.
    let secrets: Vec<String> = pins
        .iter()
        .flat_map(|p| {
            let mut v = vec![
                b64::encode(&p.fingerprint),
                b64::encode(&p.x25519_pub),
                b64::encode(&p.ed25519_pub),
                p.fingerprint
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ];
            if let Some(c) = &p.changed {
                v.push(b64::encode(&c.fingerprint));
                v.push(b64::encode(&c.x25519_pub));
            }
            v
        })
        .collect();
    let requests = server.requests.lock().clone();
    assert!(
        requests
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/changes"))
    );
    for r in &requests {
        assert!(!r.path.contains("pin"), "pin path {}", r.path);
        if r.path.contains("/public-keys") {
            assert_eq!((r.method.as_str(), r.body.as_str()), ("GET", ""));
            continue;
        }
        // Alice's own public keys were uploaded at registration (that is the
        // account record, not a pin); only check Bob's and Carol's material.
        for s in &secrets {
            let own = b64::encode(&alice.keys.public().x25519);
            let own_ed = b64::encode(&alice.keys.public().ed25519);
            if *s == own || *s == own_ed {
                continue;
            }
            assert!(
                !r.body.contains(s.as_str()),
                "{} {} leaks pin material",
                r.method,
                r.path
            );
        }
        assert!(
            !r.body.contains("verified"),
            "{} {} mentions verification",
            r.method,
            r.path
        );
    }
}
