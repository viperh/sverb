//! M2-07 T-11…T-13 against OpenSSH in Docker (`forward` profile,
//! `AllowAgentForwarding yes`): `ssh-add -l` on the remote. The loopback versions run
//! without Docker in `sverb-conn`'s `agent::loopback_tests`. The "system agent" is an
//! in-memory agent ([`MemoryAgent`]), never the developer's.
//!
//! `#[ignore]`d: `SVERB_E2E=1 cargo test -p sverb-e2e --test agent -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use sverb_conn::agent::{
    AgentForwarding, AgentKey, BuiltinAgent, DenyConfirm, StaticKeys, forward::MemoryAgent,
};
use sverb_core::{keychain::decrypt_openssh, model::AgentSource};
use sverb_e2e::{
    Headless, HeadlessOptions, Login, Profile, Sshd, keys::FixtureKey, require_docker, timeout,
};

fn fingerprint(key: FixtureKey) -> String {
    let private = decrypt_openssh(&key.private(), key.passphrase()).unwrap();
    private
        .public_key()
        .fingerprint(Default::default())
        .to_string()
}

async fn forwarding(
    vault: &[FixtureKey],
    system: &[FixtureKey],
    source: AgentSource,
) -> HeadlessOptions {
    let vault_keys = vault
        .iter()
        .map(|k| {
            AgentKey::new(
                "vault",
                decrypt_openssh(&k.private(), k.passphrase()).unwrap(),
            )
        })
        .collect();
    let system_keys: Vec<_> = system
        .iter()
        .map(|k| decrypt_openssh(&k.private(), k.passphrase()).unwrap())
        .collect();
    let forwarding = AgentForwarding::new(Arc::new(BuiltinAgent::new(
        Arc::new(StaticKeys::new(vault_keys)),
        Arc::new(DenyConfirm),
    )))
    .with_system(Arc::new(MemoryAgent::start(&system_keys).await.unwrap()));
    HeadlessOptions {
        agent: Some((forwarding, source)),
        ..HeadlessOptions::default()
    }
}

/// T-11: `builtin` → the remote `ssh-add -l` lists exactly the forwardable keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t11_builtin_forwarding() {
    require_docker!();
    let sshd = Sshd::start(Profile::Forward).await.unwrap();
    let opts = forwarding(
        &[FixtureKey::Ed25519],
        &[FixtureKey::EcdsaP256],
        AgentSource::Builtin,
    )
    .await;
    let mut s = Headless::connect_with(Login::sshd_password(&sshd), opts);
    s.wait_connected().await.unwrap();
    s.wait_for_text("$", timeout()).await.unwrap();
    s.send("ssh-add -l; echo DONE-$?\r").await;
    let grid = s.wait_for_text("DONE-", timeout()).await.unwrap();
    assert!(grid.contains(&fingerprint(FixtureKey::Ed25519)), "{grid}");
    assert!(
        !grid.contains(&fingerprint(FixtureKey::EcdsaP256)),
        "{grid}"
    );
    s.close().await;
}

/// T-12: `system` with an agent holding a different key → the remote sees that key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t12_system_forwarding() {
    require_docker!();
    let sshd = Sshd::start(Profile::Forward).await.unwrap();
    let opts = forwarding(
        &[FixtureKey::Ed25519],
        &[FixtureKey::EcdsaP256],
        AgentSource::System,
    )
    .await;
    let mut s = Headless::connect_with(Login::sshd_password(&sshd), opts);
    s.wait_connected().await.unwrap();
    s.wait_for_text("$", timeout()).await.unwrap();
    s.send("ssh-add -l; echo DONE-$?\r").await;
    let grid = s.wait_for_text("DONE-", timeout()).await.unwrap();
    assert!(grid.contains(&fingerprint(FixtureKey::EcdsaP256)), "{grid}");
    assert!(!grid.contains(&fingerprint(FixtureKey::Ed25519)), "{grid}");
    s.close().await;
}

/// T-13: forwarding off → "Could not open a connection to your authentication agent".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker (SVERB_E2E=1)"]
async fn t13_forwarding_off() {
    require_docker!();
    let sshd = Sshd::start(Profile::Forward).await.unwrap();
    let mut s = Headless::connect(Login::sshd_password(&sshd));
    s.wait_connected().await.unwrap();
    s.wait_for_text("$", timeout()).await.unwrap();
    s.send("ssh-add -l\r").await;
    s.wait_for_text(
        "Could not open a connection to your authentication agent",
        timeout(),
    )
    .await
    .unwrap();
    s.close().await;
}
