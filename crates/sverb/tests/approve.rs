//! M2-10 T-06 / T-07 (SPEC §17.1, §16): values that arrived from another device (via
//! `apply_remote`) are not acted on by headless commands (exit 5 with the exact
//! message), and `sverb approve <host>` lists and approves them on a PTY.
//!
//! The OS keyring is disabled (`SVERB_KEYRING=off`); the vault is unlocked on the PTY.
//! Nothing connects anywhere: the checks fail before any connection.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{path::Path, sync::Arc, time::Duration};

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault, unique_home};
use portable_pty::CommandBuilder;
use sverb_core::{
    model::{
        DeviceId, ForwardKind, HlcClock, Host, ItemBody, ItemId, ItemKind, PortForward, Proxy,
        current_schema,
    },
    paths::{MapEnv, Paths},
    resolve::approval::value_sha256,
};
use sverb_store::{RemoteItem, Store};
use sverb_tui::services::vault::{VaultEngine, items::ItemOps};

/// Harmless if it ever runs (`true` ignores its arguments; never the real `ssh`).
const CMD: &str = "true -W %h:%p bastion";

fn paths(home: &Path) -> Paths {
    Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn ops(home: &Path) -> (Store, ItemOps) {
    let store = Store::open(&paths(home)).unwrap();
    let engine = VaultEngine::new(
        store.clone(),
        Arc::new(sverb_core::vault::NoKeyring),
        sverb_core::vault::Argon2Cost::TEST,
    );
    let vault = engine.unlock_with_password(TEST_PASSWORD).await.unwrap();
    (store, ItemOps::new(engine, Arc::new(vault)))
}

/// Write `edit`'s fields into item `id` as another device would, through sync.
async fn from_other_device(
    store: &Store,
    ops: &ItemOps,
    id: ItemId,
    kind: ItemKind,
    revision: i64,
    edit: impl FnOnce(&mut ItemBody, &mut HlcClock, DeviceId),
) {
    let vault = ops.vault().personal_vault().unwrap();
    let mut body = match ops.load(id).await.unwrap() {
        Some(l) => l.body,
        None => ItemBody::new(kind, current_schema(kind)),
    };
    let mut clock = HlcClock::default();
    edit(&mut body, &mut clock, DeviceId::from_bytes([0xee; 16]));
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

/// Host `db` with a synced ProxyCommand and a loopback rule `web`; host `wide` (no
/// proxy) with a synced rule `open` listening on 0.0.0.0.
fn setup(tag: &str) -> (std::path::PathBuf, ItemId) {
    let home = unique_home(tag);
    init_vault(&home);
    let db = ItemId::new();
    runtime().block_on(async {
        let (store, ops) = ops(&home).await;
        from_other_device(&store, &ops, db, ItemKind::Host, 1, |b, c, d| {
            Host {
                label: "db".into(),
                address: "127.0.0.1".into(),
                port: Some(9),
                username: Some("u".into()),
                proxy: Some(Proxy::Command(CMD.into())),
                ..Host::default()
            }
            .apply_to(b, c, d);
        })
        .await;
        from_other_device(
            &store,
            &ops,
            ItemId::new(),
            ItemKind::PortForward,
            2,
            |b, c, d| {
                PortForward {
                    label: "web".into(),
                    kind: ForwardKind::Local,
                    host_id: db,
                    bind_addr: "127.0.0.1".into(),
                    bind_port: 18080,
                    dest_host: Some("127.0.0.1".into()),
                    dest_port: Some(80),
                    auto_start: false,
                    read_only: false,
                }
                .apply_to(b, c, d);
            },
        )
        .await;
        let wide = ItemId::new();
        from_other_device(&store, &ops, wide, ItemKind::Host, 3, |b, c, d| {
            Host {
                label: "wide".into(),
                address: "127.0.0.1".into(),
                port: Some(9),
                ..Host::default()
            }
            .apply_to(b, c, d);
        })
        .await;
        from_other_device(
            &store,
            &ops,
            ItemId::new(),
            ItemKind::PortForward,
            4,
            |b, c, d| {
                PortForward {
                    label: "open".into(),
                    kind: ForwardKind::Local,
                    host_id: wide,
                    bind_addr: "0.0.0.0".into(),
                    bind_port: 18081,
                    dest_host: Some("127.0.0.1".into()),
                    dest_port: Some(80),
                    auto_start: false,
                    read_only: false,
                }
                .apply_to(b, c, d);
            },
        )
        .await;
    });
    (home, db)
}

fn command(home: &Path, args: &[&str]) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.args(args);
    cmd.env("SVERB_HOME", home);
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("TERM", "xterm-256color");
    cmd
}

/// Spawn `args` on a PTY and type the master password.
fn unlocked(home: &Path, args: &[&str]) -> Result<(PtyRun, usize), Box<dyn std::error::Error>> {
    let mut run = PtyRun::spawn(command(home, args))?;
    let at = run.wait_for("Master password:", 0)?;
    run.poll(Duration::from_millis(500));
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    Ok((run, at))
}

/// T-06: the headless forward fails with exit 5 and the exact §17.1 message.
#[test]
fn t06_headless_forward_with_unapproved_values_exits_5() -> TestResult {
    let (home, _) = setup("m2-10-t06");
    let (mut run, _) = unlocked(&home, &["forward", "web"])?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 5, "{}", run.output());
    assert!(
        run.output().contains(
            "error: host \"db\" uses a local command that has not been approved on this \
             device. Run: sverb approve db"
        ),
        "{}",
        run.output()
    );
    // A synced non-loopback bind.
    let (mut run, _) = unlocked(&home, &["forward", "open"])?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 5, "{}", run.output());
    assert!(
        run.output().contains(
            "error: host \"wide\" has a forward listening on a non-loopback address that has \
             not been approved on this device. Run: sverb approve wide"
        ),
        "{}",
        run.output()
    );
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

/// T-07: `sverb approve db` lists the values with their status and approves on `y`.
#[test]
fn t07_approve_lists_and_approves_interactively() -> TestResult {
    let (home, db) = setup("m2-10-t07");
    let (mut run, at) = unlocked(&home, &["approve", "db"])?;
    let at = run.wait_for(&format!("[needs approval] ProxyCommand: {CMD}"), at)?;
    run.wait_for(
        &format!("This host runs a local command: `{CMD}`. Allow? [y/N]"),
        at,
    )?;
    run.poll(Duration::from_millis(200));
    run.send(b"y\r")?;
    let status = run.wait_exit()?;
    assert!(status.success(), "{status:?}: {}", run.output());
    assert!(
        run.output()
            .contains(&format!("approved: ProxyCommand: {CMD}")),
        "{}",
        run.output()
    );
    // The row is stored for the host item with the value's hash.
    let rows = runtime().block_on(async {
        Store::open(&paths(&home))
            .unwrap()
            .list_local_approvals()
            .await
            .unwrap()
    });
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].item_id,
            rows[0].field.as_str(),
            rows[0].value_sha256
        ),
        (db, "proxy.command", value_sha256(CMD))
    );
    // Again: nothing left to approve.
    let (mut run, at) = unlocked(&home, &["approve", "db"])?;
    run.wait_for("everything is approved", at)?;
    assert!(run.wait_exit()?.success());
    // Declining leaves the value unapproved (exit 0).
    let (mut run, at) = unlocked(&home, &["approve", "wide"])?;
    run.wait_for("[needs approval] forward listens on: 0.0.0.0:18081", at)?;
    run.wait_for("Allow? [y/N]", at)?;
    run.poll(Duration::from_millis(200));
    run.send(b"n\r")?;
    assert!(run.wait_exit()?.success(), "{}", run.output());
    assert!(run.output().contains("1 value(s) left unapproved"));
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

/// T-07 (`--all --yes`): approves every value without asking and prints them.
#[test]
fn t07_approve_all_yes() -> TestResult {
    let (home, _) = setup("m2-10-t07-yes");
    let (mut run, _) = unlocked(&home, &["approve", "db", "--all", "--yes"])?;
    let status = run.wait_exit()?;
    assert!(status.success(), "{status:?}: {}", run.output());
    assert!(
        run.output()
            .contains(&format!("approved: ProxyCommand: {CMD}")),
        "{}",
        run.output()
    );
    let (mut run, at) = unlocked(&home, &["forward", "web"])?;
    // Approved now: the ProxyCommand check passes (the connection itself then fails:
    // nothing listens behind the fake bastion), so the exit code is no longer 5.
    let _ = at;
    let status = run.wait_exit()?;
    assert_ne!(status.exit_code(), 5, "{}", run.output());
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
