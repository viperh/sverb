//! `sverb --workspace <name>` opens the saved workspace right after unlock;
//! an unknown name shows a toast listing the saved ones. The workspace holds a local
//! shell (no network), seeded into the vault through the item service.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;
use sverb_core::layout::{Layout, PaneId};
use sverb_core::model::{
    ItemKind,
    workspace::{Broadcast, LeafRef, WorkspaceSpec, WorkspaceTab},
};

/// Store workspace `name`: one tab titled `title` with a local shell in `cwd`.
fn seed_workspace(home: &std::path::Path, name: &str, title: &str, cwd: &std::path::Path) {
    use sverb_core::paths::{MapEnv, Paths};
    let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = sverb_store::Store::open(&paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store,
            Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        let vault = engine.unlock_with_password(TEST_PASSWORD).await.unwrap();
        let ops = sverb_tui::services::vault::items::ItemOps::new(engine, Arc::new(vault));
        let spec = WorkspaceSpec {
            name: name.to_owned(),
            tabs: vec![WorkspaceTab {
                title_override: Some(title.to_owned()),
                layout: Layout::leaf(PaneId(0)),
                leaves: vec![LeafRef::Local {
                    cwd: Some(cwd.to_string_lossy().into_owned()),
                }],
                focused: 0,
                broadcast: Broadcast::Off,
            }],
            active: 0,
        };
        let item = spec.to_item();
        ops.save(
            ItemKind::Workspace,
            None,
            None,
            move |body, clock, device| {
                item.apply_to(body, clock, device);
                Ok(())
            },
        )
        .await
        .unwrap();
    });
}

fn sverb(home: &std::path::Path, workspace: &str) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.args(["--workspace", workspace]);
    cmd.env("SVERB_HOME", home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("SHELL", "/bin/sh");
    cmd.env("PS1", "$ ");
    cmd.env("ENV", "/dev/null");
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd.env_remove("RUST_BACKTRACE");
    cmd
}

#[test]
fn t07_workspace_opens_after_unlock_and_unknown_names_toast() -> TestResult {
    let home = unique_home("m3-03-workspace");
    init_vault(&home);
    let dir = home.join("wsdir-m303");
    std::fs::create_dir_all(&dir)?;
    seed_workspace(&home, "dev", "wsdev", &dir);

    // Known name: the tab (with its saved title) and its shell, in the saved cwd.
    let mut run = PtyRun::spawn(sverb(&home, "dev"))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    // Not `unlock()`: the session area replaces the Hosts view it waits for.
    let prompt = run.wait_for("Unlock sverb", entered)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    let tab = run.wait_for("wsdev", prompt)?;
    std::thread::sleep(Duration::from_millis(300));
    run.send(b"echo M3_$((40+3)); pwd\r")?;
    run.wait_for("M3_43", tab)?;
    run.wait_for("wsdir-m303", tab)?;
    run.child.kill()?;

    // Unknown name: a toast naming the saved workspaces, and no tab.
    let mut run = PtyRun::spawn(sverb(&home, "nope"))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    let unlocked = unlock(&mut run, entered)?;
    // The toast can be drawn in the same frame as the Hosts view `unlock` waits for.
    run.wait_for("No workspace named \"nope\" (available: dev)", entered)?;
    assert!(!String::from_utf8_lossy(run.bytes_from(unlocked)).contains("wsdev"));
    run.child.kill()?;
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
