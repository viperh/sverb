//! Snippet writes reach the Snippets view, the `leader e` picker and the command
//! palette at once: the snippet service and the item service against a real vault,
//! their events fed to the reducer. Small Argon2 parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sverb_core::model::{ItemId, RunMode, Snippet};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::hosts::ItemEffect;
use sverb_tui::app::{
    App, Config, Effect, SnippetsEffect, SnippetsEvent, UiEvent, UnlockRequest, VaultEffect,
    VaultPassword,
};
use sverb_tui::services::snippets::execute;
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::views::palette::PaletteTarget;
use tokio::sync::mpsc::{self, Receiver, Sender};

const PW: &str = "correct horse battery staple violin";

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "snippets-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            clock: Arc::new(ManualClock::new(1_800_000_000_000)),
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

/// The running app: an unlocked vault service and a reducer that has loaded the
/// (empty) snippet list.
struct Rig {
    vault: VaultService,
    app: App,
    tx: Sender<UiEvent>,
    rx: Receiver<UiEvent>,
}

impl Rig {
    async fn new(fx: &Fixture) -> Self {
        fx.engine().initialize(PW, false).await.unwrap();
        let vault = VaultService::new(fx.engine());
        let (tx, rx) = mpsc::channel(64);
        vault.execute(
            VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
            &tx,
        );
        let mut rig = Self {
            vault,
            app: App::new(Arc::new(Config::default())),
            tx,
            rx,
        };
        rig.settle(|app| app.views().snippets.loaded).await;
        rig
    }

    /// Run the reducer's snippet effects through the service.
    fn run(&self, effects: Vec<Effect>) {
        for e in effects {
            if let Effect::Snippets(op) = e {
                execute(Some(&self.vault), op, &self.tx);
            }
        }
    }

    /// Feed service events to the reducer until `done` holds and no snippet load is
    /// in flight. Panics after a few seconds (the change never reached the app).
    async fn settle(&mut self, done: impl Fn(&App) -> bool) {
        let wait = async {
            loop {
                if done(&self.app) && !self.app.views().snippets.loading {
                    return;
                }
                let ev = self.rx.recv().await.unwrap();
                if let UiEvent::Snippets(SnippetsEvent::Failed(r)) = &ev {
                    panic!("{r:?}");
                }
                let effects = self.app.handle(ev);
                self.run(effects);
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("the snippet change never reached the app");
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .app
            .views()
            .snippets
            .list
            .rows()
            .iter()
            .map(|r| r.snippet.name.clone())
            .collect();
        names.sort();
        names
    }

    fn id_of(&self, name: &str) -> Option<ItemId> {
        self.app
            .views()
            .snippets
            .list
            .rows()
            .iter()
            .find(|r| r.snippet.name == name)
            .map(|r| r.id)
    }

    /// The palette's snippet entries (`!`, from the search index).
    fn palette_snippets(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .app
            .palette_entries("!", false)
            .into_iter()
            .filter(|e| matches!(e.target, PaletteTarget::Snippet(_)))
            .map(|e| e.title)
            .collect();
        names.sort();
        names
    }
}

fn snippet(name: &str, script: &str) -> Snippet {
    Snippet {
        name: name.into(),
        script: script.into(),
        description: None,
        tags: Vec::new(),
        variables: Vec::new(),
        run_mode: RunMode::Paste,
        read_only: false,
    }
}

/// The bug report: a snippet added in the editor only showed up after a restart.
/// The save must update the search index, which reloads the view (and the palette
/// and `leader e` picker that read from them).
#[tokio::test]
async fn added_snippet_appears_without_restart() {
    let fx = Fixture::new("add");
    let mut rig = Rig::new(&fx).await;
    assert!(rig.names().is_empty());

    execute(
        Some(&rig.vault),
        SnippetsEffect::Save {
            id: None,
            snippet: snippet("uptime", "uptime"),
        },
        &rig.tx,
    );
    rig.settle(|app| app.views().snippets.list.rows().len() == 1)
        .await;
    assert_eq!(rig.names(), ["uptime"]);
    assert_eq!(rig.palette_snippets(), ["uptime"]);
}

/// Editing renames in place; duplicating and deleting (the item service) follow too.
#[tokio::test]
async fn edit_duplicate_delete_appear_without_restart() {
    let fx = Fixture::new("edit");
    let mut rig = Rig::new(&fx).await;
    execute(
        Some(&rig.vault),
        SnippetsEffect::Save {
            id: None,
            snippet: snippet("uptime", "uptime"),
        },
        &rig.tx,
    );
    rig.settle(|app| app.views().snippets.list.rows().len() == 1)
        .await;
    let id = rig.id_of("uptime").unwrap();

    // Edit.
    execute(
        Some(&rig.vault),
        SnippetsEffect::Save {
            id: Some(id),
            snippet: snippet("load", "uptime; cat /proc/loadavg"),
        },
        &rig.tx,
    );
    rig.settle(|app| {
        app.views()
            .snippets
            .get(id)
            .is_some_and(|s| s.name == "load")
    })
    .await;
    assert_eq!(rig.names(), ["load"]);
    assert_eq!(rig.palette_snippets(), ["load"]);

    // Duplicate.
    rig.vault
        .execute(VaultEffect::Items(ItemEffect::Duplicate(id)), &rig.tx);
    rig.settle(|app| app.views().snippets.list.rows().len() == 2)
        .await;
    assert_eq!(rig.palette_snippets().len(), 2);

    // Delete.
    rig.vault
        .execute(VaultEffect::Items(ItemEffect::Delete(id)), &rig.tx);
    rig.settle(|app| app.views().snippets.get(id).is_none())
        .await;
    assert_eq!(rig.names().len(), 1);
    assert_eq!(rig.palette_snippets().len(), 1);
}
