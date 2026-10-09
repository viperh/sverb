//! down (exit 6), `devices list` / `revoke` formatting and id picking (T-07; the
//! list / revoke round trip against the in-process server is
//! `crates/sverb-sync/tests/account.rs::m4_09_devices_list_revoke_and_local_info`).
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pretty_assertions::assert_eq;
use sverb_core::config::{Config, Validators};
use sverb_core::model::VaultId;
use sverb_core::paths::{MapEnv, Paths};
use sverb_proto::auth::{DeviceView, TokenPair};
use sverb_store::VaultKind;
use sverb_sync::{LocalSyncInfo, TokenManager, VaultPending};

use super::account::{self, StatusJson, status_text};
use super::devices::{self, pick, table};
use super::exit::{self, CliError};
use super::output::to_json;
use super::{Ctx, Tty};

fn vault(n: u8) -> VaultId {
    VaultId::from_bytes([n; 16])
}

fn synced_info() -> LocalSyncInfo {
    LocalSyncInfo {
        server_url: Some("https://sync.example.test".into()),
        signed_in: true,
        email: Some("me@example.test".into()),
        // 2026-10-08 12:00:00 UTC
        last_sync_ms: Some(1_791_460_800_000),
        pending: vec![
            VaultPending {
                vault: vault(1),
                kind: Some(VaultKind::Personal),
                pending: 3,
            },
            VaultPending {
                vault: vault(2),
                kind: Some(VaultKind::Shared),
                pending: 1,
            },
        ],
    }
}

// The text and `--json` forms.
#[test]
fn t06_status_text_and_json() {
    let local = LocalSyncInfo::default();
    assert!(status_text(&local).starts_with("local-only"));
    assert_eq!(
        to_json(&StatusJson::from_info(&local)).unwrap(),
        r#"{"version":1,"data":{"connected":false,"server":null,"signed_in":false,"email":null,"last_sync":null,"pending_total":0,"pending":[]}}"#
    );

    let info = synced_info();
    let text = status_text(&info);
    assert!(
        text.contains("server:     https://sync.example.test\n"),
        "{text}"
    );
    assert!(text.contains("account:    me@example.test\n"), "{text}");
    assert!(text.contains("signed in:  yes\n"), "{text}");
    assert!(
        text.contains("last sync:  2026-10-08 12:00:00 UTC\n"),
        "{text}"
    );
    assert!(text.contains("pending:    4\n"), "{text}");
    insta::assert_snapshot!(
        "sync_status_json",
        to_json(&StatusJson::from_info(&info)).unwrap()
    );
}

// Without flags `sync` prints the status; a fresh home stays untouched.
#[test]
fn t06_sync_defaults_to_status_and_creates_nothing() {
    let home = tempfile_home("status");
    let ctx = ctx_at(&home);
    let rt = rt();
    for args in [vec![], vec!["--status"], vec!["--status", "--json"]] {
        let cli = super::Cli::try_parse_with(
            &ctx.paths,
            ["sverb", "sync"].into_iter().chain(args.iter().copied()),
        )
        .unwrap();
        let mut out = Vec::new();
        let res = rt.block_on(super::run(cli, &ctx, &mut out));
        assert_eq!(res, Ok(exit::OK), "{args:?}");
        let out = String::from_utf8(out).unwrap();
        if args.contains(&"--json") {
            assert!(out.contains(r#""connected":false"#), "{out}");
        } else {
            assert!(out.starts_with("local-only"), "{out}");
        }
    }
    assert!(!ctx.paths.db_file().exists(), "no database created");
    let _ = std::fs::remove_dir_all(&home);
}

// `sync --now` with the server down: exit 6, the changes stay queued.
#[test]
fn t06_sync_now_server_down_exits_6() {
    let home = tempfile_home("now");
    let ctx = ctx_at(&home);
    let rt = rt();
    let (res, out) = rt.block_on(async {
        ctx.paths.ensure(sverb_core::paths::DirKind::Data).unwrap();
        let store = sverb_store::Store::open(&ctx.paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store.clone(),
            std::sync::Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        let init = engine
            .initialize("correct horse battery staple violin", false)
            .await
            .unwrap();
        let lmk = init.vault.lmk().clone();
        // Port 1 on loopback: nothing listens.
        let pair = TokenPair {
            access_token: "a".into(),
            refresh_token: "r".into(),
            access_expires_in_s: 900,
            refresh_expires_in_s: 86_400,
        };
        TokenManager::save_login(&store, &lmk, "http://127.0.0.1:1", None, &pair)
            .await
            .unwrap();
        let mut out = Vec::new();
        let res = account::sync_now(&store, &lmk, init.vault.hlc(), &ctx, true, &mut out).await;
        (res, String::from_utf8(out).unwrap())
    });
    let err = res.unwrap_err();
    assert!(matches!(err, CliError::Network(_)), "{err:?}");
    assert_eq!(err.exit_code(), exit::NETWORK);
    assert!(out.contains(r#""status":"offline (0 pending)""#), "{out}");
    let _ = std::fs::remove_dir_all(&home);
}

fn device(id: &str, current: bool, name: &str) -> DeviceView {
    let t = chrono::DateTime::from_timestamp(1_791_460_800, 0).unwrap();
    DeviceView {
        id: id.parse().unwrap(),
        name: Some(name.into()),
        platform: Some("linux".into()),
        created_at: Some(t),
        last_seen_at: None,
        current,
        revoked_at: None,
    }
}

// T-07 (formatting): the table marks this device; ids are picked by unique prefix.
#[test]
fn t07_devices_table_and_pick() {
    let list = [
        device("11111111-0000-4000-8000-000000000001", true, "laptop"),
        device("22222222-0000-4000-8000-000000000002", false, "phone"),
        device("22223333-0000-4000-8000-000000000003", false, "tablet"),
    ];
    let t = table(&list);
    let mut lines = t.lines();
    assert!(lines.next().unwrap().starts_with("  ID"));
    let first = lines.next().unwrap();
    assert!(first.starts_with("* 11111111-"), "{t}");
    assert!(
        first.contains("laptop") && first.contains("2026-10-08 12:00"),
        "{t}"
    );
    assert!(t.ends_with("(* this device)\n"));
    assert_eq!(pick(&list, "1111").unwrap().id, list[0].id);
    assert_eq!(
        pick(&list, "22222222-0000-4000-8000-000000000002")
            .unwrap()
            .id,
        list[1].id
    );
    assert_eq!(
        pick(&list, "2222").unwrap_err().exit_code(),
        exit::NOT_FOUND
    );
    assert_eq!(pick(&list, "9").unwrap_err().exit_code(), exit::NOT_FOUND);
    let json = to_json(
        &list
            .iter()
            .map(devices::DeviceJson::from)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(
        json.contains(r#""created_at":"2026-10-08T12:00:00Z","last_seen_at":null,"current":true"#),
        "{json}"
    );
}

// Not signed in: `devices list` explains how to sign in (exit 2).
#[test]
fn t07_devices_need_a_sign_in() {
    let home = tempfile_home("devices");
    let ctx = ctx_at(&home);
    let rt = rt();
    let res = rt.block_on(async {
        ctx.paths.ensure(sverb_core::paths::DirKind::Data).unwrap();
        let store = sverb_store::Store::open(&ctx.paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store,
            std::sync::Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        let init = engine
            .initialize("correct horse battery staple violin", false)
            .await
            .unwrap();
        sverb_sync::account::list_devices(
            engine.store(),
            init.vault.lmk(),
            &account::account_config(),
        )
        .await
    });
    assert!(matches!(
        res,
        Err(sverb_sync::account::AccountError::NotSignedIn)
    ));
    let _ = std::fs::remove_dir_all(&home);
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn tempfile_home(tag: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("sverb-m4-09-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    home
}

fn ctx_at(home: &std::path::Path) -> Ctx {
    Ctx {
        paths: Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap(),
        config: Config::default(),
        validators: Validators::default(),
        tty: Tty {
            stdin: false,
            stdout: false,
            stderr: false,
        },
    }
}
