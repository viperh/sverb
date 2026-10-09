//! `sverb snippet run` with a fake executor: T-11, T-12 and errors.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use sverb_conn::ssh::exec::snippets::{HostExecutor, RunJob, RunTarget};
use sverb_core::model::{Host, ItemId, ItemKind, RunMode, Snippet, VarDef};
use sverb_core::snippet::{Builtins, HostRunResult, RenderStyle};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::Store;
use sverb_tui::services::vault::{VaultEngine, items::ItemOps};

use super::*;

const PW: &str = "correct horse battery staple violin";

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn ops(tag: &str) -> (ItemOps, Home) {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sverb-m2-09-cli-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = Store::open_at(dir.join("sverb.db"), Arc::new(sverb_store::SystemClock)).unwrap();
    let engine = VaultEngine::new(store, Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    let vault = engine.initialize(PW, false).await.unwrap().vault;
    (ItemOps::new(engine, Arc::new(vault)), Home(dir))
}

async fn add_host(ops: &ItemOps, label: &str, tags: Vec<ItemId>) -> ItemId {
    let host = Host {
        label: label.into(),
        address: format!("{label}.example"),
        username: Some("ops".into()),
        tags,
        ..Host::default()
    };
    ops.save(ItemKind::Host, None, None, move |b, c, d| {
        host.apply_to(b, c, d);
        Ok(())
    })
    .await
    .unwrap()
    .id
}

async fn add_snippet(ops: &ItemOps, name: &str, script: &str, variables: Vec<VarDef>) -> ItemId {
    let s = Snippet {
        name: name.into(),
        script: script.into(),
        description: None,
        tags: Vec::new(),
        variables,
        // Ignored by the CLI: always Exec on hosts.
        run_mode: RunMode::Paste,
        read_only: false,
    };
    ops.save(ItemKind::Snippet, None, None, move |b, c, d| {
        s.apply_to(b, c, d);
        Ok(())
    })
    .await
    .unwrap()
    .id
}

/// "Runs" the rendered command: fails on hosts whose label contains `bad`.
struct Fake;

#[async_trait]
impl HostExecutor for Fake {
    async fn run(&self, target: &RunTarget, job: &RunJob) -> HostRunResult {
        let b = Builtins {
            label: target.label.clone(),
            date: "D".into(),
            ..Builtins::default()
        };
        let cmd = job
            .template
            .render(&job.values, &b, RenderStyle::Final)
            .unwrap();
        let bad = target.label.contains("bad");
        HostRunResult {
            host: target.label.clone(),
            exit: Some(u32::from(bad)),
            stdout: format!("{cmd}\n").into_bytes(),
            stderr: if bad { b"nope\n".to_vec() } else { Vec::new() },
            duration: Duration::from_millis(1500),
            ..HostRunResult::default()
        }
    }
}

fn args(snippet: &str, on: &[&str], json: bool, vars: &[&str]) -> RunArgs {
    RunArgs {
        snippet: snippet.into(),
        on: on.iter().map(|s| (*s).to_owned()).collect(),
        json,
        vars: vars.iter().map(|s| (*s).to_owned()).collect(),
        concurrency: None,
        timeout_secs: None,
    }
}

async fn run(ops: &ItemOps, a: RunArgs, ask: Option<AskVar<'_>>) -> (Result<u8, CliError>, String) {
    let mut out = Vec::new();
    let res = run_with(a, ops, Arc::new(Fake), 30, ask, &mut out).await;
    (res, String::from_utf8(out).unwrap())
}

#[tokio::test]
async fn t11_run_on_tag_json_then_partial() {
    let (ops, _home) = ops("t11").await;
    let web = ops.save_tag(None, "web".into(), None).await.unwrap().id;
    add_host(&ops, "web-2", vec![web]).await;
    add_host(&ops, "web-1", vec![web]).await;
    add_host(&ops, "db-1", Vec::new()).await;
    add_snippet(&ops, "uptime", "uptime # {{host.label}}", Vec::new()).await;

    let (res, out) = run(&ops, args("uptime", &["#web"], true, &[]), None).await;
    assert_eq!(res, Ok(0));
    assert_eq!(
        out,
        concat!(
            r#"{"version":1,"data":["#,
            r#"{"host":"web-1","exit":0,"signal":null,"stdout":"uptime # web-1\n","stderr":"","truncated":false,"duration_ms":1500},"#,
            r#"{"host":"web-2","exit":0,"signal":null,"stdout":"uptime # web-2\n","stderr":"","truncated":false,"duration_ms":1500}"#,
            "]}\n"
        )
    );

    // One failure → exit 7; the text output has per-host blocks.
    add_host(&ops, "bad-web", vec![web]).await;
    let (res, out) = run(&ops, args("uptime", &["#web", "web-1"], false, &[]), None).await;
    assert_eq!(res, Ok(exit::PARTIAL));
    assert_eq!(
        out,
        "== bad-web (exit 1, 1.5s) ==\nuptime # bad-web\nnope\n\
         == web-1 (ok, 1.5s) ==\nuptime # web-1\n\
         == web-2 (ok, 1.5s) ==\nuptime # web-2\n"
    );
    // All failed → exit 1.
    let (res, _) = run(&ops, args("uptime", &["bad-web"], false, &[]), None).await;
    assert_eq!(res, Ok(exit::FAILURE));
}

#[tokio::test]
async fn t12_missing_vars_without_tty_exit_2() {
    let (ops, _home) = ops("t12").await;
    add_host(&ops, "app", Vec::new()).await;
    let vars = vec![
        VarDef {
            name: "svc".into(),
            default: None,
            secret: false,
        },
        VarDef {
            name: "token".into(),
            default: None,
            secret: true,
        },
        VarDef {
            name: "n".into(),
            default: Some("3".into()),
            secret: false,
        },
    ];
    add_snippet(
        &ops,
        "restart",
        "systemctl restart {{svc}} {{token|q}} {{n}} {{extra:x}}",
        vars,
    )
    .await;
    let (res, out) = run(&ops, args("restart", &["app"], false, &[]), None).await;
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert_eq!(
        err.to_string(),
        "missing values for variables: svc, token (pass --var name=value)"
    );
    assert!(out.is_empty());

    // --var supplies them.
    let (res, out) = run(
        &ops,
        args("restart", &["app"], false, &["svc=nginx", "token=a b"]),
        None,
    )
    .await;
    assert_eq!(res, Ok(0));
    assert_eq!(
        out,
        "== app (ok, 1.5s) ==\nsystemctl restart nginx 'a b' 3 x\n"
    );

    // On a terminal the missing ones are asked (secret ones flagged).
    let mut asked = Vec::new();
    let mut ask = |v: &VarDef| {
        asked.push((v.name.clone(), v.secret));
        Some(format!("<{}>", v.name))
    };
    let (res, out) = run(
        &ops,
        args("restart", &["app"], false, &["n=9"]),
        Some(&mut ask),
    )
    .await;
    assert_eq!(res, Ok(0));
    assert_eq!(
        out,
        "== app (ok, 1.5s) ==\nsystemctl restart <svc> '<token>' 9 x\n"
    );
    assert_eq!(
        asked,
        vec![("svc".to_owned(), false), ("token".to_owned(), true)]
    );

    // Unknown and malformed --var.
    let (res, _) = run(&ops, args("restart", &["app"], false, &["nope=1"]), None).await;
    assert_eq!(res.unwrap_err().exit_code(), 2);
    let (res, _) = run(&ops, args("restart", &["app"], false, &["svc"]), None).await;
    assert_eq!(res.unwrap_err().exit_code(), 2);
}

#[tokio::test]
async fn unknown_snippet_and_targets_exit_4() {
    let (ops, _home) = ops("t13").await;
    add_host(&ops, "app", Vec::new()).await;
    let id = add_snippet(&ops, "Deploy", "echo hi", Vec::new()).await;
    let (res, _) = run(&ops, args("nope", &["app"], false, &[]), None).await;
    assert_eq!(res.unwrap_err().exit_code(), 4);
    let (res, _) = run(&ops, args("deploy", &["#none"], false, &[]), None).await;
    assert_eq!(res.unwrap_err().exit_code(), 4);
    let (res, _) = run(&ops, args("deploy", &["zzz"], false, &[]), None).await;
    assert_eq!(res.unwrap_err().exit_code(), 4);
    // Case-insensitive name and id both work.
    let (res, _) = run(&ops, args("deploy", &["app"], false, &[]), None).await;
    assert_eq!(res, Ok(0));
    let (res, _) = run(&ops, args(&id.to_string(), &["app"], false, &[]), None).await;
    assert_eq!(res, Ok(0));
}
