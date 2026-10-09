//! with keyring unlock; T-04: median < 200 ms on CI).
//!
//! A vault with 1,000 hosts and keyring unlock enabled (the test-only file keyring,
//! `SVERB_KEYRING=file:<dir>`, `test-hooks` builds). Each run spawns `sverb` on a
//! PTY and measures the time until the host list (the first host's label) is drawn;
//! 20 runs, the median is reported and gated.
//!
//! A performance test, so ignored by default; run it on a release build:
//! `cargo test --release -p sverb --features test-hooks --test startup -- --ignored --nocapture`.
//! `SVERB_STARTUP_GATE_MS` overrides the gate (default 200 ms, the CI allowance).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{PtyRun, TestResult, unique_home};
use portable_pty::CommandBuilder;
use sverb_core::model::{ItemBody, ItemId, ItemKind};
use sverb_core::paths::{DirKind, MapEnv, Paths};

const HOSTS: usize = 1_000;
const RUNS: usize = 20;

const PASSWORD: &str = "correct horse battery staple violin";

/// A vault with keyring unlock and `HOSTS` hosts (`perf-host-0000` …).
fn fixture(home: &std::path::Path, keyring_dir: &std::path::Path) {
    let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap();
    paths.ensure(DirKind::Data).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = sverb_store::Store::open(&paths).unwrap();
        let keyring = Arc::new(sverb_tui::services::vault::FileKeyring::new(
            keyring_dir.to_path_buf(),
        ));
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store.clone(),
            keyring,
            sverb_core::vault::Argon2Cost::TEST,
        );
        let init = engine.initialize(PASSWORD, true).await.unwrap();
        assert!(init.keyring_error.is_none(), "{:?}", init.keyring_error);
        let vault = init.vault;
        let vid = vault.personal_vault().unwrap();
        let mut clock = vault.hlc();
        let device = vault.device_id();
        let mut sealed = Vec::with_capacity(HOSTS);
        for i in 0..HOSTS {
            let mut body = ItemBody::new(ItemKind::Host, 1);
            body.set("label", format!("perf-host-{i:04}"), &mut clock, device);
            body.set(
                "address",
                format!("10.0.{}.{}", i / 256, i % 256),
                &mut clock,
                device,
            );
            body.set("username", "deploy", &mut clock, device);
            let id = ItemId::new();
            let (kv, env) = vault.seal(vid, id, &body).unwrap();
            sealed.push((id, kv, env));
        }
        store
            .write(move |w| {
                for (id, kv, env) in &sealed {
                    w.put_item(vid, *id, *kv, env, false, true)?;
                }
                Ok(())
            })
            .await
            .unwrap();
        store.set_meta("seen_leader_notice", vec![1]).await.unwrap();
    });
}

fn one_run(
    home: &std::path::Path,
    keyring_dir: &std::path::Path,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SVERB_KEYRING", format!("file:{}", keyring_dir.display()));
    cmd.env_remove("SSH_AUTH_SOCK");
    cmd.env_remove("SVERB_TEST_HOOK");
    let started = Instant::now();
    let mut run = PtyRun::spawn(cmd)?;
    // Answer the startup terminal query (`CSI ? u` + DA1) like a terminal without the
    // kitty protocol does, at once; otherwise the 50 ms probe timeout is measured.
    let asked = run.wait_for("\x1b[c", 0)?;
    run.send(b"\x1b[?62;22c")?;
    run.wait_for("perf-host-0000", asked)?;
    let elapsed = started.elapsed();
    run.send(b"\x1cq")?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{status:?}");
    Ok(elapsed)
}

#[test]
#[ignore = "performance: run on a release build (see the module docs)"]
fn startup_to_hosts_keyring() -> TestResult {
    let home = unique_home("m7-06-startup");
    let keyring_dir = home.join("keyring");
    fixture(&home, &keyring_dir);
    // One warm-up run (page cache, dynamic loader).
    one_run(&home, &keyring_dir)?;
    let mut times: Vec<Duration> = (0..RUNS)
        .map(|_| one_run(&home, &keyring_dir))
        .collect::<Result<_, _>>()?;
    times.sort();
    let median = times[RUNS / 2];
    let gate = std::env::var("SVERB_STARTUP_GATE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200u64);
    println!(
        "startup_to_hosts_keyring: median {:.1} ms, min {:.1} ms, max {:.1} ms ({RUNS} runs, {HOSTS} hosts, gate {gate} ms)",
        median.as_secs_f64() * 1e3,
        times[0].as_secs_f64() * 1e3,
        times[RUNS - 1].as_secs_f64() * 1e3,
    );
    // `SVERB_STARTUP_KEEP=1` keeps the fixture home for profiling.
    if std::env::var_os("SVERB_STARTUP_KEEP").is_some() {
        println!("fixture kept: {}", home.display());
    } else {
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(
        median <= Duration::from_millis(gate),
        "startup median {median:?} is over the {gate} ms gate"
    );
    Ok(())
}
