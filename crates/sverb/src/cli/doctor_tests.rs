//! M7-04 tests: report snapshots with injected facts (T-01), the `--json` schema
//! (T-02), permission warnings (T-03), `--algos` (T-04), and the exit code with the
//! sync server down (T-06, CLI half; the server half is
//! `crates/sverb-sync/tests/doctor.rs`). T-05 (no TTY) is `crates/sverb/tests/doctor.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use sverb_conn::agent_client::{Agent, AgentConnector, AgentError};
use sverb_conn::ssh::algorithms::{AlgoKind, LEGACY_KEX, secure_table, supported};
use sverb_core::config::{Config, Validators};
use sverb_core::paths::{MapEnv, Paths};
use sverb_core::vault::MemKeyring;
use sverb_store::health::DbHealth;
use sverb_tui::runtime::capabilities::TermEnv;

use super::*;
use crate::cli::output::to_json;
use crate::cli::{Ctx, Tty};

fn term_env(vars: &[(&str, &str)]) -> TermEnv {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    TermEnv::from_lookup(|k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
}

fn path(label: &'static str, p: &str, state: PathState, dir: bool) -> PathFact {
    PathFact {
        label,
        path: PathBuf::from(p),
        state,
        private_mode: if dir { 0o700 } else { 0o600 },
    }
}

fn env_facts(paths: Vec<PathFact>, config: ConfigFact, db: DbFact) -> EnvFacts {
    EnvFacts {
        version: "0.1.0-test (2026-10-08)".to_owned(),
        features: "sync",
        os: "linux",
        arch: "x86_64",
        sverb_home: None,
        paths,
        config,
        db,
        log_writable: Some(true),
    }
}

fn all_ok() -> Facts {
    Facts {
        env: env_facts(
            vec![
                path(
                    "config dir",
                    "/home/u/.config/sverb",
                    PathState::Exists(Some(0o700)),
                    true,
                ),
                path(
                    "data dir",
                    "/home/u/.local/share/sverb",
                    PathState::Exists(Some(0o700)),
                    true,
                ),
                path(
                    "state dir",
                    "/home/u/.local/state/sverb",
                    PathState::Exists(Some(0o700)),
                    true,
                ),
                path(
                    "runtime dir",
                    "/run/user/1000/sverb",
                    PathState::Exists(Some(0o700)),
                    true,
                ),
                path(
                    "database file",
                    "/home/u/.local/share/sverb/sverb.db",
                    PathState::Exists(Some(0o600)),
                    false,
                ),
            ],
            ConfigFact::Valid { warnings: vec![] },
            DbFact::Health(DbHealth {
                schema_version: 7,
                supported_version: 7,
                problems: vec![],
            }),
        ),
        term: TermFacts {
            env: term_env(&[
                ("TERM", "xterm-kitty"),
                ("COLORTERM", "truecolor"),
                ("TERM_PROGRAM", "kitty"),
            ]),
            answers: Some(TerminalAnswers {
                kitty: Ok(true),
                wide_char_width: Ok(Some(2)),
            }),
            mouse: true,
            osc52: true,
        },
        agent: AgentFacts {
            system_source: Some("/run/user/1000/ssh-agent.socket".to_owned()),
            system: AgentState::Identities(2),
            builtin_endpoint: "/run/user/1000/sverb/agent.sock".to_owned(),
            builtin: AgentState::Identities(1),
        },
        keyring: KeyringFacts {
            disabled: false,
            available: Some(true),
            unlock_enabled: Some(true),
        },
        sync: SyncFacts::Checked {
            server: "https://sync.example.test".to_owned(),
            checks: vec![
                check(
                    "sync.server",
                    Status::Ok,
                    "server",
                    "https://sync.example.test is reachable",
                ),
                check(
                    "sync.protocol",
                    Status::Ok,
                    "protocol",
                    "protocol version 1 (this client speaks 1)",
                ),
                check(
                    "sync.readiness",
                    Status::Ok,
                    "readiness",
                    "the server is ready",
                ),
                check(
                    "sync.clock",
                    Status::Ok,
                    "clock",
                    "offset to the server +0 s",
                ),
                check(
                    "sync.token",
                    Status::Ok,
                    "token",
                    "the access token is accepted",
                ),
                check(
                    "sync.websocket",
                    Status::Ok,
                    "websocket",
                    "live updates connect and authenticate",
                ),
            ],
        },
    }
}

fn mixed() -> Facts {
    let mut f = all_ok();
    f.env.paths[1].state = PathState::Exists(Some(0o755));
    f.env.config = ConfigFact::Invalid {
        errors: vec!["/home/u/.config/sverb/config.toml:3:1: ui.theme: unknown theme".into()],
    };
    f.env.db = DbFact::Health(DbHealth {
        schema_version: 6,
        supported_version: 7,
        problems: vec![],
    });
    f.term = TermFacts {
        env: term_env(&[
            ("TERM", "tmux-256color"),
            ("TMUX", "/tmp/tmux-1000/default,1,0"),
            ("TERM_PROGRAM", "tmux"),
            ("SSH_CONNECTION", "10.0.0.2 5555 10.0.0.1 22"),
        ]),
        answers: None,
        mouse: false,
        osc52: true,
    };
    f.agent.system_source = None;
    f.agent.system = AgentState::Absent;
    f.agent.builtin = AgentState::Absent;
    f.keyring = KeyringFacts {
        disabled: false,
        available: Some(false),
        unlock_enabled: Some(false),
    };
    f.sync = SyncFacts::Checked {
        server: "https://sync.example.test".to_owned(),
        checks: vec![
            check(
                "sync.server",
                Status::Fail,
                "server",
                "https://sync.example.test is unreachable: connection refused",
            )
            .hint("check the server URL and the network; local changes stay queued"),
        ],
    };
    f
}

// T-01: the text report with injected probes (all ok; mixed), symbols and ASCII.
#[test]
fn t01_text_report_snapshots() {
    let ok = build_report(&all_ok());
    assert!(ok.ok);
    assert_eq!(ok.exit_code(), exit::OK);
    insta::assert_snapshot!("doctor_all_ok", render_text(&ok, true));

    let mixed = build_report(&mixed());
    assert!(!mixed.ok);
    assert_eq!(mixed.exit_code(), exit::FAILURE);
    assert_eq!(mixed.problems, 2, "config + sync server");
    insta::assert_snapshot!("doctor_mixed_ascii", render_text(&mixed, false));
    insta::assert_snapshot!("doctor_mixed_symbols", render_text(&mixed, true));
}

// T-02: the `--json` schema.
#[test]
fn t02_json_schema() {
    let json = to_json(&build_report(&mixed())).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["version"], 1);
    let data = &v["data"];
    assert_eq!(data["ok"], false);
    assert_eq!(data["problems"], 2);
    let ids: Vec<&str> = data["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["environment", "terminal", "agent", "keyring", "sync"]);
    for section in data["sections"].as_array().unwrap() {
        for c in section["checks"].as_array().unwrap() {
            assert!(
                ["ok", "info", "warn", "fail"].contains(&c["status"].as_str().unwrap()),
                "{c}"
            );
            for key in ["id", "label", "detail"] {
                assert!(c[key].is_string(), "{key} in {c}");
            }
        }
    }
    let pretty = serde_json::to_string_pretty(&v).unwrap();
    insta::assert_snapshot!("doctor_json", pretty);
}

// T-03: a 0755 data directory is warned about with a chmod hint; 0700 is fine.
#[test]
fn t03_permission_warning() {
    let fact = path(
        "data dir",
        "/home/u/.local/share/sverb",
        PathState::Exists(Some(0o755)),
        true,
    );
    let c = path_check(&fact);
    assert_eq!(c.status, Status::Warn);
    assert_eq!(
        c.detail,
        "/home/u/.local/share/sverb is 0755 (expected 0700)"
    );
    assert_eq!(
        c.hint.as_deref(),
        Some("chmod 700 /home/u/.local/share/sverb")
    );
    let ok = path("data dir", "/x", PathState::Exists(Some(0o700)), true);
    assert_eq!(path_check(&ok).status, Status::Ok);
    let db = path(
        "database file",
        "/x/sverb.db",
        PathState::Exists(Some(0o644)),
        false,
    );
    assert_eq!(
        path_check(&db).hint.as_deref(),
        Some("chmod 600 /x/sverb.db")
    );
    let spaced = path("data dir", "/a b", PathState::Exists(Some(0o750)), true);
    assert_eq!(
        path_check(&spaced).hint.as_deref(),
        Some("chmod 700 '/a b'")
    );
}

// T-03 on a real directory.
#[cfg(unix)]
#[test]
fn t03_permission_warning_on_disk() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempHome::new("perm");
    let data = dir.0.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(inspect_path(&data, true), PathState::Exists(Some(0o755)));
    assert_eq!(inspect_path(&data, false), PathState::WrongKind);
    assert_eq!(inspect_path(&dir.0.join("nope"), true), PathState::Missing);
}

// T-04: `--algos` is the M1-13 preference table filtered by russh, legacy marked.
#[test]
fn t04_algos_match_the_preference_table() {
    let categories = algo_categories(&supported());
    let table = secure_table();
    assert_eq!(categories.len(), 5);
    for (cat, kind) in categories.iter().zip([
        AlgoKind::Kex,
        AlgoKind::HostKey,
        AlgoKind::Cipher,
        AlgoKind::Mac,
        AlgoKind::Compression,
    ]) {
        let named = |status: &str| -> Vec<String> {
            cat.algorithms
                .iter()
                .filter(|a| a.status == status)
                .map(|a| a.name.clone())
                .collect()
        };
        assert_eq!(named("default"), table.list(kind), "{}", cat.kind);
        let legacy: Vec<String> = kind
            .legacy()
            .iter()
            .filter(|n| kind.is_supported(n))
            .map(|n| (*n).to_owned())
            .collect();
        assert_eq!(named("legacy"), legacy, "{}", cat.kind);
        for name in named("unavailable") {
            assert!(!kind.is_supported(&name), "{name}");
            assert!(
                kind.secure().contains(&name.as_str()) || kind.legacy().contains(&name.as_str())
            );
        }
        if kind == AlgoKind::HostKey {
            assert!(named("certificate").contains(&"ssh-ed25519-cert-v01@openssh.com".to_owned()));
        }
    }
    let kex = &categories[0];
    assert_eq!(kex.algorithms[0].name, "mlkem768x25519-sha256");
    for legacy in LEGACY_KEX {
        assert!(
            kex.algorithms
                .iter()
                .any(|a| a.name == *legacy && a.status == "legacy"),
            "{legacy}"
        );
    }
    // ssh-dss is in the legacy list but the pinned russh is built without DSA.
    assert!(
        categories[1]
            .algorithms
            .iter()
            .any(|a| a.name == "ssh-dss" && a.status == "unavailable")
    );
    let text = render_algos(&categories);
    assert!(
        text.contains("  default      curve25519-sha256\n"),
        "{text}"
    );
    assert!(text.contains("  legacy       ssh-rsa\n"), "{text}");
}

// --------------------------------------------------------- gather (temp homes)

/// A temporary SVERB_HOME (removed on drop).
struct TempHome(PathBuf);

impl TempHome {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sverb-m7-04-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn ctx(&self) -> Ctx {
        Ctx {
            paths: Paths::resolve(&MapEnv::new().var("SVERB_HOME", self.0.clone())).unwrap(),
            config: Config::default(),
            validators: Validators::default(),
            tty: Tty {
                stdin: false,
                stdout: false,
                stderr: false,
            },
        }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct NoAgent;

#[async_trait]
impl AgentConnector for NoAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        Err(AgentError("connection refused".into()))
    }
}

fn fake_probes(stdout_tty: bool) -> Probes {
    Probes {
        term_env: term_env(&[("TERM", "xterm-256color")]),
        stdout_tty,
        terminal: Box::new(|| TerminalAnswers {
            kitty: Ok(false),
            wide_char_width: Ok(Some(2)),
        }),
        system_agent: Arc::new(NoAgent),
        system_agent_source: None,
        keyring: Arc::new(MemKeyring::default()),
        keyring_disabled: false,
        sync_timeout: Duration::from_secs(5),
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn find<'a>(r: &'a Report, id: &str) -> &'a Check {
    r.sections
        .iter()
        .flat_map(|s| &s.checks)
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no {id}"))
}

// A fresh home: nothing exists, nothing is created, exit 0.
#[test]
fn fresh_home_is_fine_and_untouched() {
    let home = TempHome::new("fresh");
    let ctx = home.ctx();
    let probes = fake_probes(false);
    let mut out = Vec::new();
    let args = DoctorArgs {
        algos: false,
        json: false,
        ascii: true,
    };
    let code = block_on(run_with(args, &ctx, &probes, true, &mut out)).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(code, exit::OK, "{text}");
    assert!(
        text.contains("[info] kitty keyboard    skipped: not a terminal"),
        "{text}"
    );
    assert!(
        text.contains("[info] unicode width     skipped: not a terminal"),
        "{text}"
    );
    assert!(!text.contains('\x1b'), "{text}");
    assert!(!text.contains('✓'), "--ascii");
    // Read-only: the home is still empty.
    assert_eq!(std::fs::read_dir(&home.0).unwrap().count(), 0);
}

// The terminal probe runs only with a TTY on stdout.
#[test]
fn terminal_probes_only_with_a_tty() {
    let home = TempHome::new("tty");
    let ctx = home.ctx();
    let facts = block_on(gather(&ctx, &fake_probes(true)));
    assert_eq!(
        facts.term.answers,
        Some(TerminalAnswers {
            kitty: Ok(false),
            wide_char_width: Ok(Some(2)),
        })
    );
    let report = build_report(&facts);
    assert_eq!(find(&report, "term.kitty").status, Status::Warn);
    assert_eq!(find(&report, "term.width").status, Status::Ok);
    let facts = block_on(gather(&ctx, &fake_probes(false)));
    assert_eq!(facts.term.answers, None);
}

// T-03 through `gather`: a 0755 data dir and a database that is checked read-only.
#[cfg(unix)]
#[test]
fn t03_gather_reports_a_0755_data_dir() {
    use std::os::unix::fs::PermissionsExt;
    let home = TempHome::new("gather");
    let ctx = home.ctx();
    let data = ctx.paths.data_dir().to_path_buf();
    drop(sverb_store::Store::open(&ctx.paths).unwrap());
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    let report = build_report(&block_on(gather(&ctx, &fake_probes(false))));
    let c = find(&report, "env.path.data_dir");
    assert_eq!(c.status, Status::Warn, "{c:?}");
    assert!(c.detail.ends_with("is 0755 (expected 0700)"), "{c:?}");
    let db = find(&report, "env.database");
    assert_eq!(db.status, Status::Ok, "{db:?}");
    assert!(db.detail.contains("integrity ok"), "{db:?}");
    // An initialized-less database: keyring unlock is reported as disabled.
    assert_eq!(
        find(&report, "keyring.unlock")
            .detail
            .starts_with("disabled"),
        true
    );
    assert_eq!(find(&report, "keyring.available").status, Status::Ok);
}

// An invalid config.toml is a ✗ (exit 1).
#[test]
fn invalid_config_fails() {
    let home = TempHome::new("config");
    let ctx = home.ctx();
    std::fs::create_dir_all(ctx.paths.config_dir()).unwrap();
    std::fs::write(ctx.paths.config_file(), "[ui]\nnot_a_key = 1\n").unwrap();
    let report = build_report(&block_on(gather(&ctx, &fake_probes(false))));
    let c = find(&report, "env.config");
    assert_eq!(c.status, Status::Fail, "{c:?}");
    assert_eq!(report.exit_code(), exit::FAILURE);
}

// T-06 (CLI half): sync configured, server down → ✗ and exit 1.
#[cfg(feature = "sync")]
#[test]
fn t06_server_down_exits_1() {
    let home = TempHome::new("sync");
    let ctx = home.ctx();
    // A loopback port that nothing listens on.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    block_on(async {
        let paths = ctx.paths.clone();
        let store = tokio::task::spawn_blocking(move || sverb_store::Store::open(&paths))
            .await
            .unwrap()
            .unwrap();
        store
            .set_sync_state(sverb_store::SyncState {
                server_url: Some(format!("http://127.0.0.1:{port}")),
                device_id: None,
                tokens_enc: None,
            })
            .await
            .unwrap();
    });
    let mut out = Vec::new();
    let args = DoctorArgs {
        algos: false,
        json: true,
        ascii: false,
    };
    let code = block_on(run_with(args, &ctx, &fake_probes(false), true, &mut out)).unwrap();
    assert_eq!(code, exit::FAILURE);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let sync = v["data"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "sync")
        .unwrap();
    assert_eq!(sync["checks"][0]["id"], "sync.server");
    assert_eq!(sync["checks"][0]["status"], "fail", "{sync}");
    assert!(
        sync["checks"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("unreachable"),
        "{sync}"
    );
}

// `--algos --json` is the category list.
#[test]
fn algos_json() {
    let home = TempHome::new("algos");
    let ctx = home.ctx();
    let mut out = Vec::new();
    let args = DoctorArgs {
        algos: true,
        json: true,
        ascii: false,
    };
    let code = block_on(run_with(args, &ctx, &fake_probes(false), true, &mut out)).unwrap();
    assert_eq!(code, exit::OK);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["data"][0]["kind"], "kex");
    assert_eq!(v["data"][0]["algorithms"][0]["status"], "default");
}
