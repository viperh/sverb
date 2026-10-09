//! M0-07 tests: parsing (T-01..T-04, T-06), help snapshots (T-05), exit codes (T-11),
//! stubs (T-12) and the vault/TTY conventions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use clap::{CommandFactory, error::ErrorKind};
use pretty_assertions::assert_eq;
use sverb_core::{
    config::{Config, Validators},
    error_report::ErrorReport,
    host_arg::HostArgError,
    paths::{MapEnv, Paths},
};

use super::{
    exit::{self, CliError},
    export::ExportCmd,
    hosts::HostsCmd,
    // M2-11: OnConflict
    import::{ImportArgs, ImportSource, OnConflict},
    keys::{KeyType, KeysArgs, KeysCmd},
    snippet::SnippetCmd,
    *,
};

fn paths() -> Paths {
    Paths::resolve(&MapEnv::new().var("SVERB_HOME", "/nonexistent/sverb-home")).unwrap()
}

fn parse(args: &str) -> Result<Cli, clap::Error> {
    let argv = std::iter::once("sverb").chain(args.split_whitespace());
    Cli::try_parse_with(&paths(), argv)
}

fn cmd(args: &str) -> Command {
    parse(args)
        .unwrap_or_else(|e| panic!("`{args}` should parse: {e}"))
        .command
        .unwrap_or_else(|| panic!("`{args}` has no subcommand"))
}

fn ctx() -> Ctx {
    Ctx {
        paths: paths(),
        config: Config::default(),
        validators: Validators::default(),
        tty: Tty {
            stdin: false,
            stdout: false,
            stderr: false,
        },
    }
}

fn run_args(args: &str) -> (Result<u8, CliError>, String) {
    let cli = parse(args).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut out = Vec::new();
    let res = rt.block_on(run(cli, &ctx(), &mut out));
    (res, String::from_utf8(out).unwrap())
}

// T-01
#[test]
fn clap_debug_assert() {
    Cli::command().debug_assert();
}

// T-02: one row per SPEC §16 line (plus the forms named in the task).
#[test]
fn documented_forms_parse() {
    let s = |v: &str| v.to_owned();
    let p = PathBuf::from;

    let launch = parse("").unwrap();
    assert_eq!(
        (launch.command, launch.workspace, launch.debug),
        (None, None, false)
    );
    let ws = parse("--debug --workspace prod").unwrap();
    assert_eq!((ws.workspace, ws.debug), (Some(s("prod")), true));
    assert!(parse("hosts list --debug").unwrap().debug);

    let rows: Vec<(&str, Command)> = vec![
        (
            "connect root@db:2222",
            Command::Connect {
                target: s("root@db:2222"),
            },
        ),
        (
            "hosts list --json --tag a --tag b --group g",
            Command::Hosts(HostsCmd::List {
                json: true,
                tags: vec![s("a"), s("b")],
                group: Some(s("g")),
            }),
        ),
        (
            "hosts add 10.0.0.1 --user root --port 2222 --tag a --tag b",
            Command::Hosts(HostsCmd::Add {
                address: s("10.0.0.1"),
                label: None,
                user: Some(s("root")),
                port: Some(2222),
                group: None,
                create_group: false,
                tags: vec![s("a"), s("b")],
            }),
        ),
        (
            "hosts add h --label L --group G",
            Command::Hosts(HostsCmd::Add {
                address: s("h"),
                label: Some(s("L")),
                user: None,
                port: None,
                group: Some(s("G")),
                create_group: false,
                tags: vec![],
            }),
        ),
        (
            "hosts rm web",
            Command::Hosts(HostsCmd::Rm {
                host: s("web"),
                yes: false,
            }),
        ),
        (
            "keys list",
            Command::Keys(KeysArgs {
                dump: false,
                json: false,
                // M2-03: `--json`.
                cmd: Some(KeysCmd::List { json: false }),
            }),
        ),
        (
            "keys generate",
            Command::Keys(KeysArgs {
                dump: false,
                json: false,
                cmd: Some(KeysCmd::Generate {
                    key_type: KeyType::Ed25519,
                    label: None,
                    // M2-03
                    comment: None,
                    no_passphrase: false,
                }),
            }),
        ),
        (
            "keys generate --type rsa-4096 --label work",
            Command::Keys(KeysArgs {
                dump: false,
                json: false,
                cmd: Some(KeysCmd::Generate {
                    key_type: KeyType::Rsa4096,
                    label: Some(s("work")),
                    // M2-03
                    comment: None,
                    no_passphrase: false,
                }),
            }),
        ),
        (
            "keys import id_ed25519",
            Command::Keys(KeysArgs {
                dump: false,
                json: false,
                cmd: Some(KeysCmd::Import {
                    file: p("id_ed25519"),
                    // M2-03
                    label: None,
                }),
            }),
        ),
        (
            "keys export work --public",
            Command::Keys(KeysArgs {
                dump: false,
                json: false,
                cmd: Some(KeysCmd::Export {
                    key: s("work"),
                    public: true,
                    // M2-03
                    output: None,
                }),
            }),
        ),
        (
            "keys --dump",
            Command::Keys(KeysArgs {
                dump: true,
                json: false,
                cmd: None,
            }),
        ),
        (
            "keymap --dump --json",
            Command::Keymap(keys::KeymapArgs {
                dump: true,
                json: true,
            }),
        ),
        (
            "forward db-tunnel --detach",
            Command::Forward(forward::ForwardArgs {
                rule: s("db-tunnel"),
                detach: true,
                // M2-08
                detached_child: false,
            }),
        ),
        (
            "snippet run s --on h1 --on #web --json",
            Command::Snippet(SnippetCmd::Run {
                snippet: s("s"),
                on: vec![s("h1"), s("#web")],
                json: true,
                // M2-09:
                vars: vec![],
                concurrency: None,
                timeout: None,
            }),
        ),
        // M2-09:
        (
            "snippet run s --on g --var a=1 --var b=x=y --concurrency 3 --timeout 9",
            Command::Snippet(SnippetCmd::Run {
                snippet: s("s"),
                on: vec![s("g")],
                json: false,
                vars: vec![s("a=1"), s("b=x=y")],
                concurrency: Some(3),
                timeout: Some(9),
            }),
        ),
        (
            "import ssh-config",
            Command::Import(ImportArgs {
                dry_run: false,
                // M2-11
                vault: None,
                group: None,
                on_conflict: OnConflict::Skip,
                yes: false,
                identity_files: false,
                source: ImportSource::SshConfig { path: None },
            }),
        ),
        (
            "import known-hosts /tmp/kh --dry-run",
            Command::Import(ImportArgs {
                dry_run: true,
                // M2-11
                vault: None,
                group: None,
                on_conflict: OnConflict::Skip,
                yes: false,
                identity_files: false,
                source: ImportSource::KnownHosts {
                    path: Some(p("/tmp/kh")),
                },
            }),
        ),
        (
            "import putty",
            Command::Import(ImportArgs {
                dry_run: false,
                // M2-11
                vault: None,
                group: None,
                on_conflict: OnConflict::Skip,
                yes: false,
                identity_files: false,
                // M7-03
                source: ImportSource::Putty { path: None },
            }),
        ),
        (
            "import csv f.csv --dry-run",
            Command::Import(ImportArgs {
                dry_run: true,
                // M2-11
                vault: None,
                group: None,
                on_conflict: OnConflict::Skip,
                yes: false,
                identity_files: false,
                source: ImportSource::Csv { file: p("f.csv") },
            }),
        ),
        (
            "import --dry-run backup b.sverb",
            Command::Import(ImportArgs {
                dry_run: true,
                // M2-11
                vault: None,
                group: None,
                on_conflict: OnConflict::Skip,
                yes: false,
                identity_files: false,
                source: ImportSource::Backup { file: p("b.sverb") },
            }),
        ),
        (
            "export backup b.sverb",
            // M2-11: --force / --include-shared
            Command::Export(ExportCmd::Backup {
                file: p("b.sverb"),
                force: false,
                include_shared: false,
            }),
        ),
        (
            "export ssh-config out",
            Command::Export(ExportCmd::SshConfig {
                file: p("out"),
                force: false,
            }),
        ),
        (
            "export csv out.csv",
            Command::Export(ExportCmd::Csv {
                file: p("out.csv"),
                force: false,
            }),
        ),
        (
            "export recording 0190a5f2-7c1e-7000-8000-000000000000 out.cast",
            Command::Export(ExportCmd::Recording {
                id: s("0190a5f2-7c1e-7000-8000-000000000000"),
                out: p("out.cast"),
                // M3-05
                yes: false,
            }),
        ),
        (
            "export recording abc out.cast --yes",
            Command::Export(ExportCmd::Recording {
                id: s("abc"),
                out: p("out.cast"),
                // M3-05
                yes: true,
            }),
        ),
        (
            "approve db",
            // M2-10
            Command::Approve(approve::ApproveArgs {
                host: s("db"),
                all: false,
                yes: false,
            }),
        ),
        // M2-10
        (
            "approve db --all --yes",
            Command::Approve(approve::ApproveArgs {
                host: s("db"),
                all: true,
                yes: true,
            }),
        ),
        (
            "agent --socket /run/a.sock",
            Command::Agent(agent::AgentArgs {
                socket: Some(p("/run/a.sock")),
            }),
        ),
        ("agent", Command::Agent(agent::AgentArgs { socket: None })),
        ("lock", Command::Lock),
        ("unlock", Command::Unlock),
        (
            "config --check",
            Command::Config(config::ConfigArgs {
                check: true,
                print_default: false,
                path: false,
                schema: false,
                file: None,
            }),
        ),
        (
            "config --print-default",
            Command::Config(config::ConfigArgs {
                check: false,
                print_default: true,
                path: false,
                schema: false,
                file: None,
            }),
        ),
        (
            "config --path",
            Command::Config(config::ConfigArgs {
                check: false,
                print_default: false,
                path: true,
                schema: false,
                file: None,
            }),
        ),
        (
            "config --schema",
            Command::Config(config::ConfigArgs {
                check: false,
                print_default: false,
                path: false,
                schema: true,
                file: None,
            }),
        ),
        (
            "doctor --algos",
            Command::Doctor(doctor::DoctorArgs {
                algos: true,
                json: false,
                ascii: false,
            }),
        ),
    ];
    for (args, expected) in rows {
        assert_eq!(cmd(args), expected, "{args}");
    }
}

// T-02, sync rows.
#[cfg(feature = "sync")]
#[test]
fn sync_forms_parse() {
    let s = |v: &str| v.to_owned();
    let rows: Vec<(&str, Command)> = vec![
        (
            "join https://share.example/#k",
            Command::Join {
                link: s("https://share.example/#k"),
            },
        ),
        (
            "login --server https://sync.example",
            Command::Login(account::LoginArgs {
                server: Some(s("https://sync.example")),
                // M4-08
                email: None,
            }),
        ),
        (
            "logout --keep-local",
            Command::Logout(account::LogoutArgs { keep_local: true }),
        ),
        // M4-08
        (
            "register --server https://sync.example --email a@b.c",
            Command::Register(account::RegisterArgs {
                server: Some(s("https://sync.example")),
                email: Some(s("a@b.c")),
            }),
        ),
        (
            "sync --now --status",
            Command::Sync(account::SyncArgs {
                now: true,
                status: true,
                json: false,
            }),
        ),
        (
            "devices list --json",
            Command::Devices(devices::DevicesCmd::List { json: true }),
        ),
        (
            "devices revoke d1",
            Command::Devices(devices::DevicesCmd::Revoke { id: s("d1") }),
        ),
        (
            "team list",
            Command::Team(team::TeamCmd::List { json: false }),
        ),
        (
            "team invite a@b.c",
            Command::Team(team::TeamCmd::Invite {
                email: s("a@b.c"),
                org: None,
                role: sverb_proto::orgs::Role::Member,
            }),
        ),
        (
            "team verify alice",
            Command::Team(team::TeamCmd::Verify { user: s("alice") }),
        ),
    ];
    for (args, expected) in rows {
        assert_eq!(cmd(args), expected, "{args}");
    }
}

// T-03
#[test]
fn invalid_forms_are_usage_errors() {
    for args in [
        "hosts add",
        "keys generate --type dsa",
        "hosts add x --port 70000",
        "hosts add x --port 0",
        "snippet run s",
        "config",
        "config --check --path",
        "keys --dump list",
        "--workspace w hosts list",
        "--tick-rate 4",
        "--frame-rate 60",
    ] {
        let err = parse(args).expect_err(args);
        assert_eq!(err.exit_code(), 2, "{args}: {err}");
        // clap prints the usage line, or (for bad values) a pointer to `--help`.
        let text = err.render().to_string();
        assert!(
            text.contains("Usage:") || text.contains("try '--help'"),
            "{args}: {text}"
        );
    }
}

/// Every command path in the tree (`["hosts", "list"]`, …), root first.
fn command_paths() -> Vec<Vec<String>> {
    fn walk(cmd: &clap::Command, prefix: &[String], out: &mut Vec<Vec<String>>) {
        out.push(prefix.to_vec());
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let mut path = prefix.to_vec();
            path.push(sub.get_name().to_owned());
            walk(sub, &path, out);
        }
    }
    let mut out = Vec::new();
    walk(&Cli::command(), &[], &mut out);
    out
}

fn long_help(path: &[String]) -> String {
    let mut cmd = Cli::command().term_width(100);
    cmd.build();
    let mut cur = &mut cmd;
    for name in path {
        cur = cur.find_subcommand_mut(name).unwrap();
    }
    cur.clone().term_width(100).render_long_help().to_string()
}

// T-04 (and its sync counterpart)
#[test]
fn sync_commands_follow_the_feature() {
    let help = long_help(&[]);
    for name in SYNC_COMMANDS {
        let listed = help
            .lines()
            .any(|l| l.trim_start().starts_with(&format!("{name} ")));
        assert_eq!(listed, cfg!(feature = "sync"), "{name} in help:\n{help}");
    }
}

#[cfg(not(feature = "sync"))]
#[test]
fn sync_commands_print_the_no_sync_message() {
    for name in SYNC_COMMANDS {
        let (res, out) = run_args(&format!("{name} --server x"));
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(exit::NO_SYNC), "{err}");
        assert!(out.is_empty());
    }
    let (res, _) = run_args("frobnicate");
    assert_eq!(res.unwrap_err().exit_code(), 2);
}

// T-05
#[test]
fn help_snapshots() {
    let mut all = String::new();
    for path in command_paths() {
        let title = std::iter::once("sverb")
            .chain(path.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        all.push_str(&format!("===== {title} --help\n{}\n", long_help(&path)));
    }
    let suffix = if cfg!(feature = "sync") {
        "sync"
    } else {
        "local"
    };
    insta::with_settings!({ snapshot_suffix => suffix, prepend_module_to_snapshot => false }, {
        insta::assert_snapshot!("help", all);
    });
}

// T-06
#[test]
fn version_text() {
    let v = version(&paths());
    assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "{v}");
    assert!(v.contains(env!("VERGEN_GIT_DESCRIBE")), "{v}");
    assert!(v.contains(&format!("features: {FEATURES}")), "{v}");
    assert!(v.contains("SVERB_HOME"), "{v}");
    let err = parse("--version").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    assert!(err.to_string().contains(&format!("features: {FEATURES}")));
}

// T-11
#[test]
fn errors_map_to_documented_exit_codes() {
    let r = || ErrorReport::msg("x");
    let table = [
        (
            CliError::NotImplemented {
                command: "x",
                milestone: "M9-99",
            },
            exit::FAILURE,
        ),
        (CliError::Failure(r()), exit::FAILURE),
        (CliError::NoTty, exit::FAILURE),
        (CliError::Usage("x".into()), exit::USAGE),
        (
            CliError::NoSync {
                command: "login".into(),
            },
            exit::USAGE,
        ),
        (CliError::VaultLocked, exit::VAULT_LOCKED),
        (CliError::UnlockFailed(r()), exit::VAULT_LOCKED),
        (CliError::NotFound("x".into()), exit::NOT_FOUND),
        (
            CliError::HostArg(HostArgError::NotFound { query: "x".into() }),
            exit::NOT_FOUND,
        ),
        (
            CliError::ApprovalRequired { host: "db".into() },
            exit::APPROVAL_REQUIRED,
        ),
        (CliError::Network(r()), exit::NETWORK),
        (
            CliError::Partial {
                failed: 1,
                total: 3,
            },
            exit::PARTIAL,
        ),
    ];
    for (err, code) in table {
        assert_eq!(err.exit_code(), code, "{err:?}");
        assert!(
            exit::HELP.contains(&format!("  {code}  ")),
            "{code} undocumented"
        );
        assert!(err.report().to_string().starts_with("error: "));
    }
    assert_eq!(
        CliError::ApprovalRequired { host: "db".into() }.to_string(),
        "`db` has synced settings that act on this machine and are not approved yet; \
         review them with `sverb approve db`"
    );
    assert!(long_help(&[]).contains(exit::HELP.lines().next().unwrap()));
}

// T-12: every headless command that is still a stub says so and names a task.
#[test]
fn stubs_return_not_implemented() {
    let forms: Vec<&str> = vec![
        // M1-07: `hosts list | add | rm` are implemented (see `cli/hosts.rs`).
        // M2-03: `keys list | generate | import | export` are implemented (see
        // `cli/keys.rs` tests).
        // M0-10: `keys --dump` / `keymap --dump` are implemented (see `keys_dump`).
        // M2-08: `forward` is implemented (see `crates/sverb/tests/forward.rs`).
        // M2-09: `snippet run` is implemented (see `cli/snippet_tests.rs`).
        // M2-11: `import ssh-config | known-hosts | csv | backup` and `export backup |
        // ssh-config | csv` are implemented (see `cli/import_tests.rs`).
        // M7-03: `import putty` is implemented (see `cli/import_tests.rs`).
        // M3-05: `export recording` is implemented (see `crates/sverb/tests/export_recording.rs`).
        // M2-10: `approve` is implemented (see `crates/sverb/tests/approve.rs`).
        // M2-07: `agent` is implemented (see `cli/agent.rs`; it serves until stopped).
        // M7-04: `doctor` is implemented (see `cli/doctor_tests.rs`, tests/doctor.rs).
    ];
    // Sync builds: every sync command is implemented now. M4-08: `login`, `logout`,
    // `register` (`account_commands_need_a_terminal`, crates/sverb-sync/tests/account.rs);
    // M4-07: `sync`; M4-09: `devices list | revoke` (`cli/sync_tests.rs`); M5-01: `team
    // list | invite | create | accept` and M5-03: `team verify` (`cli/team.rs`).
    // Guard: every leaf command except the TUI launchers and `config` is listed.
    let leaves: Vec<String> = command_paths()
        .into_iter()
        .filter(|p| !p.is_empty())
        .filter(|p| {
            !command_paths()
                .iter()
                .any(|q| q.len() > p.len() && q.starts_with(p))
        })
        .map(|p| p.join(" "))
        .collect();
    for leaf in &leaves {
        let covered = matches!(
            leaf.as_str(),
            // M1-04: `lock` / `unlock` are implemented (see `vault_commands`).
            "connect" | "join" | "config" | "keymap" | "lock" | "unlock"
            // M1-07
            | "hosts list" | "hosts add" | "hosts rm"
            // M3-05: `export recording` is implemented (tests/export_recording.rs).
            | "export recording"
            // M2-08: `forward` is implemented (tests/forward.rs).
            | "forward"
            // M2-07
            | "agent"
            // M2-10: implemented (tests/approve.rs).
            | "approve"
            // M2-09: implemented (see `cli/snippet_tests.rs`).
            | "snippet run"
            // M2-03: implemented (see the `cli/keys.rs` tests).
            | "keys list" | "keys generate" | "keys import" | "keys export"
            // M2-11: implemented (see `cli/import_tests.rs`).
            | "import ssh-config" | "import known-hosts" | "import csv" | "import backup"
            // M7-03
            | "import putty"
            // M4-07: one headless engine cycle / the local sync state.
            | "sync"
            // M4-09
            | "devices list" | "devices revoke"
            // M5-03: implemented (see the `cli/team.rs` tests).
            | "team verify"
            // M5-01
            | "team list" | "team invite" | "team create" | "team accept"
            | "export backup" | "export ssh-config" | "export csv"
            // M4-08
            | "login" | "logout" | "register"
            // M7-04
            | "doctor"
            // M7-07: see `cli/generate.rs` tests.
            | "generate man" | "generate completions"
        ) || forms.iter().any(|f| f.starts_with(leaf.as_str()));
        assert!(covered, "`{leaf}` is not covered by the stub test");
    }
    for form in forms {
        let (res, out) = run_args(form);
        match res {
            Err(CliError::NotImplemented { milestone, .. }) => {
                assert!(milestone.starts_with('M'), "{form}: {milestone}");
            }
            other => panic!("{form}: expected NotImplemented, got {other:?}"),
        }
        assert!(out.is_empty(), "{form} printed {out:?}");
    }
}

// M4-08 T-11: without a terminal, `register` fails at once with exit 2 and
// prints nothing (the recovery words are only ever shown on a TTY); `login`
// and a wiping `logout` refuse to run too.
#[cfg(feature = "sync")]
#[test]
fn account_commands_need_a_terminal() {
    for args in [
        "register",
        "register --server https://sync.example --email a@b.c",
        "login --server https://sync.example --email a@b.c",
        "logout",
    ] {
        let (res, out) = run_args(args);
        let err = res.unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{args}: {err:?}");
        assert_eq!(err.exit_code(), exit::USAGE, "{args}");
        assert!(out.is_empty(), "{args} printed {out:?}");
    }
}

// T-09 (unit half): the TUI never starts without a terminal on stdout.
#[test]
fn tui_needs_a_terminal() {
    for args in ["", "connect db", "--workspace w"] {
        let (res, out) = run_args(args);
        assert_eq!(res, Err(CliError::NoTty), "{args}");
        assert!(out.is_empty());
    }
}

// T-08 / M1-04 T-16 (unit half): an initialized vault, keyring disabled, no terminal:
// exit 3 at once, never a prompt.
#[test]
fn vault_without_a_terminal_fails_fast() {
    let home = std::env::temp_dir().join(format!("sverb-m1-04-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", &home)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        paths.ensure(sverb_core::paths::DirKind::Data).unwrap();
        let store = sverb_store::Store::open(&paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store,
            std::sync::Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        engine
            .initialize("correct horse battery staple violin", false)
            .await
            .unwrap();
    });
    let mut ctx = ctx();
    ctx.paths = paths;
    ctx.tty = Tty {
        stdin: false,
        stdout: true,
        stderr: true,
    };
    let err = rt.block_on(vault::require_unlocked(&ctx)).unwrap_err();
    assert_eq!(err, CliError::VaultLocked);
    assert_eq!(err.exit_code(), 3);
    assert_eq!(
        err.report().to_string(),
        "error: vault is locked and no terminal is available to enter the master password"
    );
    let _ = std::fs::remove_dir_all(&home);
}

// M1-04: `lock` / `unlock` without a vault and without a terminal.
#[test]
fn vault_commands() {
    let (res, out) = run_args("lock");
    assert_eq!(res, Ok(exit::OK));
    assert!(out.is_empty());
    // Fresh home (nothing on disk is created): not initialized, exit 3.
    let (res, _) = run_args("unlock");
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert_eq!(
        err.report().to_string(),
        "error: sverb is not initialized; run `sverb` once to set a master password"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt.block_on(vault::require_unlocked(&ctx())).unwrap_err();
    assert_eq!(err.exit_code(), 3);
}

#[test]
fn headless_detection() {
    assert!(!parse("").unwrap().is_headless());
    assert!(!parse("connect x").unwrap().is_headless());
    assert!(parse("config --path").unwrap().is_headless());
    assert!(parse("hosts list").unwrap().is_headless());
}

#[test]
fn json_envelope() {
    #[derive(serde::Serialize)]
    struct Host {
        label: &'static str,
        port: u16,
    }
    let text = output::to_json(&vec![Host {
        label: "db",
        port: 22,
    }])
    .unwrap();
    insta::assert_snapshot!(text, @r#"{"version":1,"data":[{"label":"db","port":22}]}"#);
}

#[test]
fn config_print_default_and_path() {
    let (res, out) = run_args("config --print-default");
    assert_eq!(res, Ok(0));
    assert_eq!(out, sverb_core::config::DEFAULT_CONFIG_TOML);
    let (res, out) = run_args("config --path");
    assert_eq!(res, Ok(0));
    assert_eq!(out.trim_end(), paths().config_file().display().to_string());
    let (res, out) = run_args("config --schema");
    assert_eq!(res, Ok(0));
    assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
}

#[test]
fn config_located_errors() {
    let err = sverb_core::config::Config::from_toml_str(
        "[ssh]\nkeepalive_secs = \"x\"\n",
        &Validators::default(),
    )
    .errors
    .remove(0);
    let line = config::located(std::path::Path::new("/c/config.toml"), &err);
    assert!(line.starts_with("/c/config.toml:2:"), "{line}");
}

// M0-10 (T-20, CLI half): `sverb keys --dump` prints the effective keymap.
#[test]
fn keys_dump() {
    for args in ["keys --dump", "keymap --dump"] {
        let (res, out) = run_args(args);
        assert_eq!(res, Ok(0), "{args}");
        let first = out.lines().next().unwrap();
        assert!(first.starts_with("MODE"), "{first}");
        assert!(first.trim_end().ends_with("SOURCE"), "{first}");
        assert!(out.contains("ctrl-\\ ctrl-\\  send_leader"), "{out}");
        assert!(out.contains("ctrl-\\ -"), "{out}");
        assert!(
            out.lines()
                .any(|l| l.starts_with("normal") && l.contains("ctrl-k"))
        );
    }
    for args in ["keys --dump --json", "keymap --dump --json"] {
        let (res, out) = run_args(args);
        assert_eq!(res, Ok(0), "{args}");
        assert_eq!(out.lines().count(), 1, "one JSON line");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], 1);
        let rows = v["data"].as_array().unwrap();
        assert_eq!(rows[0]["action"], "send_leader");
        assert_eq!(rows[0]["mode"], "leader");
        assert!(
            rows.iter()
                .any(|r| r["keys"] == "ctrl-\\ p" && r["action"] == "palette")
        );
    }
}
