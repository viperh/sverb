//! M0-04 integration tests for the global logging setup (T-01, T-02, T-03, T-04,
//! T-05, T-07, T-08, T-11, T-12).
//!
//! `logging::init` installs a process-global subscriber, so every scenario runs in a
//! child process: this binary re-executes itself with `SVERB_LOG_TEST_CHILD=<scenario>`.
//! It is built with `harness = false` so the child's stdout and stderr contain only
//! what sverb writes (T-12 asserts they're empty).

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode, Output},
};

use sverb_core::{
    logging::{self, LogOptions},
    paths::{Paths, SystemEnv},
    secret::SecretString,
};
use tracing::{debug, error, info, trace, warn};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Test = (&'static str, fn() -> TestResult);

const CHILD_ENV: &str = "SVERB_LOG_TEST_CHILD";
const MSG_ENV: &str = "SVERB_LOG_TEST_MSG";

fn main() -> ExitCode {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        return match child(&scenario) {
            Ok(()) => ExitCode::SUCCESS,
            // The parent asserts on the exit code only; printing would break T-12.
            Err(_) => ExitCode::from(2),
        };
    }

    let tests: &[Test] = &[
        ("t01_file_in_state_dir", t01_file_in_state_dir),
        (
            "t02_no_truncation_across_runs",
            t02_no_truncation_across_runs,
        ),
        (
            "t03_retention_keeps_seven_files",
            t03_retention_keeps_seven_files,
        ),
        (
            "t04_sverb_log_controls_the_filter",
            t04_sverb_log_controls_the_filter,
        ),
        ("t04_rust_log_is_ignored", t04_rust_log_is_ignored),
        (
            "t05_invalid_sverb_log_degrades",
            t05_invalid_sverb_log_degrades,
        ),
        (
            "t07_global_crash_ring_filters",
            t07_global_crash_ring_filters,
        ),
        ("t08_redaction_canary", t08_redaction_canary),
        ("t11_non_blocking_flush", t11_non_blocking_flush),
        (
            "t12_stdout_and_stderr_stay_clean",
            t12_stdout_and_stderr_stay_clean,
        ),
    ];
    let filter: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let mut failed = 0;
    let mut ran = 0;
    for (name, test) in tests {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        match test() {
            Ok(()) => println!("test {name} ... ok"),
            Err(err) => {
                failed += 1;
                println!("test {name} ... FAILED\n    {err}");
            }
        }
    }
    println!(
        "\ntest result: {}. {} passed; {failed} failed",
        if failed == 0 { "ok" } else { "FAILED" },
        ran - failed
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------- child side

fn child(scenario: &str) -> Result<(), Box<dyn std::error::Error>> {
    let paths = Paths::resolve(&SystemEnv)?;
    let opts = LogOptions {
        debug: std::env::var_os("SVERB_LOG_TEST_DEBUG").is_some(),
        headless: true,
    };
    let guard = logging::init(&paths, opts)?;
    let msg = std::env::var(MSG_ENV).unwrap_or_default();
    match scenario {
        "emit" => info!("{msg}"),
        "levels" => {
            trace!("lvl-trace");
            debug!("lvl-debug");
            info!("lvl-info");
            warn!("lvl-warn");
            error!("lvl-error");
            debug!(target: "sverb_conn", "lvl-conn-debug");
            debug!(target: "sverb_store", "lvl-store-debug");
        }
        "canary" => {
            let secret = SecretString::from("CANARY-1b9f");
            info!(pw = ?secret, "x");
            info!(pw = %secret, "y");
            debug!("{:?}", secret);
            error!("{secret}");
        }
        "flood" => {
            for i in 0..10_000 {
                info!("flood-{i:05}");
            }
        }
        "crash_ring" => {
            debug!("cr-debug");
            info!("cr-info");
            let ring = logging::crash_ring().ok_or("no global crash ring")?;
            let msgs: Vec<_> = ring.snapshot().into_iter().map(|l| l.message).collect();
            if msgs.iter().any(|m| m == "cr-debug") || !msgs.iter().any(|m| m == "cr-info") {
                return Err("crash ring content".into());
            }
            if guard.debug_ring().is_some() {
                return Err("debug ring without --debug".into());
            }
        }
        other => return Err(format!("unknown scenario {other}").into()),
    }
    // Dropping the guard flushes the non-blocking writer.
    drop(guard);
    Ok(())
}

// --------------------------------------------------------------- parent side

/// A fresh, unique `SVERB_HOME`, removed on drop.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "sverb-logging-it-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }

    /// Runs a child scenario with this home and `env`, asserting success.
    fn run(
        &self,
        scenario: &str,
        env: &[(&str, &str)],
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.env(CHILD_ENV, scenario)
            .env("SVERB_HOME", &self.0)
            .env_remove("SVERB_LOG")
            .env_remove("RUST_LOG")
            .env_remove("SVERB_LOG_TEST_DEBUG");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(format!("child {scenario} failed: {:?}", out.status).into());
        }
        Ok(out)
    }

    /// The dated log files in the state dir, sorted by name.
    fn log_files(&self) -> std::io::Result<Vec<String>> {
        let mut names: Vec<String> = std::fs::read_dir(self.state())?
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("sverb.") && n.ends_with(".log"))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Contents of today's log file.
    fn today(&self) -> std::io::Result<String> {
        std::fs::read_to_string(self.state().join(format!("sverb.{}.log", utc_today())))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Today's UTC date as `YYYY-MM-DD` (the appender rotates on UTC days).
fn utc_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let z = secs / 86_400 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn ensure(cond: bool, what: &str) -> TestResult {
    if cond {
        Ok(())
    } else {
        Err(what.to_owned().into())
    }
}

fn is_empty_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir).map_or(true, |mut d| d.next().is_none())
}

// T-01
fn t01_file_in_state_dir() -> TestResult {
    let home = Home::new("t01")?;
    home.run("emit", &[(MSG_ENV, "t01-hello")])?;
    let log = home.today()?;
    ensure(
        log.contains("t01-hello"),
        "message missing from state/sverb.<date>.log",
    )?;
    ensure(home.log_files()?.len() == 1, "exactly one log file")?;
    ensure(
        is_empty_dir(&home.0.join("data")),
        "something was created in data/",
    )?;
    Ok(())
}

// T-02
fn t02_no_truncation_across_runs() -> TestResult {
    let home = Home::new("t02")?;
    home.run("emit", &[(MSG_ENV, "t02-run-A")])?;
    home.run("emit", &[(MSG_ENV, "t02-run-B")])?;
    let log = home.today()?;
    ensure(log.contains("t02-run-A"), "first run's line was lost")?;
    ensure(log.contains("t02-run-B"), "second run's line missing")?;
    Ok(())
}

// T-03
fn t03_retention_keeps_seven_files() -> TestResult {
    let home = Home::new("t03")?;
    std::fs::create_dir_all(home.state())?;
    // Created oldest first: the appender prunes by creation time.
    for day in 20..30 {
        let path = home.state().join(format!("sverb.2026-09-{day}.log"));
        std::fs::write(path, format!("old {day}\n"))?;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    home.run("emit", &[(MSG_ENV, "t03-new")])?;
    let files = home.log_files()?;
    ensure(
        files.len() <= 7,
        &format!("more than 7 log files: {files:?}"),
    )?;
    let today = format!("sverb.{}.log", utc_today());
    ensure(files.contains(&today), "today's file missing")?;
    // The oldest were removed; the newest pre-existing ones remain.
    ensure(
        !files.contains(&"sverb.2026-09-20.log".to_owned()),
        "oldest file kept",
    )?;
    ensure(
        files.contains(&"sverb.2026-09-29.log".to_owned()),
        "newest old file removed",
    )?;
    Ok(())
}

// T-04
fn t04_sverb_log_controls_the_filter() -> TestResult {
    let home = Home::new("t04a")?;
    home.run("levels", &[("SVERB_LOG", "warn")])?;
    let log = home.today()?;
    ensure(!log.contains("lvl-info"), "SVERB_LOG=warn kept info")?;
    ensure(
        log.contains("lvl-warn") && log.contains("lvl-error"),
        "warn/error missing",
    )?;

    let home = Home::new("t04b")?;
    home.run("levels", &[("SVERB_LOG", "sverb_conn=debug")])?;
    let log = home.today()?;
    ensure(
        log.contains("lvl-conn-debug"),
        "sverb_conn=debug not enabled",
    )?;
    ensure(
        !log.contains("lvl-store-debug"),
        "debug leaked to another target",
    )?;
    ensure(!log.contains("lvl-debug"), "global debug enabled")?;
    ensure(log.contains("lvl-info"), "default info lost")?;
    Ok(())
}

// T-04
fn t04_rust_log_is_ignored() -> TestResult {
    let home = Home::new("t04c")?;
    home.run("levels", &[("RUST_LOG", "trace")])?;
    let log = home.today()?;
    ensure(
        !log.contains("lvl-trace") && !log.contains("lvl-debug"),
        "RUST_LOG had an effect",
    )?;
    ensure(log.contains("lvl-info"), "info missing")?;
    Ok(())
}

// T-05
fn t05_invalid_sverb_log_degrades() -> TestResult {
    let home = Home::new("t05")?;
    home.run("levels", &[("SVERB_LOG", "=[[[")])?;
    let log = home.today()?;
    ensure(
        log.contains("ignoring invalid SVERB_LOG"),
        "no warning about the bad directive",
    )?;
    ensure(
        log.contains("lvl-info") && !log.contains("lvl-debug"),
        "not the default info level",
    )?;
    Ok(())
}

// T-07
fn t07_global_crash_ring_filters() -> TestResult {
    let home = Home::new("t07")?;
    home.run("crash_ring", &[])?;
    Ok(())
}

// T-08
fn t08_redaction_canary() -> TestResult {
    let home = Home::new("t08")?;
    let out = home.run("canary", &[("SVERB_LOG", "trace")])?;
    let log = home.today()?;
    ensure(log.contains("[REDACTED]"), "no [REDACTED] in the log")?;
    ensure(
        !log.contains("CANARY-1b9f"),
        "canary leaked into the log file",
    )?;
    ensure(
        log.matches("[REDACTED]").count() >= 4,
        "some secret lines missing",
    )?;
    let printed = [out.stdout, out.stderr].concat();
    ensure(
        !String::from_utf8_lossy(&printed).contains("CANARY"),
        "canary printed",
    )?;
    Ok(())
}

// T-11
fn t11_non_blocking_flush() -> TestResult {
    let home = Home::new("t11")?;
    home.run("flood", &[])?;
    let log = home.today()?;
    let n = log.lines().filter(|l| l.contains("flood-")).count();
    ensure(n == 10_000, &format!("expected 10000 lines, found {n}"))?;
    ensure(log.contains("flood-09999"), "last line missing")?;
    Ok(())
}

// T-12
fn t12_stdout_and_stderr_stay_clean() -> TestResult {
    for (tag, env) in [
        ("t12a", vec![("SVERB_LOG", "trace")]),
        ("t12b", vec![("SVERB_LOG", "=[[[")]),
        ("t12c", vec![("SVERB_LOG_TEST_DEBUG", "1")]),
    ] {
        let home = Home::new(tag)?;
        let out = home.run("levels", &env)?;
        ensure(
            out.stdout.is_empty(),
            &format!("{tag}: stdout not empty: {:?}", out.stdout),
        )?;
        ensure(
            out.stderr.is_empty(),
            &format!("{tag}: stderr not empty: {:?}", out.stderr),
        )?;
        ensure(
            home.today()?.contains("lvl-error"),
            "logs did not reach the file",
        )?;
    }
    Ok(())
}
