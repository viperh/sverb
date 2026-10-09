//! Entry point.
//!
//! The binary owns process setup (panic hook, paths, logging, CLI, config); the UI
//! lives in `sverb-tui` (reducer, views, runtime loop) and domain logic in
//! `sverb-core`, so both stay testable without a TTY.
//!
//! The order is fixed: panic hook → paths → CLI → logging → config → tokio
//! runtime → [`cli::dispatch`]. The runtime is built by hand (not `#[tokio::main]`)
//! so the panic hook and logging exist before it, and it is shut down with a timeout.

use std::io::Write as _;
use std::{process::ExitCode, time::Duration};

use cli::{Cli, Ctx, Tty};
use sverb_core::config::Config;
use sverb_core::paths::{Paths, SystemEnv};

mod cli;
// `config.rs` (the template key parser) moved to `sverb_tui::keymap::chord`.
mod logging;
// `errors.rs` → `panic.rs`; the template `tui.rs` is deleted (the panic hook
// restores the terminal through `sverb_tui::runtime::terminal`).
mod panic;

/// How long background tasks get to finish after the command returns.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    match try_main() {
        Ok(code) => ExitCode::from(code),
        // Unexpected internal errors only: the color-eyre report (exit 1).
        Err(report) => {
            // Not `eprintln!`: it panics when stderr is gone (the terminal closed).
            let _ = writeln!(std::io::stderr(), "{report:?}");
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> color_eyre::Result<u8> {
    // First, so even a panic while resolving paths or starting logging
    // restores the terminal. A panicking UI task unwinds out of `block_on` (exit 101)
    // after the hook restored the terminal and wrote the crash report.
    crate::panic::install()?;
    // No core dumps, no same-user ptrace (Linux), before any secret exists
    // (SPEC §17). Best effort; the outcome is logged at debug once logging is up.
    let hardening = sverb_core::hardening::harden_process();
    // Resolve the directories once, before anything touches the disk,
    // and pass them explicitly to logging, the CLI, config and the app.
    let paths = Paths::resolve(&SystemEnv)?;
    // Crash reports go to `<state>/crash/`.
    crate::panic::set_crash_dir(&paths);
    // Parse the CLI before logging, which needs `--debug`. The guard flushes
    // the log file when dropped, so it must outlive everything that logs.
    let args = Cli::parse_with(&paths);
    let log_guard = crate::logging::init(
        &paths,
        crate::logging::LogOptions {
            debug: args.debug,
            headless: args.is_headless(),
        },
    )?;
    for warning in paths.warnings() {
        tracing::warn!("{warning}");
    }
    tracing::debug!(
        core_dumps_disabled = hardening.core_dumps_disabled,
        non_dumpable = hardening.non_dumpable,
        failures = ?hardening.failures,
        "process hardening"
    );

    // config.toml (SPEC §15). A bad file never stops startup: the defaults are
    // used and every problem is logged (reload errors become toasts in the reducer).
    // The real keymap validator; The real theme and scheme catalog.
    let validators = sverb_tui::keymap::validators();
    // Publish the user color schemes (`themes/*.toml`) so `terminal.color_scheme`
    // may name one; broken scheme files are logged and skipped.
    let (_, scheme_errors) =
        sverb_tui::widgets::terminal_pane::load_schemes(Some(&paths.themes_dir()));
    for err in &scheme_errors {
        tracing::warn!("color scheme skipped: {err}");
    }
    let loaded = Config::load(&paths, &validators);
    for problem in loaded.errors.iter().chain(&loaded.warnings) {
        tracing::warn!("config: {problem}");
    }
    if !loaded.is_ok() {
        tracing::warn!("config.toml has errors; using the defaults");
    }

    // Built by hand, after the panic hook and logging.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sverb-rt")
        .build()?;
    let ctx = Ctx {
        paths,
        config: loaded.config,
        validators,
        tty: Tty::detect(),
    };
    let code = runtime.block_on(cli::dispatch(args, &ctx, &mut std::io::stdout()));
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    // Flush the log file before exiting.
    drop(log_guard);
    Ok(code)
}

// `keymap_from_config` removed with the template config.
