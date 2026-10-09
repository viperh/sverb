//! Process logging at the binary edge.
//!
//! The subscriber itself (daily-rotated file in the state dir, `SVERB_LOG`, crash and
//! debug rings, `ErrorLayer`) lives in [`sverb_core::logging`], so the TUI log pane
//!  and the panic hook can share its rings. This module only adds the
//! user-facing `--debug` warning for headless commands (the TUI shows it as a one-time

use sverb_core::{
    logging::{DEBUG_WARNING, LoggingGuard},
    paths::Paths,
};

pub(crate) use sverb_core::logging::LogOptions;

/// Installs the global subscriber. Keep the returned guard alive until exit:
/// dropping it flushes the log file.
pub(crate) fn init(paths: &Paths, opts: LogOptions) -> color_eyre::Result<LoggingGuard> {
    let guard = sverb_core::logging::init(paths, opts)?;
    // The TUI shows the warning as a one-time toast (it reads the debug ring
    // through `sverb_core::logging::debug_ring()`); headless commands use stderr
    // .
    if opts.debug && opts.headless {
        eprintln!("warning: {DEBUG_WARNING}");
    }
    Ok(guard)
}
