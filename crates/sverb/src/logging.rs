//! M0-04: process logging at the binary edge.
//!
//! The subscriber itself (daily-rotated file in the state dir, `SVERB_LOG`, crash and
//! debug rings, `ErrorLayer`) lives in [`sverb_core::logging`], so the TUI log pane
//! (M0-11) and the panic hook (M0-05) can share its rings. This module only adds the
//! user-facing `--debug` warning for headless commands (the TUI shows it as a one-time
//! toast, M0-11). Logging itself never writes to stdout or stderr.

use sverb_core::{
    logging::{DEBUG_WARNING, LoggingGuard},
    paths::Paths,
};

pub(crate) use sverb_core::logging::LogOptions;

/// Installs the global subscriber. Keep the returned guard alive until exit:
/// dropping it flushes the log file.
pub(crate) fn init(paths: &Paths, opts: LogOptions) -> color_eyre::Result<LoggingGuard> {
    let guard = sverb_core::logging::init(paths, opts)?;
    // M0-11: the TUI shows the warning as a one-time toast (it reads the debug ring
    // through `sverb_core::logging::debug_ring()`); headless commands use stderr
    // (M0-04 §2.2).
    if opts.debug && opts.headless {
        eprintln!("warning: {DEBUG_WARNING}");
    }
    Ok(guard)
}
