//! Structured logging (SPEC §18): JSON lines on stdout by default.
//!
//! The level filter comes from `SVERB_LOG`, else `RUST_LOG`, else `info`.

use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

fn filter() -> EnvFilter {
    EnvFilter::try_from_env("SVERB_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Installs the global subscriber. Calling it twice is harmless (the second
/// call is ignored).
pub fn init(format: LogFormat) {
    let builder = tracing_subscriber::fmt().with_env_filter(filter());
    let result = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    // Already initialised (tests, or the admin CLI after serve): keep the first.
    drop(result);
}
