//! Process-wide `tracing` setup (SPEC §17, §18).
//!
//! [`init`] installs, once per process:
//! 1. a **file layer**: `<state dir>/sverb.<YYYY-MM-DD>.log`, rotated daily (UTC), at most
//!    [`MAX_LOG_FILES`] files kept, appended to (never truncated), written by a background
//!    thread (`tracing_appender::non_blocking`) so the UI task never blocks on disk.
//!    Format: RFC 3339 UTC timestamp, level, target, file:line, no ANSI;
//! 2. the **crash ring** ([`CRASH_RING_CAPACITY`] lines, `info`+, always on, for crash
//!    reports; see [`crash_ring`]);
//! 3. the **debug ring** ([`DEBUG_RING_CAPACITY`] lines, same filter as the file, only
//!    with `--debug` in the TUI) for the log pane;
//! 4. `tracing_error::ErrorLayer`, for color-eyre span traces.
//!
//! The filter comes from [`LOG_ENV`] (`SVERB_LOG`) only; `RUST_LOG` is ignored. The
//! default is `info`, or `debug` with `--debug`; directives in `SVERB_LOG` refine or
//! override that default. An invalid `SVERB_LOG` never aborts startup: the default
//! is used and a warning is logged right after init.
//!
//! Nothing here ever writes to stdout or stderr (stdout belongs to the TUI).
//! See `docs/logging.md` for the logging policy (no hostnames, usernames or commands
//! at `info` and above).

pub mod ring;

use std::{path::Path, sync::OnceLock, time::Duration};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::Subscriber;
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Layer, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

pub use self::ring::{LogLine, LogRing, RingLayer};
use crate::paths::{DirKind, Paths};

/// The only environment variable that controls the log filter.
pub const LOG_ENV: &str = "SVERB_LOG";
/// Log file names are `<prefix>.<YYYY-MM-DD>.<suffix>`.
pub const LOG_FILE_PREFIX: &str = "sverb";
/// See [`LOG_FILE_PREFIX`].
pub const LOG_FILE_SUFFIX: &str = "log";
/// Number of daily log files kept (SPEC §18: 7 days).
pub const MAX_LOG_FILES: usize = 7;
/// Lines kept by the `--debug` ring that the TUI log pane reads.
pub const DEBUG_RING_CAPACITY: usize = 5_000;
/// Lines kept by the always-on `info`+ ring that crash reports include.
pub const CRASH_RING_CAPACITY: usize = 200;
/// Shown once when `--debug` is on (TUI toast, or stderr for headless commands).
pub const DEBUG_WARNING: &str = "Debug logging is on: log files may contain hostnames.";

/// How the process wants logging set up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogOptions {
    /// `--debug`: default level `debug`, plus the debug ring for the log pane.
    pub debug: bool,
    /// A headless CLI command (no TUI): no log pane, so no debug ring. The caller
    /// prints [`DEBUG_WARNING`] to stderr instead of showing a toast.
    pub headless: bool,
}

/// Errors from [`init`].
#[derive(Debug, Error)]
pub enum LoggingError {
    /// The state directory could not be created.
    #[error("cannot create the log directory {path}: {source}")]
    StateDir {
        /// The directory.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The rolling log file could not be opened.
    #[error("cannot open the log file: {0}")]
    Appender(#[from] tracing_appender::rolling::InitError),
    /// A global subscriber was already installed in this process.
    #[error("logging is already initialized")]
    AlreadyInitialized,
}

/// Keeps logging alive. Dropping it flushes the file writer (see [`shutdown`]).
///
/// Hold it in `main` for the whole run.
#[derive(Debug)]
pub struct LoggingGuard {
    options: LogOptions,
    crash_ring: LogRing,
    debug_ring: Option<LogRing>,
}

impl LoggingGuard {
    /// The options logging was initialized with.
    pub fn options(&self) -> LogOptions {
        self.options
    }

    /// The always-on `info`+ ring (also reachable through [`crash_ring`]).
    pub fn crash_ring(&self) -> &LogRing {
        &self.crash_ring
    }

    /// The `--debug` ring for the log pane, if enabled.
    pub fn debug_ring(&self) -> Option<&LogRing> {
        self.debug_ring.as_ref()
    }
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        shutdown();
    }
}

/// The file writer's worker guard. A static so the panic hook can flush it
/// with [`shutdown`] without access to `main`'s locals.
static WORKER: Mutex<Option<WorkerGuard>> = Mutex::new(None);
/// The crash ring, for the panic hook.
static CRASH_RING: OnceLock<LogRing> = OnceLock::new();
/// The `--debug` ring (TUI only), for the log pane.
static DEBUG_RING: OnceLock<LogRing> = OnceLock::new();

/// Flushes and stops the background file writer. Idempotent; events logged
/// afterwards are dropped. Safe to call from a panic hook: it waits at most
/// 100 ms for the lock.
pub fn shutdown() {
    let worker = WORKER
        .try_lock_for(Duration::from_millis(100))
        .and_then(|mut slot| slot.take());
    drop(worker);
}

/// The crash ring installed by [`init`], if logging is initialized.
pub fn crash_ring() -> Option<LogRing> {
    CRASH_RING.get().cloned()
}

/// The `--debug` ring installed by [`init`] (same as [`LoggingGuard::debug_ring`]), if
/// logging is initialized with `--debug` for the TUI. The TUI runtime reads it here so
/// the log pane needs no plumbing through the CLI layer.
pub fn debug_ring() -> Option<LogRing> {
    DEBUG_RING.get().cloned()
}

/// Installs the global subscriber. Reads the filter from [`LOG_ENV`].
///
/// Creates the state directory (`0700` on Unix) first.
pub fn init(paths: &Paths, opts: LogOptions) -> Result<LoggingGuard, LoggingError> {
    let filter = std::env::var(LOG_ENV).ok();
    init_with_filter(paths, opts, filter.as_deref())
}

/// [`init`] with an explicit `SVERB_LOG` value instead of reading the environment.
pub fn init_with_filter(
    paths: &Paths,
    opts: LogOptions,
    sverb_log: Option<&str>,
) -> Result<LoggingGuard, LoggingError> {
    paths
        .ensure(DirKind::State)
        .map_err(|source| LoggingError::StateDir {
            path: paths.log_dir().display().to_string(),
            source,
        })?;
    let built = build(paths.log_dir(), opts, sverb_log)?;
    let Built {
        subscriber,
        worker,
        crash_ring,
        debug_ring,
        filter_warning,
    } = built;
    if subscriber.try_init().is_err() {
        drop(worker);
        return Err(LoggingError::AlreadyInitialized);
    }
    *WORKER.lock() = Some(worker);
    let _ = CRASH_RING.set(crash_ring.clone());
    if let Some(ring) = &debug_ring {
        let _ = DEBUG_RING.set(ring.clone());
    }
    if let Some(warning) = filter_warning {
        tracing::warn!("{warning}");
    }
    Ok(LoggingGuard {
        options: opts,
        crash_ring,
        debug_ring,
    })
}

/// Everything [`init`] installs, before it is installed (tests use it with
/// `tracing::subscriber::with_default`).
pub(crate) struct Built<S> {
    pub(crate) subscriber: S,
    pub(crate) worker: WorkerGuard,
    pub(crate) crash_ring: LogRing,
    pub(crate) debug_ring: Option<LogRing>,
    /// A warning about an invalid `SVERB_LOG`, to log once the subscriber is active.
    pub(crate) filter_warning: Option<String>,
}

pub(crate) fn build(
    log_dir: &Path,
    opts: LogOptions,
    sverb_log: Option<&str>,
) -> Result<Built<impl Subscriber + Send + Sync + 'static>, LoggingError> {
    let appender = rolling::Builder::new()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(MAX_LOG_FILES)
        .build(log_dir)?;
    let (writer, worker) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .thread_name("sverb-log")
        .finish(appender);

    let (file_filter, filter_warning) = filter(opts, sverb_log);
    let file_layer = fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_timer(fmt::time::SystemTime)
        .with_target(true)
        .with_level(true)
        .with_file(true)
        .with_line_number(true)
        // Never fall back to stderr when the writer fails (stdout/stderr belong to the TUI).
        .log_internal_errors(false)
        .with_filter(file_filter);

    let crash_ring = LogRing::new(CRASH_RING_CAPACITY);
    let crash_layer = RingLayer::new(crash_ring.clone()).with_filter(LevelFilter::INFO);

    let debug_ring = (opts.debug && !opts.headless).then(|| LogRing::new(DEBUG_RING_CAPACITY));
    let debug_layer = debug_ring
        .clone()
        .map(|ring| RingLayer::new(ring).with_filter(filter(opts, sverb_log).0));

    let subscriber = tracing_subscriber::registry()
        .with(file_layer)
        .with(crash_layer)
        .with(debug_layer)
        .with(ErrorLayer::default());
    Ok(Built {
        subscriber,
        worker,
        crash_ring,
        debug_ring,
        filter_warning,
    })
}

/// Builds the filter from `SVERB_LOG` (`sverb_log`) over the default level. Returns
/// the default filter and a warning when the value doesn't parse.
pub(crate) fn filter(opts: LogOptions, sverb_log: Option<&str>) -> (EnvFilter, Option<String>) {
    let default = if opts.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let builder = || EnvFilter::builder().with_default_directive(default.into());
    let raw = sverb_log.map(str::trim).unwrap_or_default();
    match builder().parse(raw) {
        // `with_default_directive` only applies when `raw` is empty. Keep the default
        // level for everything else when `SVERB_LOG` only names targets
        // (`sverb_conn=debug` should not silence the rest).
        Ok(filter)
            if !raw
                .split(',')
                .any(|d| d.trim().parse::<LevelFilter>().is_ok()) =>
        {
            (filter.add_directive(default.into()), None)
        }
        Ok(filter) => (filter, None),
        Err(err) => (
            EnvFilter::default().add_directive(default.into()),
            Some(format!(
                "ignoring invalid {LOG_ENV} ({err}); using the default level `{default}`"
            )),
        ),
    }
}

#[cfg(test)]
mod tests;
