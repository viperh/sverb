//! Unit tests for the subscriber layout.
//!
//! These install the subscriber with `tracing::subscriber::with_default` (scoped to
//! the test thread), so they can run in parallel. The child-process tests that use
//! the global [`init`](super::init) are in `tests/logging.rs`.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use tracing::{Level, debug, info, trace, warn};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh, unique temp directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "sverb-logging-unit-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Concatenation of every log file in `dir`.
fn read_logs(dir: &Path) -> std::io::Result<String> {
    let mut out = String::new();
    for entry in std::fs::read_dir(dir)? {
        out.push_str(&std::fs::read_to_string(entry?.path())?);
    }
    Ok(out)
}

/// Builds the subscriber for `opts`/`sverb_log` in a temp dir, runs `f` under it
/// (logging the filter warning first, as `init` does), flushes, and returns the
/// file contents and the rings.
fn run(
    tag: &str,
    opts: LogOptions,
    sverb_log: Option<&str>,
    f: impl FnOnce(),
) -> Result<(String, LogRing, Option<LogRing>), Box<dyn std::error::Error>> {
    let dir = TempDir::new(tag)?;
    let Built {
        subscriber,
        worker,
        crash_ring,
        debug_ring,
        filter_warning,
    } = build(&dir.0, opts, sverb_log)?;
    tracing::subscriber::with_default(subscriber, || {
        if let Some(w) = filter_warning {
            warn!("{w}");
        }
        f();
    });
    drop(worker);
    Ok((read_logs(&dir.0)?, crash_ring, debug_ring))
}

#[test]
fn sverb_log_warn_drops_info() -> TestResult {
    let (log, ..) = run("warn", LogOptions::default(), Some("warn"), || {
        info!("t04-info-line");
        warn!("t04-warn-line");
    })?;
    assert!(!log.contains("t04-info-line"), "{log}");
    assert!(log.contains("t04-warn-line"), "{log}");
    Ok(())
}

#[test]
fn sverb_log_target_directive_enables_debug_for_that_target_only() -> TestResult {
    let (log, ..) = run(
        "target",
        LogOptions::default(),
        Some("sverb_conn=debug"),
        || {
            debug!(target: "sverb_conn", "t04-conn-debug");
            debug!(target: "sverb_store", "t04-store-debug");
            info!(target: "sverb_store", "t04-store-info");
        },
    )?;
    assert!(log.contains("t04-conn-debug"), "{log}");
    assert!(!log.contains("t04-store-debug"), "{log}");
    assert!(log.contains("t04-store-info"), "{log}");
    Ok(())
}

// Defaults
#[test]
fn default_is_info_or_debug_with_flag() -> TestResult {
    let (log, ..) = run("default", LogOptions::default(), None, || {
        debug!("t04-default-debug");
        info!("t04-default-info");
    })?;
    assert!(!log.contains("t04-default-debug"), "{log}");
    assert!(log.contains("t04-default-info"), "{log}");

    let opts = LogOptions {
        debug: true,
        headless: false,
    };
    let (log, ..) = run("debugflag", opts, None, || {
        trace!("t04-flag-trace");
        debug!("t04-flag-debug");
    })?;
    assert!(!log.contains("t04-flag-trace"), "{log}");
    assert!(log.contains("t04-flag-debug"), "{log}");
    Ok(())
}

#[test]
fn invalid_sverb_log_falls_back_to_info_with_a_warning() -> TestResult {
    let (filter_, warning) = filter(LogOptions::default(), Some("=[[["));
    assert!(warning.is_some());
    assert_eq!(filter_.max_level_hint(), Some(LevelFilter::INFO));

    let (log, ..) = run("invalid", LogOptions::default(), Some("=[[["), || {
        debug!("t05-debug");
        info!("t05-info");
    })?;
    assert!(log.contains("ignoring invalid SVERB_LOG"), "{log}");
    assert!(log.contains("t05-info"), "{log}");
    assert!(!log.contains("t05-debug"), "{log}");
    Ok(())
}

// File format: no ANSI, RFC 3339 UTC timestamp, level, target, file:line.
#[test]
fn file_format() -> TestResult {
    let (log, ..) = run("format", LogOptions::default(), None, || {
        info!(target: "fmt_target", "fmt-line");
    })?;
    let line = log
        .lines()
        .find(|l| l.contains("fmt-line"))
        .ok_or("line missing")?;
    assert!(!line.contains('\u{1b}'), "{line}");
    let ts = line.split_whitespace().next().ok_or("empty")?;
    assert_eq!(ts.len(), "2026-10-07T20:00:00.123456Z".len(), "{line}");
    assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{line}");
    assert!(line.contains(" INFO "), "{line}");
    assert!(line.contains("fmt_target"), "{line}");
    assert!(line.contains("logging/tests.rs:"), "{line}");
    Ok(())
}

#[test]
fn debug_ring_keeps_the_last_5000_in_order() -> TestResult {
    let opts = LogOptions {
        debug: true,
        headless: false,
    };
    let (_, _, ring) = run("ring", opts, None, || {
        for i in 0..6_000 {
            debug!("ring-line-{i}");
        }
    })?;
    let ring = ring.ok_or("no debug ring")?;
    let lines = ring.snapshot();
    assert_eq!(lines.len(), DEBUG_RING_CAPACITY);
    for (n, line) in lines.iter().enumerate() {
        assert_eq!(line.message, format!("ring-line-{}", n + 1_000));
        assert_eq!(line.level, Level::DEBUG);
    }
    Ok(())
}

// No debug ring without --debug, nor for headless commands.
#[test]
fn debug_ring_only_with_debug_in_the_tui() -> TestResult {
    let dir = TempDir::new("noring")?;
    assert!(
        build(&dir.0, LogOptions::default(), None)?
            .debug_ring
            .is_none()
    );
    let headless = LogOptions {
        debug: true,
        headless: true,
    };
    assert!(build(&dir.0, headless, None)?.debug_ring.is_none());
    Ok(())
}

// Concurrency
#[test]
fn ring_concurrent_writer_and_reader_do_not_deadlock() -> TestResult {
    let ring = LogRing::new(DEBUG_RING_CAPACITY);
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let ring = ring.clone();
        let done = Arc::clone(&done);
        thread::spawn(move || {
            let mut reads = 0_u64;
            while !done.load(Ordering::Relaxed) || reads < 10_000 {
                let snap = ring.tail(100);
                assert!(snap.len() <= 100);
                reads += 1;
            }
            reads
        })
    };
    let writer = {
        let ring = ring.clone();
        thread::spawn(move || {
            let layer = RingLayer::new(ring);
            let subscriber = tracing_subscriber::registry().with(layer);
            tracing::subscriber::with_default(subscriber, || {
                for i in 0..10_000 {
                    info!("w{i}");
                }
            });
        })
    };
    writer.join().map_err(|_| "writer panicked")?;
    done.store(true, Ordering::Relaxed);
    let reads = reader.join().map_err(|_| "reader panicked")?;
    assert!(reads >= 10_000);
    assert_eq!(ring.total_pushed(), 10_000);
    assert_eq!(ring.len(), DEBUG_RING_CAPACITY);
    Ok(())
}

#[test]
fn crash_ring_holds_info_and_above_only() -> TestResult {
    let (_, crash, debug_ring) = run("crash", LogOptions::default(), Some("trace"), || {
        trace!("t07-trace");
        debug!("t07-debug");
        info!("t07-info");
        warn!("t07-warn");
    })?;
    assert!(debug_ring.is_none());
    let msgs: Vec<_> = crash.snapshot().into_iter().map(|l| l.message).collect();
    assert_eq!(msgs, ["t07-info", "t07-warn"]);
    assert_eq!(crash.capacity(), CRASH_RING_CAPACITY);

    // Also with --debug: the crash ring still never sees debug lines.
    let opts = LogOptions {
        debug: true,
        headless: false,
    };
    let (_, crash, debug_ring) = run("crash-debug", opts, None, || {
        debug!("t07b-debug");
        info!("t07b-info");
    })?;
    let msgs: Vec<_> = crash.snapshot().into_iter().map(|l| l.message).collect();
    assert_eq!(msgs, ["t07b-info"]);
    let debug_ring = debug_ring.ok_or("no debug ring")?;
    assert_eq!(debug_ring.len(), 2);
    Ok(())
}

// T-08 (unit half): the rings redact secrets too.
#[test]
fn rings_redact_secrets() -> TestResult {
    let secret = crate::secret::SecretString::from("CANARY-1b9f");
    let opts = LogOptions {
        debug: true,
        headless: false,
    };
    let (log, crash, debug_ring) = run("redact", opts, None, || {
        info!(pw = ?secret, "x");
        debug!("{:?}", secret);
    })?;
    assert!(
        log.contains("[REDACTED]") && !log.contains("CANARY-1b9f"),
        "{log}"
    );
    let debug_ring = debug_ring.ok_or("no debug ring")?;
    for line in crash.snapshot().iter().chain(debug_ring.snapshot().iter()) {
        assert!(!line.message.contains("CANARY-1b9f"), "{line}");
    }
    assert_eq!(crash.snapshot()[0].message, "x pw=[REDACTED]");
    Ok(())
}
