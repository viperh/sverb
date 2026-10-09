//! Process hardening. Its own test binary: both tests change
//! process-wide state (the dumpable flag, `RLIMIT_CORE`, `RLIMIT_MEMLOCK`) of this test
//! process only, never of another process.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use sverb_core::hardening::{self, Locked};

/// After `harden_process`, the process is not dumpable (Linux) and its core
/// limit is 0 (unix). The binary-level twin is `crates/sverb/tests/hardening.rs`.
#[test]
fn t01_harden_process_disables_core_dumps() {
    let report = hardening::harden_process();
    assert!(report.core_dumps_disabled, "{report:?}");
    #[cfg(target_os = "linux")]
    {
        assert!(report.non_dumpable, "{report:?}");
        assert_eq!(hardening::is_dumpable(), Some(false));
        // /proc/self stays readable by the process itself.
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status.contains("Name:"), "{status}");
    }
    #[cfg(unix)]
    assert_eq!(hardening::core_dump_limit(), Some(0));
    // Idempotent.
    let again = hardening::harden_process();
    assert!(again.core_dumps_disabled, "{again:?}");
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// With `RLIMIT_MEMLOCK = 0`, locking fails gracefully: the key is still usable,
/// zeroized on drop, and one `debug` line explains why (once per process).
#[cfg(unix)]
#[test]
fn t02_mlock_fallback_with_zero_memlock_limit() {
    hardening::set_memlock_limit(0).unwrap();
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let (first_locked, second_locked) = tracing::subscriber::with_default(subscriber, || {
        let key = Locked::new([0x5a_u8; 32]);
        assert_eq!(key[31], 0x5a);
        let second = Locked::new([0x33_u8; 32]);
        assert_eq!(second[0], 0x33);
        (key.is_locked(), second.is_locked())
    });
    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    if first_locked {
        // Privileged (CAP_IPC_LOCK) runs ignore the limit: nothing to fall back from.
        eprintln!("SKIP: mlock succeeded despite RLIMIT_MEMLOCK=0 (privileged?)");
        return;
    }
    assert!(!second_locked);
    assert_eq!(
        log.matches("mlock unavailable").count(),
        1,
        "expected exactly one debug line: {log}"
    );
    assert!(log.contains("DEBUG"), "{log}");
    assert_eq!(hardening::locked_page_count(), 0);
}
