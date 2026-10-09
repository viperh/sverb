//! Crash-path hooks for the binary's PTY integration tests.
//!
//! Compiled only with the `test-hooks` feature (never in release builds). The tests
//! set `SVERB_TEST_HOOK` before launching the binary; the hook runs right after the
//! terminal entered TUI mode:
//!
//! - `panic-ui`: panic on the UI task,
//! - `panic-thread`: panic on a plain `std::thread` (no runtime context); the UI
//!   treats it as fatal and resumes the unwind,
//! - `panic-blocking`: the same inside `tokio::task::spawn_blocking`,
//! - `exit:<ms>`: return exit code 0 after `<ms>` milliseconds (normal shutdown path).
//!
//! Before panicking it logs one `debug` line (must not reach the crash report) and
//! `info!("last words")` (must reach the log file).

use std::time::Duration;

/// The environment variable the tests set.
pub(crate) const TEST_HOOK_ENV: &str = "SVERB_TEST_HOOK";

/// Runs the hook selected by [`TEST_HOOK_ENV`]. `Some(code)` makes `run` return.
pub(crate) async fn after_start() -> Option<i32> {
    let hook = std::env::var(TEST_HOOK_ENV).ok()?;
    if let Some(ms) = hook.strip_prefix("exit:") {
        let ms = ms.parse().unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        return Some(0);
    }
    tracing::debug!("test hook debug line: host=debug-only.example");
    tracing::info!("last words");
    match hook.as_str() {
        "panic-ui" => panic!("sverb test hook: panic on the UI task"),
        "panic-thread" => {
            let joined = std::thread::Builder::new()
                .name("test-hook-thread".into())
                .spawn(|| {
                    panic!("sverb test hook: panic on a plain thread");
                })
                .map(std::thread::JoinHandle::join);
            if let Ok(Err(payload)) = joined {
                // A panicked UI-side thread is fatal: continue unwinding the UI task.
                std::panic::resume_unwind(payload);
            }
            None
        }
        "panic-blocking" => {
            let joined = tokio::task::spawn_blocking(|| {
                panic!("sverb test hook: panic in spawn_blocking");
            })
            .await;
            if let Err(err) = joined
                && err.is_panic()
            {
                std::panic::resume_unwind(err.into_panic());
            }
            None
        }
        _ => None,
    }
}
