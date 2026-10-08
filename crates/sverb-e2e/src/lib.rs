//! End-to-end test harness for sverb (M1-18, SPEC §19 "Transports (e2e)").
//!
//! Not published. The workspace layering checks also live here, in
//! `tests/workspace_metadata.rs`.
//!
//! # Pieces
//! - [`Sshd`] / [`JumpNet`]: OpenSSH servers in Docker (via `testcontainers`), one
//!   image (`tests/fixtures/sshd/`) with runtime-selected [`Profile`]s: password, key,
//!   cert, keyboard-interactive, `MaxAuthTries 2`, legacy-only, env, forward, jump and
//!   windows-like.
//! - [`keys`]: the committed, **test-only** fixture keys and CAs.
//! - [`TestHome`]: a temporary `SVERB_HOME` with an initialized vault (cheap Argon2),
//!   and helpers that write hosts, keys and known hosts through the item service.
//! - [`Headless`]: drives a session through the real `SessionManager` and SSH
//!   connector without a TUI, and reads the emulator grid ([`Headless::grid_text`],
//!   [`Headless::wait_for_text`]).
//! - [`PtyApp`]: the real `sverb` binary in a PTY, keys sent in chord syntax
//!   (`"ctrl-\\ q"`), the screen read through a local alacritty emulator.
//! - [`diag`]: failure diagnostics. When a test panics, live harness objects dump the
//!   container logs and the last screen to the test output.
//!
//! # Running
//! Container tests are `#[ignore]`d so `cargo test` stays fast and Docker-free:
//!
//! ```text
//! SVERB_E2E=1 cargo test -p sverb-e2e -- --ignored
//! ```
//!
//! Every container test starts with [`require_docker!`], which returns early with a
//! skip message unless `SVERB_E2E=1` is set and Docker answers (on CI, `CI=true`, a
//! missing Docker daemon is a failure instead). The harness self-tests that need no
//! Docker (`Headless` against the in-process russh server, `PtyApp` against the local
//! binary) run in the normal suite.
//!
//! # Reliability rules
//! No fixed sleeps: everything polls with a timeout ([`timeout`]: 10 s, 20 s on CI).
//! Each test starts its own containers, so tests are parallel-safe.

pub mod diag;
pub mod home;
pub mod keys;
pub mod pty;
pub mod session;
pub mod sshd;

use std::{fmt, time::Duration};

pub use home::TestHome;
pub use pty::{PtyApp, PtyOptions, Screen};
pub use session::{Headless, HeadlessOptions, Login, RecordingVerifier, WaitError};
pub use sshd::{ExecOutput, JumpNet, Profile, Sshd, SshdOptions, ssh_key_file_type};

/// The default polling timeout: 10 s locally, 20 s on CI (`CI` set).
pub fn timeout() -> Duration {
    if on_ci() {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(10)
    }
}

/// Whether the tests run on CI (`CI` is set to anything but `false`/`0`).
pub fn on_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "false" && v != "0")
}

/// Whether e2e tests were asked for (`SVERB_E2E=1`).
pub fn e2e_requested() -> bool {
    std::env::var("SVERB_E2E").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Why a container test should be skipped, or `None` to run it.
///
/// - `SVERB_E2E` unset: skip (`SVERB_E2E=1` opts in).
/// - Docker does not answer a ping: skip locally; **panic on CI**, so a broken CI
///   setup never passes silently.
pub async fn docker_skip_reason() -> Option<String> {
    if !e2e_requested() {
        return Some("set SVERB_E2E=1 to run the docker e2e tests".into());
    }
    match sshd::ping_docker().await {
        Ok(()) => None,
        Err(e) if on_ci() => panic!("SVERB_E2E=1 on CI but Docker is unavailable: {e}"),
        Err(e) => Some(format!("Docker is unavailable ({e})")),
    }
}

/// Return early from a container test (with a message on stderr) unless the e2e
/// suite is enabled and Docker is reachable. See [`docker_skip_reason`].
#[macro_export]
macro_rules! require_docker {
    () => {
        if let Some(reason) = $crate::docker_skip_reason().await {
            eprintln!("skipped: {reason}");
            return;
        }
    };
}

/// A harness failure (Docker, the image build, a timeout, I/O).
#[derive(Clone, PartialEq, Eq)]
pub struct E2eError(pub String);

impl E2eError {
    /// An error with `msg`.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// The Debug form is what `unwrap()` prints: keep multi-line dumps readable.
impl fmt::Debug for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for E2eError {}

impl From<testcontainers::TestcontainersError> for E2eError {
    fn from(e: testcontainers::TestcontainersError) -> Self {
        Self(format!("testcontainers: {e}"))
    }
}

impl From<std::io::Error> for E2eError {
    fn from(e: std::io::Error) -> Self {
        Self(format!("io: {e}"))
    }
}

/// Harness result.
pub type Result<T, E = E2eError> = std::result::Result<T, E>;
