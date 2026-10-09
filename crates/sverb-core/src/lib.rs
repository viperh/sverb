//! Domain logic for the application, with no knowledge of the terminal.
//!
//! Keep everything here UI-agnostic. The `sverb` crate owns rendering, key
//! handling and the event loop; this crate owns state and the rules that
//! govern it, so it can be unit tested without spawning a terminal.
//!
//! Domain state arrives in M1 through the store and services; the UI state machine
//! lives in `sverb-tui` (M0-08).

// M0-03: platform paths and SVERB_HOME (SPEC §5.1).
pub mod paths;

// M0-06: config.toml model, validation, schema and hot reload (SPEC §15).
pub mod config;

// M0-08: user-facing error reports (short message + cause chain); extended by M0-05.
pub mod error_report;

// M0-07: `<host>` argument resolution for the CLI (SPEC §16).
pub mod host_arg;
pub use host_arg::resolve_host_arg;

// M0-04: secret types that are redacted when formatted (SPEC §11.5, §17).
pub mod secret;

// M7-05: core dumps off, same-user ptrace blocked, mlocked key material (SPEC §17). The
// only module (with the Windows agent DACL) allowed `unsafe`.
pub mod hardening;

// M0-04: file logging with daily rotation, SVERB_LOG, crash/debug rings (SPEC §18).
pub mod logging;

// M1-02: item model: ItemBody, Stamped fields, HLC, typed views, validation (SPEC §4).
pub mod model;

// M1-04: vault logic: KDF params, unlock backoff, lock state, password strength,
// the keyring seam (SPEC §5.3, §11.2). The service that owns the keys is in sverb-tui.
pub mod vault;

// M1-05: in-memory decrypted index and fuzzy search (SPEC §5.2, §8.5, §9.1).
pub mod search;

// M2-01: settings resolution Host → Group chain → vault defaults → global config,
// with provenance (SPEC §4.3). M1-13's connector consumes `ResolvedHost`.
pub mod resolve;

// M1-07: quick-connect target parser and "copy as ssh command" (SPEC §9.1).
pub mod quick_connect;
pub mod ssh_command;

// M1-17: the pane layout tree of a tab (SPEC §8.4), serialized by workspaces (M3-03).
pub mod layout;

// M1-15: known_hosts parsing, matching (hashed, globs, CAs, revoked), host-key checks,
// fingerprints and randomart (SPEC §9.5).
pub mod known_hosts;

// M2-03: the keychain: key generation, import (OpenSSH, PEM, PKCS#8, .pub, importer
// hook), export, passphrase changes, certificates (SPEC §4.5, §4.6, §9.4).
pub mod keychain;

// M2-04: POSIX single-quote escaping (install key on host, snippet `|q`).
pub mod shell_quote;

// M2-11: import (ssh_config, known_hosts, CSV, backup) with the dry-run preview, and
// export (backup, ssh_config, CSV) (SPEC §9.13).
pub mod exporters;
pub mod importers;

// M2-09: snippets: the template engine (`{{name}}`, `{{name:default}}`, `{{name|q}}`,
// built-ins, `\{{`), variables, `--on` targets, run results and exports (SPEC §9.7).
pub mod snippet;

// M7-01: command history: prompt learning, heuristic capture, suggestions, the per-host
// cap, the static set of common commands (SPEC §9.10).
pub mod history;

// M0-04: `tracing` re-exported for `trace_dbg!`, so callers need no direct dependency.
#[doc(hidden)]
pub use tracing as __tracing;

/// M0-04: like `std::dbg!`, but emits a `tracing` event instead of printing, and
/// returns the value.
///
/// The default level is `DEBUG`; `level:` and `target:` override it. The value is
/// recorded with `Debug`, so **never** use it on values containing user data
/// (hostnames, usernames, commands, snippet bodies) at `info` or above (SPEC §17,
/// `docs/logging.md`). Secret types print `[REDACTED]`.
///
/// ```
/// let n = sverb_core::trace_dbg!(1 + 1);
/// assert_eq!(n, 2);
/// let n = sverb_core::trace_dbg!(level: tracing::Level::TRACE, n * 2);
/// assert_eq!(n, 4);
/// ```
#[macro_export]
macro_rules! trace_dbg {
    (target: $target:expr, level: $level:expr, $ex:expr) => {
        match $ex {
            value => {
                $crate::__tracing::event!(target: $target, $level, ?value, stringify!($ex));
                value
            }
        }
    };
    (level: $level:expr, $ex:expr) => {
        $crate::trace_dbg!(target: module_path!(), level: $level, $ex)
    };
    (target: $target:expr, $ex:expr) => {
        $crate::trace_dbg!(target: $target, level: $crate::__tracing::Level::DEBUG, $ex)
    };
    ($ex:expr) => {
        $crate::trace_dbg!(level: $crate::__tracing::Level::DEBUG, $ex)
    };
}

use thiserror::Error;

/// Errors produced by the core.
///
/// The `sverb` crate converts these into `color_eyre` reports at the boundary,
/// which is why this enum carries no formatting or reporting concerns of its own.
#[derive(Debug, Error)]
pub enum Error {
    /// The core was asked to do something its current state does not allow.
    #[error("invalid state transition: {0}")]
    InvalidState(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
