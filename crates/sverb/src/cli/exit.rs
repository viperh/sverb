//! M0-07: exit codes and the CLI error type (SPEC §16).
//!
//! The codes are stable and documented in `sverb --help` ([`HELP`]). Every
//! [`CliError`] maps to exactly one of them ([`CliError::exit_code`]).

use std::fmt;

use sverb_core::{error_report::ErrorReport, host_arg::HostArgError};

/// Success.
pub(crate) const OK: u8 = 0;
/// Something failed (including internal errors and unimplemented commands).
pub(crate) const FAILURE: u8 = 1;
/// Bad command line (clap uses 2 as well).
pub(crate) const USAGE: u8 = 2;
/// The vault is locked or could not be unlocked.
pub(crate) const VAULT_LOCKED: u8 = 3;
/// A host, key or other item was not found, or the argument was ambiguous.
pub(crate) const NOT_FOUND: u8 = 4;
/// Synced settings that act locally must be approved first (SPEC §17.1).
pub(crate) const APPROVAL_REQUIRED: u8 = 5;
/// Network or sync-server error.
pub(crate) const NETWORK: u8 = 6;
/// Some targets succeeded and some failed (e.g. `snippet run --on #tag`).
pub(crate) const PARTIAL: u8 = 7;

/// Shown after `sverb --help`.
pub(crate) const HELP: &str = "\
Exit codes:
  0  success
  1  failure
  2  usage error
  3  vault locked or unlock failed
  4  not found (or ambiguous host)
  5  approval required (run `sverb approve <host>`)
  6  network or server error
  7  partial failure";

/// The message when a headless command needs the vault and cannot prompt.
pub(crate) const VAULT_LOCKED_NO_TTY: &str =
    "vault is locked and no terminal is available to enter the master password";

/// The message when the TUI is started without a terminal.
pub(crate) const NO_TTY: &str = "sverb's TUI needs an interactive terminal";

/// The message for sync-only commands in a local-only build.
pub(crate) const NO_SYNC: &str = "this build of sverb was compiled without sync support";

/// Why a command failed. Printed as an [`ErrorReport`] (`error: …` / `  caused by: …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CliError {
    /// The command exists but its feature task has not landed yet.
    NotImplemented {
        /// The command, e.g. `hosts list`.
        command: &'static str,
        /// The task that implements it, e.g. `M1-07`.
        milestone: &'static str,
    },
    /// A command-line problem clap cannot detect.
    Usage(String),
    /// A sync-only command in a local-only build.
    #[cfg_attr(feature = "sync", allow(dead_code))]
    NoSync {
        /// The command name as typed.
        command: String,
    },
    /// The TUI was started without a terminal on stdout.
    NoTty,
    /// The vault is locked and there is no terminal to prompt on.
    #[allow(dead_code)] // M1-04: returned by `vault::require_unlocked` once commands use it.
    VaultLocked,
    /// Unlocking failed (wrong password, keyring error).
    #[allow(dead_code)] // M1-04
    UnlockFailed(ErrorReport),
    /// Something named on the command line does not exist.
    NotFound(String),
    /// A `<host>` argument did not resolve to exactly one host.
    #[allow(dead_code)] // M1-07: hosts rm / approve / connect resolve hosts.
    HostArg(HostArgError),
    /// A synced value that acts locally needs approval first.
    #[allow(dead_code)] // M2-10
    ApprovalRequired {
        /// The host as the user named it.
        host: String,
    },
    // M2-10
    /// A value that acts locally is not approved on this device; the message names
    /// the host and `sverb approve <host>` (§17.1).
    NeedsApproval(String),
    /// Network or server error.
    #[allow(dead_code)] // M4-08
    Network(ErrorReport),
    /// Some targets failed.
    #[allow(dead_code)] // M2-09
    Partial {
        /// How many failed.
        failed: usize,
        /// How many were attempted.
        total: usize,
    },
    /// Any other failure.
    Failure(ErrorReport),
}

impl CliError {
    /// The process exit code for this error.
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::NotImplemented { .. } | Self::NoTty | Self::Failure(_) => FAILURE,
            Self::Usage(_) | Self::NoSync { .. } => USAGE,
            Self::VaultLocked | Self::UnlockFailed(_) => VAULT_LOCKED,
            Self::NotFound(_) | Self::HostArg(_) => NOT_FOUND,
            Self::ApprovalRequired { .. } => APPROVAL_REQUIRED,
            // M2-10
            Self::NeedsApproval(_) => APPROVAL_REQUIRED,
            Self::Network(_) => NETWORK,
            Self::Partial { .. } => PARTIAL,
        }
    }

    /// The user-facing report.
    pub(crate) fn report(&self) -> ErrorReport {
        match self {
            Self::UnlockFailed(r) | Self::Network(r) | Self::Failure(r) => r.clone(),
            other => ErrorReport::msg(other.to_string()),
        }
    }

    /// Wrap any error as a [`CliError::Failure`].
    pub(crate) fn failure(err: &(dyn std::error::Error + 'static)) -> Self {
        Self::Failure(ErrorReport::from_error(err))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { command, milestone } => write!(
                f,
                "`sverb {command}` is not implemented yet (planned in {milestone})"
            ),
            Self::Usage(msg) | Self::NotFound(msg) => f.write_str(msg),
            // M2-10
            Self::NeedsApproval(msg) => f.write_str(msg),
            Self::NoSync { command } => write!(f, "`sverb {command}`: {NO_SYNC}"),
            Self::NoTty => f.write_str(NO_TTY),
            Self::VaultLocked => f.write_str(VAULT_LOCKED_NO_TTY),
            Self::HostArg(e) => write!(f, "{e}"),
            Self::ApprovalRequired { host } => write!(
                f,
                "`{host}` has synced settings that act on this machine and are not approved \
                 yet; review them with `sverb approve {host}`"
            ),
            Self::Partial { failed, total } => write!(f, "{failed} of {total} targets failed"),
            Self::UnlockFailed(r) | Self::Network(r) | Self::Failure(r) => f.write_str(&r.short),
        }
    }
}

impl From<HostArgError> for CliError {
    fn from(e: HostArgError) -> Self {
        Self::HostArg(e)
    }
}
