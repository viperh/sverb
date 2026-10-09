//! "install key on host" over exec (SPEC §9.4).
//!
//! For each host: `uname` first (a POSIX `sh` login shell is required; Windows OpenSSH
//! fails it), then the §9.4 command with the public key line POSIX-single-quoted. The
//! command is extended with markers so "installed" and "already present" can be told
//! apart, keeping its semantics (see [`install_command`], documented in
//! `docs/keychain.md`).

use std::time::Duration;

use sverb_core::shell_quote::{ShellQuoteError, posix_single_quote};

use super::exec::{ExecOpts, ExecResult, SshConnection, exec};

/// Printed when the key line is already in `authorized_keys`.
pub const PRESENT_MARKER: &str = "SVERB_PRESENT";
/// Printed after the key line was appended.
pub const INSTALLED_MARKER: &str = "SVERB_INSTALLED";

/// The message for a non-POSIX remote shell.
pub const UNSUPPORTED: &str = "unsupported: remote shell is not POSIX (Windows OpenSSH?)";

/// Why a public key can't be installed (before connecting).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallKeyError {
    /// Empty, or more than one line.
    #[error("the public key must be exactly one line")]
    NotOneLine,
    /// A NUL byte.
    #[error(transparent)]
    Quote(#[from] ShellQuoteError),
}

/// The §9.4 command for `public_key` (one OpenSSH public key line; surrounding
/// whitespace is trimmed), with the markers:
///
/// ```text
/// umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '<pub>' ~/.ssh/authorized_keys && echo SVERB_PRESENT || (printf '%s\n' '<pub>' >> ~/.ssh/authorized_keys && echo SVERB_INSTALLED))
/// ```
///
/// # Errors
/// [`InstallKeyError`] for an empty or multi-line key, or a NUL byte.
pub fn install_command(public_key: &str) -> Result<String, InstallKeyError> {
    let line = public_key.trim();
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(InstallKeyError::NotOneLine);
    }
    let q = posix_single_quote(line)?;
    Ok(format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
         (grep -qxF {q} ~/.ssh/authorized_keys && echo {PRESENT_MARKER} || \
         (printf '%s\\n' {q} >> ~/.ssh/authorized_keys && echo {INSTALLED_MARKER}))"
    ))
}

/// Whether a `uname` run says the remote shell is POSIX: exit 0 and a first output
/// line that looks like a kernel name (`Linux`, `Darwin`, `FreeBSD`, `CYGWIN_NT-10.0`,
/// `GNU/kFreeBSD`, …).
pub fn looks_posix(uname: &ExecResult) -> bool {
    if !uname.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&uname.stdout);
    let first = text.lines().map(str::trim).find(|l| !l.is_empty());
    first.is_some_and(|name| {
        name.len() <= 64
            && name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
    })
}

/// The outcome for one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The key line was appended.
    Installed,
    /// The key line was already there.
    AlreadyPresent,
    /// `uname` failed: not a POSIX shell.
    Unsupported,
    /// The command failed.
    Failed {
        /// One line for the table.
        short: String,
        /// Its stderr / stdout, for the expanded row.
        detail: String,
    },
}

impl InstallOutcome {
    /// `installed` / `already present` / `unsupported: …` / `error: …`.
    pub fn text(&self) -> String {
        match self {
            Self::Installed => "installed".to_owned(),
            Self::AlreadyPresent => "already present".to_owned(),
            Self::Unsupported => UNSUPPORTED.to_owned(),
            Self::Failed { short, .. } => format!("error: {short}"),
        }
    }

    /// Installed or already present.
    pub fn ok(&self) -> bool {
        matches!(self, Self::Installed | Self::AlreadyPresent)
    }
}

/// The first non-empty line of `bytes`, at most 120 characters.
fn first_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(120).collect())
}

fn detail_of(r: &ExecResult) -> String {
    let mut s = String::from_utf8_lossy(&r.stderr).into_owned();
    if s.trim().is_empty() {
        s = String::from_utf8_lossy(&r.stdout).into_owned();
    }
    s
}

/// What an install command's result means.
pub fn classify(r: &ExecResult) -> InstallOutcome {
    let out = String::from_utf8_lossy(&r.stdout);
    let has = |m: &str| out.lines().any(|l| l.trim() == m);
    if r.success() && has(INSTALLED_MARKER) {
        return InstallOutcome::Installed;
    }
    if r.success() && has(PRESENT_MARKER) {
        return InstallOutcome::AlreadyPresent;
    }
    let short = if r.timed_out() {
        "timed out".to_owned()
    } else if let Some(line) = first_line(&r.stderr) {
        line
    } else if let Some(sig) = &r.signal {
        format!("killed by signal {sig}")
    } else {
        match r.exit {
            Some(code) => format!("exit {code}"),
            None => "no exit status".to_owned(),
        }
    };
    InstallOutcome::Failed {
        short,
        detail: detail_of(r),
    }
}

/// Probe with `uname`, then install `public_key` (`command` from
/// [`install_command`]) on `conn`. Each step gets `timeout`.
pub async fn install_on(conn: &SshConnection, command: &str, timeout: Duration) -> InstallOutcome {
    let opts = || ExecOpts {
        timeout,
        // The markers are parsed from stdout; a PTY would mix stderr in.
        request_pty: Some(false),
        stdin: None,
    };
    match exec(conn, "uname", opts()).await {
        Ok(r) if looks_posix(&r) => {}
        Ok(_) => return InstallOutcome::Unsupported,
        Err(e) => {
            return InstallOutcome::Failed {
                short: e.to_string(),
                detail: String::new(),
            };
        }
    }
    match exec(conn, command, opts()).await {
        Ok(r) => classify(&r),
        Err(e) => InstallOutcome::Failed {
            short: e.to_string(),
            detail: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use bytes::Bytes;

    use super::*;

    #[test]
    fn command_is_the_spec_command_with_markers() {
        let cmd = install_command("ssh-ed25519 AAAA bob's key\n").unwrap();
        let q = r"'ssh-ed25519 AAAA bob'\''s key'";
        assert_eq!(
            cmd,
            format!(
                "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF {q} \
                 ~/.ssh/authorized_keys && echo SVERB_PRESENT || (printf '%s\\n' {q} >> \
                 ~/.ssh/authorized_keys && echo SVERB_INSTALLED))"
            )
        );
        assert_eq!(install_command(" \n"), Err(InstallKeyError::NotOneLine));
        assert_eq!(install_command("a\nb"), Err(InstallKeyError::NotOneLine));
        assert!(matches!(
            install_command("a\0b"),
            Err(InstallKeyError::Quote(_))
        ));
    }

    fn result(exit: Option<u32>, stdout: &str, stderr: &str) -> ExecResult {
        ExecResult {
            stdout: Bytes::from(stdout.to_owned()),
            stderr: Bytes::from(stderr.to_owned()),
            exit,
            ..ExecResult::default()
        }
    }

    #[test]
    fn uname_check() {
        for name in [
            "Linux\n",
            "Darwin\n",
            "FreeBSD",
            "CYGWIN_NT-10.0\n",
            "GNU/kFreeBSD\n",
        ] {
            assert!(looks_posix(&result(Some(0), name, "")), "{name}");
        }
        assert!(!looks_posix(&result(
            Some(1),
            "",
            "'uname' is not recognized as an internal or external command"
        )));
        assert!(!looks_posix(&result(Some(0), "", "")));
        assert!(!looks_posix(&result(
            Some(0),
            "The term 'uname' is not",
            ""
        )));
    }

    #[test]
    fn classify_outcomes() {
        assert_eq!(
            classify(&result(Some(0), "SVERB_INSTALLED\n", "")),
            InstallOutcome::Installed
        );
        assert_eq!(
            classify(&result(Some(0), "SVERB_PRESENT\n", "")),
            InstallOutcome::AlreadyPresent
        );
        let failed = classify(&result(
            Some(1),
            "",
            "mkdir: cannot create directory '/x/.ssh': Permission denied\n",
        ));
        assert_eq!(
            failed.text(),
            "error: mkdir: cannot create directory '/x/.ssh': Permission denied"
        );
        assert_eq!(classify(&result(Some(2), "", "")).text(), "error: exit 2");
    }
}
