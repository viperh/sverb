//! M2-11: exports (SPEC §9.13): the encrypted sverb backup, a lossy `ssh_config` and
//! CSV. Files are written with mode 0600 and never replace an existing file unless the
//! caller confirmed it (`--force` in the CLI) — see [`write_file`].

use std::io::{self, Write as _};
use std::path::Path;

pub mod backup;
pub mod csv;
pub mod ssh_config;

/// The warning written at the top of an `ssh_config` export and shown before any
/// non-backup export.
pub const SECRETS_WARNING: &str =
    "Secrets (passwords, private keys stored in sverb) are NOT exported.";

/// Writes `bytes` to `path` with mode 0600 (Unix). An existing file is an
/// [`io::ErrorKind::AlreadyExists`] error unless `overwrite`.
///
/// # Errors
/// I/O errors; `AlreadyExists` as above.
pub fn write_file(path: &Path, bytes: &[u8], overwrite: bool) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // An overwritten file keeps its old mode otherwise.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()
}
