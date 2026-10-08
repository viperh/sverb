//! M1-04: the OS keyring (`keyring` crate: Secret Service, macOS Keychain, Windows
//! Credential Manager) behind [`KeyringStore`].
//!
//! Tests never use this type: they inject `sverb_core::vault::MemKeyring`. The
//! binary picks it unless `SVERB_KEYRING=off` (see [`keyring_from_env`]), which the
//! binary's PTY tests set so they never touch the real keyring.

use std::sync::Arc;

use sverb_core::vault::{KEYRING_SERVICE, KeyringError, KeyringStore, NoKeyring};
use zeroize::Zeroizing;

/// Environment switch: `off` (or `0`, `none`, `disabled`) disables keyring unlock.
pub const KEYRING_ENV: &str = "SVERB_KEYRING";

/// The platform keyring.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsKeyring;

fn err(e: &keyring::Error) -> KeyringError {
    KeyringError(e.to_string())
}

fn entry(account: &str) -> Result<keyring::Entry, KeyringError> {
    keyring::Entry::new(KEYRING_SERVICE, account).map_err(|e| err(&e))
}

impl KeyringStore for OsKeyring {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        match entry(account)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(err(&e)),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
        entry(account)?.set_secret(secret).map_err(|e| err(&e))
    }

    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        match entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(err(&e)),
        }
    }
}

/// The keyring the binary uses: [`OsKeyring`], or [`NoKeyring`] when
/// `SVERB_KEYRING` is `off`/`0`/`none`/`disabled`.
pub fn keyring_from_env() -> Arc<dyn KeyringStore> {
    // M7-06: `SVERB_KEYRING=file:<dir>` (test-hooks builds only) for the startup
    // benchmark, which needs keyring unlock in a child process.
    #[cfg(feature = "test-hooks")]
    if let Some(dir) = std::env::var(KEYRING_ENV)
        .ok()
        .and_then(|v| v.strip_prefix("file:").map(std::path::PathBuf::from))
    {
        return Arc::new(FileKeyring::new(dir));
    }
    let off = std::env::var(KEYRING_ENV).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "none" | "disabled" | "false"
        )
    });
    if off {
        Arc::new(NoKeyring)
    } else {
        Arc::new(OsKeyring)
    }
}

// M7-06
/// A keyring kept as plain files in a directory: **test builds only** (the
/// `test-hooks` feature, never in release builds). One file per account, named by
/// the account's hex encoding. The startup benchmark uses it to unlock by keyring
/// in a child process without touching the real OS keyring.
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone)]
pub struct FileKeyring {
    dir: std::path::PathBuf,
}

#[cfg(feature = "test-hooks")]
impl FileKeyring {
    /// A keyring in `dir` (created on the first write).
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, account: &str) -> std::path::PathBuf {
        let name: String = account.bytes().map(|b| format!("{b:02x}")).collect();
        self.dir.join(name)
    }
}

#[cfg(feature = "test-hooks")]
impl KeyringStore for FileKeyring {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        match std::fs::read(self.path(account)) {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeyringError(e.to_string())),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| KeyringError(e.to_string()))?;
        std::fs::write(self.path(account), secret).map_err(|e| KeyringError(e.to_string()))
    }

    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        match std::fs::remove_file(self.path(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyringError(e.to_string())),
        }
    }
}
