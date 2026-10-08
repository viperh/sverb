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
