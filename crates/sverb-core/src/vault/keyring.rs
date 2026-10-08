//! M1-04: the keyring seam for keyring unlock (SPEC §5.3).
//!
//! The vault service talks to the OS keyring only through [`KeyringStore`]. The real
//! implementation (the `keyring` crate) lives in `sverb_tui::services::vault`; tests
//! use [`MemKeyring`] and never touch the OS keyring.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use zeroize::Zeroizing;

/// The account used by [`KeyringStore::probe`].
pub const PROBE_ACCOUNT: &str = "probe";

/// A keyring failure. Carries a short reason for the user (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyringError(pub String);

/// A secret store keyed by account, under the `sverb` service.
pub trait KeyringStore: Send + Sync + fmt::Debug {
    /// The secret for `account`; `Ok(None)` when there is no entry.
    ///
    /// # Errors
    /// The keyring is unavailable, or the user cancelled the OS prompt.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError>;

    /// Store `secret` for `account`, replacing any entry.
    ///
    /// # Errors
    /// The keyring is unavailable or refused the write.
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError>;

    /// Delete the entry for `account` (no error if it does not exist).
    ///
    /// # Errors
    /// The keyring is unavailable.
    fn delete(&self, account: &str) -> Result<(), KeyringError>;

    /// Whether the keyring works: writes and deletes a test entry.
    fn probe(&self) -> bool {
        self.set(PROBE_ACCOUNT, b"probe").is_ok() && self.delete(PROBE_ACCOUNT).is_ok()
    }
}

/// No keyring at all (`SVERB_KEYRING=off`, unsupported platforms).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoKeyring;

impl KeyringStore for NoKeyring {
    fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        Err(KeyringError("no keyring is available".into()))
    }

    fn set(&self, _account: &str, _secret: &[u8]) -> Result<(), KeyringError> {
        Err(KeyringError("no keyring is available".into()))
    }

    fn delete(&self, _account: &str) -> Result<(), KeyringError> {
        Err(KeyringError("no keyring is available".into()))
    }
}

/// An in-memory keyring for tests. Clones share entries.
#[derive(Clone, Default)]
pub struct MemKeyring {
    inner: Arc<MemInner>,
}

#[derive(Default)]
struct MemInner {
    entries: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    gets: AtomicUsize,
    unavailable: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for MemKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemKeyring")
            .field("accounts", &self.accounts())
            .finish()
    }
}

impl MemKeyring {
    /// An empty, available keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// The accounts that have an entry, sorted.
    pub fn accounts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.entries.lock().keys().cloned().collect();
        v.sort();
        v
    }

    /// Remove an entry behind sverb's back (simulates a user deleting it).
    pub fn remove(&self, account: &str) {
        self.inner.entries.lock().remove(account);
    }

    /// Make every call fail (simulates a locked or missing keyring service).
    pub fn set_unavailable(&self, unavailable: bool) {
        self.inner.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// How many times [`KeyringStore::get`] was called.
    pub fn get_calls(&self) -> usize {
        self.inner.gets.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), KeyringError> {
        if self.inner.unavailable.load(Ordering::SeqCst) {
            Err(KeyringError("keyring unavailable".into()))
        } else {
            Ok(())
        }
    }
}

impl KeyringStore for MemKeyring {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        self.inner.gets.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        Ok(self.inner.entries.lock().get(account).cloned())
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
        self.check()?;
        self.inner
            .entries
            .lock()
            .insert(account.to_owned(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        self.check()?;
        self.inner.entries.lock().remove(account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_keyring_roundtrip_and_probe() {
        let k = MemKeyring::new();
        assert!(k.probe());
        assert!(k.accounts().is_empty(), "probe leaves nothing behind");
        k.set("a", b"s").unwrap_or_default();
        assert_eq!(
            k.get("a").ok().flatten().map(|s| s.to_vec()),
            Some(b"s".to_vec())
        );
        k.set_unavailable(true);
        assert!(k.get("a").is_err());
        assert!(!k.probe());
        assert!(!NoKeyring.probe());
    }
}
