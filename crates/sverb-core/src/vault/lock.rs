//! The lock state machine and the auto-lock rule (SPEC §5.3).
//!
//! The reducer only knows [`LockState`]; keys live in the vault service. Idle
//! auto-lock is a reset-on-input timer: every input event while unlocked re-arms a
//! one-shot timer of [`auto_lock_timeout`]; when it fires, the vault locks.

use std::time::Duration;

/// What the UI knows about the vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LockState {
    /// No keys in memory. Items are unreadable; session panes are covered.
    #[default]
    Locked,
    /// An unlock (Argon2 or keyring) is running.
    Unlocking,
    /// Keys are in memory (owned by the vault service, never by the UI).
    Unlocked,
}

impl LockState {
    /// `Locked` or `Unlocking`.
    pub fn is_locked(self) -> bool {
        !matches!(self, Self::Unlocked)
    }

    /// Whether an unlock may start (not while one runs).
    pub fn can_start_unlock(self) -> bool {
        matches!(self, Self::Locked)
    }
}

/// The idle timeout for `general.auto_lock_minutes`; `None` when `0` (disabled).
pub fn auto_lock_timeout(minutes: u32) -> Option<Duration> {
    (minutes > 0).then(|| Duration::from_secs(u64::from(minutes) * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_rule() {
        assert_eq!(auto_lock_timeout(0), None);
        assert_eq!(auto_lock_timeout(1), Some(Duration::from_secs(60)));
        assert_eq!(auto_lock_timeout(15), Some(Duration::from_secs(900)));
    }

    #[test]
    fn states() {
        assert!(LockState::default().is_locked());
        assert!(LockState::Unlocking.is_locked());
        assert!(!LockState::Unlocked.is_locked());
        assert!(LockState::Locked.can_start_unlock());
        assert!(!LockState::Unlocking.can_start_unlock());
    }
}
