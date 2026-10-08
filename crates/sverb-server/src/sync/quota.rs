//! Storage quota (§10.5).
//!
//! * **Personal vaults:** the sum of the envelope bytes in all personal
//!   vaults of the vault's owner is limited by `storage_quota_mib`
//!   (default 100 MiB).
//! * **Shared vaults (v1 decision, open question):** not counted against any
//!   user; each shared vault is capped at
//!   [`super::SHARED_VAULT_CAP_BYTES`] (1 GiB). Org-level quotas are left
//!   for M5.
//!
//! Usage is measured under the vault row lock, so concurrent pushes to the
//! same vault can't both pass the check. A user has exactly one personal
//! vault (created at registration), so the vault lock also serializes all
//! pushes that count against one personal quota.
//!
//! A change only needs room for its growth (`new − old` bytes); changes that
//! shrink or keep usage are accepted even when the account is already over
//! quota (e.g. after the quota was lowered), so users can always delete.

use sqlx_core::query_as::query_as;
use sqlx_postgres::PgConnection;
use sverb_proto::sync::VaultKind;
use uuid::Uuid;

use super::{Res, SyncLimits, VaultAccess};

/// Bytes used and allowed, updated as a batch is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaBudget {
    used: u64,
    limit: u64,
}

impl QuotaBudget {
    /// `used` of `limit` bytes.
    #[must_use]
    pub const fn new(used: u64, limit: u64) -> Self {
        Self { used, limit }
    }

    /// No limit.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::new(0, u64::MAX)
    }

    /// Bytes used so far.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Replaces an item of `old` bytes (0 when new) by one of `new` bytes if
    /// that fits; returns whether it did.
    pub fn try_replace(&mut self, old: u64, new: u64) -> bool {
        if new > old {
            let after = self.used.saturating_add(new - old);
            if after > self.limit {
                return false;
            }
            self.used = after;
        } else {
            self.used = self.used.saturating_sub(old - new);
        }
        true
    }
}

/// What a vault's pushes count against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaScope {
    /// All personal vaults of this user.
    User(Uuid),
    /// This shared vault alone.
    Vault(Uuid),
}

/// The scope and limit for pushes to `vault_id`.
#[must_use]
pub fn scope(vault_id: Uuid, access: &VaultAccess, limits: SyncLimits) -> (QuotaScope, u64) {
    match (access.kind, access.owner_user_id) {
        (VaultKind::Personal, Some(owner)) => {
            (QuotaScope::User(owner), limits.personal_quota_bytes)
        }
        _ => (QuotaScope::Vault(vault_id), limits.shared_vault_cap_bytes),
    }
}

/// The budget for a push, read inside the push transaction (after the
/// vault row lock).
///
/// # Errors
/// Database errors.
pub async fn pg_budget(
    conn: &mut PgConnection,
    vault_id: Uuid,
    access: &VaultAccess,
    limits: SyncLimits,
) -> Res<QuotaBudget> {
    let (scope, limit) = scope(vault_id, access, limits);
    let (used,): (i64,) = match scope {
        QuotaScope::User(owner) => {
            query_as(
                "SELECT COALESCE(SUM(octet_length(i.envelope)), 0)::BIGINT \
                 FROM items i JOIN vaults v ON v.id = i.vault_id \
                 WHERE v.kind = 'personal' AND v.owner_user_id = $1",
            )
            .bind(owner)
            .fetch_one(&mut *conn)
            .await?
        }
        QuotaScope::Vault(id) => {
            query_as(
                "SELECT COALESCE(SUM(octet_length(envelope)), 0)::BIGINT \
                 FROM items WHERE vault_id = $1",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    Ok(QuotaBudget::new(u64::try_from(used).unwrap_or(0), limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_only_counts() {
        let mut b = QuotaBudget::new(90, 100);
        assert!(b.try_replace(0, 10));
        assert_eq!(b.used(), 100);
        assert!(!b.try_replace(0, 1));
        assert!(b.try_replace(10, 10));
        assert!(b.try_replace(50, 5));
        assert_eq!(b.used(), 55);
        let mut over = QuotaBudget::new(200, 100);
        assert!(over.try_replace(20, 10));
        assert!(!over.try_replace(10, 11));
    }
}
