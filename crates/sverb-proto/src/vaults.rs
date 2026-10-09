//! M5-02: shared vaults (SPEC §10.4 "Vaults and sync", §13.1, §13.2).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/vaults` | [`CreateVaultRequest`] | [`crate::sync::VaultView`] |
//! | `GET /v1/vaults/{id}/members` | – | [`VaultMembersView`] |
//! | `PUT /v1/vaults/{id}/members/{user}` | [`GrantRequest`] | 204 |
//! | `DELETE /v1/vaults/{id}/members/{user}` | – | 204 |
//! | `GET /v1/orgs/{id}/vaults` | – | `[`[`OrgVaultView`]`]` |
//!
//! The server never holds a vault key: a shared vault is created with the
//! creator's **self-grant** (`manage`), and every other member is granted by a
//! `manage` member's client, which HPKE-wraps the key to the member's pinned
//! X25519 key and signs the wrap (§11.3, §13.3). Org owners and admins
//! implicitly have `manage` on every org vault (§13.1): they may grant and revoke,
//! and a vault they hold no key for is listed by `GET /v1/orgs/{id}/vaults` with
//! `has_key = false` ("needs key") until a `manage` member's client grants it.
//!
//! Errors (the §10.4 envelope): `404 not_found` for a vault or org the caller
//! can't see, `403 forbidden` when the caller may not create, grant or revoke,
//! `400 invalid` for a grant to a non-member or for a stale key version,
//! `409 conflict` for a vault id that exists.
//!
//! `GET /v1/vaults/{id}/members` and `GET /v1/orgs/{id}/vaults` are additions
//! to the §10.4 table: the grant UI and the client's grant checks (§13.3:
//! "the granter has `manage`") need the membership list.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::GrantUpload;
use crate::orgs::Role;
use crate::sync::Permission;

/// Longest encrypted vault name accepted (the sealed name of at most a few
/// hundred characters).
pub const MAX_NAME_ENC_BYTES: usize = 4096;

/// `POST /v1/vaults`: create a shared vault (org admin+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Client-generated UUIDv7.
    pub id: Uuid,
    /// The owning org.
    pub org_id: Uuid,
    /// The vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// The creator's self-grant (permission `manage`).
    pub self_grant: GrantUpload,
}

/// `PUT /v1/vaults/{id}/members/{user}`: grant (or change) access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// The member's permission.
    pub permission: Permission,
    /// The vault key version wrapped (the vault's current one).
    pub key_version: u32,
    /// The vault key HPKE-wrapped to the member's X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The granter's Ed25519 signature over the canonical grant.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// One org member as seen from a shared vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMemberView {
    /// The user.
    pub user_id: Uuid,
    /// Their email.
    #[serde(default)]
    pub email: Option<String>,
    /// Their org role.
    pub org_role: Role,
    /// Their explicit vault permission (`None`: no grant).
    #[serde(default)]
    pub permission: Option<Permission>,
    /// They hold a grant for the vault's **current** key version.
    pub has_key: bool,
    /// Who granted their newest grant.
    #[serde(default)]
    pub granted_by: Option<Uuid>,
}

impl VaultMemberView {
    /// The permission in effect: the explicit one, or `manage` for org owners
    /// and admins (§13.1).
    #[must_use]
    pub fn effective(&self) -> Option<Permission> {
        if self.org_role >= Role::Admin {
            Some(Permission::Manage)
        } else {
            self.permission
        }
    }
}

/// `GET /v1/vaults/{id}/members`: every member of the owning org with their
/// vault permission. **Untrusted** on the client: it can only narrow trust
/// (§13.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMembersView {
    /// The vault.
    pub vault_id: Uuid,
    /// The owning org.
    pub org_id: Uuid,
    /// The vault's current key version.
    pub key_version: u32,
    /// The user whose self-grant created the vault (TOFU-trusted granter).
    #[serde(default)]
    pub created_by: Option<Uuid>,
    /// The org's members, by email.
    pub members: Vec<VaultMemberView>,
}

/// An element of `GET /v1/orgs/{id}/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgVaultView {
    /// The vault.
    pub id: Uuid,
    /// The vault name sealed under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current key version.
    pub key_version: u32,
    /// The caller's effective permission (`manage` for org owners and admins).
    pub permission: Permission,
    /// The caller holds a grant for the current key version (`false`: "needs key").
    pub has_key: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn grant_request_wire() {
        let g = GrantRequest {
            permission: Permission::Write,
            key_version: 1,
            wrapped_vault_key: vec![1, 2],
            signature: vec![3],
        };
        let s = serde_json::to_string(&g).unwrap();
        assert_eq!(
            s,
            r#"{"permission":"write","key_version":1,"wrapped_vault_key":"AQI","signature":"Aw"}"#
        );
        assert_eq!(serde_json::from_str::<GrantRequest>(&s).unwrap(), g);
    }

    #[test]
    fn admins_manage_implicitly() {
        let mut m = VaultMemberView {
            user_id: Uuid::nil(),
            email: None,
            org_role: Role::Member,
            permission: Some(Permission::Read),
            has_key: true,
            granted_by: None,
        };
        assert_eq!(m.effective(), Some(Permission::Read));
        m.org_role = Role::Admin;
        assert_eq!(m.effective(), Some(Permission::Manage));
        m.org_role = Role::Member;
        m.permission = None;
        assert_eq!(m.effective(), None);
    }
}
