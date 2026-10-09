//! Vault and sync DTOs (SPEC §10.4 "Vaults and sync", §12.2, §12.3;
//! task M4-04). Shared by the server and the client sync engine (M4-07).
//!
//! Binary fields (envelopes, wrapped keys, signatures, encrypted names) are
//! base64url without padding ([`crate::b64`]). Revisions are per-vault,
//! gap-free and start at 1; `0` means "nothing yet" (a pull cursor of 0, or
//! the base revision of an item the client believes is new).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `GET /v1/vaults` | – | `[`[`VaultView`]`]` |
//! | `GET /v1/vaults/{id}/changes?since=&limit=` | [`PullQuery`] | [`PullResponse`] |
//! | `POST /v1/vaults/{id}/changes` | [`PushRequest`] | [`PushResponse`] |
//!
//! Errors (all as the §10.4 envelope):
//! * `404 not_found`: unknown vault **or** not a member (existence is not
//!   revealed);
//! * `410 gone` (pull): `since` is below the vault's GC floor and not 0, the
//!   client must do a full resync from `since=0` (§12.2);
//! * `403 forbidden` (push): the caller only has `read` permission (§13.2);
//! * `409 rotating` (push): a key rotation is in progress (§13.2);
//! * `400 invalid` (push): more than [`MAX_BATCH_ITEMS`] changes, more than
//!   [`MAX_BATCH_BYTES`] of envelopes, a duplicate item id, or a change whose
//!   `key_version` is not the vault's current one (the client has a stale
//!   vault key and must refresh `GET /v1/vaults` first).
//!
//! Per-item outcomes are in [`PushResult`]; see [`PushStatus`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum size of one item envelope (§10.5): 1 MiB. Larger envelopes get
/// [`PushStatus::TooLarge`].
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Maximum number of changes in one push (§10.5).
pub const MAX_BATCH_ITEMS: usize = 500;

/// Maximum total envelope bytes (decoded) in one push (§10.5): 8 MiB.
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Maximum (and default) page size of a pull (§12.2).
pub const MAX_PULL_LIMIT: u32 = 500;

/// [`PushResult::message`] of a change rejected because it would exceed the
/// storage quota (status [`PushStatus::TooLarge`]).
pub const QUOTA_EXCEEDED_MESSAGE: &str = "quota exceeded";

/// [`PushResult::message`] of a change whose envelope exceeds
/// [`MAX_ENVELOPE_BYTES`] (status [`PushStatus::TooLarge`]).
pub const ENVELOPE_TOO_LARGE_MESSAGE: &str = "envelope exceeds 1 MiB";

// ------------------------------------------------------------------ vaults

/// `vaults.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    /// The user's own vault (created at registration).
    Personal,
    /// An org vault (M5).
    Shared,
}

impl VaultKind {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
        }
    }

    /// Parses the database spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(Self::Personal),
            "shared" => Some(Self::Shared),
            _ => None,
        }
    }
}

/// `vault_members.permission` (§13.1). Ordered: `Read < Write < Manage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Pull only; pushes are rejected with `403 forbidden` (§13.2).
    Read,
    /// Pull and push.
    Write,
    /// Pull, push, grant and revoke.
    Manage,
}

impl Permission {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Manage => "manage",
        }
    }

    /// Parses the database spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }

    /// Whether this permission may push.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::Manage)
    }
}

/// One wrapped vault key of the caller (`vault_members` row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    /// Key version this wrap is for.
    pub key_version: u32,
    /// The vault key HPKE-wrapped to the caller's X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped_vault_key: Vec<u8>,
    /// The granting user (verify `signature` with their Ed25519 key).
    pub wrapped_by: Uuid,
    /// Ed25519 signature by the granter (§13.3).
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// A key rotation in progress (§13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationView {
    /// Always `true` when present.
    pub in_progress: bool,
    /// The key version the rotation will commit, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key_version: Option<u32>,
    // M5-04
    /// The user running the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Uuid>,
    /// When it began (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    /// Older than 15 minutes (§13.2): the next `manage` client should restart
    /// it ([`crate::rotation`]).
    #[serde(default)]
    pub abandoned: bool,
}

/// An element of `GET /v1/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultView {
    /// Vault id.
    pub id: Uuid,
    /// Personal or shared.
    pub kind: VaultKind,
    /// The owning org (shared vaults).
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// Vault name encrypted under the vault key.
    #[serde(with = "crate::b64")]
    pub name_enc: Vec<u8>,
    /// Current key version: pushes must use it.
    pub key_version: u32,
    /// Highest assigned revision.
    pub head_revision: u64,
    /// The caller's permission.
    pub permission: Permission,
    /// The caller's wrapped keys, every key version still present
    /// (several during a rotation), ascending.
    pub grants: Vec<VaultGrant>,
    /// Present while a key rotation is in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationView>,
}

// -------------------------------------------------------------------- pull

/// Query of `GET /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PullQuery {
    /// The client's cursor: return revisions strictly greater (default 0).
    #[serde(default)]
    pub since: u64,
    /// Page size, 1..=[`MAX_PULL_LIMIT`] (default and cap
    /// [`MAX_PULL_LIMIT`]; larger values are clamped, 0 is rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// An item as stored on the server (pull page entry, and
/// [`PushResult::current`] on conflict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteItem {
    /// Item id.
    pub id: Uuid,
    /// The revision assigned when this version was pushed.
    pub revision: u64,
    /// Key version the envelope is sealed under.
    pub key_version: u32,
    /// The sealed item (§9).
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone (the envelope carries the delete stamp, §12.4).
    #[serde(default)]
    pub deleted: bool,
}

/// Response of `GET /v1/vaults/{id}/changes`.
///
/// `items` is ordered by `revision` ascending, all `> since`. When `more` is
/// `false` the page reached the end of a consistent snapshot and the client
/// may set its cursor to `head_revision`; otherwise it sets the cursor to the
/// last item's revision and pulls again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    /// The page.
    pub items: Vec<RemoteItem>,
    /// The vault's head revision in the same snapshot.
    pub head_revision: u64,
    /// More items after this page.
    pub more: bool,
}

// -------------------------------------------------------------------- push

/// One change of a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushChange {
    /// Item id (client-generated).
    pub id: Uuid,
    /// The server revision this change is based on (0 for a new item).
    pub base_revision: u64,
    /// Must equal the vault's current key version.
    pub key_version: u32,
    /// The sealed item.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
    /// Tombstone.
    #[serde(default)]
    pub deleted: bool,
}

/// Body of `POST /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PushRequest {
    /// The batch, applied in one transaction, revisions assigned in order.
    pub changes: Vec<PushChange>,
}

/// Per-change outcome of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    /// Accepted; [`PushResult::revision`] is the new revision.
    Ok,
    /// `base_revision` is stale; [`PushResult::current`] is the server's
    /// version (absent when the item does not exist on the server, e.g. its
    /// tombstone was purged: push it again with `base_revision = 0`).
    Conflict,
    /// Reserved for per-item ACLs (a `read` member gets a whole-request 403).
    Forbidden,
    /// The envelope exceeds [`MAX_ENVELOPE_BYTES`], or accepting it would
    /// exceed the storage quota ([`PushResult::message`] says which).
    TooLarge,
}

/// One element of [`PushResponse::results`], in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    /// Item id.
    pub id: Uuid,
    /// Outcome.
    pub status: PushStatus,
    /// New revision (`ok` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// The server's current item (`conflict` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<RemoteItem>,
    /// Human-readable detail (`too_large`: [`QUOTA_EXCEEDED_MESSAGE`] or
    /// [`ENVELOPE_TOO_LARGE_MESSAGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Response of `POST /v1/vaults/{id}/changes`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PushResponse {
    /// One result per change, in request order.
    pub results: Vec<PushResult>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn push_roundtrip_and_wire_names() {
        let id = Uuid::nil();
        let req = PushRequest {
            changes: vec![PushChange {
                id,
                base_revision: 0,
                key_version: 1,
                envelope: vec![0xfb, 0xff],
                deleted: false,
            }],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["changes"][0]["envelope"], "-_8");
        assert_eq!(serde_json::from_value::<PushRequest>(v).unwrap(), req);

        let res = PushResponse {
            results: vec![
                PushResult {
                    id,
                    status: PushStatus::TooLarge,
                    revision: None,
                    current: None,
                    message: Some(QUOTA_EXCEEDED_MESSAGE.into()),
                },
                PushResult {
                    id,
                    status: PushStatus::Conflict,
                    revision: None,
                    current: Some(RemoteItem {
                        id,
                        revision: 7,
                        key_version: 1,
                        envelope: vec![1],
                        deleted: true,
                    }),
                    message: None,
                },
            ],
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["results"][0]["status"], "too_large");
        assert!(v["results"][0].get("revision").is_none());
        assert_eq!(v["results"][1]["status"], "conflict");
        assert_eq!(v["results"][1]["current"]["revision"], 7);
        assert_eq!(serde_json::from_value::<PushResponse>(v).unwrap(), res);
    }

    #[test]
    fn deleted_defaults_to_false() {
        let c: PushChange = serde_json::from_str(&format!(
            r#"{{"id":"{}","base_revision":3,"key_version":2,"envelope":"AQ"}}"#,
            Uuid::nil()
        ))
        .unwrap();
        assert!(!c.deleted);
        assert_eq!(c.envelope, vec![1]);
    }

    #[test]
    fn vault_view_wire_form() {
        let v = VaultView {
            id: Uuid::nil(),
            kind: VaultKind::Personal,
            org_id: None,
            name_enc: vec![1, 2],
            key_version: 1,
            head_revision: 0,
            permission: Permission::Manage,
            grants: vec![],
            rotation: None,
        };
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["kind"], "personal");
        assert_eq!(j["permission"], "manage");
        assert!(j.get("rotation").is_none());
        assert!(j["org_id"].is_null());
        assert_eq!(serde_json::from_value::<VaultView>(j).unwrap(), v);
        assert!(Permission::Read < Permission::Write);
        assert!(!Permission::Read.can_write() && Permission::Write.can_write());
        assert_eq!(Permission::parse("manage"), Some(Permission::Manage));
        assert_eq!(VaultKind::parse("shared"), Some(VaultKind::Shared));
    }

    #[test]
    fn pull_query_defaults() {
        let q: PullQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q, PullQuery::default());
    }
}
