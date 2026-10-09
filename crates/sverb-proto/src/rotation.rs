//! M5-04: vault key rotation (SPEC §13.2 steps 1–5, §10.3
//! `items_rotation_staging`, §10.4 `POST /v1/vaults/{id}/rotate`).
//!
//! One endpoint, three actions (the `action` tag of [`RotateRequest`]):
//!
//! | Action | Request | Effect |
//! |---|---|---|
//! | `begin` | `new_key_version` (= current + 1) | sets `vaults.rotation = {by, new_key_version, started_at}`; pushes now get `409 rotating` |
//! | `upload` | up to [`MAX_ROTATION_CHUNK`] `{id, envelope}` | upserts into `items_rotation_staging` (idempotent) |
//! | `commit` | one `{user, wrapped, signature}` per remaining member | one transaction: full coverage check, fresh revisions, new grants, old grants removed, `key_version` bumped |
//!
//! Every action answers [`RotateResponse`]. Errors (the §10.4 envelope):
//! * `404 not_found`: unknown vault, not visible, or a personal vault;
//! * `403 forbidden`: the caller has no `manage` on the vault;
//! * `409 rotating`: `begin` while another rotation is active and not
//!   abandoned; `upload` / `commit` by someone else than the rotating user;
//! * `400 invalid`: `new_key_version` is not current + 1, no rotation is
//!   running, an oversized chunk or envelope, staging that does not cover
//!   every item (the message names the missing count; nothing is applied), or
//!   wrapped keys that miss a member, name a non-member, or are malformed.
//!
//! **Abandonment:** a rotation whose `started_at` is more than
//! [`ROTATION_ABANDON_SECS`] in the past counts as abandoned. `GET /v1/vaults`
//! then reports [`crate::sync::RotationView::abandoned`]; the next `begin` by
//! any `manage` client (or `admin gc`) discards its staging and clears it. The
//! same user calling `begin` again for the same key version **resumes** the
//! rotation (staging kept).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Most items per `upload` (§13.2: chunks of up to 500).
pub const MAX_ROTATION_CHUNK: usize = 500;

/// A rotation older than this (seconds since `started_at`) is abandoned
/// (§13.2: 15 minutes).
pub const ROTATION_ABANDON_SECS: i64 = 15 * 60;

/// One re-encrypted item (same id, AAD key version = the new one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedItem {
    /// Item id (unchanged).
    pub id: Uuid,
    /// The item sealed under the new vault key.
    #[serde(with = "crate::b64")]
    pub envelope: Vec<u8>,
}

/// The new vault key wrapped for one remaining member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationGrant {
    /// The member.
    pub user: Uuid,
    /// The new vault key HPKE-wrapped to the member's pinned X25519 key.
    #[serde(with = "crate::b64")]
    pub wrapped: Vec<u8>,
    /// The committer's Ed25519 signature over the canonical grant (§13.3).
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// Body of `POST /v1/vaults/{id}/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RotateRequest {
    /// Step 1: start (or resume) a rotation to `new_key_version`.
    Begin {
        /// Must be the vault's key version + 1.
        new_key_version: u32,
    },
    /// Step 3: stage re-encrypted items.
    Upload {
        /// At most [`MAX_ROTATION_CHUNK`].
        items: Vec<RotatedItem>,
    },
    /// Step 4: swap the staged items in and install the new grants.
    Commit {
        /// One per remaining member, the committer included.
        wrapped_keys: Vec<RotationGrant>,
    },
}

/// Response of every rotate action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateResponse {
    /// The vault's key version (after `commit`: the new one).
    pub key_version: u32,
    /// The key version being rotated to (`commit`: equals `key_version`).
    pub new_key_version: u32,
    /// The vault's head revision (after `commit`: the new head).
    pub head_revision: u64,
    /// Items currently staged (0 after `commit`).
    pub staged: u64,
    /// `begin`: an existing rotation of the caller was resumed.
    #[serde(default)]
    pub resumed: bool,
    /// `begin`: an abandoned rotation was discarded first.
    #[serde(default)]
    pub replaced_abandoned: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wire_form() {
        let begin = RotateRequest::Begin { new_key_version: 2 };
        let j = serde_json::to_value(&begin).unwrap();
        assert_eq!(j["action"], "begin");
        assert_eq!(j["new_key_version"], 2);
        let up = RotateRequest::Upload {
            items: vec![RotatedItem {
                id: Uuid::nil(),
                envelope: vec![0xfb, 0xff],
            }],
        };
        let j = serde_json::to_value(&up).unwrap();
        assert_eq!(j["action"], "upload");
        assert_eq!(j["items"][0]["envelope"], "-_8");
        assert_eq!(serde_json::from_value::<RotateRequest>(j).unwrap(), up);
        let c = RotateRequest::Commit {
            wrapped_keys: vec![RotationGrant {
                user: Uuid::nil(),
                wrapped: vec![1],
                signature: vec![2],
            }],
        };
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["action"], "commit");
        assert_eq!(serde_json::from_value::<RotateRequest>(j).unwrap(), c);
        let r: RotateResponse = serde_json::from_str(
            r#"{"key_version":1,"new_key_version":2,"head_revision":5,"staged":0}"#,
        )
        .unwrap();
        assert!(!r.resumed && !r.replaced_abandoned);
    }
}
