//! User public keys (SPEC §10.4 "Teams", §13.3).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `GET /v1/users/{id}/public-keys` | – | [`UserPublicKeys`] |
//!
//! The server serves whatever keys it has. Clients never trust them blindly: they
//! are pinned on first sight and compared on every later fetch (TOFU, §13.3), and a
//! changed key is a loud warning, not an update.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user's account public keys (`GET /v1/users/{id}/public-keys`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublicKeys {
    /// The user.
    pub user_id: Uuid,
    /// Display name (the account email). Untrusted: for display and lookups only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// X25519 public key (32 B), for HPKE-wrapping vault keys.
    #[serde(with = "crate::b64")]
    pub x25519_pub: Vec<u8>,
    /// Ed25519 public key (32 B), for verifying grant signatures.
    #[serde(with = "crate::b64")]
    pub ed25519_pub: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn round_trip() {
        let k = UserPublicKeys {
            user_id: Uuid::nil(),
            email: Some("bob@example.test".into()),
            x25519_pub: vec![1; 32],
            ed25519_pub: vec![2; 32],
        };
        let s = serde_json::to_string(&k).unwrap();
        assert_eq!(serde_json::from_str::<UserPublicKeys>(&s).unwrap(), k);
        let no_email: UserPublicKeys = serde_json::from_str(
            r#"{"user_id":"00000000-0000-0000-0000-000000000000","x25519_pub":"","ed25519_pub":""}"#,
        )
        .unwrap();
        assert_eq!(no_email.email, None);
    }
}
