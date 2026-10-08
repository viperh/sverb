//! `/v1/ws` notification protocol (SPEC §10.4; task M4-05).
//!
//! JSON text messages tagged by `type`. The access token is never put in the
//! URL: the client's first message must be [`ClientMsg::Auth`] within
//! [`AUTH_TIMEOUT_SECS`], otherwise the server closes with
//! [`CLOSE_AUTH_REQUIRED`] (`4401`).
//!
//! | Direction | Message |
//! |---|---|
//! | client → server | `{"type":"auth","token":"…"}` (first message) |
//! | server → client | `{"type":"vault_changed","vault_id","head_revision"}` |
//! | server → client | `{"type":"vault_access","vault_id","change":"granted\|revoked\|rotated"}` |
//! | server → client | `{"type":"account_changed","key_version"}` |
//! | server → client | `{"type":"share_join_request","share_id","viewer"}` |
//! | both | `{"type":"ping"}` / `{"type":"pong"}` every [`PING_INTERVAL_SECS`] |
//!
//! Close codes: [`CLOSE_AUTH_REQUIRED`] (no/invalid auth message, expired
//! access token, revoked device, disabled account: refresh, then reconnect)
//! and [`CLOSE_PING_TIMEOUT`] ([`MAX_MISSED_PONGS`] unanswered pings:
//! reconnect with backoff).
//!
//! Notifications are hints only; correctness comes from pull (§12.2), so a
//! missed message is harmless. Receivers must ignore message types they
//! don't know (newer servers may add some).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Path of the notification socket (under [`crate::version::API_PREFIX`]).
pub const WS_PATH: &str = "/ws";

/// Close code: authentication required or no longer valid.
pub const CLOSE_AUTH_REQUIRED: u16 = 4401;

/// Close code: the peer missed [`MAX_MISSED_PONGS`] pongs in a row.
pub const CLOSE_PING_TIMEOUT: u16 = 4408;

/// The auth message must arrive within this many seconds of the upgrade.
pub const AUTH_TIMEOUT_SECS: u64 = 5;

/// Both sides send `ping` this often.
pub const PING_INTERVAL_SECS: u64 = 30;

/// A side closes after this many consecutive pings without a `pong`.
pub const MAX_MISSED_PONGS: u32 = 2;

/// Client → server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// The first message: the access token (never logged).
    Auth {
        /// The access token (base64url).
        token: String,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a server `ping`.
    Pong,
}

impl std::fmt::Debug for ClientMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth { .. } => f.write_str("Auth { token: <redacted> }"),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
        }
    }
}

/// What happened to the caller's access to a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChange {
    /// The caller became a member: pull `GET /v1/vaults` for the wrapped key.
    Granted,
    /// The caller is no longer a member: drop the vault locally.
    Revoked,
    /// The vault key was rotated (§13.2): refresh the vault key.
    Rotated,
}

/// A viewer asking to join one of the caller's shares (§14, task M6-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareViewer {
    /// Relay-assigned viewer id.
    pub viewer_id: u32,
    /// Display name the viewer gave, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The viewer's account email when signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Coarse IP hint (/24, /48 or a country).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_hint: Option<String>,
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// A push committed: pull if `head_revision` is beyond the local cursor.
    VaultChanged {
        /// The vault.
        vault_id: Uuid,
        /// Its new head revision.
        head_revision: u64,
    },
    /// Membership or key change.
    VaultAccess {
        /// The vault.
        vault_id: Uuid,
        /// What changed.
        change: AccessChange,
    },
    /// The account password / key bundle changed on another device
    /// (§11.2.1).
    AccountChanged {
        /// The new `account_keys.version`.
        key_version: u32,
    },
    /// A viewer waits for approval on one of the caller's shares (M6-01).
    ShareJoinRequest {
        /// The share.
        share_id: Uuid,
        /// Who asks.
        viewer: ShareViewer,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a client `ping`.
    Pong,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn rt<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        v: &T,
        json: &str,
    ) {
        assert_eq!(serde_json::to_string(v).unwrap(), json);
        assert_eq!(&serde_json::from_str::<T>(json).unwrap(), v);
    }

    #[test]
    fn client_messages_match_the_spec() {
        rt(
            &ClientMsg::Auth {
                token: "t0k".into(),
            },
            r#"{"type":"auth","token":"t0k"}"#,
        );
        rt(&ClientMsg::Ping, r#"{"type":"ping"}"#);
        rt(&ClientMsg::Pong, r#"{"type":"pong"}"#);
        assert!(
            !format!(
                "{:?}",
                ClientMsg::Auth {
                    token: "secret".into()
                }
            )
            .contains("secret")
        );
    }

    #[test]
    fn server_messages_match_the_spec() {
        let v = Uuid::nil();
        rt(
            &ServerMsg::VaultChanged {
                vault_id: v,
                head_revision: 7,
            },
            &format!(r#"{{"type":"vault_changed","vault_id":"{v}","head_revision":7}}"#),
        );
        for (c, s) in [
            (AccessChange::Granted, "granted"),
            (AccessChange::Revoked, "revoked"),
            (AccessChange::Rotated, "rotated"),
        ] {
            rt(
                &ServerMsg::VaultAccess {
                    vault_id: v,
                    change: c,
                },
                &format!(r#"{{"type":"vault_access","vault_id":"{v}","change":"{s}"}}"#),
            );
        }
        rt(
            &ServerMsg::AccountChanged { key_version: 3 },
            r#"{"type":"account_changed","key_version":3}"#,
        );
        rt(
            &ServerMsg::ShareJoinRequest {
                share_id: v,
                viewer: ShareViewer {
                    viewer_id: 1,
                    name: Some("bob".into()),
                    account: None,
                    ip_hint: None,
                },
            },
            &format!(
                r#"{{"type":"share_join_request","share_id":"{v}","viewer":{{"viewer_id":1,"name":"bob"}}}}"#
            ),
        );
        rt(&ServerMsg::Ping, r#"{"type":"ping"}"#);
        rt(&ServerMsg::Pong, r#"{"type":"pong"}"#);
    }

    #[test]
    fn unknown_types_are_rejected_so_receivers_can_skip_them() {
        assert!(serde_json::from_str::<ServerMsg>(r#"{"type":"future_thing"}"#).is_err());
    }
}
