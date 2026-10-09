//! Terminal-share relay wire types (SPEC §10.4 "Sharing", §14.1, §14.2; task
//!
//! # HTTP
//!
//! | Method | Path | Body → response |
//! |---|---|---|
//! | POST | `/v1/shares` | [`CreateShareRequest`] → [`CreateShareResponse`] |
//! | DELETE | `/v1/shares/{id}` | → `204` (owner only; ends the share) |
//! | GET (WS) | `/v1/shares/{id}/host` | host stream (owner only) |
//! | GET (WS) | `/v1/shares/{id}/join` | viewer stream (auth optional per share) |
//!
//! The share key never reaches the server: it lives in the link fragment
//! (§14.1), see `sverb_crypto::share`.
//!
//! # WebSocket framing
//!
//! * **Text** messages are JSON control messages tagged by `type`
//!   ([`HostClientMsg`], [`HostServerMsg`], [`ViewerClientMsg`],
//!   [`ViewerServerMsg`]). Receivers must ignore types they don't know.
//! * **Binary** messages are [`RelayEnvelope`]s: `viewer_id (u32 BE) ||
//!   payload`, at most [`MAX_RELAY_MESSAGE`] bytes in total. The payload is
//!   opaque to the server (a `share_frame::SharePayload`).
//!   * host → server: `viewer_id` names the destination viewer. Unknown ids
//!     and [`CONTROL_VIEWER_ID`] are dropped. There is no broadcast: every
//!     viewer has its own channel key (§14.2).
//!   * server → viewer: the envelope as the host sent it (its own id).
//!   * viewer → server: the id the viewer puts there is **ignored**; the
//!     server overwrites it with the viewer's real id before forwarding to
//!     the host (no spoofing).
//!
//! # Host stream
//!
//! 1. First message within [`crate::ws::AUTH_TIMEOUT_SECS`]:
//!    `{"type":"auth","token"}` → `4401` if missing or invalid, `4403` if
//!    the caller isn't the share's owner (or the share doesn't exist),
//!    `4410` if it is already closed or expired.
//! 2. Server → host `{"type":"ready",…}`, then `viewer_joined` for every
//!    viewer already waiting (a reconnecting host restarts their
//!    handshakes). A new host connection replaces the previous one, which is
//!    closed with [`CLOSE_REPLACED`].
//! 3. Host → server `{"type":"kick","viewer_id"}` closes that viewer with
//!    [`CLOSE_KICKED`]. Approve/deny travel end to end inside the encrypted
//!    channel; the server doesn't see them.
//!
//! # Viewer stream
//!
//! First message within the same window: `{"type":"join","name"}` (anonymous;
//! `4401` when the share requires an account) or
//! `{"type":"auth","token","name"?}`. Then `4429` when the share is full,
//! otherwise `{"type":"joined","viewer_id","mode"}` (the `viewer_id` both
//!
//! # Heartbeat and ending
//!
//! Both streams use `{"type":"ping"}` / `{"type":"pong"}` like `/v1/ws`
//! (every [`crate::ws::PING_INTERVAL_SECS`], close `4408` after
//! [`crate::ws::MAX_MISSED_PONGS`] missed pongs). A share ends when the owner
//! deletes it, when the host stays disconnected for [`HOST_GRACE_SECS`], or at
//! its expiry: every socket is closed with [`CLOSE_SHARE_ENDED`] (`4410`).
//! A viewer whose send queue ([`VIEWER_QUEUE`] messages) overflows is closed
//! with [`CLOSE_SLOW_CONSUMER`] instead of slowing the host down.

use core::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::ws::ShareViewer;

/// Collection path (under [`crate::version::API_PREFIX`]).
pub const SHARES_PATH: &str = "/shares";

/// Reserved `viewer_id`: never assigned to a viewer (control).
pub const CONTROL_VIEWER_ID: u32 = 0;

/// Largest binary or text message on a share stream (1 MiB, header
/// included).
pub const MAX_RELAY_MESSAGE: usize = 1024 * 1024;

/// Messages queued towards one viewer before it counts as slow.
pub const VIEWER_QUEUE: usize = 256;

/// How long a share survives without a host connection.
pub const HOST_GRACE_SECS: u64 = 60;

/// Close code: authentication missing, invalid, or required by the share.
pub const CLOSE_AUTH_REQUIRED: u16 = crate::ws::CLOSE_AUTH_REQUIRED;
/// Close code: the caller may not host this share (not the owner, or no
/// such share).
pub const CLOSE_FORBIDDEN: u16 = 4403;
/// Close code: no such share (viewer stream).
pub const CLOSE_NOT_FOUND: u16 = 4404;
/// Close code: the viewer's queue overflowed (or the peer missed pongs).
pub const CLOSE_SLOW_CONSUMER: u16 = crate::ws::CLOSE_PING_TIMEOUT;
/// Close code: a newer host connection replaced this one.
pub const CLOSE_REPLACED: u16 = 4409;
/// Close code: the share ended (deleted, host gone, or expired).
pub const CLOSE_SHARE_ENDED: u16 = 4410;
/// Close code: the host kicked this viewer.
pub const CLOSE_KICKED: u16 = 4411;
/// Close code: the share already has `max_viewers` viewers.
pub const CLOSE_SHARE_FULL: u16 = 4429;

/// What viewers may do (§14.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareMode {
    /// Read-only.
    #[default]
    View,
    /// The host may grant input to viewers.
    Control,
}

impl ShareMode {
    /// The `share_sessions.mode` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Control => "control",
        }
    }

    /// Parses a `share_sessions.mode` value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "view" => Some(Self::View),
            "control" => Some(Self::Control),
            _ => None,
        }
    }
}

/// `POST /v1/shares`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShareRequest {
    /// View or control.
    #[serde(default)]
    pub mode: ShareMode,
    /// Lifetime in seconds; default and maximum are the server's share TTL
    /// (24 h unless configured). Larger values are clamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_s: Option<u64>,
    /// Viewer cap; default and maximum are the server's limit (10 unless
    /// configured). Larger values are clamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_viewers: Option<u32>,
    /// Viewers must authenticate with a sverb account.
    #[serde(default)]
    pub require_account: bool,
}

/// Response to `POST /v1/shares`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShareResponse {
    /// The share.
    pub share_id: Uuid,
    /// When it ends at the latest.
    pub expires_at: DateTime<Utc>,
    /// The effective viewer cap (after clamping).
    pub max_viewers: u32,
}

/// A binary relay message: `viewer_id (u32 BE) || payload` (§14.2).
#[derive(Clone, PartialEq, Eq)]
pub struct RelayEnvelope {
    /// Destination (host → viewer) or source (viewer → host) viewer.
    pub viewer_id: u32,
    /// Opaque payload (never inspected or logged by the server).
    pub payload: Vec<u8>,
}

/// A malformed [`RelayEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// Fewer than [`RelayEnvelope::HEADER_LEN`] bytes.
    Short,
    /// More than [`MAX_RELAY_MESSAGE`] bytes.
    TooLarge,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Short => "relay message shorter than its header",
            Self::TooLarge => "relay message too large",
        })
    }
}

impl std::error::Error for RelayError {}

impl RelayEnvelope {
    /// Header length (the `viewer_id`).
    pub const HEADER_LEN: usize = 4;

    /// Wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.viewer_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses the wire form.
    ///
    /// # Errors
    /// [`RelayError`] for short or oversized messages.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        let viewer_id = Self::peek_viewer_id(bytes)?;
        Ok(Self {
            viewer_id,
            payload: bytes[Self::HEADER_LEN..].to_vec(),
        })
    }

    /// The `viewer_id` of a wire message without copying the payload.
    ///
    /// # Errors
    /// [`RelayError`] for short or oversized messages.
    pub fn peek_viewer_id(bytes: &[u8]) -> Result<u32, RelayError> {
        if bytes.len() > MAX_RELAY_MESSAGE {
            return Err(RelayError::TooLarge);
        }
        let head: [u8; 4] = bytes
            .get(..Self::HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(RelayError::Short)?;
        Ok(u32::from_be_bytes(head))
    }

    /// Overwrites the `viewer_id` of a wire message in place (the server
    /// stamps viewer → host messages).
    ///
    /// # Errors
    /// [`RelayError`] for short or oversized messages.
    pub fn stamp(bytes: &mut [u8], viewer_id: u32) -> Result<(), RelayError> {
        Self::peek_viewer_id(bytes)?;
        bytes[..Self::HEADER_LEN].copy_from_slice(&viewer_id.to_be_bytes());
        Ok(())
    }
}

impl fmt::Debug for RelayEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print payload bytes (they may be terminal contents).
        f.debug_struct("RelayEnvelope")
            .field("viewer_id", &self.viewer_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Why a viewer left (in [`HostServerMsg::ViewerLeft`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaveReason {
    /// The viewer disconnected.
    Left,
    /// The host kicked it.
    Kicked,
    /// Its queue overflowed or it stopped answering pings.
    Slow,
}

/// Host → server (text).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostClientMsg {
    /// The first message: the owner's access token (never logged).
    Auth {
        /// Access token.
        token: String,
    },
    /// Disconnect a viewer.
    Kick {
        /// The viewer.
        viewer_id: u32,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a server `ping`.
    Pong,
}

impl fmt::Debug for HostClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth { .. } => f.write_str("Auth { token: <redacted> }"),
            Self::Kick { viewer_id } => write!(f, "Kick {{ viewer_id: {viewer_id} }}"),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
        }
    }
}

/// Server → host (text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostServerMsg {
    /// Authenticated; the relay is live.
    Ready {
        /// The share.
        share_id: Uuid,
        /// Its mode.
        mode: ShareMode,
        /// Its expiry.
        expires_at: DateTime<Utc>,
    },
    /// A viewer connected (start the join handshake when its `Hello`
    /// arrives).
    ViewerJoined(ShareViewer),
    /// A viewer is gone.
    ViewerLeft {
        /// The viewer.
        viewer_id: u32,
        /// Why.
        reason: LeaveReason,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a host `ping`.
    Pong,
}

/// Viewer → server (text).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ViewerClientMsg {
    /// First message, signed in (required when the share requires an
    /// account).
    Auth {
        /// Access token (never logged).
        token: String,
        /// Optional display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// First message, anonymous.
    Join {
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Heartbeat.
    Ping,
    /// Answer to a server `ping`.
    Pong,
}

impl fmt::Debug for ViewerClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth { name, .. } => {
                write!(f, "Auth {{ token: <redacted>, name: {name:?} }}")
            }
            Self::Join { name } => write!(f, "Join {{ name: {name:?} }}"),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
        }
    }
}

/// Server → viewer (text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ViewerServerMsg {
    /// Admitted: the relay-assigned id (bound into the frame AAD) and the
    /// share's mode.
    Joined {
        /// This viewer's id.
        viewer_id: u32,
        /// The share's mode.
        mode: ShareMode,
    },
    /// A host connection is live (send or re-send `Hello`).
    HostConnected,
    /// The host connection dropped; the share ends unless it returns within
    /// [`HOST_GRACE_SECS`].
    HostDisconnected,
    /// Heartbeat.
    Ping,
    /// Answer to a viewer `ping`.
    Pong,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn rt<T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug>(v: &T, json: &str) {
        assert_eq!(serde_json::to_string(v).unwrap(), json);
        assert_eq!(&serde_json::from_str::<T>(json).unwrap(), v);
    }

    #[test]
    fn envelope_round_trip_and_stamp() {
        let e = RelayEnvelope {
            viewer_id: 0x0102_0304,
            payload: b"opaque".to_vec(),
        };
        let mut w = e.encode();
        assert_eq!(&w[..4], &[1, 2, 3, 4]);
        assert_eq!(RelayEnvelope::decode(&w).unwrap(), e);
        RelayEnvelope::stamp(&mut w, 7).unwrap();
        assert_eq!(RelayEnvelope::peek_viewer_id(&w).unwrap(), 7);
        assert_eq!(&w[4..], b"opaque");
        assert_eq!(RelayEnvelope::decode(&[0, 0, 1]), Err(RelayError::Short));
        assert_eq!(
            RelayEnvelope::decode(&vec![0; MAX_RELAY_MESSAGE + 1]),
            Err(RelayError::TooLarge)
        );
        assert!(RelayEnvelope::decode(&vec![0; MAX_RELAY_MESSAGE]).is_ok());
        assert!(!format!("{e:?}").contains("opaque"));
    }

    #[test]
    fn create_request_defaults() {
        let r: CreateShareRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(
            r,
            CreateShareRequest {
                mode: ShareMode::View,
                expires_in_s: None,
                max_viewers: None,
                require_account: false
            }
        );
        rt(
            &CreateShareRequest {
                mode: ShareMode::Control,
                expires_in_s: Some(60),
                max_viewers: Some(3),
                require_account: true,
            },
            r#"{"mode":"control","expires_in_s":60,"max_viewers":3,"require_account":true}"#,
        );
    }

    #[test]
    fn control_messages_match_the_task() {
        rt(
            &HostClientMsg::Kick { viewer_id: 2 },
            r#"{"type":"kick","viewer_id":2}"#,
        );
        rt(
            &HostServerMsg::ViewerJoined(ShareViewer {
                viewer_id: 1,
                name: Some("bob".into()),
                account: None,
                ip_hint: Some("198.51.100.0/24".into()),
            }),
            r#"{"type":"viewer_joined","viewer_id":1,"name":"bob","ip_hint":"198.51.100.0/24"}"#,
        );
        rt(
            &HostServerMsg::ViewerLeft {
                viewer_id: 1,
                reason: LeaveReason::Kicked,
            },
            r#"{"type":"viewer_left","viewer_id":1,"reason":"kicked"}"#,
        );
        rt(
            &ViewerClientMsg::Join {
                name: Some("bob".into()),
            },
            r#"{"type":"join","name":"bob"}"#,
        );
        rt(
            &ViewerServerMsg::Joined {
                viewer_id: 3,
                mode: ShareMode::View,
            },
            r#"{"type":"joined","viewer_id":3,"mode":"view"}"#,
        );
        rt(
            &ViewerServerMsg::HostConnected,
            r#"{"type":"host_connected"}"#,
        );
        let auth = ViewerClientMsg::Auth {
            token: "secret".into(),
            name: None,
        };
        rt(&auth, r#"{"type":"auth","token":"secret"}"#);
        assert!(!format!("{auth:?}").contains("secret"));
        assert!(
            !format!(
                "{:?}",
                HostClientMsg::Auth {
                    token: "secret".into()
                }
            )
            .contains("secret")
        );
    }
}
