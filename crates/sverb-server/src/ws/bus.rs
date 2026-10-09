//! The cross-replica event bus (SPEC §10.7).
//!
//! Every notification goes through a [`Bus`]: the publisher (a push commit,
//! a device revocation, …) calls [`Bus::publish`], and every replica's
//! [`super::hub::Hub`] receives the event from [`Bus::subscribe`]. The
//! publishing replica receives its own events back through the same path,
//! so a single-replica deployment runs exactly the multi-replica code.
//!
//! * [`super::pg_notify::PgBus`]: production, `NOTIFY sverb_events` /
//!   `LISTEN sverb_events` (payload < 8 KB: ids only);
//! * [`LocalBus`]: in-process (the in-memory test backend; several
//!   `AppState`s sharing one `LocalBus` model several replicas sharing one
//!   database).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sverb_proto::ws::{AccessChange, ShareViewer};
use tokio::sync::broadcast;
use uuid::Uuid;

/// The PostgreSQL notification channel.
pub const CHANNEL: &str = "sverb_events";

/// PostgreSQL rejects `NOTIFY` payloads of 8000 bytes or more; events are
/// ids only, so this is never reached in practice (oversized events are
/// dropped with a warning, notifications are hints).
pub const MAX_PAYLOAD_BYTES: usize = 7900;

/// Longest viewer name/account/IP hint carried in an event (characters).
const MAX_VIEWER_FIELD: usize = 256;

/// How many undelivered events a slow subscriber may lag behind before it
/// skips ahead (hints only, see the module docs).
pub const BUS_CAPACITY: usize = 1024;

/// One notification, as it travels between replicas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum BusEvent {
    /// A push committed (to the vault's members).
    VaultChanged {
        /// Vault.
        vault_id: Uuid,
        /// New head.
        head_revision: u64,
    },
    /// Membership/key change. With `user_id` (grant, revoke) it goes to that
    /// user only and also changes their subscriptions; without (rotation)
    /// to all current members.
    VaultAccess {
        /// Vault.
        vault_id: Uuid,
        /// The affected user, for grants and revocations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_id: Option<Uuid>,
        /// What changed.
        change: AccessChange,
    },
    /// Password change or recovery (§11.2.1): the user's other devices.
    AccountChanged {
        /// Account.
        user_id: Uuid,
        /// New `account_keys.version`.
        key_version: u32,
        /// The device that made the change (not notified).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin_device: Option<Uuid>,
    },
    /// A share viewer waits for approval: the owner's sockets.
    ShareJoinRequest {
        /// Share owner.
        owner_user_id: Uuid,
        /// Share.
        share_id: Uuid,
        /// Viewer.
        viewer: ShareViewer,
    },
    /// Internal: a device was revoked; its sockets close with 4401.
    DeviceRevoked {
        /// Owner.
        user_id: Uuid,
        /// Device.
        device_id: Uuid,
    },
    /// Internal: an account was disabled; all its sockets close with 4401.
    UserDisabled {
        /// Account.
        user_id: Uuid,
    },
}

fn cap(s: Option<String>) -> Option<String> {
    s.map(|s| s.chars().take(MAX_VIEWER_FIELD).collect())
}

impl BusEvent {
    /// A share join request with the free-text fields capped, so the
    /// payload always fits a `NOTIFY`.
    #[must_use]
    pub fn share_join_request(owner_user_id: Uuid, share_id: Uuid, viewer: ShareViewer) -> Self {
        Self::ShareJoinRequest {
            owner_user_id,
            share_id,
            viewer: ShareViewer {
                viewer_id: viewer.viewer_id,
                name: cap(viewer.name),
                account: cap(viewer.account),
                ip_hint: cap(viewer.ip_hint),
            },
        }
    }

    /// The JSON `NOTIFY` payload; `None` if it would exceed
    /// [`MAX_PAYLOAD_BYTES`].
    #[must_use]
    pub fn to_payload(&self) -> Option<String> {
        serde_json::to_string(self)
            .ok()
            .filter(|p| p.len() <= MAX_PAYLOAD_BYTES)
    }

    /// Parses a payload (`None` for garbage or events of a newer version).
    #[must_use]
    pub fn from_payload(payload: &str) -> Option<Self> {
        serde_json::from_str(payload).ok()
    }
}

/// Receives the bus' health: `true` when connected (events flow), `false`
/// while reconnecting (readiness is degraded).
pub type StatusSink = Arc<dyn Fn(bool) + Send + Sync>;

/// A fan-out bus shared by all replicas.
pub trait Bus: Send + Sync + std::fmt::Debug {
    /// Publishes an event to every replica (this one included).
    /// Fire-and-forget: never blocks, never fails the caller.
    fn publish(&self, event: BusEvent);

    /// Starts receiving events (and, for a networked bus, its listener).
    /// `status` is told about connection changes.
    fn subscribe(&self, status: StatusSink) -> broadcast::Receiver<BusEvent>;
}

/// The in-process bus.
#[derive(Debug)]
pub struct LocalBus {
    tx: broadcast::Sender<BusEvent>,
}

impl LocalBus {
    /// A new, empty bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(BUS_CAPACITY).0,
        }
    }
}

impl Default for LocalBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for LocalBus {
    fn publish(&self, event: BusEvent) {
        // Same size rule as NOTIFY, so tests catch oversized events.
        if event.to_payload().is_none() {
            tracing::warn!(?event, "bus event too large; dropped");
            return;
        }
        // No subscribers yet (no socket ever connected): nothing to do.
        let _ = self.tx.send(event);
    }

    fn subscribe(&self, status: StatusSink) -> broadcast::Receiver<BusEvent> {
        status(true);
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn payloads_round_trip_and_stay_small() {
        let events = [
            BusEvent::VaultChanged {
                vault_id: Uuid::now_v7(),
                head_revision: u64::MAX,
            },
            BusEvent::VaultAccess {
                vault_id: Uuid::now_v7(),
                user_id: Some(Uuid::now_v7()),
                change: AccessChange::Revoked,
            },
            BusEvent::AccountChanged {
                user_id: Uuid::now_v7(),
                key_version: 2,
                origin_device: None,
            },
            BusEvent::share_join_request(
                Uuid::now_v7(),
                Uuid::now_v7(),
                ShareViewer {
                    viewer_id: 9,
                    name: Some("x".repeat(100_000)),
                    account: Some("y".repeat(100_000)),
                    ip_hint: Some("z".repeat(100_000)),
                },
            ),
            BusEvent::DeviceRevoked {
                user_id: Uuid::now_v7(),
                device_id: Uuid::now_v7(),
            },
            BusEvent::UserDisabled {
                user_id: Uuid::now_v7(),
            },
        ];
        for e in events {
            let p = e.to_payload().unwrap();
            assert!(p.len() < 8000, "{} bytes", p.len());
            assert_eq!(BusEvent::from_payload(&p).unwrap(), e);
        }
        assert!(BusEvent::from_payload(r#"{"e":"newer_thing"}"#).is_none());
    }
}
