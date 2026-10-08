//! WebSocket notifications at `/v1/ws` and multi-replica fan-out (SPEC
//! §10.4, §10.7; task M4-05).
//!
//! ```text
//!  push commit ─┐                       ┌─ replica A: Hub ─ sockets
//!  revoke etc. ─┼─ WsRuntime::publish ─ Bus (NOTIFY/LISTEN) ─┤
//!  admin CLI ───┘   (pg_notify in tx)   └─ replica B: Hub ─ sockets
//! ```
//!
//! * [`bus`]: [`BusEvent`] and the [`Bus`] trait, [`LocalBus`] (in-process);
//! * [`pg_notify`]: [`PgBus`], PostgreSQL `LISTEN/NOTIFY` with a reconnecting
//!   listener that degrades readiness while down;
//! * [`hub`]: topic → local sockets, live (un)subscription;
//! * [`session`]: one connection (auth, heartbeat, expiry, forwarding).
//!
//! Every event takes the bus path, also on a single replica, so there is
//! one code path. Notifications are hints only: nothing is persisted and a
//! missed message is repaired by the client's pull (§12.5).

pub mod bus;
pub mod hub;
pub mod pg_notify;
pub mod session;

use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use sverb_proto::ws::{AccessChange, ShareViewer, WS_PATH};
use uuid::Uuid;

pub use bus::{Bus, BusEvent, LocalBus};
pub use hub::{Hub, HubMsg, Topic};
pub use pg_notify::PgBus;
pub use session::{Frame, WsTiming};

use crate::auth::AuthStore;
use crate::state::AppState;
use crate::sync::ChangeNotifier;

/// Largest client message accepted (the auth message is ~60 bytes).
pub const MAX_CLIENT_MESSAGE: usize = 16 * 1024;

/// The readiness component marked degraded while the bus listener is down.
pub const READINESS_COMPONENT: &str = "ws_listener";

/// WebSocket state shared by the handlers (part of `AppState`).
#[derive(Debug)]
pub struct WsRuntime {
    hub: Arc<Hub>,
    bus: Arc<dyn Bus>,
    timing: WsTiming,
    pump: OnceLock<()>,
}

impl WsRuntime {
    /// A runtime publishing to and receiving from `bus`.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>, timing: WsTiming) -> Self {
        Self {
            hub: Arc::new(Hub::new()),
            bus,
            timing,
            pump: OnceLock::new(),
        }
    }

    /// The bus matching an auth backend: `LISTEN/NOTIFY` on PostgreSQL, a
    /// private [`LocalBus`] for the in-memory model.
    #[must_use]
    pub fn bus_for_auth(store: &AuthStore) -> Arc<dyn Bus> {
        match store {
            AuthStore::Postgres(pool) => Arc::new(PgBus::new(pool.clone())),
            AuthStore::Memory(_) => Arc::new(LocalBus::new()),
        }
    }

    /// This replica's hub.
    #[must_use]
    pub const fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// The bus.
    #[must_use]
    pub const fn bus(&self) -> &Arc<dyn Bus> {
        &self.bus
    }

    /// Session timing.
    #[must_use]
    pub const fn timing(&self) -> WsTiming {
        self.timing
    }

    /// The push-commit hook for [`crate::sync::SyncRuntime::set_notifier`].
    #[must_use]
    pub fn notifier(&self) -> Arc<dyn ChangeNotifier> {
        Arc::new(BusNotifier(self.bus.clone()))
    }

    /// Starts draining the bus into the hub (and the bus listener). Called
    /// by `serve::run` and on the first upgrade; idempotent. Needs a Tokio
    /// runtime.
    pub fn ensure_started(&self, state: &AppState) {
        if self.pump.set(()).is_err() {
            return;
        }
        let st = state.clone();
        let status: bus::StatusSink = Arc::new(move |healthy| {
            st.readiness().set_degraded(READINESS_COMPONENT, !healthy);
        });
        let mut rx = self.bus.subscribe(status);
        let hub = self.hub.clone();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match rx.recv().await {
                    Ok(ev) => hub.dispatch(&ev),
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "ws hub lagged; notifications dropped");
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        });
    }

    /// Publishes an event to all replicas.
    pub fn publish(&self, event: BusEvent) {
        self.bus.publish(event);
    }

    /// A user gained or lost a vault (M5 membership routes): the user's
    /// sockets (un)subscribe and receive `vault_access`.
    pub fn vault_access(&self, user_id: Uuid, vault_id: Uuid, change: AccessChange) {
        self.publish(BusEvent::VaultAccess {
            vault_id,
            user_id: Some(user_id),
            change,
        });
    }

    /// A vault's key was rotated: `vault_access rotated` to all members.
    pub fn vault_rotated(&self, vault_id: Uuid) {
        self.publish(BusEvent::VaultAccess {
            vault_id,
            user_id: None,
            change: AccessChange::Rotated,
        });
    }

    /// Password change / recovery: `account_changed` to the user's other
    /// devices.
    pub fn account_changed(&self, user_id: Uuid, key_version: u32, origin_device: Option<Uuid>) {
        self.publish(BusEvent::AccountChanged {
            user_id,
            key_version,
            origin_device,
        });
    }

    /// A viewer waits on one of `owner`'s shares (M6-01 hook).
    pub fn share_join_request(&self, owner: Uuid, share_id: Uuid, viewer: ShareViewer) {
        self.publish(BusEvent::share_join_request(owner, share_id, viewer));
    }

    /// A device was revoked: its sockets close with 4401.
    pub fn device_revoked(&self, user_id: Uuid, device_id: Uuid) {
        self.publish(BusEvent::DeviceRevoked { user_id, device_id });
    }

    /// An account was disabled: its sockets close with 4401.
    pub fn user_disabled(&self, user_id: Uuid) {
        self.publish(BusEvent::UserDisabled { user_id });
    }
}

/// Push commits → `vault_changed` on the bus.
#[derive(Debug)]
struct BusNotifier(Arc<dyn Bus>);

impl ChangeNotifier for BusNotifier {
    fn vault_changed(&self, vault_id: Uuid, head_revision: u64) {
        self.0.publish(BusEvent::VaultChanged {
            vault_id,
            head_revision,
        });
    }
}

/// `GET /v1/ws` (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new().route(WS_PATH, get(upgrade))
}

async fn upgrade(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(MAX_CLIENT_MESSAGE)
        .max_frame_size(MAX_CLIENT_MESSAGE)
        .on_upgrade(move |socket| serve_socket(state, socket))
}

fn from_axum(msg: Message) -> Frame {
    match msg {
        Message::Text(t) => Frame::Text(t.as_str().to_owned()),
        Message::Close(c) => Frame::Close {
            code: c.as_ref().map_or(1005, |c| c.code),
            reason: c.map(|c| c.reason.as_str().to_owned()).unwrap_or_default(),
        },
        Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => Frame::Other,
    }
}

fn to_axum(frame: Frame) -> Message {
    match frame {
        Frame::Text(t) => Message::Text(t.into()),
        Frame::Close { code, reason } => Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        Frame::Other => Message::Ping(Default::default()),
    }
}

async fn serve_socket(state: AppState, socket: WebSocket) {
    let (sink, stream) = socket.split();
    let incoming = stream.filter_map(|m| std::future::ready(m.ok().map(from_axum)));
    let outgoing = sink.with(|f: Frame| std::future::ready(Ok::<_, axum::Error>(to_axum(f))));
    session::run(state, Box::pin(incoming), Box::pin(outgoing)).await;
}
