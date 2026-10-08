//! The in-process hub: topic → local sockets.
//!
//! Each socket [`Hub::register`]s once and gets a bounded queue; it then
//! (un)subscribes to [`Topic`]s, live (a grant or revocation changes the
//! subscription set of an open socket). [`Hub::dispatch`] maps a
//! [`BusEvent`] to a topic and enqueues a [`HubMsg`] for every subscriber.
//!
//! Queues are bounded and `try_send` drops on overflow: notifications are
//! hints, and a socket that can't keep up still converges by pull (the
//! session also revalidates its token on every heartbeat, so even a dropped
//! revocation takes effect within one ping interval).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use sverb_proto::ws::{AccessChange, ServerMsg};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::bus::BusEvent;

/// Messages queued per socket before new ones are dropped.
pub const SESSION_QUEUE: usize = 256;

/// What a socket can subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Topic {
    /// A vault the user is a member of.
    Vault(Uuid),
    /// Account-level events of a user (and their share join requests).
    User(Uuid),
}

/// What the hub hands a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubMsg {
    /// Forward as is.
    Notify(ServerMsg),
    /// The socket's user gained or lost a vault: update subscriptions, then
    /// forward as `vault_access`.
    Access {
        /// Vault.
        vault_id: Uuid,
        /// Change.
        change: AccessChange,
    },
    /// Forward as `account_changed` unless the socket is `origin_device`.
    AccountChanged {
        /// New key version.
        key_version: u32,
        /// The device that changed it.
        origin_device: Option<Uuid>,
    },
    /// Close with 4401 if the socket is that device.
    DeviceRevoked {
        /// Device.
        device_id: Uuid,
    },
    /// Close with 4401.
    UserDisabled,
}

#[derive(Debug, Default)]
struct Inner {
    next_id: u64,
    queues: HashMap<u64, mpsc::Sender<HubMsg>>,
    topics: HashMap<Topic, HashSet<u64>>,
    subs: HashMap<u64, HashSet<Topic>>,
}

/// The per-replica hub.
#[derive(Debug, Default)]
pub struct Hub {
    inner: Mutex<Inner>,
}

impl Hub {
    /// A new hub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a socket; dropping the [`Subscription`] unregisters it.
    #[must_use]
    pub fn register(self: &Arc<Self>) -> Subscription {
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.queues.insert(id, tx);
        inner.subs.insert(id, HashSet::new());
        drop(inner);
        Subscription {
            id,
            hub: self.clone(),
            rx,
        }
    }

    /// Local sockets subscribed to `topic`.
    #[must_use]
    pub fn subscribers(&self, topic: Topic) -> usize {
        self.lock().topics.get(&topic).map_or(0, HashSet::len)
    }

    /// Registered local sockets.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.lock().queues.len()
    }

    fn subscribe(&self, id: u64, topic: Topic) {
        let mut inner = self.lock();
        inner.topics.entry(topic).or_default().insert(id);
        inner.subs.entry(id).or_default().insert(topic);
    }

    fn unsubscribe(&self, id: u64, topic: Topic) {
        let mut inner = self.lock();
        if let Some(set) = inner.topics.get_mut(&topic) {
            set.remove(&id);
            if set.is_empty() {
                inner.topics.remove(&topic);
            }
        }
        if let Some(set) = inner.subs.get_mut(&id) {
            set.remove(&topic);
        }
    }

    fn remove(&self, id: u64) {
        let mut inner = self.lock();
        inner.queues.remove(&id);
        for topic in inner.subs.remove(&id).unwrap_or_default() {
            if let Some(set) = inner.topics.get_mut(&topic) {
                set.remove(&id);
                if set.is_empty() {
                    inner.topics.remove(&topic);
                }
            }
        }
    }

    fn send(&self, topic: Topic, msg: &HubMsg) {
        let inner = self.lock();
        let Some(ids) = inner.topics.get(&topic) else {
            return;
        };
        for id in ids {
            if let Some(q) = inner.queues.get(id)
                && q.try_send(msg.clone()).is_err()
            {
                tracing::debug!(session = id, "ws queue full; notification dropped");
            }
        }
    }

    /// Delivers a bus event to the local subscribers of its topic.
    pub fn dispatch(&self, event: &BusEvent) {
        match event {
            BusEvent::VaultChanged {
                vault_id,
                head_revision,
            } => self.send(
                Topic::Vault(*vault_id),
                &HubMsg::Notify(ServerMsg::VaultChanged {
                    vault_id: *vault_id,
                    head_revision: *head_revision,
                }),
            ),
            BusEvent::VaultAccess {
                vault_id,
                user_id: Some(user_id),
                change,
            } => self.send(
                Topic::User(*user_id),
                &HubMsg::Access {
                    vault_id: *vault_id,
                    change: *change,
                },
            ),
            BusEvent::VaultAccess {
                vault_id,
                user_id: None,
                change,
            } => self.send(
                Topic::Vault(*vault_id),
                &HubMsg::Notify(ServerMsg::VaultAccess {
                    vault_id: *vault_id,
                    change: *change,
                }),
            ),
            BusEvent::AccountChanged {
                user_id,
                key_version,
                origin_device,
            } => self.send(
                Topic::User(*user_id),
                &HubMsg::AccountChanged {
                    key_version: *key_version,
                    origin_device: *origin_device,
                },
            ),
            BusEvent::ShareJoinRequest {
                owner_user_id,
                share_id,
                viewer,
            } => self.send(
                Topic::User(*owner_user_id),
                &HubMsg::Notify(ServerMsg::ShareJoinRequest {
                    share_id: *share_id,
                    viewer: viewer.clone(),
                }),
            ),
            BusEvent::DeviceRevoked { user_id, device_id } => self.send(
                Topic::User(*user_id),
                &HubMsg::DeviceRevoked {
                    device_id: *device_id,
                },
            ),
            BusEvent::UserDisabled { user_id } => {
                self.send(Topic::User(*user_id), &HubMsg::UserDisabled);
            }
        }
    }
}

/// One socket's registration (unregisters on drop).
#[derive(Debug)]
pub struct Subscription {
    id: u64,
    hub: Arc<Hub>,
    rx: mpsc::Receiver<HubMsg>,
}

impl Subscription {
    /// Starts receiving `topic`.
    pub fn subscribe(&self, topic: Topic) {
        self.hub.subscribe(self.id, topic);
    }

    /// Stops receiving `topic`.
    pub fn unsubscribe(&self, topic: Topic) {
        self.hub.unsubscribe(self.id, topic);
    }

    /// The next message (never `None` while the hub lives).
    pub async fn recv(&mut self) -> Option<HubMsg> {
        self.rx.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn routes_by_topic_and_cleans_up() {
        let hub = Arc::new(Hub::new());
        let v = Uuid::now_v7();
        let mut a = hub.register();
        let b = hub.register();
        a.subscribe(Topic::Vault(v));
        assert_eq!(hub.subscribers(Topic::Vault(v)), 1);
        hub.dispatch(&BusEvent::VaultChanged {
            vault_id: v,
            head_revision: 4,
        });
        assert_eq!(
            a.recv().await.unwrap(),
            HubMsg::Notify(ServerMsg::VaultChanged {
                vault_id: v,
                head_revision: 4
            })
        );
        a.unsubscribe(Topic::Vault(v));
        assert_eq!(hub.subscribers(Topic::Vault(v)), 0);
        b.subscribe(Topic::Vault(v));
        drop(b);
        assert_eq!(hub.subscribers(Topic::Vault(v)), 0);
        assert_eq!(hub.sessions(), 1);
    }

    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        let hub = Arc::new(Hub::new());
        let v = Uuid::now_v7();
        let mut a = hub.register();
        a.subscribe(Topic::Vault(v));
        for i in 0..(SESSION_QUEUE as u64 + 10) {
            hub.dispatch(&BusEvent::VaultChanged {
                vault_id: v,
                head_revision: i,
            });
        }
        let mut n = 0;
        while let Ok(_m) = a.rx.try_recv() {
            n += 1;
        }
        assert_eq!(n, SESSION_QUEUE);
    }
}
