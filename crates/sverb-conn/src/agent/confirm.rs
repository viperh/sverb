//! M2-07: `confirm_on_use` prompts (SPEC §6.1.6): "**<host>** requests a signature
//! with key **<key>** — [a]llow once / [d]eny".
//!
//! [`ConfirmQueue`] is the [`Confirmer`] for a UI: each request gets an id and goes
//! out on a channel ([`AgentConfirmRequest`]); the UI shows a modal and answers with
//! [`ConfirmQueue::answer`]. Requests are asked **one at a time** (concurrent ones
//! queue), and a request without an answer after [`CONFIRM_TIMEOUT`] is denied. A
//! closed UI channel denies at once.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::builtin::{ConfirmRequest, Confirmer};

/// How long a confirm prompt waits before denying.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);

/// A prompt for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfirmRequest {
    /// Answer with this id ([`ConfirmQueue::answer`]).
    pub id: u64,
    /// Who asks, what key.
    pub request: ConfirmRequest,
    /// How long the prompt stays up before it denies.
    pub timeout: Duration,
}

/// Queues `confirm_on_use` prompts for a UI.
#[derive(Debug)]
pub struct ConfirmQueue {
    tx: mpsc::UnboundedSender<AgentConfirmRequest>,
    pending: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    turn: tokio::sync::Mutex<()>,
    next: AtomicU64,
    timeout: Duration,
}

impl ConfirmQueue {
    /// A queue and the receiver of its prompts.
    pub fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<AgentConfirmRequest>) {
        Self::with_timeout(CONFIRM_TIMEOUT)
    }

    /// [`ConfirmQueue::new`] with another timeout (tests).
    pub fn with_timeout(
        timeout: Duration,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<AgentConfirmRequest>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queue = Arc::new(Self {
            tx,
            pending: Mutex::new(HashMap::new()),
            turn: tokio::sync::Mutex::new(()),
            next: AtomicU64::new(1),
            timeout,
        });
        (queue, rx)
    }

    /// The UI's answer for prompt `id` (unknown or late ids are ignored).
    pub fn answer(&self, id: u64, allow: bool) {
        if let Some(reply) = self.pending.lock().remove(&id) {
            let _ = reply.send(allow);
        }
    }

    /// Prompts waiting for an answer (0 or 1: they are asked one at a time).
    pub fn waiting(&self) -> usize {
        self.pending.lock().len()
    }
}

#[async_trait]
impl Confirmer for ConfirmQueue {
    async fn confirm(&self, request: ConfirmRequest) -> bool {
        let _turn = self.turn.lock().await;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = oneshot::channel();
        self.pending.lock().insert(id, reply);
        let prompt = AgentConfirmRequest {
            id,
            request,
            timeout: self.timeout,
        };
        if self.tx.send(prompt).is_err() {
            self.pending.lock().remove(&id);
            debug!("agent confirm: no UI; denied");
            return false;
        }
        let allowed = match tokio::time::timeout(self.timeout, answer).await {
            Ok(Ok(allow)) => allow,
            Ok(Err(_)) => false,
            Err(_) => {
                debug!(id, "agent confirm timed out; denied");
                false
            }
        };
        self.pending.lock().remove(&id);
        allowed
    }
}
