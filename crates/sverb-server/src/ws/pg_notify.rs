//! Multi-replica fan-out over PostgreSQL `LISTEN/NOTIFY` (SPEC §10.7).
//!
//! * publish: `SELECT pg_notify('sverb_events', '<json>')` on the pool,
//!   after the commit that caused it (or inside the transaction, see
//!   [`notify_in`], where PostgreSQL delivers it at commit);
//! * receive: one dedicated `LISTEN sverb_events` connection per replica
//!   feeds a broadcast channel that the replica's hub drains. The listener
//!   reconnects with exponential backoff; while it is down, readiness is
//!   degraded (`ws_listener`) and events are missed, which is harmless
//!   because notifications are hints (clients still poll, §12.5).

use std::sync::OnceLock;
use std::time::Duration;

use sqlx_core::query::query;
use sqlx_postgres::{PgConnection, PgListener, PgPool};
use tokio::sync::broadcast;

use super::bus::{BUS_CAPACITY, Bus, BusEvent, CHANNEL, StatusSink};

/// First reconnect delay of the listener.
const RECONNECT_MIN: Duration = Duration::from_millis(500);
/// Largest reconnect delay of the listener.
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// The PostgreSQL bus.
#[derive(Debug)]
pub struct PgBus {
    pool: PgPool,
    tx: broadcast::Sender<BusEvent>,
    listener: OnceLock<()>,
}

impl PgBus {
    /// A bus on `pool` (the listener starts on the first
    /// [`Bus::subscribe`]).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            tx: broadcast::channel(BUS_CAPACITY).0,
            listener: OnceLock::new(),
        }
    }
}

/// Sends `event` with `pg_notify` on `conn` (inside a transaction it is
/// delivered at commit, and not at all on rollback). Used by the admin CLI,
/// which runs in its own process.
///
/// # Errors
/// Database errors.
pub async fn notify_in(conn: &mut PgConnection, event: &BusEvent) -> Result<(), sqlx_core::Error> {
    let Some(payload) = event.to_payload() else {
        tracing::warn!(?event, "bus event too large; dropped");
        return Ok(());
    };
    query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(payload)
        .execute(conn)
        .await?;
    Ok(())
}

impl Bus for PgBus {
    fn publish(&self, event: BusEvent) {
        let Some(payload) = event.to_payload() else {
            tracing::warn!(?event, "bus event too large; dropped");
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("bus publish outside a runtime; dropped");
            return;
        };
        let pool = self.pool.clone();
        rt.spawn(async move {
            if let Err(e) = query("SELECT pg_notify($1, $2)")
                .bind(CHANNEL)
                .bind(payload)
                .execute(&pool)
                .await
            {
                tracing::warn!(error = %e, "NOTIFY failed; notification dropped");
            }
        });
    }

    fn subscribe(&self, status: StatusSink) -> broadcast::Receiver<BusEvent> {
        let rx = self.tx.subscribe();
        if self.listener.set(()).is_ok() {
            status(false);
            tokio::spawn(listen_loop(self.pool.clone(), self.tx.clone(), status));
        }
        rx
    }
}

async fn connect(pool: &PgPool) -> Result<PgListener, sqlx_core::Error> {
    let mut l = PgListener::connect_with(pool).await?;
    l.listen(CHANNEL).await?;
    Ok(l)
}

/// The listener: (re)connect with backoff, forward every notification.
async fn listen_loop(pool: PgPool, tx: broadcast::Sender<BusEvent>, status: StatusSink) {
    let mut delay = RECONNECT_MIN;
    loop {
        match connect(&pool).await {
            Ok(mut listener) => {
                tracing::info!(channel = CHANNEL, "LISTEN connected");
                status(true);
                delay = RECONNECT_MIN;
                loop {
                    match listener.try_recv().await {
                        Ok(Some(n)) => match BusEvent::from_payload(n.payload()) {
                            Some(ev) => {
                                let _ = tx.send(ev);
                            }
                            None => tracing::debug!("unknown sverb_events payload ignored"),
                        },
                        Ok(None) => {
                            tracing::warn!("LISTEN connection lost");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "LISTEN failed");
                            break;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, retry_in = ?delay, "LISTEN connect failed"),
        }
        status(false);
        if pool.is_closed() {
            return;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RECONNECT_MAX);
    }
}
