//! Shared application state handed to every handler.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx_postgres::PgPool;

// M4-02: auth runtime (store, clock, OPAQUE setup).
use crate::auth::AuthRuntime;
use crate::config::Config;
use crate::middleware::rate_limit::RateLimiters;
use crate::secrets::ServerSecrets;
// M6-01
use crate::share::ShareRuntime;
// M4-04
use crate::sync::SyncRuntime;
// M4-05
use crate::ws::{Bus, WsRuntime, WsTiming};

/// Components that can mark the server "not ready" without being fatal
/// (e.g. the LISTEN/NOTIFY listener reconnecting, M4-05).
#[derive(Debug, Default)]
pub struct Readiness {
    degraded: Mutex<BTreeSet<&'static str>>,
}

impl Readiness {
    /// Marks `component` degraded (`true`) or healthy (`false`).
    pub fn set_degraded(&self, component: &'static str, degraded: bool) {
        if let Ok(mut set) = self.degraded.lock() {
            if degraded {
                set.insert(component);
            } else {
                set.remove(component);
            }
        }
    }

    /// The currently degraded components.
    #[must_use]
    pub fn degraded(&self) -> Vec<&'static str> {
        self.degraded
            .lock()
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
struct Inner {
    config: Config,
    db: PgPool,
    secrets: ServerSecrets,
    rate_limits: Arc<RateLimiters>,
    metrics: PrometheusHandle,
    readiness: Readiness,
    // M4-02
    auth: AuthRuntime,
    // M4-04
    sync: SyncRuntime,
    // M4-05
    ws: WsRuntime,
    // M6-01
    shares: ShareRuntime,
    // M5-01
    orgs: crate::orgs::OrgStore,
    mailer: std::sync::RwLock<crate::mail::Mailer>,
}

/// Cheaply clonable state (`Arc` inside).
#[derive(Debug, Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    /// Builds the state; derives the `server_secrets` key from the config.
    #[must_use]
    pub fn new(config: Config, db: PgPool) -> Self {
        Self::with_rate_limits(config, db, RateLimiters::default())
    }

    /// Like [`Self::new`] with custom rate limiters.
    #[must_use]
    pub fn with_rate_limits(config: Config, db: PgPool, rate_limits: RateLimiters) -> Self {
        let auth = AuthRuntime::postgres(db.clone());
        Self::with_auth(config, db, rate_limits, auth)
    }

    /// M4-02: like [`Self::with_rate_limits`] with a custom auth runtime
    /// (tests: the in-memory store and a manual clock).
    #[must_use]
    pub fn with_auth(
        config: Config,
        db: PgPool,
        rate_limits: RateLimiters,
        auth: AuthRuntime,
    ) -> Self {
        // M4-05: LISTEN/NOTIFY on PostgreSQL, in-process for the memory model.
        let bus = WsRuntime::bus_for_auth(auth.store());
        Self::with_bus(config, db, rate_limits, auth, bus)
    }

    /// M4-05: like [`Self::with_auth`] on an explicit fan-out bus (tests:
    /// several states sharing one [`crate::ws::LocalBus`] are several
    /// replicas sharing one database).
    #[must_use]
    pub fn with_bus(
        config: Config,
        db: PgPool,
        rate_limits: RateLimiters,
        auth: AuthRuntime,
        bus: Arc<dyn Bus>,
    ) -> Self {
        let secrets = ServerSecrets::new(&config.server_secret);
        // M4-04: sync runs on the same backend as auth.
        let sync = SyncRuntime::for_auth(&auth, &config);
        // M4-05: push commits publish `vault_changed` on the bus.
        let ws = WsRuntime::new(bus, WsTiming::default());
        sync.set_notifier(ws.notifier());
        // M6-01: share sessions on the same backend as auth.
        let shares = ShareRuntime::for_auth(&auth, &config);
        // M5-01: orgs on the same backend as auth; invite mail when SMTP is set.
        let orgs = crate::orgs::OrgStore::for_auth(auth.store());
        let mailer = std::sync::RwLock::new(crate::mail::Mailer::from_config(config.smtp.as_ref()));
        Self(Arc::new(Inner {
            config,
            db,
            secrets,
            rate_limits: Arc::new(rate_limits),
            metrics: crate::metrics::handle(),
            readiness: Readiness::default(),
            auth,
            sync,
            ws,
            shares,
            orgs,
            mailer,
        }))
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The database pool.
    #[must_use]
    pub fn db(&self) -> &PgPool {
        &self.0.db
    }

    /// The `server_secrets` helper.
    #[must_use]
    pub fn secrets(&self) -> &ServerSecrets {
        &self.0.secrets
    }

    /// The rate limiters.
    #[must_use]
    pub fn rate_limits(&self) -> &Arc<RateLimiters> {
        &self.0.rate_limits
    }

    /// The Prometheus handle.
    #[must_use]
    pub fn metrics(&self) -> &PrometheusHandle {
        &self.0.metrics
    }

    /// M4-02: authentication state (store, clock, OPAQUE setup).
    #[must_use]
    pub fn auth(&self) -> &AuthRuntime {
        &self.0.auth
    }

    /// M4-04: sync state (store, limits, change notifier).
    #[must_use]
    pub fn sync(&self) -> &SyncRuntime {
        &self.0.sync
    }

    /// M4-05: WebSocket hub and fan-out bus.
    #[must_use]
    pub fn ws(&self) -> &WsRuntime {
        &self.0.ws
    }

    /// M6-01: share sessions and this replica's relays.
    #[must_use]
    pub fn shares(&self) -> &ShareRuntime {
        &self.0.shares
    }

    /// M5-01: orgs, members, invites, the audit log.
    #[must_use]
    pub fn orgs(&self) -> &crate::orgs::OrgStore {
        &self.0.orgs
    }

    /// M5-01: the invite mailer.
    #[must_use]
    pub fn mailer(&self) -> crate::mail::Mailer {
        self.0.mailer.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// M5-01: replaces the mailer (tests: [`crate::mail::Mailer::Recording`]).
    pub fn set_mailer(&self, mailer: crate::mail::Mailer) {
        if let Ok(mut m) = self.0.mailer.write() {
            *m = mailer;
        }
    }

    /// Non-fatal readiness flags.
    #[must_use]
    pub fn readiness(&self) -> &Readiness {
        &self.0.readiness
    }
}
