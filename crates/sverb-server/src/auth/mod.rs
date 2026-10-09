//!
//! * [`opaque`]: the server half of OPAQUE (suite from
//!   `sverb_crypto::opaque`) and the `ServerSetup` stored in
//!   `server_secrets`;
//! * [`tokens`]: access/refresh/reauth tokens (hash-only storage, TTLs);
//! * [`totp`]: the optional second factor;
//! * [`extractor`]: `Authorization: Bearer` → [`AuthCtx`] for handlers
//! * [`store`]: persistence (PostgreSQL, plus an in-memory model for tests);
//! * [`clock`]: injectable time.
//!
//! The routes live in `crate::routes::{auth, account, devices}`.

pub mod clock;
pub mod extractor;
pub mod opaque;
pub mod store;
pub mod tokens;
pub mod totp;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;
use sverb_crypto::opaque::ServerSetup;
use tokio::sync::OnceCell;

pub use clock::{Clock, ManualClock, SystemClock};
pub use extractor::AuthCtx;
pub use store::AuthStore;

use crate::error::ApiError;
use crate::secrets::ServerSecrets;

/// Auth state shared by all handlers (part of `AppState`).
pub struct AuthRuntime {
    store: AuthStore,
    clock: Arc<dyn Clock>,
    setup: OnceCell<Arc<ServerSetup>>,
}

impl std::fmt::Debug for AuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRuntime")
            .field("store", &self.store)
            .field("clock", &self.clock)
            .field("setup_loaded", &self.setup.initialized())
            .finish()
    }
}

impl AuthRuntime {
    /// A runtime on `store` with `clock`.
    #[must_use]
    pub fn new(store: AuthStore, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            setup: OnceCell::new(),
        }
    }

    /// The production runtime: PostgreSQL and the system clock.
    #[must_use]
    pub fn postgres(pool: PgPool) -> Self {
        Self::new(AuthStore::Postgres(pool), Arc::new(SystemClock))
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &AuthStore {
        &self.store
    }

    /// The current time.
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// The OPAQUE `ServerSetup`, loaded from `server_secrets` (or generated
    /// and stored on first use) once per process.
    ///
    /// # Errors
    /// Database errors, or a setup that can't be decrypted or parsed.
    pub async fn server_setup(
        &self,
        secrets: &ServerSecrets,
    ) -> Result<Arc<ServerSetup>, ApiError> {
        self.setup
            .get_or_try_init(|| async {
                opaque::load_or_init(&self.store, secrets)
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }
}
