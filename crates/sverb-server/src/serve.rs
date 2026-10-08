//! `sverb-server serve`: startup checks, listeners, graceful shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use sqlx_postgres::PgPool;

use crate::config::{Config, ConfigError};
use crate::db::{self, MigrationStatus};
use crate::registration;
use crate::secrets::SecretsError;
use crate::state::AppState;

/// Grace period for in-flight requests on shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Reasons the server refuses to start.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// Invalid configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Database unreachable or failing.
    #[error("database error: {0}")]
    Db(#[from] sqlx_core::Error),
    /// Migration failure.
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx_core::migrate::MigrateError),
    /// Pending migrations without `--migrate`.
    #[error(
        "the database has pending migrations {0:?}; run `sverb-server migrate` (after a backup) \
         or start with `sverb-server serve --migrate`"
    )]
    PendingMigrations(Vec<i64>),
    /// The schema is in a state this binary must not touch.
    #[error("database schema mismatch: {0}")]
    SchemaMismatch(String),
    /// Wrong `SVERB_SERVER_SECRET` (or another `server_secrets` failure).
    #[error(transparent)]
    Secrets(#[from] SecretsError),
    /// M4-02: the OPAQUE server setup can't be loaded or created.
    #[error("cannot load the OPAQUE server setup: {0}")]
    OpaqueSetup(String),
    /// TLS setup failed.
    #[error("TLS configuration error: {0}")]
    Tls(std::io::Error),
    /// Binding or serving failed.
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        /// The address.
        addr: SocketAddr,
        /// The I/O error.
        source: std::io::Error,
    },
}

/// Connects, checks or applies migrations, verifies `server_secrets` and
/// runs the setup-token bootstrap. Returns the ready state.
///
/// # Errors
/// [`StartupError`].
pub async fn prepare(config: Config, apply_migrations: bool) -> Result<AppState, StartupError> {
    let pool = db::connect(config.require_database_url()?).await?;
    prepare_with_pool(config, pool, apply_migrations).await
}

/// [`prepare`] on an existing pool (used by tests).
///
/// # Errors
/// [`StartupError`].
pub async fn prepare_with_pool(
    config: Config,
    pool: PgPool,
    apply_migrations: bool,
) -> Result<AppState, StartupError> {
    match db::migration_status(&pool).await? {
        MigrationStatus::Current => {}
        MigrationStatus::Pending(versions) => {
            if !apply_migrations {
                return Err(StartupError::PendingMigrations(versions));
            }
            tracing::info!(?versions, "applying migrations");
            db::migrate(&pool).await?;
        }
        MigrationStatus::Mismatch(reason) => return Err(StartupError::SchemaMismatch(reason)),
    }
    let state = AppState::new(config, pool);
    state.secrets().verify_or_init(state.db()).await?;
    // M4-02: load (or generate on first start) the OPAQUE ServerSetup now,
    // so a broken secret or database fails the start, not the first login.
    if let Err(e) = state.auth().server_setup(state.secrets()).await {
        let detail = match &e {
            crate::error::ApiError::Internal(cause) => cause.to_string(),
            other => other.to_string(),
        };
        return Err(StartupError::OpaqueSetup(detail));
    }
    if let Some(token) = registration::bootstrap(state.db()).await? {
        registration::log_setup_token(&token, &state.config().public_url);
    }
    Ok(state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown requested");
}

/// Runs the server until SIGINT/SIGTERM.
///
/// # Errors
/// [`StartupError`].
pub async fn run(config: Config, apply_migrations: bool) -> Result<(), StartupError> {
    // rustls 0.23 needs a process-wide provider; `ring` is the only one built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = prepare(config, apply_migrations).await?;
    let config = state.config().clone();

    let _cleanup = state.rate_limits().clone().spawn_cleanup();
    let _upkeep = crate::metrics::spawn_upkeep(state.metrics().clone());
    // M4-04: periodic GC (tokens, invites, shares, tombstones).
    let _gc = crate::sync::gc::spawn_background(state.clone());
    // M4-05: LISTEN for fan-out from the start (readiness reflects it).
    state.ws().ensure_started(&state);

    if let Some(addr) = config.metrics_bind {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| StartupError::Listen { addr, source })?;
        let app = crate::routes::ops::metrics_router(state.clone());
        tracing::info!(%addr, "metrics listener started");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "metrics listener failed");
            }
        });
    } else if config.metrics_token.is_none() {
        tracing::warn!(
            "/metrics is disabled: set SVERB_METRICS_TOKEN or SVERB_METRICS_BIND to expose it"
        );
    }

    let app = crate::app::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let addr = config.bind;

    match &config.tls {
        Some(tls) => {
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert, &tls.key)
                    .await
                    .map_err(StartupError::Tls)?;
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                h.graceful_shutdown(Some(SHUTDOWN_GRACE));
            });
            tracing::info!(%addr, public_url = %config.public_url, tls = true, "sverb-server listening");
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app)
                .await
                .map_err(|source| StartupError::Listen { addr, source })?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|source| StartupError::Listen { addr, source })?;
            tracing::info!(%addr, public_url = %config.public_url, tls = false, "sverb-server listening");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(|source| StartupError::Listen { addr, source })?;
        }
    }
    tracing::info!("sverb-server stopped");
    Ok(())
}
