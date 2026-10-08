//! axum backend (lib + bin).
//!
//! The library holds the server so integration tests can run it in-process;
//! the `sverb-server` binary is a thin entry point around [`cli`].
//!
//! Map (M4-01 skeleton; later tasks add `auth/`, `sync/`, `ws/`, … and
//! routes under [`routes`]):
//! * [`config`]: env + TOML configuration,
//! * [`db`]: pool, embedded migrations, migration status,
//! * [`error`]: `ApiError` → JSON envelope,
//! * [`middleware`]: request IDs, protocol version, client IP, rate limits,
//!   error normalisation,
//! * [`app`]: router and middleware stack,
//! * [`routes`]: `/healthz`, `/readyz`, `/metrics`, `/v1/…`,
//! * [`secrets`]: AEAD-encrypted `server_secrets`,
//! * [`registration`]: registration modes, setup-token bootstrap, policy,
//! * [`auth`]: OPAQUE login, tokens, devices, TOTP (M4-02),
//! * [`sync`]: vaults, pull, push, quota, tombstone GC (M4-04),
//! * [`ws`]: `/v1/ws` notifications and `LISTEN/NOTIFY` fan-out (M4-05),
//! * [`share`]: terminal-share relay, `/v1/shares` (M6-01),
//! * [`admin`]: admin CLI operations, [`cli`]: argument parsing,
//! * [`serve`]: startup checks and listeners.

pub mod admin;
pub mod app;
// M4-02: OPAQUE, tokens, TOTP, the bearer extractor and auth persistence.
pub mod auth;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod healthcheck;
pub mod logging;
pub mod mail;
pub mod metrics;
pub mod middleware;
pub mod registration;
pub mod routes;
pub mod secrets;
pub mod serve;
pub mod settings;
// M6-01: terminal-share relay (/v1/shares).
pub mod share;
pub mod state;
// M4-04: vault list, pull, push, quota and tombstone GC.
pub mod sync;
// M4-05: WebSocket notifications and multi-replica fan-out.
pub mod ws;

pub use config::Config;
pub use error::ApiError;
pub use state::AppState;
