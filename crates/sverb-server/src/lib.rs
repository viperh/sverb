//! axum backend (lib + bin).
//!
//! The library holds the server so integration tests can run it in-process;
//! the `sverb-server` binary is a thin entry point around [`cli`].
//!
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
//! * [`auth`]: OPAQUE login, tokens, devices, TOTP,
//! * [`sync`]: vaults, pull, push, quota, tombstone GC,
//! * [`ws`]: `/v1/ws` notifications and `LISTEN/NOTIFY` fan-out,
//! * [`share`]: terminal-share relay, `/v1/shares`,
//! * [`orgs`]: orgs, roles, invites and the audit log,
//! * [`admin`]: admin CLI operations, [`cli`]: argument parsing,
//! * [`serve`]: startup checks and listeners.

pub mod admin;
pub mod app;
// OPAQUE, tokens, TOTP, the bearer extractor and auth persistence.
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
// Orgs, roles, invites, the audit log.
pub mod orgs;
pub mod registration;
pub mod routes;
pub mod secrets;
pub mod serve;
pub mod settings;
// Terminal-share relay (/v1/shares).
pub mod share;
pub mod state;
// Vault list, pull, push, quota and tombstone GC.
pub mod sync;
// WebSocket notifications and multi-replica fan-out.
pub mod ws;

pub use config::Config;
pub use error::ApiError;
pub use state::AppState;
