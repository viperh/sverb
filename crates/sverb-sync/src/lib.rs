//! Client sync engine (HTTP + WS).
//!
//! Optional: the `sverb` binary only links it with the `sync` feature, so a
//! local-only build (`--no-default-features`) contains no sync code.

// M4-05: the `/v1/ws` notification client (reconnect, heartbeat, 4401 → refresh).
pub mod ws;

// M5-03: TOFU pins, safety numbers and grant-signature verification (§13.3).
pub mod trust;

// M4-07: the engine: HTTP client, token manager, push, pull, full resync, status.
pub mod engine;
pub mod error;
pub mod http;
pub mod keys;
mod pull;
mod push;
mod resync;
pub mod status;
pub mod tokens;

// M4-08: account flows (register, login, password change, recovery, logout).
pub mod account;

pub use engine::{
    EngineConfig, MAX_CONFLICT_ROUNDS, SharedHlc, SyncEngine, SyncHandle, SyncPolicy, shared_hlc,
};
pub use error::SyncError;
pub use http::ApiClient;
pub use keys::{NoKeySource, VaultKeySource, VaultKeys};
pub use status::{SyncEvent, SyncStatus, ToastLevel};
pub use tokens::TokenManager;
