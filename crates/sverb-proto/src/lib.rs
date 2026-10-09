//! API DTOs, sync/share wire types (serde), versioned.
//!
//! Shared by the client (`sverb-sync`) and the server (`sverb-server`), so it
//! must stay free of UI, storage and SSH dependencies.

// Error envelope and protocol-version constants.
pub mod error;
pub mod version;

// Terminal-share frames and relay payloads (ShareFrame, Hello/Welcome wire forms).
pub mod share_frame;

// Terminal-share relay DTOs (RelayEnvelope, control messages, close codes).
pub mod share;

// Auth, account and device DTOs (and the base64url serde helper).
pub mod auth;
pub mod b64;

// Vault list, pull and push DTOs (shared with the client sync engine).
pub mod sync;

// `/v1/ws` notification messages and close codes.
pub mod ws;

// User public keys (`GET /v1/users/{id}/public-keys`), pinned by clients (§13.3).
pub mod users;

// Orgs, members, invites, the audit log.
pub mod orgs;

// Shared vaults (create, members, grants).
pub mod vaults;

// Vault key rotation (`POST /v1/vaults/{id}/rotate`).
pub mod rotation;

pub use error::{ErrorBody, ErrorCode, ErrorEnvelope};
