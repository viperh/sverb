//! API DTOs, sync/share wire types (serde), versioned.
//!
//! Shared by the client (`sverb-sync`) and the server (`sverb-server`), so it
//! must stay free of UI, storage and SSH dependencies.

// M4-01: error envelope and protocol-version constants.
pub mod error;
pub mod version;

// M6-02: terminal-share frames and relay payloads (ShareFrame, Hello/Welcome wire forms).
pub mod share_frame;

// M6-01: terminal-share relay DTOs (RelayEnvelope, control messages, close codes).
pub mod share;

// M4-02: auth, account and device DTOs (and the base64url serde helper).
pub mod auth;
pub mod b64;

// M4-04: vault list, pull and push DTOs (shared with the client sync engine).
pub mod sync;

// M4-05: `/v1/ws` notification messages and close codes.
pub mod ws;

// M5-03: user public keys (`GET /v1/users/{id}/public-keys`), pinned by clients (§13.3).
pub mod users;

// M5-01: orgs, members, invites, the audit log.
pub mod orgs;

// M5-02: shared vaults (create, members, grants).
pub mod vaults;

// M5-04: vault key rotation (`POST /v1/vaults/{id}/rotate`).
pub mod rotation;

pub use error::{ErrorBody, ErrorCode, ErrorEnvelope};
