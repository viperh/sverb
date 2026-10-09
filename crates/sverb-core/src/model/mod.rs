//! The synced data model (SPEC §4): field-stamped [`ItemBody`]s, the HLC that stamps
//! them, typed views per [`ItemKind`], validation and schema migrations.
//!
//! - Every write goes through [`ItemBody::set`] and is HLC-stamped; writing an
//!   unchanged value creates no stamp.
//! - Nested structs are flattened to dotted keys (`proxy.addr`, `defaults.port`).
//! - Typed views ([`Host`], [`Group`], …) are built with `TryFrom<&ItemBody>` and
//!   written back with `apply_to`, which only touches fields that changed and never
//!   drops keys the view doesn't know (§4.1).
//! - [`ItemBody::to_cbor`] gives the deterministic bytes that
//!   `sverb_crypto::envelope::seal_item` encrypts.
//!
//! Field names, CBOR shapes and enum strings are documented in `docs/data-model.md`.
//! Merging (§12.4) lives in `merge.rs`.

mod body;
pub(crate) mod fields;
mod hlc;
mod host;
mod ids;
mod items;
mod kinds;
// Field-level merge (§12.4).
pub mod merge;
pub mod migrate;
pub mod validate;
// Group tree helpers, tag palette and tag rules (§4.3, §4.11, §9.2).
pub mod group;
pub mod tag;
// Identity usage counts, vault scoping, convert-to-inline (§4.4, §9.3).
pub mod identity;
// The typed form of a saved workspace (tabs, layout leaves, broadcast sets).
pub mod workspace;
// Per-user credential overrides and cross-vault reference rules (§13.4).
mod credential_override;
pub mod vault_refs;

#[cfg(test)]
mod tests;

pub use body::{BodyCodecError, ItemBody, SECRET_FIELDS, Stamped, is_secret_field};
pub use credential_override::CredentialOverride;
pub use fields::{ViewError, WireEnum};
pub use hlc::{ClockSkew, Hlc, HlcClock, MAX_SKEW, ManualClock, PhysicalClock, SystemClock};
pub use host::ExplicitEmpty;
pub use host::resolve_record_sessions;
pub use host::{
    AgentSource, AlgoOverrides, Backspace, DEFAULT_SSH_PORT, GROUP_DEFAULTS_PREFIX, Group, Host,
    HostDefaults, Proxy, ProxyAuth,
};
pub use ids::{
    ConnId, DeviceId, IdGen, IdParseError, ItemId, OrgId, SeqGen, SessionId, UserId, V7Gen, VaultId,
};
pub use items::{
    Certificate, ConnLog, ConnResult, DEFAULT_BIND_ADDR, ForwardKind, HistoryEntry, Identity, Key,
    KeyAlgorithm, KnownHost, KnownHostMarker, PortForward, RunMode, Snippet, Tag, UnixMillis,
    VarDef, Workspace,
};
pub use kinds::ItemKind;
pub use merge::{MergeOutcome, SchemaOutcome, merge, merge_all};
pub use migrate::{CURRENT_SCHEMA, MigrateOutcome, current_schema, migrate};
pub use validate::ValidationError;
