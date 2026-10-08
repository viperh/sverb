//! M1-15: known hosts and host-key verification (SPEC §9.5, §4.7). Pure: no I/O, no
//! clock (callers pass `now`), randomness only for new hashed salts.
//!
//! - [`parse`]: the OpenSSH `known_hosts` text format (`parse_known_hosts`, export).
//!   Shared with the `~/.ssh/known_hosts` importer (M2-11).
//! - [`lookup`](mod@lookup): the lookup key (`host` / `[host]:port`), OpenSSH pattern lists
//!   (`*`, `?`, `!negation`, commas) and the entries that apply to a host.
//! - [`hashed`]: `|1|base64(salt)|base64(HMAC-SHA1(salt, host))` entries.
//! - [`check`](mod@check): what a presented key (plain or host certificate) is against the entries
//!   (revoked > CA-signed cert > known > changed > unknown), and what the policy
//!   (`strict` / `ask` / `accept-new`) makes of it.
//! - [`fingerprint`] and [`randomart`](mod@randomart): `SHA256:…` fingerprints and the OpenSSH
//!   "drunken bishop" picture, byte-identical to `ssh-keygen -lv`.

pub mod check;
pub mod fingerprint;
pub mod hashed;
pub mod lookup;
pub mod parse;
pub mod randomart;

pub use check::{
    CheckResult, KeyInfo, PolicyDecision, PresentedKey, check, decide, new_entry, same_key_type,
};
pub use fingerprint::{fingerprint_sha256, key_blob};
pub use lookup::{KnownKeys, key_types_for, lookup, lookup_key, pattern_list_matches};
pub use parse::{ParseWarning, export, parse_known_hosts, to_line};
pub use randomart::randomart;

#[cfg(test)]
mod tests;
