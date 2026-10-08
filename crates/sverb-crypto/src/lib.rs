//! Key hierarchy, envelopes, HPKE and OPAQUE wrappers (no I/O).
//!
//! This crate performs no I/O of any kind: no files, no sockets, no async
//! runtime. Callers hand it bytes and get bytes back, which keeps it usable
//! from the client, the server and tests alike.
//!
//! Randomness is always injected as a `rand_core::CryptoRng` parameter;
//! production code passes [`random::os_rng()`]. Every byte string fed to an
//! AEAD or KDF is built in [`canon`].

// M1-01: crypto modules (primitives, canonical encodings, item envelopes).
pub mod aead;
pub mod canon;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod pad;
pub mod random;
pub mod recording;
pub mod wrap;

// M4-03: account keys, recovery key, vault-key grants, fingerprints.
pub mod account;
pub mod fingerprint;
pub mod grant;
pub mod hpke;
pub mod recovery;
pub mod sign;

// M4-02: the shared OPAQUE cipher suite and client/server wrappers.
pub mod opaque;

// M6-02: terminal-share join handshake, channel keys, sequenced frames, links.
pub mod share;

pub use error::{CryptoError, Result};
pub use keys::{Key32, Nonce24};
