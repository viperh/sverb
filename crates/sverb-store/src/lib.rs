//! SQLite persistence for the client (rusqlite + migrations), SPEC §5.2.
//!
//! - [`Store`] owns one writer connection (behind a `tokio::sync::Mutex`) and a
//!   pool of 4 read-only connections; every connection runs with WAL,
//!   `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000` and
//!   `temp_store = MEMORY`. The database file and its `-wal`/`-shm` siblings are
//!   mode `0600` on Unix.
//! - Schema migrations live in `crates/sverb-store/migrations/` (the repository's
//!   `migrations/client/` links there) and run transactionally on open. A database
//!   from a newer sverb is refused with [`StoreError::NewerSchema`] and left untouched.
//! - The repository API exists twice: as async one-shot methods on [`Store`], and
//!   as methods on [`WriteTx`] / [`ReadTx`] for combining several operations in one
//!   transaction via [`Store::write`] / [`Store::read`].
//! - **The store only handles ciphertext.** Item bodies arrive as envelopes sealed by
//!   `sverb-crypto` (checked on every write), wrapped keys and tokens arrive already
//!   wrapped. Decrypted data may only go to the optional TEMP `item_index`
//!   ([`index`]), which lives in memory.

// M2-10: the device-local allowlist of locally-acting values (§17.1).
pub mod approvals;
pub mod clock;
pub mod db;
pub mod device_local;
pub mod error;
pub mod index;
pub mod items;
pub mod meta;
pub mod outbox;
// M5-03: TOFU pins of account public keys (§13.3), device-local.
pub mod pins;
pub mod schema;
pub mod sync_state;
pub mod vaults;

pub use approvals::LocalApproval;
pub use clock::{Clock, ManualClock, SystemClock};
pub use db::{READER_POOL_SIZE, ReadTx, Store, WriteTx};
pub use device_local::DeviceLocal;
pub use error::{Result, StoreError};
pub use index::IndexRow;
pub use items::{ItemRow, RemoteItem};
pub use outbox::OutboxRow;
pub use pins::{KeyChange, PinObservation, PinState, PinnedKey, SetVerified};
pub use schema::SCHEMA_VERSION;
pub use sync_state::SyncState;
pub use vaults::{VaultKind, VaultRow};
