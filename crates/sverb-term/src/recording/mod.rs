//! M3-05: encrypted session recording (SPEC §7.5) and replay (SPEC §9.12).
//!
//! - [`asciicast`]: asciicast v2 header and event lines,
//! - [`writer`]: the `.cast.sv` container (sealed ≤ 64 KiB chunks, last-chunk flag) and the
//!   event → line [`Recorder`](writer::Recorder),
//! - [`tap`]: the never-blocking session tap and the writer task (5 s flush, fsync on close),
//! - [`reader`]: streaming decryption, truncation detection, plain export,
//! - [`player`]: the replay engine (idle cap, speed, checkpointed seeking).
//!
//! Keys come from `sverb_crypto::recording` (`HKDF(LMK, "sverb/recording/v1")`); this
//! module only does the file I/O. Recordings live in `state_dir/recordings/` and never sync.

pub mod asciicast;
pub mod player;
pub mod reader;
pub mod tap;
pub mod writer;

#[cfg(test)]
mod tests;

pub use asciicast::{Event, EventKind, Header};
pub use player::{Player, Speed};
pub use reader::{Recording, RecordingError, export_plain, read_recording};
pub use tap::{
    RecorderHandle, RecorderOptions, RecordingSummary, RecordingTap, SyncWrite,
    create_recording_file, recording_file_name, spawn_recorder,
};
pub use writer::RecorderMeta;
