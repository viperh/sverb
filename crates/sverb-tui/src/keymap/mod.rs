//! Keys: chords, the action registry, the effective keymap, the leader state machine,
//! which-key, `sverb keys --dump` and the config validator (SPEC §8.2–§8.3).
//!
//! - **Terminal mode** (a live session pane has focus): every key except the leader
//!   goes to the session. There is no Terminal-mode table and no config for one.
//! - The **leader** (`ctrl-\` by default) works in every mode; the key after it is
//!   looked up in the after-leader table (`[keys.terminal]`). Leader twice sends it.
//! - **Normal mode** (sverb views): the Normal table, then the focused view's keys.
//!
//! Input routing itself lives in the reducer (`app/input.rs`).

pub mod action;
pub mod chord;
pub mod dump;
#[allow(clippy::module_inception)]
pub mod keymap;
pub mod leader;
pub mod validate;
pub mod whichkey;

#[cfg(test)]
mod tests;

pub use keymap::{BindingRow, DEFAULT_LEADER, Keymap, Lookup, Source, Table};
pub use validate::{TuiKeymapValidator, validators};
