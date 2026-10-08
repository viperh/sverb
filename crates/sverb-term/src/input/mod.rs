//! M1-11: input encoding (SPEC §7.3): keys, mouse and paste → bytes for the remote.
//!
//! Everything here is pure: a function of the input and the pane's [`TermModes`], so the
//! session actor encodes **per pane** with its own emulator's modes (SPEC §9.8: broadcast
//! targets each encode the same key with their own DECCKM, keypad and kitty state).
//!
//! sverb-term never sees crossterm or the UI's `KeyChord`: the UI converts its chords to
//! [`KeyInput`] at the boundary.
//!
//! [`TermModes`]: crate::TermModes

pub mod keys;
pub mod mouse;
pub mod paste;

pub use keys::{BackspaceMode, EncodeOpts, Key, KeyInput, KeyMods, KeypadKey, encode_key};
pub use mouse::{
    MouseAction, MouseButton, MouseInput, MouseRoute, WHEEL_LINES, encode_mouse, route_mouse,
};
pub use paste::{
    PASTE_END, PASTE_START, PastePreview, encode_paste, needs_confirmation, normalize_newlines,
    preview, strip_paste_markers,
};
