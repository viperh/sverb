//! Terminal emulator wrapper, key/mouse encoding, recording.
//!
//! Renders into `ratatui-core` buffers but never touches the real terminal:
//! no crossterm here.

pub mod alacritty;
pub mod charset;
// Color depth and 256-color downsampling (shared with the UI theme).
pub mod color;
pub mod emulator;
pub mod modes;
pub mod policy;
// Encrypted session recording (asciicast v2), reader and replay player.
pub mod recording;
// Styled rendering and terminal color schemes.
pub mod render;
pub mod scheme;
// Copy mode's selection model, motions and scrollback search.
pub mod search;
pub mod selection;
// OSC 133 shell integration: command capture and the prompt state.
pub mod osc133;
// Fuzz entry points (cargo-fuzz targets in `fuzz/`, property-tested here).
#[doc(hidden)]
pub mod fuzz;
// Input encoding (keys, mouse, paste). The module is declared in `modes.rs`
// (`src/input/`); this makes it `sverb_term::input` as well.
pub use modes::input;

pub use alacritty::AlacrittyEmulator;
pub use charset::{CharsetCodec, UnknownCharset};
pub use color::ColorDepth;
pub use emulator::{
    ClipboardTarget, ColorScheme, CursorInfo, DEFAULT_SCROLLBACK, Direction, Emulator,
    EmulatorConfig, GridPoint, HyperlinkInfo, Match, PromptMarkKind, Rgb, TermEvent, ViewState,
};
pub use emulator::{OverlayStyle, Selection};
pub use modes::{CursorShape, KittyKeyboardFlags, MouseEncoding, MouseMode, TermModes};
pub use scheme::{SchemeCatalog, SchemeError};
