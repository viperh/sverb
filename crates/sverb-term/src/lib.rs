//! Terminal emulator wrapper, key/mouse encoding, recording.
//!
//! Renders into `ratatui-core` buffers but never touches the real terminal:
//! no crossterm here.

pub mod alacritty;
pub mod charset;
// M0-11: color depth and 256-color downsampling (shared with the UI theme).
pub mod color;
pub mod emulator;
pub mod modes;
pub mod policy;
// M3-05: encrypted session recording (asciicast v2), reader and replay player.
pub mod recording;
// M1-10: styled rendering and terminal color schemes.
pub mod render;
pub mod scheme;
// M3-04: copy mode's selection model, motions and scrollback search.
pub mod search;
pub mod selection;
// M7-01: OSC 133 shell integration: command capture and the prompt state.
pub mod osc133;
// M7-05: fuzz entry points (cargo-fuzz targets in `fuzz/`, property-tested here).
#[doc(hidden)]
pub mod fuzz;
// M1-11: input encoding (keys, mouse, paste). The module is declared in `modes.rs`
// (`src/input/`); this makes it `sverb_term::input` as well.
pub use modes::input;

pub use alacritty::AlacrittyEmulator;
pub use charset::{CharsetCodec, UnknownCharset};
pub use emulator::{
    ClipboardTarget, ColorScheme, CursorInfo, DEFAULT_SCROLLBACK, Direction, Emulator,
    EmulatorConfig, GridPoint, HyperlinkInfo, Match, PromptMarkKind, Rgb, TermEvent, ViewState,
};
// M1-10
pub use color::ColorDepth;
pub use emulator::{OverlayStyle, Selection};
pub use modes::{CursorShape, KittyKeyboardFlags, MouseEncoding, MouseMode, TermModes};
pub use scheme::{SchemeCatalog, SchemeError};
