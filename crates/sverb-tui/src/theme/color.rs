//! Color depth and 256-color downsampling.
//!
//! The implementation lives in [`sverb_term::color`], so the terminal pane uses
//! exactly the same mapping without depending on this crate. Re-exported here for the
//! UI theme.

pub use sverb_term::color::{ColorDepth, ansi256_to_rgb, downsample, rgb_to_ansi256};
