//! Color depth and 256-color downsampling (M0-11).
//!
//! The implementation lives in [`sverb_term::color`], so the terminal pane (M1-10) uses
//! exactly the same mapping without depending on this crate. Re-exported here for the
//! UI theme.

pub use sverb_term::color::{ColorDepth, ansi256_to_rgb, downsample, rgb_to_ansi256};
