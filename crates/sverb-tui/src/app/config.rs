//! The configuration snapshot the reducer and views read.
//!
//! This is the `config.toml` model from `sverb-core` (SPEC §15). The
//! placeholder `Config`/`General`/`Ui` structs that lived here had the same field
//! paths (`general.confirm_quit`, `ui.mouse`), so the swap is only this re-export.

pub use sverb_core::config::{Config, GeneralConfig as General, UiConfig as Ui};
