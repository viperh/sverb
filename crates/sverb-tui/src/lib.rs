//! ratatui app: views, widgets, keymap, theme.
//!
//! Sync UI is compiled only with the `sync` feature.
//!
//! Architecture (M0-08, SPEC §2.1, `docs/architecture.md`):
//! `UiEvent → App::handle → Vec<Effect> → Services / runtime loop → UiEvent`.
//! - [`app`]: the pure reducer ([`app::App`], [`app::UiEvent`], [`app::Effect`]),
//! - [`views`]: the [`views::View`] trait and the views it owns,
//! - [`keymap`]: key chords, the global keymap and the action registry,
//! - [`services`]: the effect executor,
//! - [`runtime`]: terminal I/O and the event loop (M0-09: priorities, dirty-driven
//!   frames, timers, signals; the session backpressure contract is in `runtime::sessions`),
//! - [`theme`] (M0-11): UI themes, `NO_COLOR` and color depth,
//! - [`widgets`] (M0-11): shell chrome (top bar, tab bar, status bar, toasts, which-key, log pane),
//! - `testing` (feature `test-util`): `AppHarness` for scripted reducer tests.

pub mod app;
pub mod keymap;
pub mod runtime;
pub mod services;
// M0-11: shell, theme, toast and log-pane tests (T-04..T-16).
#[cfg(test)]
mod shell_tests;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
// M0-11
pub mod theme;
pub mod views;
// M0-11
pub mod widgets;

pub use app::LaunchIntent;
pub use runtime::{LaunchCtx, run};
