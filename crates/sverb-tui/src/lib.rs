//! ratatui app: views, widgets, keymap, theme.
//!
//! Sync UI is compiled only with the `sync` feature.
//!
//! Architecture (SPEC §2.1, `docs/architecture.md`):
//! `UiEvent → App::handle → Vec<Effect> → Services / runtime loop → UiEvent`.
//! - [`app`]: the pure reducer ([`app::App`], [`app::UiEvent`], [`app::Effect`]),
//! - [`views`]: the [`views::View`] trait and the views it owns,
//! - [`keymap`]: key chords, the global keymap and the action registry,
//! - [`services`]: the effect executor,
//! - [`runtime`]: terminal I/O and the event loop (priorities, dirty-driven
//!   frames, timers, signals; the session backpressure contract is in `runtime::sessions`),
//! - [`theme`]: UI themes, `NO_COLOR` and color depth,
//! - [`widgets`]: shell chrome (top bar, tab bar, status bar, toasts, which-key, log pane),
//! - `testing` (feature `test-util`): `AppHarness` for scripted reducer tests.

pub mod app;
pub mod keymap;
pub mod runtime;
pub mod services;
// Shell, theme, toast and log-pane tests (T-04..T-16).
#[cfg(test)]
mod shell_tests;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod theme;
pub mod views;
pub mod widgets;

pub use app::LaunchIntent;
pub use runtime::{LaunchCtx, run};
