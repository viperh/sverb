//! The Logs section (SPEC §9.12).
//!
//! - M3-05: [`replay`], the recording player ([`ReplayView`]), built to be embedded by the
//!   Logs view.
//! - M3-06: [`list`], the ConnLog list ([`LogsView`]: newest first, host/result filters,
//!   reconnect, details, replay, export, clear), and [`detail`], the detail pane and the
//!   Logs dialogs.

pub mod replay;

pub use replay::{ReplayOutcome, ReplayView};

// M3-06
pub mod detail;
pub mod list;

pub use detail::{LogsClear, LogsDelete, LogsDialog, LogsExport, ReplayHandle};
pub use list::{LogEntry, LogsRequest, LogsView, ResultFilter};
