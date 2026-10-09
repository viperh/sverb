//! The history seam for snippet runs (SPEC §9.7, §9.10, §4.12).
//!
//! History does not exist yet. Runs report what they typed or executed through
//! [`HistorySink`]; [`record_run`] is the only way snippet code writes to it, and it
//! renders with [`RenderStyle::History`], so a **secret value never reaches the sink**:
//! secret variables stay `{{name}}` placeholders. Nothing here logs values.

use std::sync::Arc;

use super::template::{RenderStyle, Template};
use super::vars::{Builtins, Values};
use crate::model::ItemId;

/// One history entry from a snippet run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRecord {
    /// The command, secrets as `{{name}}`.
    pub command: String,
    /// The target host (`None`: a local pane or an unsaved target).
    pub host_id: Option<ItemId>,
    /// The snippet.
    pub snippet: Option<ItemId>,
}

pub trait HistorySink: Send + Sync {
    /// Save one entry.
    fn record(&self, record: HistoryRecord);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoHistory;

impl HistorySink for NoHistory {
    fn record(&self, _record: HistoryRecord) {}
}

/// A shared sink.
pub type SharedHistory = Arc<dyn HistorySink>;

/// The history text of a run: the template with values, secrets left as placeholders.
pub fn history_command(template: &Template, values: &Values, builtins: &Builtins) -> String {
    template
        .render(values, builtins, RenderStyle::History)
        .unwrap_or_default()
}

/// Record a run of `template` on `host_id`.
pub fn record_run(
    sink: &dyn HistorySink,
    template: &Template,
    values: &Values,
    builtins: &Builtins,
    host_id: Option<ItemId>,
    snippet: Option<ItemId>,
) {
    sink.record(HistoryRecord {
        command: history_command(template, values, builtins),
        host_id,
        snippet,
    });
}
