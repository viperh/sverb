//! Command history and autocomplete (SPEC §9.10, §4.12 `HistoryEntry`, §15
//! `[history]`). UI-agnostic pieces:
//!
//! - [`prompt_learn`]: learning the prompt prefix for the heuristic tier,
//! - [`capture`]: the heuristic (tier 2) capture and its secret-prompt guard,
//! - [`mod@suggest`]: suggestion sources (host / global history, snippets, common commands)
//!   and ranking,
//! - [`mod@static_commands`]: the shipped set of common commands,
//! - [`trim_to_cap`]: the per-host cap (`history.max_entries_per_host`, oldest first).
//!
//! Tier 1 (OSC 133 shell integration) lives in `sverb_term::osc133`; the shell hooks and
//! the install snippet in [`crate::snippet::builtin::shell_integration`].

pub mod capture;
pub mod prompt_learn;
pub mod static_commands;
pub mod suggest;

#[cfg(test)]
mod tests;

use crate::model::{HistoryEntry, ItemId};

pub use capture::{CaptureContext, clean_command, heuristic_capture, is_secret_prompt};
pub use prompt_learn::{PromptLearner, PromptPattern};
pub use static_commands::static_commands;
pub use suggest::{
    SnippetSource, Source, SuggestRequest, Suggestion, ghost_suggestion, remainder, suggest,
};

/// A stored history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    /// The item.
    pub id: ItemId,
    /// Its value.
    pub entry: HistoryEntry,
}

/// The entries of `host` beyond its newest `max` (the oldest ones, to tombstone). The
/// input order does not matter. `max = 0` keeps none.
pub fn trim_to_cap(entries: &[StoredEntry], host: Option<ItemId>, max: u32) -> Vec<ItemId> {
    let mut own: Vec<&StoredEntry> = entries.iter().filter(|e| e.entry.host_id == host).collect();
    let keep = usize::try_from(max).unwrap_or(usize::MAX);
    if own.len() <= keep {
        return Vec::new();
    }
    // Newest first; ties broken by id (UUIDv7 ids are time-ordered).
    own.sort_by(|a, b| {
        b.entry
            .executed_at
            .cmp(&a.entry.executed_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    own.into_iter().skip(keep).map(|e| e.id).collect()
}

/// The ids of every entry of `host` (purge "Clear history").
pub fn entries_of(entries: &[StoredEntry], host: Option<ItemId>) -> Vec<ItemId> {
    entries
        .iter()
        .filter(|e| e.entry.host_id == host)
        .map(|e| e.id)
        .collect()
}
