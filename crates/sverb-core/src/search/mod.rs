//! M1-05: in-memory decrypted search index and fuzzy search (SPEC §5.2, §8.5, §9.1).
//!
//! - [`ItemIndex`]: the mutable index, owned by the vault service (`sverb-tui`
//!   `services::vault`). Full build on unlock, incremental updates on writes and
//!   remote applies, dropped (zeroized) on lock.
//! - [`IndexSnapshot`]: the immutable `Arc` the UI receives
//!   (`UiEvent::IndexUpdated`) and queries without locking.
//! - [`Query`]: the query language (`word`, `"phrase"`, `#tag`, `@vault`, `kind:`).
//! - Matching uses `nucleo-matcher` (fuzzy, smart case, Unicode normalization).
//!   Results are ranked by score, then pinned → frecency → alphabetical (§9.1).
//! - [`resolve_host_arg`]: `<host>` argument resolution over a snapshot (SPEC §16).

mod index;
mod query;

#[cfg(test)]
mod tests;

pub use index::{
    DeviceLocalLookup, GROUP_PATH_SEPARATOR, Hit, IndexEntry, IndexSnapshot, ItemIndex,
    NoDeviceLocal, Scope, Text, compare_entries,
};
pub use query::{Query, parse_kind};

use crate::host_arg::{self, HostArgError, HostCandidate, MatchKind};
use crate::model::ItemId;

/// Why a host argument did not resolve (`NotFound` / `Ambiguous`).
pub type ResolveError = HostArgError;

/// Resolve a `<host>` argument against the hosts of `snapshot`: exact label, exact
/// address, then exactly one fuzzy (`nucleo`) match on label or address
/// ([`host_arg::resolve_host_arg`]). Hosts are considered in view order (pinned →
/// frecency → alphabetical), which is also the order of ambiguity candidates.
///
/// # Errors
/// [`HostArgError::NotFound`] or [`HostArgError::Ambiguous`].
pub fn resolve_host_arg(snapshot: &IndexSnapshot, arg: &str) -> Result<ItemId, ResolveError> {
    resolve_host_arg_kind(snapshot, arg).map(|(id, _)| id)
}

/// [`resolve_host_arg`], also reporting how the host matched.
///
/// # Errors
/// As [`resolve_host_arg`].
pub fn resolve_host_arg_kind(
    snapshot: &IndexSnapshot,
    arg: &str,
) -> Result<(ItemId, MatchKind), ResolveError> {
    let hosts: Vec<HostCandidate<ItemId>> = snapshot
        .ordered(Scope::Hosts, snapshot)
        .into_iter()
        .map(|e| HostCandidate {
            id: e.item_id,
            label: e.display_label().to_owned(),
            address: e.address.to_string(),
        })
        .collect();
    host_arg::resolve_host_arg(arg, &hosts).map(|(h, kind)| (h.id, kind))
}
