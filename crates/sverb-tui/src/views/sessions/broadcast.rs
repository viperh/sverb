//! Broadcast input sets (SPEC §9.8), pure set logic and target computation.
//!
//! Every tab has a [`BroadcastSet`]:
//! - [`BroadcastSet::Off`]: input goes to the focused pane only,
//! - [`BroadcastSet::AllPanes`] (`leader b`): every pane of the tab, including panes
//!   split later (membership is computed from the layout, so a new pane joins at once),
//! - [`BroadcastSet::Custom`] (`leader B`): the marked panes. A pane split later does
//!   not join; a closed pane leaves ([`BroadcastSet::remove`]).
//!
//! A set with fewer than [`MIN_ACTIVE`] members is **pending**: its members are
//! highlighted, but nothing is duplicated. Input is duplicated only when the focused
//! pane is a member of an active set ([`plan`]); otherwise it goes to the focused pane
//! alone. Unavailable members (disconnected, locked, awaiting a prompt) are skipped and
//! counted.
//!
//! The reducer side (actions, routing, confirmation, drawing) is `app/broadcast.rs`.

use std::collections::BTreeSet;

use sverb_core::layout::PaneId;

/// Members needed before input is duplicated.
pub const MIN_ACTIVE: usize = 2;

/// Turning broadcast on for more than this many panes asks first (once per run).
pub const CONFIRM_ABOVE: usize = 4;

/// The marker shown in the tab title and the pane border title of broadcast members.
pub const MARKER: &str = "≋";

/// The broadcast set of a tab.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BroadcastSet {
    /// No broadcast.
    #[default]
    Off,
    /// Every pane of the tab.
    AllPanes,
    /// The marked panes (never empty: an emptied set becomes `Off`).
    Custom(BTreeSet<PaneId>),
}

impl BroadcastSet {
    /// No broadcast (`Tab::new` uses it).
    pub fn new() -> Self {
        Self::Off
    }

    /// Whether broadcast is off.
    pub fn is_off(&self) -> bool {
        *self == Self::Off
    }

    /// `leader b`: `Off` → `AllPanes`; `AllPanes` or `Custom` → `Off`.
    #[must_use]
    pub fn toggled_all(&self) -> Self {
        match self {
            Self::Off => Self::AllPanes,
            Self::AllPanes | Self::Custom(_) => Self::Off,
        }
    }

    /// `leader B`: toggle `pane`'s membership of a custom set. From `Off` it starts a set
    /// with `pane`; from `AllPanes` it starts from every pane in `panes` (so `B` takes the
    /// focused pane out). An emptied set is `Off`.
    #[must_use]
    pub fn toggled_member(&self, pane: PaneId, panes: &[PaneId]) -> Self {
        let mut set = match self {
            Self::Off => BTreeSet::new(),
            Self::AllPanes => panes.iter().copied().collect(),
            Self::Custom(set) => set.clone(),
        };
        if !set.remove(&pane) {
            set.insert(pane);
        }
        if set.is_empty() {
            Self::Off
        } else {
            Self::Custom(set)
        }
    }

    /// A pane closed: it leaves a custom set (an emptied set is `Off`).
    pub fn remove(&mut self, pane: &PaneId) {
        if let Self::Custom(set) = self {
            set.remove(pane);
            if set.is_empty() {
                *self = Self::Off;
            }
        }
    }

    /// Whether `pane` is a member (with `panes` the tab's panes).
    pub fn contains(&self, pane: PaneId, panes: &[PaneId]) -> bool {
        match self {
            Self::Off => false,
            Self::AllPanes => panes.contains(&pane),
            Self::Custom(set) => set.contains(&pane) && panes.contains(&pane),
        }
    }

    /// The members, in `panes` order (the tab's layout order).
    pub fn members(&self, panes: &[PaneId]) -> Vec<PaneId> {
        panes
            .iter()
            .copied()
            .filter(|p| self.contains(*p, panes))
            .collect()
    }

    /// At least [`MIN_ACTIVE`] members: input is duplicated.
    pub fn is_active(&self, panes: &[PaneId]) -> bool {
        self.members(panes).len() >= MIN_ACTIVE
    }

    /// Some members but fewer than [`MIN_ACTIVE`]: highlighted, nothing duplicated.
    pub fn is_pending(&self, panes: &[PaneId]) -> bool {
        let n = self.members(panes).len();
        n > 0 && n < MIN_ACTIVE
    }
}

/// Where one input goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The panes that receive it (the focused pane first).
    pub targets: Vec<PaneId>,
    /// Members skipped because they can't take input now.
    pub skipped: usize,
    /// Whether this is a broadcast (the focused pane is a member of an active set).
    pub broadcast: bool,
}

/// The targets of input typed into `focused`. `panes` is the tab's panes in layout
/// order; `available` says whether a pane can take input now. The focused pane always
/// receives the input (Terminal mode only routes keys to a live pane), even when
/// `available` says otherwise.
pub fn plan(
    set: &BroadcastSet,
    focused: PaneId,
    panes: &[PaneId],
    available: impl Fn(PaneId) -> bool,
) -> Plan {
    let alone = Plan {
        targets: vec![focused],
        skipped: 0,
        broadcast: false,
    };
    if !set.is_active(panes) || !set.contains(focused, panes) {
        return alone;
    }
    let mut targets = vec![focused];
    let mut skipped = 0;
    for p in set.members(panes) {
        if p == focused {
            continue;
        }
        if available(p) {
            targets.push(p);
        } else {
            skipped += 1;
        }
    }
    Plan {
        targets,
        skipped,
        broadcast: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: &[u64]) -> Vec<PaneId> {
        n.iter().copied().map(PaneId).collect()
    }

    #[test]
    fn toggle_all_and_custom() {
        let panes = ids(&[1, 2, 3]);
        let s = BroadcastSet::new();
        assert!(s.is_off());
        let all = s.toggled_all();
        assert_eq!(all, BroadcastSet::AllPanes);
        assert_eq!(all.members(&panes), panes);
        assert!(all.is_active(&panes));
        assert!(all.toggled_all().is_off());

        let one = s.toggled_member(PaneId(1), &panes);
        assert!(one.is_pending(&panes) && !one.is_active(&panes));
        let two = one.toggled_member(PaneId(3), &panes);
        assert_eq!(two.members(&panes), ids(&[1, 3]));
        assert!(two.is_active(&panes));
        // `leader b` on a custom set turns broadcast off.
        assert!(two.toggled_all().is_off());
        // Unmarking every member is `Off`.
        let back = two
            .toggled_member(PaneId(1), &panes)
            .toggled_member(PaneId(3), &panes);
        assert!(back.is_off());
        // `B` on `AllPanes` takes the pane out of an explicit set.
        let minus = all.toggled_member(PaneId(2), &panes);
        assert_eq!(minus.members(&panes), ids(&[1, 3]));
    }

    #[test]
    fn splits_and_closes() {
        let mut custom = BroadcastSet::Custom(ids(&[1, 2]).into_iter().collect());
        // A new pane joins `AllPanes` (computed from the layout), not a custom set.
        let more = ids(&[1, 2, 3]);
        assert!(BroadcastSet::AllPanes.contains(PaneId(3), &more));
        assert!(!custom.contains(PaneId(3), &more));
        custom.remove(&PaneId(2));
        assert!(custom.is_pending(&more));
        custom.remove(&PaneId(1));
        assert!(custom.is_off());
        let mut all = BroadcastSet::AllPanes;
        all.remove(&PaneId(1));
        assert_eq!(all, BroadcastSet::AllPanes);
    }

    #[test]
    fn plans() {
        let panes = ids(&[1, 2, 3]);
        let all = BroadcastSet::AllPanes;
        let p = plan(&all, PaneId(2), &panes, |_| true);
        assert_eq!(p.targets, ids(&[2, 1, 3]));
        assert!(p.broadcast);
        let p = plan(&all, PaneId(1), &panes, |p| p != PaneId(3));
        assert_eq!((p.targets, p.skipped), (ids(&[1, 2]), 1));
        // Off, pending, or the focused pane outside the set: alone.
        for set in [
            BroadcastSet::Off,
            BroadcastSet::Custom(ids(&[1]).into_iter().collect()),
            BroadcastSet::Custom(ids(&[1, 3]).into_iter().collect()),
        ] {
            let p = plan(&set, PaneId(2), &panes, |_| true);
            assert_eq!(p.targets, ids(&[2]), "{set:?}");
            assert!(!p.broadcast);
        }
        // Stale members (closed panes) don't count.
        let stale = BroadcastSet::Custom(ids(&[1, 9]).into_iter().collect());
        assert!(stale.is_pending(&panes));
    }
}
