//! Group tree helpers (SPEC §4.3, §9.2).
//!
//! Groups nest through `parent_id`. Writes reject cycles
//! (`validate::validate_group_parent`), but synced data can still be inconsistent, so
//! every walk here is cycle-safe: it stops on a revisited id and after
//! [`MAX_GROUP_DEPTH`] steps.
//!
//! Deleting a group (§9.2) either moves its hosts and subgroups to the parent group
//! or deletes the whole subtree; [`plan_delete`] computes which items change, and the
//! item service carries it out.

use std::collections::{BTreeMap, BTreeSet};

use super::ids::ItemId;

/// The deepest group chain a walk follows (defensive; writes reject cycles).
pub const MAX_GROUP_DEPTH: usize = 64;

/// Above this many affected items, "delete them all" asks to type the count.
pub const DELETE_CONFIRM_THRESHOLD: usize = 10;

/// The ancestors of `start` (its parent first), cycle-safe and depth-limited.
pub fn ancestors(start: ItemId, parent_of: impl Fn(ItemId) -> Option<ItemId>) -> Vec<ItemId> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::from([start]);
    let mut cur = parent_of(start);
    while let Some(p) = cur {
        if out.len() >= MAX_GROUP_DEPTH || !seen.insert(p) {
            break;
        }
        out.push(p);
        cur = parent_of(p);
    }
    out
}

/// Every group below `root` (not `root` itself), breadth first. `groups` is
/// `(group, parent)` for every group. Cycle-safe.
pub fn descendants(
    root: ItemId,
    groups: impl IntoIterator<Item = (ItemId, Option<ItemId>)>,
) -> Vec<ItemId> {
    let mut children: BTreeMap<ItemId, Vec<ItemId>> = BTreeMap::new();
    for (g, parent) in groups {
        if let Some(p) = parent {
            children.entry(p).or_default().push(g);
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::from([root]);
    let mut queue = std::collections::VecDeque::from([root]);
    while let Some(g) = queue.pop_front() {
        for &c in children.get(&g).map_or(&[][..], Vec::as_slice) {
            if seen.insert(c) {
                out.push(c);
                queue.push_back(c);
            }
        }
    }
    out
}

/// What happens to a deleted group's contents (§9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteGroupMode {
    /// Move its hosts and direct subgroups to the parent group (the default).
    MoveToParent,
    /// Delete every host and group below it.
    DeleteAll,
}

/// The writes a group deletion makes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeletePlan {
    /// Hosts whose `group_id` becomes [`DeletePlan::new_parent`].
    pub move_hosts: Vec<ItemId>,
    /// Groups whose `parent_id` becomes [`DeletePlan::new_parent`].
    pub move_groups: Vec<ItemId>,
    /// The deleted group's parent (`None`: the top level).
    pub new_parent: Option<ItemId>,
    /// Hosts to delete.
    pub delete_hosts: Vec<ItemId>,
    /// Groups to delete, the group itself last.
    pub delete_groups: Vec<ItemId>,
}

impl DeletePlan {
    /// Items deleted besides the group itself (for the typed confirmation).
    pub fn deleted_contents(&self) -> usize {
        self.delete_hosts.len() + self.delete_groups.len().saturating_sub(1)
    }
}

/// Plan the deletion of `group` (whose parent is `parent`). `hosts` is
/// `(host, group_id)`, `groups` is `(group, parent_id)` for every live item.
pub fn plan_delete(
    group: ItemId,
    parent: Option<ItemId>,
    hosts: &[(ItemId, Option<ItemId>)],
    groups: &[(ItemId, Option<ItemId>)],
    mode: DeleteGroupMode,
) -> DeletePlan {
    // A parent inside the subtree (corrupt data) would orphan the moved items.
    let below = descendants(group, groups.iter().copied());
    let new_parent = parent.filter(|p| *p != group && !below.contains(p));
    match mode {
        DeleteGroupMode::MoveToParent => DeletePlan {
            move_hosts: hosts
                .iter()
                .filter(|(_, g)| *g == Some(group))
                .map(|(h, _)| *h)
                .collect(),
            move_groups: groups
                .iter()
                .filter(|(g, p)| *p == Some(group) && *g != group)
                .map(|(g, _)| *g)
                .collect(),
            new_parent,
            delete_hosts: Vec::new(),
            delete_groups: vec![group],
        },
        DeleteGroupMode::DeleteAll => {
            let mut all: BTreeSet<ItemId> = below.iter().copied().collect();
            all.insert(group);
            let mut delete_groups: Vec<ItemId> = below.into_iter().rev().collect();
            delete_groups.push(group);
            DeletePlan {
                move_hosts: Vec::new(),
                move_groups: Vec::new(),
                new_parent,
                delete_hosts: hosts
                    .iter()
                    .filter(|(_, g)| g.is_some_and(|g| all.contains(&g)))
                    .map(|(h, _)| *h)
                    .collect(),
                delete_groups,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> ItemId {
        ItemId::from_bytes([b; 16])
    }

    #[test]
    fn ancestors_stop_on_cycles() {
        let parent = |g: ItemId| match g.as_bytes()[0] {
            1 => Some(id(2)),
            2 => Some(id(3)),
            3 => Some(id(1)),
            _ => None,
        };
        assert_eq!(ancestors(id(1), parent), vec![id(2), id(3)]);
        assert!(ancestors(id(9), parent).is_empty());
    }

    #[test]
    fn descendants_are_breadth_first_and_cycle_safe() {
        let groups = [
            (id(2), Some(id(1))),
            (id(3), Some(id(2))),
            (id(4), Some(id(1))),
            (id(1), Some(id(3))), // corrupt: a cycle back to the root
        ];
        assert_eq!(descendants(id(1), groups), vec![id(2), id(4), id(3)]);
    }

    #[test]
    fn plans() {
        let groups = [
            (id(1), Some(id(9))),
            (id(2), Some(id(1))),
            (id(3), Some(id(2))),
        ];
        let hosts = [
            (id(10), Some(id(1))),
            (id(11), Some(id(2))),
            (id(12), None),
            (id(13), Some(id(3))),
        ];
        let p = plan_delete(
            id(1),
            Some(id(9)),
            &hosts,
            &groups,
            DeleteGroupMode::MoveToParent,
        );
        assert_eq!(p.move_hosts, vec![id(10)]);
        assert_eq!(p.move_groups, vec![id(2)]);
        assert_eq!(p.new_parent, Some(id(9)));
        assert_eq!(p.delete_groups, vec![id(1)]);
        let p = plan_delete(
            id(1),
            Some(id(9)),
            &hosts,
            &groups,
            DeleteGroupMode::DeleteAll,
        );
        assert_eq!(p.delete_hosts, vec![id(10), id(11), id(13)]);
        assert_eq!(p.delete_groups, vec![id(3), id(2), id(1)]);
        assert_eq!(p.deleted_contents(), 5);
    }
}
