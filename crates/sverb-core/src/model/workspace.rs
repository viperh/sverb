//! M3-03: the typed form of a saved workspace (SPEC §9.9, §4.10, §8.4).
//!
//! A workspace is a list of tabs; each tab is a layout tree (`crate::layout::Layout`)
//! whose pane ids are **leaf indices** (`PaneId(i)` is `leaves[i]`) plus the leaves
//! themselves: a saved host (`host_id`) or a local shell (with an optional cwd). The
//! split ratios, the focused pane, a user-set tab title and the tab's broadcast set are
//! kept; ephemeral panes (quick connect, share viewers) are not saveable and are left
//! out by [`WorkspaceTab::capture`].
//!
//! # Item encoding
//! The generic [`Workspace`] item view (M1-02) keeps two whole-value LWW fields; this
//! module gives them their shape:
//!
//! ```text
//! layout = { "v": 1, "active": uint, "tabs": [tab, …] }
//!   tab  = { "title"?: text, "focused": uint, "leaves": [leaf, …], "tree": node }
//!   leaf = { "host": bytes(16) } | { "local": null | text(cwd) }
//!   node = uint (leaf index) | { "dir": "h" | "v", "ratio": [float, …], "children": [node, …] }
//! broadcast_groups = [ { "tab": uint, "panes": "all" | [uint, …] }, … ]
//! ```
//!
//! Unknown map keys are ignored (a newer build may add some); a structurally invalid
//! value is an error ([`WorkspaceError`]), never a panic.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;

use super::ids::ItemId;
use super::items::Workspace;
use crate::layout::{Layout, PaneId, Rect, SplitDir};

/// Sessions of a workspace that connect at the same time when it opens (SPEC §9.9:
/// "in parallel with bounded concurrency"). A constant for now; it could become a
/// config key.
pub const OPEN_CONCURRENCY: usize = 8;

/// The version of the `layout` encoding written by this build.
pub const FORMAT_VERSION: u64 = 1;

/// What a workspace pane opens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LeafRef {
    /// A saved host (it may have been deleted since: the pane opens as a placeholder).
    Host(ItemId),
    /// A local shell, optionally in a working directory.
    Local {
        /// The working directory (`None`: the user's home).
        cwd: Option<String>,
    },
}

/// A tab's broadcast set (M3-02) over pane ids `P`: leaf indices in a saved
/// workspace ([`BroadcastSpec`]), live pane ids in the TUI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Broadcast<P: Ord> {
    /// No broadcast.
    #[default]
    Off,
    /// Every pane of the tab.
    AllPanes,
    /// The marked panes.
    Custom(BTreeSet<P>),
}

/// The broadcast set of a saved tab (leaf indices).
pub type BroadcastSpec = Broadcast<u32>;

impl<P: Ord + Copy> Broadcast<P> {
    /// Map the members (members `f` drops are left out; an emptied custom set is `Off`).
    pub fn filter_map<Q: Ord>(&self, mut f: impl FnMut(P) -> Option<Q>) -> Broadcast<Q> {
        match self {
            Self::Off => Broadcast::Off,
            Self::AllPanes => Broadcast::AllPanes,
            Self::Custom(set) => {
                let out: BTreeSet<Q> = set.iter().filter_map(|p| f(*p)).collect();
                if out.is_empty() {
                    Broadcast::Off
                } else {
                    Broadcast::Custom(out)
                }
            }
        }
    }
}

/// One saved tab.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceTab {
    /// A user-set tab title (`leader ,`).
    pub title_override: Option<String>,
    /// The layout tree; `PaneId(i)` stands for `leaves[i]`.
    pub layout: Layout,
    /// The panes, by leaf index.
    pub leaves: Vec<LeafRef>,
    /// The focused leaf.
    pub focused: u32,
    /// The broadcast set.
    pub broadcast: BroadcastSpec,
}

// Ratios are never NaN (checked on decode), so equality is total.
impl Eq for WorkspaceTab {}

/// What [`WorkspaceTab::capture`] made of a live tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The saved tab (`None` when no pane was saveable).
    pub tab: Option<WorkspaceTab>,
    /// Panes left out (not saveable), in layout order.
    pub omitted: Vec<PaneId>,
}

/// A whole saved workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSpec {
    /// Its name (unique per vault).
    pub name: String,
    /// The tabs, in order.
    pub tabs: Vec<WorkspaceTab>,
    /// The tab that was active (index into `tabs`).
    pub active: u32,
}

/// Why a workspace item could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    /// The item has no layout.
    #[error("the workspace has no layout")]
    NoLayout,
    /// The layout encoding is newer than this build.
    #[error("the workspace was saved by a newer sverb (format {0})")]
    Newer(u64),
    /// The layout is malformed.
    #[error("invalid workspace layout: {0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> WorkspaceError {
    WorkspaceError::Invalid(msg.into())
}

/// `layout` with every pane id mapped through `f`.
pub fn map_panes(layout: &Layout, f: &mut impl FnMut(PaneId) -> PaneId) -> Layout {
    match layout {
        Layout::Leaf(p) => Layout::Leaf(f(*p)),
        Layout::Split {
            dir,
            ratio,
            children,
        } => Layout::Split {
            dir: *dir,
            ratio: ratio.clone(),
            children: children.iter().map(|c| map_panes(c, f)).collect(),
        },
    }
}

fn index_u32(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

impl WorkspaceTab {
    /// Save a live tab: `leaf_of` says what each pane opens (`None`: not saveable, the
    /// pane is left out and its siblings take its space). Pane ids are renumbered to
    /// leaf indices in layout order; ratios, the focus and the broadcast set follow.
    pub fn capture(
        title_override: Option<String>,
        layout: &Layout,
        focused: PaneId,
        broadcast: &Broadcast<PaneId>,
        mut leaf_of: impl FnMut(PaneId) -> Option<LeafRef>,
    ) -> Captured {
        let mut kept = BTreeMap::new();
        let mut omitted = Vec::new();
        for p in layout.panes() {
            match leaf_of(p) {
                Some(leaf) => {
                    kept.insert(p, leaf);
                }
                None => omitted.push(p),
            }
        }
        let mut tree = Some(layout.clone());
        for p in &omitted {
            tree = tree.and_then(|t| t.remove(*p));
        }
        let Some(tree) = tree.filter(|_| !kept.is_empty()) else {
            return Captured { tab: None, omitted };
        };
        let order = tree.panes();
        let index: BTreeMap<PaneId, u32> = order
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, index_u32(i)))
            .collect();
        let leaves = order
            .iter()
            .filter_map(|p| kept.remove(p))
            .collect::<Vec<_>>();
        let tab = Self {
            title_override,
            layout: map_panes(&tree, &mut |p| {
                PaneId(u64::from(index.get(&p).copied().unwrap_or(0)))
            }),
            leaves,
            focused: index.get(&focused).copied().unwrap_or(0),
            broadcast: broadcast.filter_map(|p| index.get(&p).copied()),
        };
        Captured {
            tab: Some(tab),
            omitted,
        }
    }

    /// Recreate the tab with live pane ids: `panes[i]` stands for `leaves[i]`. Returns
    /// the layout, the focused pane and the broadcast set. `None` if `panes` is too
    /// short.
    pub fn instantiate(&self, panes: &[PaneId]) -> Option<(Layout, PaneId, Broadcast<PaneId>)> {
        if panes.len() < self.leaves.len() {
            return None;
        }
        let at = |i: u64| usize::try_from(i).ok().and_then(|i| panes.get(i)).copied();
        let mut ok = true;
        let layout = map_panes(&self.layout, &mut |p| {
            at(p.0).unwrap_or_else(|| {
                ok = false;
                p
            })
        });
        let focused = at(u64::from(self.focused)).or_else(|| panes.first().copied())?;
        let broadcast = self.broadcast.filter_map(|i| at(u64::from(i)));
        ok.then_some((layout, focused, broadcast))
    }

    /// The structural rules: a valid layout whose panes are exactly the leaf indices,
    /// a focused leaf and broadcast members that exist.
    ///
    /// # Errors
    /// A description of the first broken rule.
    pub fn check(&self) -> Result<(), String> {
        self.layout.check()?;
        let mut panes: Vec<u64> = self.layout.panes().into_iter().map(|p| p.0).collect();
        panes.sort_unstable();
        let want: Vec<u64> = (0..self.leaves.len() as u64).collect();
        if panes != want {
            return Err("the layout's panes are not the leaves".to_owned());
        }
        if self.focused as usize >= self.leaves.len() {
            return Err("the focused pane does not exist".to_owned());
        }
        if let Broadcast::Custom(set) = &self.broadcast
            && set.iter().any(|i| *i as usize >= self.leaves.len())
        {
            return Err("a broadcast member does not exist".to_owned());
        }
        Ok(())
    }

    /// An ASCII drawing of the layout in `width`×`height` cells: each pane is a box
    /// (`+`, `-`, `|`) with its label on the first inner row.
    pub fn preview(
        &self,
        width: u16,
        height: u16,
        label: impl Fn(&LeafRef) -> String,
    ) -> Vec<String> {
        let (w, h) = (usize::from(width), usize::from(height));
        let mut grid = vec![vec![' '; w]; h];
        for (pane, r) in self.layout.rects(Rect::new(0, 0, width, height)) {
            let (x0, y0) = (usize::from(r.x), usize::from(r.y));
            let (x1, y1) = (
                x0 + usize::from(r.width).saturating_sub(1),
                y0 + usize::from(r.height).saturating_sub(1),
            );
            if r.width == 0 || r.height == 0 || x1 >= w || y1 >= h {
                continue;
            }
            for row in [y0, y1] {
                for c in &mut grid[row][x0..=x1] {
                    *c = '-';
                }
            }
            for row in grid.iter_mut().take(y1 + 1).skip(y0) {
                row[x0] = '|';
                row[x1] = '|';
            }
            for (x, y) in [(x0, y0), (x1, y0), (x0, y1), (x1, y1)] {
                grid[y][x] = '+';
            }
            let leaf = usize::try_from(pane.0)
                .ok()
                .and_then(|i| self.leaves.get(i));
            if let Some(leaf) = leaf
                && y1 > y0 + 1
                && x1 > x0 + 1
            {
                let mut text = label(leaf);
                if pane.0 == u64::from(self.focused) {
                    text.insert(0, '*');
                }
                for (x, c) in (x0 + 1..x1).zip(text.chars()) {
                    grid[y0 + 1][x] = c;
                }
            }
        }
        grid.into_iter()
            .map(|row| row.into_iter().collect())
            .collect()
    }
}

// ---------------------------------------------------------------- encoding

fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn uint(v: &Value, what: &str) -> Result<u64, WorkspaceError> {
    v.as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| invalid(format!("{what} is not an unsigned integer")))
}

fn u32_of(v: &Value, what: &str) -> Result<u32, WorkspaceError> {
    u32::try_from(uint(v, what)?).map_err(|_| invalid(format!("{what} is too large")))
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn node_value(layout: &Layout) -> Value {
    match layout {
        Layout::Leaf(p) => Value::from(p.0),
        Layout::Split {
            dir,
            ratio,
            children,
        } => Value::Map(vec![
            (
                text("dir"),
                text(match dir {
                    SplitDir::Horizontal => "h",
                    SplitDir::Vertical => "v",
                }),
            ),
            (
                text("ratio"),
                Value::Array(ratio.iter().map(|r| Value::Float(f64::from(*r))).collect()),
            ),
            (
                text("children"),
                Value::Array(children.iter().map(node_value).collect()),
            ),
        ]),
    }
}

/// Nesting deeper than this is rejected (a layout this deep can't be drawn anyway).
const MAX_DEPTH: usize = 64;

fn node_from(v: &Value, depth: usize) -> Result<Layout, WorkspaceError> {
    if depth > MAX_DEPTH {
        return Err(invalid("the layout is nested too deeply"));
    }
    if v.is_integer() {
        return Ok(Layout::Leaf(PaneId(uint(v, "a leaf")?)));
    }
    let map = v.as_map().ok_or_else(|| invalid("a node is not a map"))?;
    let dir = match get(map, "dir").and_then(Value::as_text) {
        Some("h") => SplitDir::Horizontal,
        Some("v") => SplitDir::Vertical,
        _ => return Err(invalid("a split has no direction")),
    };
    let ratio = get(map, "ratio")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("a split has no ratios"))?
        .iter()
        .map(|r| match r {
            #[allow(clippy::cast_possible_truncation)]
            Value::Float(f) if f.is_finite() => Ok(*f as f32),
            _ => Err(invalid("a ratio is not a number")),
        })
        .collect::<Result<Vec<f32>, _>>()?;
    let children = get(map, "children")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("a split has no children"))?
        .iter()
        .map(|c| node_from(c, depth + 1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Layout::Split {
        dir,
        ratio,
        children,
    })
}

fn leaf_value(leaf: &LeafRef) -> Value {
    match leaf {
        LeafRef::Host(id) => Value::Map(vec![(text("host"), Value::from(*id))]),
        LeafRef::Local { cwd } => Value::Map(vec![(
            text("local"),
            cwd.as_deref().map_or(Value::Null, text),
        )]),
    }
}

fn leaf_from(v: &Value) -> Result<LeafRef, WorkspaceError> {
    let map = v.as_map().ok_or_else(|| invalid("a leaf is not a map"))?;
    if let Some(h) = get(map, "host") {
        return ItemId::from_value(h)
            .map(LeafRef::Host)
            .ok_or_else(|| invalid("a host leaf has no host id"));
    }
    match get(map, "local") {
        Some(Value::Null) => Ok(LeafRef::Local { cwd: None }),
        Some(Value::Text(cwd)) => Ok(LeafRef::Local {
            cwd: Some(cwd.clone()),
        }),
        _ => Err(invalid("unknown leaf")),
    }
}

fn tab_value(tab: &WorkspaceTab) -> Value {
    let mut map = Vec::new();
    if let Some(t) = &tab.title_override {
        map.push((text("title"), text(t)));
    }
    map.push((text("focused"), Value::from(tab.focused)));
    map.push((
        text("leaves"),
        Value::Array(tab.leaves.iter().map(leaf_value).collect()),
    ));
    map.push((text("tree"), node_value(&tab.layout)));
    Value::Map(map)
}

fn tab_from(v: &Value) -> Result<WorkspaceTab, WorkspaceError> {
    let map = v.as_map().ok_or_else(|| invalid("a tab is not a map"))?;
    let title_override = match get(map, "title") {
        None | Some(Value::Null) => None,
        Some(Value::Text(t)) => Some(t.clone()),
        Some(_) => return Err(invalid("a tab title is not text")),
    };
    let focused = get(map, "focused").map_or(Ok(0), |v| u32_of(v, "focused"))?;
    let leaves = get(map, "leaves")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("a tab has no leaves"))?
        .iter()
        .map(leaf_from)
        .collect::<Result<Vec<_>, _>>()?;
    let layout = node_from(
        get(map, "tree").ok_or_else(|| invalid("a tab has no tree"))?,
        0,
    )?;
    Ok(WorkspaceTab {
        title_override,
        layout,
        leaves,
        focused,
        broadcast: Broadcast::Off,
    })
}

fn broadcast_value(tab: usize, set: &BroadcastSpec) -> Option<Value> {
    let panes = match set {
        Broadcast::Off => return None,
        Broadcast::AllPanes => text("all"),
        Broadcast::Custom(s) => Value::Array(s.iter().map(|i| Value::from(*i)).collect()),
    };
    Some(Value::Map(vec![
        (text("tab"), Value::from(tab as u64)),
        (text("panes"), panes),
    ]))
}

fn broadcast_from(v: &Value) -> Result<(usize, BroadcastSpec), WorkspaceError> {
    let map = v
        .as_map()
        .ok_or_else(|| invalid("a broadcast group is not a map"))?;
    let tab = usize::try_from(uint(
        get(map, "tab").ok_or_else(|| invalid("a broadcast group has no tab"))?,
        "tab",
    )?)
    .map_err(|_| invalid("tab is too large"))?;
    let set = match get(map, "panes") {
        Some(Value::Text(t)) if t == "all" => Broadcast::AllPanes,
        Some(Value::Array(a)) => {
            let set = a
                .iter()
                .map(|i| u32_of(i, "a broadcast member"))
                .collect::<Result<BTreeSet<_>, _>>()?;
            if set.is_empty() {
                Broadcast::Off
            } else {
                Broadcast::Custom(set)
            }
        }
        _ => return Err(invalid("a broadcast group has no panes")),
    };
    Ok((tab, set))
}

impl WorkspaceSpec {
    /// Every host the workspace references (deduplicated).
    pub fn host_ids(&self) -> BTreeSet<ItemId> {
        self.tabs
            .iter()
            .flat_map(|t| &t.leaves)
            .filter_map(|l| match l {
                LeafRef::Host(id) => Some(*id),
                LeafRef::Local { .. } => None,
            })
            .collect()
    }

    /// Number of panes.
    pub fn pane_count(&self) -> usize {
        self.tabs.iter().map(|t| t.leaves.len()).sum()
    }

    /// The item view to save (`layout` and `broadcast_groups`, see the module docs).
    pub fn to_item(&self) -> Workspace {
        let layout = Value::Map(vec![
            (text("v"), Value::from(FORMAT_VERSION)),
            (text("active"), Value::from(self.active)),
            (
                text("tabs"),
                Value::Array(self.tabs.iter().map(tab_value).collect()),
            ),
        ]);
        Workspace {
            name: self.name.clone(),
            layout: Some(layout),
            broadcast_groups: self
                .tabs
                .iter()
                .enumerate()
                .filter_map(|(i, t)| broadcast_value(i, &t.broadcast))
                .collect(),
            read_only: false,
        }
    }

    /// Read a saved workspace.
    ///
    /// # Errors
    /// [`WorkspaceError`] when the layout is missing, newer or malformed (including a
    /// tab that breaks [`WorkspaceTab::check`]).
    pub fn from_item(item: &Workspace) -> Result<Self, WorkspaceError> {
        let layout = item.layout.as_ref().ok_or(WorkspaceError::NoLayout)?;
        let map = layout
            .as_map()
            .ok_or_else(|| invalid("the layout is not a map"))?;
        let version = get(map, "v").map_or(Ok(1), |v| uint(v, "v"))?;
        if version > FORMAT_VERSION {
            return Err(WorkspaceError::Newer(version));
        }
        let mut tabs = get(map, "tabs")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("the layout has no tabs"))?
            .iter()
            .map(tab_from)
            .collect::<Result<Vec<_>, _>>()?;
        for g in &item.broadcast_groups {
            let (tab, set) = broadcast_from(g)?;
            let t = tabs
                .get_mut(tab)
                .ok_or_else(|| invalid("a broadcast group names a missing tab"))?;
            t.broadcast = set;
        }
        for t in &tabs {
            t.check().map_err(WorkspaceError::Invalid)?;
        }
        let active = get(map, "active").map_or(Ok(0), |v| u32_of(v, "active"))?;
        Ok(Self {
            name: item.name.clone(),
            active: if (active as usize) < tabs.len() {
                active
            } else {
                0
            },
            tabs,
        })
    }
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
