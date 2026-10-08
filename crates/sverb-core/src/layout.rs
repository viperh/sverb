//! M1-17: the pane layout tree of a tab (SPEC §8.4), pure and UI-agnostic.
//!
//! ```text
//! enum Layout { Leaf(PaneId), Split { dir: H | V, ratio: Vec<f32>, children: Vec<Layout> } }
//! ```
//!
//! It lives in `sverb-core` (not the TUI) because workspaces serialize it (M3-03).
//!
//! # Terminology
//! [`SplitDir::Horizontal`] is a **horizontal divider line**: its children are stacked
//! top/bottom (`leader -`). [`SplitDir::Vertical`] is a vertical divider: children sit
//! side by side (`leader |`). This follows the spec's naming; tmux names them the other
//! way round (`split-window -v` stacks panes).
//!
//! # Invariants (checked by [`Layout::check`], kept by every operation)
//! - a split has at least 2 children and exactly one ratio per child,
//! - ratios are > 0 and sum to 1 (normalized on every mutation),
//! - a split never has a direct child split in the same direction (they are flattened),
//! - every pane id appears once.
//!
//! # Geometry
//! [`Layout::rects`] tiles an area exactly: each child of a split gets
//! `floor(extent × ratio)` cells and the last child gets the remainder, so there are no
//! gaps or overlaps. Every pane draws its own 1-cell border inside its rect; the
//! content size is [`Rect::inner`] (2 cells less in each dimension).
//!
//! M3-01 adds resizing ([`Layout::resize`], [`Layout::move_border`] for mouse drags of
//! split borders, [`Layout::equalize`]); zoom is a per-tab flag in the TUI.

use serde::{Deserialize, Serialize};

/// Identifies a pane inside a tab layout. The TUI keeps one session per pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PaneId(pub u64);

/// The divider orientation of a split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDir {
    /// A horizontal divider: children stacked top to bottom (`leader -`).
    #[serde(rename = "h")]
    Horizontal,
    /// A vertical divider: children side by side, left to right (`leader |`).
    #[serde(rename = "v")]
    Vertical,
}

/// A focus direction (`leader h j k l` / arrows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Towards smaller x.
    Left,
    /// Towards larger x.
    Right,
    /// Towards smaller y.
    Up,
    /// Towards larger y.
    Down,
}

/// A cell rectangle (no dependency on a UI toolkit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rect {
    /// Left column.
    pub x: u16,
    /// Top row.
    pub y: u16,
    /// Width in cells.
    pub width: u16,
    /// Height in cells.
    pub height: u16,
}

impl Rect {
    /// A rectangle.
    #[must_use]
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Cells covered.
    #[must_use]
    pub fn area(&self) -> u32 {
        u32::from(self.width) * u32::from(self.height)
    }

    /// One past the right edge.
    #[must_use]
    pub fn right(&self) -> u32 {
        u32::from(self.x) + u32::from(self.width)
    }

    /// One past the bottom edge.
    #[must_use]
    pub fn bottom(&self) -> u32 {
        u32::from(self.y) + u32::from(self.height)
    }

    /// The content area inside a 1-cell border.
    #[must_use]
    pub fn inner(&self) -> Self {
        Self {
            x: self.x.saturating_add(1),
            y: self.y.saturating_add(1),
            width: self.width.saturating_sub(2),
            height: self.height.saturating_sub(2),
        }
    }

    /// Whether the cell `(col, row)` is inside.
    #[must_use]
    pub fn contains(&self, col: u16, row: u16) -> bool {
        col >= self.x
            && u32::from(col) < self.right()
            && row >= self.y
            && u32::from(row) < self.bottom()
    }
}

/// A tab's layout tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// One pane.
    Leaf(PaneId),
    /// Two or more children separated by dividers.
    Split {
        /// Divider orientation.
        dir: SplitDir,
        /// Each child's share of the extent along the split axis (sums to 1).
        ratio: Vec<f32>,
        /// The children, left to right or top to bottom.
        children: Vec<Layout>,
    },
}

// Ratios are never NaN (they are normalized positive shares), so equality is total.
impl Eq for Layout {}

/// Tolerance for the ratio sum.
pub const RATIO_EPSILON: f32 = 1e-6;

impl Layout {
    /// A single pane.
    #[must_use]
    pub const fn leaf(pane: PaneId) -> Self {
        Self::Leaf(pane)
    }

    /// The panes in tree order (left to right, top to bottom within each split).
    #[must_use]
    pub fn panes(&self) -> Vec<PaneId> {
        let mut out = Vec::new();
        self.collect_panes(&mut out);
        out
    }

    fn collect_panes(&self, out: &mut Vec<PaneId>) {
        match self {
            Self::Leaf(p) => out.push(*p),
            Self::Split { children, .. } => {
                for c in children {
                    c.collect_panes(out);
                }
            }
        }
    }

    /// Number of panes.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Leaf(_) => 1,
            Self::Split { children, .. } => children.iter().map(Self::len).sum(),
        }
    }

    /// Always `false`: a layout has at least one pane.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether `pane` is in the tree.
    #[must_use]
    pub fn contains(&self, pane: PaneId) -> bool {
        match self {
            Self::Leaf(p) => *p == pane,
            Self::Split { children, .. } => children.iter().any(|c| c.contains(pane)),
        }
    }

    /// Split `target`: the new pane `new` is inserted right after it (below for
    /// [`SplitDir::Horizontal`], to the right for [`SplitDir::Vertical`]) and gets an
    /// equal share of the split it joins (`1 / n` of it; the siblings shrink
    /// proportionally). Splitting a pane whose parent split has the same direction adds
    /// a child to that split (flattening). `None` when `target` is not in the tree or
    /// `new` already is.
    #[must_use]
    pub fn split(&self, target: PaneId, dir: SplitDir, new: PaneId) -> Option<Self> {
        if !self.contains(target) || self.contains(new) {
            return None;
        }
        let mut out = self.clone();
        out.split_in_place(target, dir, new);
        out.normalize();
        Some(out)
    }

    /// Returns whether it inserted.
    fn split_in_place(&mut self, target: PaneId, dir: SplitDir, new: PaneId) -> bool {
        match self {
            Self::Leaf(p) if *p == target => {
                *self = Self::Split {
                    dir,
                    ratio: vec![0.5, 0.5],
                    children: vec![Self::Leaf(target), Self::Leaf(new)],
                };
                true
            }
            Self::Leaf(_) => false,
            Self::Split {
                dir: d,
                ratio,
                children,
            } => {
                // The target is a direct leaf child of a same-direction split: add a sibling.
                if *d == dir
                    && let Some(i) = children
                        .iter()
                        .position(|c| matches!(c, Self::Leaf(p) if *p == target))
                {
                    let n = children.len() as f32;
                    for r in ratio.iter_mut() {
                        *r *= n / (n + 1.0);
                    }
                    ratio.insert(i + 1, 1.0 / (n + 1.0));
                    children.insert(i + 1, Self::Leaf(new));
                    return true;
                }
                children
                    .iter_mut()
                    .any(|c| c.split_in_place(target, dir, new))
            }
        }
    }

    /// Remove `pane`. Its share goes to its siblings (proportionally); a split left with
    /// one child collapses into that child (and flattens into a same-direction parent).
    /// `None` when the tree becomes empty (the last pane was removed). A pane that is
    /// not in the tree leaves the layout unchanged.
    #[must_use]
    pub fn remove(&self, pane: PaneId) -> Option<Self> {
        if !self.contains(pane) {
            return Some(self.clone());
        }
        let mut out = self.remove_rec(pane)?;
        out.normalize();
        Some(out)
    }

    fn remove_rec(&self, pane: PaneId) -> Option<Self> {
        match self {
            Self::Leaf(p) => (*p != pane).then(|| self.clone()),
            Self::Split {
                dir,
                ratio,
                children,
            } => {
                let mut kept_ratio = Vec::with_capacity(children.len());
                let mut kept = Vec::with_capacity(children.len());
                for (c, r) in children.iter().zip(ratio) {
                    if let Some(c) = c.remove_rec(pane) {
                        kept.push(c);
                        kept_ratio.push(*r);
                    }
                }
                match kept.len() {
                    0 => None,
                    1 => kept.pop(),
                    _ => Some(Self::Split {
                        dir: *dir,
                        ratio: kept_ratio,
                        children: kept,
                    }),
                }
            }
        }
    }

    /// Restore the invariants: collapse single-child splits, flatten same-direction
    /// nesting (a nested split's ratios are scaled by its share), drop invalid ratios
    /// (non-finite or ≤ 0 become equal shares) and normalize the sum to 1. Used after
    /// every mutation and on layouts loaded from workspaces.
    pub fn normalize(&mut self) {
        let Self::Split {
            dir,
            ratio,
            children,
        } = self
        else {
            return;
        };
        if ratio.len() != children.len() || ratio.iter().any(|r| !r.is_finite() || *r <= 0.0) {
            *ratio = vec![1.0; children.len()];
        }
        normalize_sum(ratio);
        let mut new_ratio = Vec::with_capacity(ratio.len());
        let mut new_children = Vec::with_capacity(children.len());
        for (mut child, share) in std::mem::take(children).into_iter().zip(ratio.iter()) {
            child.normalize();
            match child {
                Self::Split {
                    dir: d,
                    ratio: r,
                    children: c,
                } if d == *dir => {
                    for (cc, rr) in c.into_iter().zip(r) {
                        new_children.push(cc);
                        new_ratio.push(rr * share);
                    }
                }
                other => {
                    new_children.push(other);
                    new_ratio.push(*share);
                }
            }
        }
        normalize_sum(&mut new_ratio);
        match new_children.len() {
            0 => {} // unreachable for trees built by the operations; leave as is
            1 => {
                if let Some(only) = new_children.pop() {
                    *self = only;
                }
            }
            _ => {
                *ratio = new_ratio;
                *children = new_children;
            }
        }
    }

    /// Every ratio in the tree set to equal shares (M3-01 `equalize_panes`).
    #[must_use]
    pub fn equalized(&self) -> Self {
        match self {
            Self::Leaf(_) => self.clone(),
            Self::Split { dir, children, .. } => Self::Split {
                dir: *dir,
                ratio: vec![1.0 / children.len() as f32; children.len()],
                children: children.iter().map(Self::equalized).collect(),
            },
        }
    }

    /// Check the invariants (module docs). `Err` describes the first violation.
    pub fn check(&self) -> Result<(), String> {
        let panes = self.panes();
        let mut sorted = panes.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != panes.len() {
            return Err("a pane appears twice".to_owned());
        }
        self.check_rec(None)
    }

    fn check_rec(&self, parent: Option<SplitDir>) -> Result<(), String> {
        let Self::Split {
            dir,
            ratio,
            children,
        } = self
        else {
            return Ok(());
        };
        if children.len() < 2 {
            return Err(format!("split with {} children", children.len()));
        }
        if ratio.len() != children.len() {
            return Err(format!(
                "{} ratios for {} children",
                ratio.len(),
                children.len()
            ));
        }
        if ratio.iter().any(|r| !r.is_finite() || *r <= 0.0) {
            return Err(format!("non-positive ratio in {ratio:?}"));
        }
        let sum: f32 = ratio.iter().sum();
        if (sum - 1.0).abs() > RATIO_EPSILON * 10.0 {
            return Err(format!("ratios sum to {sum}"));
        }
        if parent == Some(*dir) {
            return Err("nested split in the same direction".to_owned());
        }
        children.iter().try_for_each(|c| c.check_rec(Some(*dir)))
    }

    /// The rect of every pane inside `area`, in tree order. The rects tile `area`
    /// exactly (each child gets `floor(extent × ratio)`, the last one the remainder).
    /// Tiny areas can give zero-sized rects; callers skip them.
    #[must_use]
    pub fn rects(&self, area: Rect) -> Vec<(PaneId, Rect)> {
        let mut out = Vec::new();
        self.rects_into(area, &mut out);
        out
    }

    fn rects_into(&self, area: Rect, out: &mut Vec<(PaneId, Rect)>) {
        match self {
            Self::Leaf(p) => out.push((*p, area)),
            Self::Split {
                dir,
                ratio,
                children,
            } => {
                for (child, rect) in children.iter().zip(child_rects(*dir, ratio, area)) {
                    child.rects_into(rect, out);
                }
            }
        }
    }

    /// The pane geometrically next to `pane` in `dir` (see [`neighbor_by_recency`]).
    #[must_use]
    pub fn neighbor(&self, pane: PaneId, dir: Direction, area: Rect) -> Option<PaneId> {
        neighbor(pane, dir, &self.rects(area))
    }
}

// M3-01: resizing (`leader H J K L`, resize mode, mouse drag of split borders).

/// Smallest pane content width (columns inside the border) that resizing keeps.
pub const MIN_CONTENT_COLS: u16 = 5;
/// Smallest pane content height (rows inside the border) that resizing keeps.
pub const MIN_CONTENT_ROWS: u16 = 2;
/// One resize step: this share of the split's extent (at least one cell).
pub const RESIZE_STEP: f32 = 0.05;

/// [`MIN_CONTENT_COLS`] plus the pane's border.
const MIN_RECT_COLS: u16 = MIN_CONTENT_COLS + 2;
/// [`MIN_CONTENT_ROWS`] plus the pane's border.
const MIN_RECT_ROWS: u16 = MIN_CONTENT_ROWS + 2;

/// A divider between two adjacent children of a split (what a mouse drag moves).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Border {
    /// Child indices from the root down to the split.
    pub path: Vec<usize>,
    /// The divider between child `index` and child `index + 1`.
    pub index: usize,
    /// The split's orientation.
    pub dir: SplitDir,
}

impl SplitDir {
    /// The split orientation that resizing towards `dir` acts on: left/right moves the
    /// dividers of side-by-side panes ([`SplitDir::Vertical`]), up/down those of stacked
    /// panes ([`SplitDir::Horizontal`]).
    #[must_use]
    pub const fn for_resize(dir: Direction) -> Self {
        match dir {
            Direction::Left | Direction::Right => Self::Vertical,
            Direction::Up | Direction::Down => Self::Horizontal,
        }
    }
}

impl Layout {
    /// The node at `path` (child indices from the root).
    fn node_at(&self, path: &[usize]) -> Option<&Self> {
        let Some((first, rest)) = path.split_first() else {
            return Some(self);
        };
        match self {
            Self::Leaf(_) => None,
            Self::Split { children, .. } => children.get(*first)?.node_at(rest),
        }
    }

    fn node_at_mut(&mut self, path: &[usize]) -> Option<&mut Self> {
        let Some((first, rest)) = path.split_first() else {
            return Some(self);
        };
        match self {
            Self::Leaf(_) => None,
            Self::Split { children, .. } => children.get_mut(*first)?.node_at_mut(rest),
        }
    }

    /// Child indices from the root to `pane`.
    fn path_to(&self, pane: PaneId) -> Option<Vec<usize>> {
        match self {
            Self::Leaf(p) => (*p == pane).then(Vec::new),
            Self::Split { children, .. } => children.iter().enumerate().find_map(|(i, c)| {
                let mut path = c.path_to(pane)?;
                path.insert(0, i);
                Some(path)
            }),
        }
    }

    /// The area of the node at `path` when the whole tree is drawn in `area`.
    fn area_at(&self, path: &[usize], area: Rect) -> Option<Rect> {
        let Some((first, rest)) = path.split_first() else {
            return Some(area);
        };
        match self {
            Self::Leaf(_) => None,
            Self::Split {
                dir,
                ratio,
                children,
            } => {
                let rect = *child_rects(*dir, ratio, area).get(*first)?;
                children.get(*first)?.area_at(rest, rect)
            }
        }
    }

    /// Resize `pane` by `steps` steps towards `dir` (`leader H J K L`; resize mode).
    ///
    /// The nearest ancestor split whose orientation matches the axis
    /// ([`SplitDir::for_resize`]) moves the divider next to the pane's subtree: the one
    /// on the `dir` side, or the opposite one when the pane is already at that edge of
    /// the split (then the pane shrinks, as in tmux). One step is [`RESIZE_STEP`] of the
    /// split's extent, at least one cell. The move is clamped so no pane's content gets
    /// below [`MIN_CONTENT_COLS`] × [`MIN_CONTENT_ROWS`] (or below its current size, if
    /// it is already smaller). No matching split (a single pane, or only splits of the
    /// other orientation) leaves the layout unchanged.
    #[must_use]
    pub fn resize(&self, pane: PaneId, dir: Direction, area: Rect, steps: u16) -> Self {
        let Some(path) = self.path_to(pane) else {
            return self.clone();
        };
        let want = SplitDir::for_resize(dir);
        for depth in (0..path.len()).rev() {
            let prefix = &path[..depth];
            let Some(Self::Split {
                dir: split_dir,
                children,
                ..
            }) = self.node_at(prefix)
            else {
                continue;
            };
            if *split_dir != want {
                continue;
            }
            let (i, n) = (path[depth], children.len());
            let forward = matches!(dir, Direction::Right | Direction::Down);
            let index = match (forward, i) {
                (true, i) if i + 1 < n => i,
                (true, i) => i - 1,
                (false, 0) => 0,
                (false, i) => i - 1,
            };
            let Some(split_area) = self.area_at(prefix, area) else {
                return self.clone();
            };
            let extent = along(want, split_area);
            // A step is a few cells: truncation is fine.
            #[allow(clippy::cast_possible_truncation)]
            let step = ((f32::from(extent) * RESIZE_STEP).round() as i32).max(1);
            let cells = step * i32::from(steps);
            let border = Border {
                path: prefix.to_vec(),
                index,
                dir: want,
            };
            return self.move_border(&border, area, if forward { cells } else { -cells });
        }
        self.clone()
    }

    /// Every ratio of the tree set to equal shares (`equalize_panes`; `=` in resize
    /// mode). Same as [`Layout::equalized`].
    #[must_use]
    pub fn equalize(&self) -> Self {
        self.equalized()
    }

    /// The divider under the cell `(col, row)` when the tree is drawn in `area`. Every
    /// pane draws its own border, so a divider is two cells wide: the last cell of the
    /// child before it and the first cell of the child after it. Nested dividers win.
    #[must_use]
    pub fn border_at(&self, area: Rect, col: u16, row: u16) -> Option<Border> {
        self.border_at_rec(area, col, row, &mut Vec::new())
    }

    fn border_at_rec(
        &self,
        area: Rect,
        col: u16,
        row: u16,
        path: &mut Vec<usize>,
    ) -> Option<Border> {
        let Self::Split {
            dir,
            ratio,
            children,
        } = self
        else {
            return None;
        };
        if !area.contains(col, row) {
            return None;
        }
        let rects = child_rects(*dir, ratio, area);
        for (i, (child, rect)) in children.iter().zip(&rects).enumerate() {
            path.push(i);
            if let Some(b) = child.border_at_rec(*rect, col, row, path) {
                return Some(b);
            }
            path.pop();
        }
        let pos = match dir {
            SplitDir::Vertical => col,
            SplitDir::Horizontal => row,
        };
        (0..rects.len().saturating_sub(1))
            .find(|i| {
                let p = start(*dir, rects[i + 1]);
                pos == p || pos.checked_add(1) == Some(p)
            })
            .map(|index| Border {
                path: path.clone(),
                index,
                dir: *dir,
            })
    }

    /// Where `border` is drawn in `area`: the first column (or row) of the child after
    /// it. `None` when the border is not in this tree.
    #[must_use]
    pub fn border_position(&self, border: &Border, area: Rect) -> Option<u16> {
        let split_area = self.area_at(&border.path, area)?;
        let Self::Split { dir, ratio, .. } = self.node_at(&border.path)? else {
            return None;
        };
        if *dir != border.dir {
            return None;
        }
        let rects = child_rects(*dir, ratio, split_area);
        rects.get(border.index + 1).map(|r| start(*dir, *r))
    }

    /// Move `border` by `cells` (positive: right / down), clamped like
    /// [`Layout::resize`]: the largest move of at most `cells` that keeps every pane at
    /// its minimum size. An unknown border, or no possible move, changes nothing.
    #[must_use]
    pub fn move_border(&self, border: &Border, area: Rect, cells: i32) -> Self {
        let (Some(split_area), Some(old_pos)) = (
            self.area_at(&border.path, area),
            self.border_position(border, area),
        ) else {
            return self.clone();
        };
        let extent = along(border.dir, split_area);
        if extent == 0 {
            return self.clone();
        }
        let before = self.rects(area);
        let i = border.index;
        let mut c = cells;
        while c != 0 {
            let mut cand = self.clone();
            if let Some(Self::Split { ratio, .. }) = cand.node_at_mut(&border.path) {
                // Cell counts are small: exact in f32.
                #[allow(clippy::cast_precision_loss)]
                let d = c as f32 / f32::from(extent);
                let (a, b) = (ratio[i] + d, ratio[i + 1] - d);
                if a > 0.0 && b > 0.0 {
                    ratio[i] = a;
                    ratio[i + 1] = b;
                    normalize_sum(ratio);
                    let moved = cand.border_position(border, area).is_some_and(|p| {
                        (i32::from(p) - i32::from(old_pos)).signum() == c.signum()
                    });
                    if moved && keeps_minimums(&before, &cand.rects(area)) {
                        return cand;
                    }
                }
            }
            c -= c.signum();
        }
        self.clone()
    }
}

/// The extent of `area` along a split's axis.
fn along(dir: SplitDir, area: Rect) -> u16 {
    match dir {
        SplitDir::Horizontal => area.height,
        SplitDir::Vertical => area.width,
    }
}

/// Where `rect` starts along a split's axis.
fn start(dir: SplitDir, rect: Rect) -> u16 {
    match dir {
        SplitDir::Horizontal => rect.y,
        SplitDir::Vertical => rect.x,
    }
}

/// No pane got smaller than the minimum (or than it was, if it was already smaller).
/// `before` and `after` come from the same tree shape, so they are in the same order.
fn keeps_minimums(before: &[(PaneId, Rect)], after: &[(PaneId, Rect)]) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|((_, b), (_, a))| {
            a.width >= b.width.min(MIN_RECT_COLS) && a.height >= b.height.min(MIN_RECT_ROWS)
        })
}

/// The rects of a split's children inside `area`.
fn child_rects(dir: SplitDir, ratio: &[f32], area: Rect) -> Vec<Rect> {
    let sizes = distribute(along(dir, area), ratio);
    let mut offset = 0u16;
    sizes
        .into_iter()
        .map(|size| {
            let rect = match dir {
                SplitDir::Horizontal => Rect {
                    y: area.y.saturating_add(offset),
                    height: size,
                    ..area
                },
                SplitDir::Vertical => Rect {
                    x: area.x.saturating_add(offset),
                    width: size,
                    ..area
                },
            };
            offset = offset.saturating_add(size);
            rect
        })
        .collect()
}

/// Scale `ratio` so it sums to 1.
fn normalize_sum(ratio: &mut [f32]) {
    let sum: f32 = ratio.iter().sum();
    if sum > 0.0 && sum.is_finite() {
        for r in ratio.iter_mut() {
            *r /= sum;
        }
    }
}

/// Split `extent` cells by `ratio`: `floor(extent × r)` each, the last gets the rest.
fn distribute(extent: u16, ratio: &[f32]) -> Vec<u16> {
    let mut sizes = Vec::with_capacity(ratio.len());
    let mut used = 0u16;
    for (i, r) in ratio.iter().enumerate() {
        let size = if i + 1 == ratio.len() {
            extent.saturating_sub(used)
        } else {
            // Truncation is the point: integer cells, remainder to the last child.
            // M3-01: a tiny epsilon so a ratio set from a cell count (`c / extent`)
            // gives back exactly that cell count despite f32 rounding.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let s = (f32::from(extent) * r + 1e-3).floor().max(0.0) as u16;
            s.min(extent.saturating_sub(used))
        };
        used = used.saturating_add(size);
        sizes.push(size);
    }
    sizes
}

/// The pane adjacent to `pane` in `dir` with the largest overlap along the other axis.
/// Ties go to the first in `rects` order. `None` at the edge of the tab.
#[must_use]
pub fn neighbor(pane: PaneId, dir: Direction, rects: &[(PaneId, Rect)]) -> Option<PaneId> {
    neighbor_by_recency(pane, dir, rects, &[])
}

/// [`neighbor`] with ties going to the most recently focused pane: `recency` lists pane
/// ids from least to most recently focused (panes not in it rank lowest).
#[must_use]
pub fn neighbor_by_recency(
    pane: PaneId,
    dir: Direction,
    rects: &[(PaneId, Rect)],
    recency: &[PaneId],
) -> Option<PaneId> {
    let (_, from) = rects.iter().find(|(p, _)| *p == pane)?;
    let overlap = |a0: u32, a1: u32, b0: u32, b1: u32| a1.min(b1).saturating_sub(a0.max(b0));
    let rank = |p: PaneId| recency.iter().position(|r| *r == p).map_or(0, |i| i + 1);
    let mut best: Option<(u32, usize, PaneId)> = None;
    for (p, r) in rects {
        if *p == pane || r.area() == 0 {
            continue;
        }
        let ov = match dir {
            Direction::Left if r.right() == u32::from(from.x) => {
                overlap(u32::from(from.y), from.bottom(), u32::from(r.y), r.bottom())
            }
            Direction::Right if u32::from(r.x) == from.right() => {
                overlap(u32::from(from.y), from.bottom(), u32::from(r.y), r.bottom())
            }
            Direction::Up if r.bottom() == u32::from(from.y) => {
                overlap(u32::from(from.x), from.right(), u32::from(r.x), r.right())
            }
            Direction::Down if u32::from(r.y) == from.bottom() => {
                overlap(u32::from(from.x), from.right(), u32::from(r.x), r.right())
            }
            _ => 0,
        };
        if ov == 0 {
            continue;
        }
        let key = (ov, rank(*p));
        if best.is_none_or(|(bo, br, _)| key > (bo, br)) {
            best = Some((ov, key.1, *p));
        }
    }
    best.map(|(_, _, p)| p)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use proptest::prelude::*;

    use super::*;

    const fn p(n: u64) -> PaneId {
        PaneId(n)
    }

    /// Union of rects equals the area, with no overlap.
    fn assert_tiles(rects: &[(PaneId, Rect)], area: Rect) {
        let total: u32 = rects.iter().map(|(_, r)| r.area()).sum();
        assert_eq!(total, area.area(), "{rects:?}");
        for (i, (_, a)) in rects.iter().enumerate() {
            assert!(a.x >= area.x && a.right() <= area.right(), "{a:?} outside");
            assert!(
                a.y >= area.y && a.bottom() <= area.bottom(),
                "{a:?} outside"
            );
            for (_, b) in &rects[i + 1..] {
                let ox = a.right().min(b.right()) > u32::from(a.x.max(b.x));
                let oy = a.bottom().min(b.bottom()) > u32::from(a.y.max(b.y));
                assert!(
                    !(ox && oy) || a.area() == 0 || b.area() == 0,
                    "{a:?} ∩ {b:?}"
                );
            }
        }
    }

    // T-02
    #[test]
    fn t02_three_way_vertical_split_widths() {
        let l = Layout::leaf(p(1))
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap()
            .split(p(2), SplitDir::Vertical, p(3))
            .unwrap();
        let Layout::Split {
            ratio, children, ..
        } = &l
        else {
            panic!("{l:?}")
        };
        assert_eq!(children.len(), 3, "flattened");
        assert!(
            ratio.iter().all(|r| (r - 1.0 / 3.0).abs() < 1e-6),
            "{ratio:?}"
        );
        let area = Rect::new(0, 0, 100, 30);
        let rects = l.rects(area);
        let widths: Vec<u16> = rects.iter().map(|(_, r)| r.width).collect();
        assert_eq!(widths, [33, 33, 34]);
        // Content inside each pane's own border.
        let inner: Vec<u16> = rects.iter().map(|(_, r)| r.inner().width).collect();
        assert_eq!(inner, [31, 31, 32]);
        assert_eq!(rects[1].1.x, 33);
        assert_eq!(rects[2].1.x, 66);
        assert_tiles(&rects, area);
    }

    /// 1 | 2 over 3 | 4 (top-left 1, top-right 2, bottom-left 3, bottom-right 4).
    fn grid() -> Layout {
        Layout::leaf(p(1))
            .split(p(1), SplitDir::Horizontal, p(3))
            .unwrap()
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap()
            .split(p(3), SplitDir::Vertical, p(4))
            .unwrap()
    }

    // T-04
    #[test]
    fn t04_neighbors_in_a_grid() {
        let l = grid();
        l.check().unwrap();
        let area = Rect::new(0, 0, 80, 24);
        let cases = [
            (p(1), Direction::Right, Some(p(2))),
            (p(1), Direction::Down, Some(p(3))),
            (p(1), Direction::Left, None),
            (p(1), Direction::Up, None),
            (p(4), Direction::Up, Some(p(2))),
            (p(4), Direction::Left, Some(p(3))),
            (p(2), Direction::Down, Some(p(4))),
        ];
        for (from, dir, want) in cases {
            assert_eq!(l.neighbor(from, dir, area), want, "{from:?} {dir:?}");
        }
    }

    #[test]
    fn neighbor_ties_go_to_the_most_recent() {
        // 1 on the left; 2 over 3 on the right, both overlapping 1 equally.
        let l = Layout::leaf(p(1))
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap()
            .split(p(2), SplitDir::Horizontal, p(3))
            .unwrap();
        let rects = l.rects(Rect::new(0, 0, 80, 24));
        assert_eq!(neighbor(p(1), Direction::Right, &rects), Some(p(2)));
        assert_eq!(
            neighbor_by_recency(p(1), Direction::Right, &rects, &[p(2), p(3)]),
            Some(p(3))
        );
        assert_eq!(
            neighbor_by_recency(p(1), Direction::Right, &rects, &[p(3), p(2)]),
            Some(p(2))
        );
    }

    // T-05
    #[test]
    fn t05_remove_collapses_to_the_sibling() {
        let l = Layout::leaf(p(1))
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap();
        assert_eq!(l.remove(p(2)), Some(Layout::leaf(p(1))));
        assert_eq!(l.remove(p(1)), Some(Layout::leaf(p(2))));
        assert_eq!(Layout::leaf(p(1)).remove(p(1)), None);
        assert_eq!(l.remove(p(9)), Some(l.clone()));
    }

    #[test]
    fn remove_flattens_into_the_grandparent() {
        // V[1, H[2, V[3, 4]]] minus 2 → V[1, 3, 4].
        let l = Layout::leaf(p(1))
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap()
            .split(p(2), SplitDir::Horizontal, p(3))
            .unwrap()
            .split(p(3), SplitDir::Vertical, p(4))
            .unwrap();
        l.check().unwrap();
        let r = l.remove(p(2)).unwrap();
        r.check().unwrap();
        let Layout::Split {
            dir,
            children,
            ratio,
        } = &r
        else {
            panic!("{r:?}")
        };
        assert_eq!(*dir, SplitDir::Vertical);
        assert_eq!(children.len(), 3);
        assert!((ratio[0] - 0.5).abs() < 1e-6, "{ratio:?}");
        assert_eq!(r.panes(), [p(1), p(3), p(4)]);
    }

    #[test]
    fn split_errors_and_insert_position() {
        let l = Layout::leaf(p(1));
        assert!(l.split(p(2), SplitDir::Vertical, p(3)).is_none());
        assert!(l.split(p(1), SplitDir::Vertical, p(1)).is_none());
        let l = l
            .split(p(1), SplitDir::Horizontal, p(2))
            .unwrap()
            .split(p(1), SplitDir::Horizontal, p(3))
            .unwrap();
        assert_eq!(l.panes(), [p(1), p(3), p(2)], "inserted after the target");
    }

    #[test]
    fn serde_round_trip_and_normalize() {
        let l = grid();
        let json = serde_json::to_string(&l).unwrap();
        let back: Layout = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
        // A hand-written (workspace) tree is repaired.
        let mut bad: Layout = serde_json::from_str(
            r#"{"split":{"dir":"v","ratio":[2.0,-1.0],"children":[{"leaf":1},{"split":{"dir":"v","ratio":[1.0,1.0],"children":[{"leaf":2},{"leaf":3}]}}]}}"#,
        )
        .unwrap();
        assert!(bad.check().is_err());
        bad.normalize();
        bad.check().unwrap();
        assert_eq!(bad.panes(), [p(1), p(2), p(3)]);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Split(usize, bool),
        Remove(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0usize..64, any::<bool>()).prop_map(|(i, h)| Op::Split(i, h)),
            1 => (0usize..64).prop_map(Op::Remove),
        ]
    }

    fn build(ops: &[Op]) -> Layout {
        let mut l = Layout::leaf(p(0));
        let mut next = 1;
        for op in ops {
            let panes = l.panes();
            match op {
                Op::Split(i, h) => {
                    let dir = if *h {
                        SplitDir::Horizontal
                    } else {
                        SplitDir::Vertical
                    };
                    l = l.split(panes[i % panes.len()], dir, p(next)).unwrap();
                    next += 1;
                }
                Op::Remove(i) => {
                    if let Some(r) = l.remove(panes[i % panes.len()]) {
                        l = r;
                    }
                }
            }
        }
        l
    }

    proptest! {
        // T-01
        #[test]
        fn t01_invariants_hold(ops in proptest::collection::vec(op(), 0..40)) {
            let l = build(&ops);
            prop_assert!(l.check().is_ok(), "{:?}: {:?}", l.check(), l);
        }

        // T-03
        #[test]
        fn t03_rects_tile_the_area(
            ops in proptest::collection::vec(op(), 0..12),
            w in 20u16..300,
            h in 10u16..100,
            x in 0u16..50,
            y in 0u16..50,
        ) {
            let l = build(&ops);
            let area = Rect::new(x, y, w, h);
            let rects = l.rects(area);
            prop_assert_eq!(rects.len(), l.len());
            assert_tiles(&rects, area);
        }
    }

    // ---- M3-01: resizing ----------------------------------------------------------

    fn ratios(l: &Layout) -> Vec<f32> {
        match l {
            Layout::Split { ratio, .. } => ratio.clone(),
            Layout::Leaf(_) => Vec::new(),
        }
    }

    fn two_side_by_side() -> Layout {
        Layout::leaf(p(1))
            .split(p(1), SplitDir::Vertical, p(2))
            .unwrap()
    }

    // M3-01 T-01
    #[test]
    fn m3_01_t01_resize_vertical_split() {
        let area = Rect::new(0, 0, 80, 24);
        let l = two_side_by_side().resize(p(1), Direction::Right, area, 1);
        l.check().unwrap();
        let r = ratios(&l);
        assert!(
            (r[0] - 0.55).abs() < 1e-4 && (r[1] - 0.45).abs() < 1e-4,
            "{r:?}"
        );
        // From the right pane, `L` moves its left border right: it shrinks.
        let l2 = two_side_by_side().resize(p(2), Direction::Right, area, 1);
        assert!((ratios(&l2)[0] - 0.55).abs() < 1e-4, "{l2:?}");
        // `H` from the left pane moves its right border left.
        let l3 = two_side_by_side().resize(p(1), Direction::Left, area, 1);
        assert!((ratios(&l3)[0] - 0.45).abs() < 1e-4, "{l3:?}");
        // Three steps at once.
        let l4 = two_side_by_side().resize(p(1), Direction::Right, area, 3);
        assert!((ratios(&l4)[0] - 0.65).abs() < 1e-4, "{l4:?}");
        // At least one cell on tiny extents.
        let tiny = Rect::new(0, 0, 18, 10);
        let l5 = two_side_by_side().resize(p(1), Direction::Right, tiny, 1);
        assert_eq!(l5.rects(tiny)[0].1.width, 10, "{l5:?}");
    }

    // M3-01 T-02
    #[test]
    fn m3_01_t02_clamp_keeps_five_columns() {
        let area = Rect::new(0, 0, 40, 10);
        let mut l = two_side_by_side();
        for _ in 0..50 {
            l = l.resize(p(1), Direction::Right, area, 1);
            l.check().unwrap();
            let rects = l.rects(area);
            assert!(rects[1].1.inner().width >= MIN_CONTENT_COLS, "{rects:?}");
        }
        assert_eq!(l.rects(area)[1].1.inner().width, MIN_CONTENT_COLS);
        // And the other way.
        for _ in 0..50 {
            l = l.resize(p(2), Direction::Left, area, 3);
        }
        assert_eq!(l.rects(area)[0].1.inner().width, MIN_CONTENT_COLS);
        // Rows: at height 12, a stacked pair keeps 2 content rows.
        let area = Rect::new(0, 0, 40, 12);
        let mut l = Layout::leaf(p(1))
            .split(p(1), SplitDir::Horizontal, p(2))
            .unwrap();
        for _ in 0..20 {
            l = l.resize(p(1), Direction::Down, area, 1);
        }
        assert_eq!(l.rects(area)[1].1.inner().height, MIN_CONTENT_ROWS);
    }

    // M3-01 T-03
    #[test]
    fn m3_01_t03_nested_changes_the_nearest_matching_split() {
        // V[1, H[2, 3]]: focus 3 (bottom right), `K`.
        let l = two_side_by_side()
            .split(p(2), SplitDir::Horizontal, p(3))
            .unwrap();
        let area = Rect::new(0, 0, 80, 40);
        let r = l.resize(p(3), Direction::Up, area, 1);
        r.check().unwrap();
        let (
            Layout::Split {
                ratio: outer,
                children,
                ..
            },
            Layout::Split { ratio: outer0, .. },
        ) = (&r, &l)
        else {
            panic!("{r:?}")
        };
        assert_eq!(outer, outer0, "V ratio unchanged");
        let inner = ratios(&children[1]);
        assert!((inner[0] - 0.45).abs() < 1e-4, "{inner:?}");
        // Pane 3 grew upwards.
        let h = |l: &Layout| l.rects(area)[2].1.height;
        assert!(h(&r) > h(&l));
    }

    // M3-01 T-04
    #[test]
    fn m3_01_t04_no_matching_axis_is_a_noop() {
        let area = Rect::new(0, 0, 80, 24);
        let single = Layout::leaf(p(1));
        for d in [
            Direction::Left,
            Direction::Right,
            Direction::Up,
            Direction::Down,
        ] {
            assert_eq!(single.resize(p(1), d, area, 1), single);
        }
        let stacked = Layout::leaf(p(1))
            .split(p(1), SplitDir::Horizontal, p(2))
            .unwrap();
        assert_eq!(stacked.resize(p(1), Direction::Right, area, 1), stacked);
        assert_eq!(stacked.resize(p(2), Direction::Left, area, 1), stacked);
        // Unknown pane.
        assert_eq!(stacked.resize(p(9), Direction::Down, area, 1), stacked);
    }

    #[test]
    fn m3_01_border_hit_and_drag() {
        let l = two_side_by_side();
        let area = Rect::new(0, 1, 80, 24);
        // Left pane x 0..40, right 40..80: the divider is columns 39 and 40.
        assert_eq!(l.border_at(area, 10, 5), None);
        let b = l.border_at(area, 39, 5).unwrap();
        assert_eq!(l.border_at(area, 40, 5), Some(b.clone()));
        assert_eq!(
            (b.path.as_slice(), b.index, b.dir),
            (&[][..], 0, SplitDir::Vertical)
        );
        assert_eq!(l.border_position(&b, area), Some(40));
        let moved = l.move_border(&b, area, 10);
        assert_eq!(moved.border_position(&b, area), Some(50));
        let moved = l.move_border(&b, area, -100);
        assert_eq!(moved.rects(area)[0].1.width, MIN_RECT_COLS);
        // Nested: V[1, H[2, 3]].
        let l = l.split(p(2), SplitDir::Horizontal, p(3)).unwrap();
        let b = l.border_at(area, 60, 12).unwrap();
        assert_eq!(
            (b.path.as_slice(), b.index, b.dir),
            (&[1][..], 0, SplitDir::Horizontal)
        );
        assert_eq!(l.border_at(area, 20, 12).map(|b| b.dir), None);
    }

    #[test]
    fn m3_01_equalize() {
        let area = Rect::new(0, 0, 80, 24);
        let l = two_side_by_side().resize(p(1), Direction::Right, area, 2);
        assert_eq!(l.equalize(), two_side_by_side());
    }

    fn any_dir() -> impl Strategy<Value = Direction> {
        prop_oneof![
            Just(Direction::Left),
            Just(Direction::Right),
            Just(Direction::Up),
            Just(Direction::Down),
        ]
    }

    proptest! {
        // M3-01 T-05
        #[test]
        fn m3_01_t05_resize_invariants(
            ops in proptest::collection::vec(op(), 0..12),
            moves in proptest::collection::vec((0usize..64, any_dir(), 1u16..4), 1..30),
            w in 20u16..240,
            h in 8u16..80,
        ) {
            let mut l = build(&ops);
            let area = Rect::new(0, 1, w, h);
            for (i, dir, steps) in moves {
                let panes = l.panes();
                let before = l.rects(area);
                l = l.resize(panes[i % panes.len()], dir, area, steps);
                prop_assert!(l.check().is_ok(), "{:?}: {:?}", l.check(), l);
                let after = l.rects(area);
                prop_assert_eq!(after.len(), before.len());
                assert_tiles(&after, area);
                prop_assert!(keeps_minimums(&before, &after), "{:?} -> {:?}", before, after);
            }
        }
    }
}
