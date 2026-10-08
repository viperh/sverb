# M1-17 — Tabs, layout tree, basic splits, session area

| | |
|---|---|
| **Milestone** | M1 (basic splits); M3-01 adds resize, zoom, rename and reorder |
| **Touches** | `crates/sverb-core/src/layout.rs` (pure layout tree, shared with workspaces), `crates/sverb-tui/src/views/sessions/{mod.rs, tabs.rs, panes.rs}`, `crates/sverb-tui/src/widgets/tabbar.rs` (from M0-11) |
| **Spec refs** | §8.1, §8.3 (tab/pane keys), §8.4, §4.10 (layout tree serialized in workspaces) |
| **Depends on** | M1-10, M1-11, M1-12, M1-13 |
| **Blocks** | M3-01, M3-02, M3-03 |

---

## 1. Current state in the codebase
M0-11 created a tab bar placeholder and the "session area" main mode. A single pane can show a session (M1-10), but there's no
tab or pane model.

## 2. Detailed description

### 2.1 Layout tree (`sverb-core::layout`, UI-agnostic so workspaces can serialize it)
- `Layout = Leaf(PaneId) | Split { dir: H | V, ratio: Vec<f32>, children: Vec<Layout> }` (§8.4). Invariants:
  `children.len() >= 2`, `ratio.len() == children.len()`, ratios > 0 and sum to 1 (normalize on every
  mutation), and nested splits in the same direction are **flattened** (a V split inside a V split merges).
- Operations (pure): `split(pane, dir) -> (Layout, new_pane)` (the new pane gets an equal share; it's inserted after the
  target), `remove(pane) -> Option<Layout>` (collapses single-child splits), `neighbor(pane, direction, rects) ->
  Option<PaneId>` (geometric: pick the pane whose rect is adjacent in that direction with maximum overlap, ties → the
  most recently focused), `rects(area: Rect) -> Vec<(PaneId, Rect)>` (integer division with remainder distributed
  to the last child, accounting for 1-cell borders).
- **Terminology:** `leader -` = "split horizontal" = panes stacked top/bottom (tmux `split-window -v` naming
  differs; follow the spec's naming, and document that "horizontal split" means a horizontal divider line).

### 2.2 Tabs and panes model (in `App`)
- `Tab { id, title_override: Option<String>, layout: Layout, focused: PaneId, broadcast: BroadcastSet (M3-02),
  zoomed: Option<PaneId> (M3-01) }`.
- `Pane { id, session: SessionId, kind: Ssh(host_id) | Local | Viewer(share) (M6) }`.
- **Tab title** (§8.4): the host label, or the OSC title if `terminal.use_osc_title` (the title of the tab's focused pane).
  Local tabs default to the shell name.
- **Markers** (§8.4): `●` activity (output while the tab is in the background; cleared on focus), bell marker `🔔`
  (or `!` in ASCII mode) on BEL, disconnected marker `✕` (or `x`), auth-pending `🔑` (M1-14).
- Tab bar: `1 prod-web-1 ┬ 2 db-primary ● ┬ 3 local ┬ +` (§8.1). Overflow scrolls horizontally around the active tab,
  with `‹`/`›` indicators.

### 2.3 Actions (§8.3)
- `leader c` → host picker (fuzzy over hosts, M1-05) → new tab with that session.
- `leader t` → new local tab (M1-12; `03-KEYBINDINGS.md` moved it off `l`). `leader o` → quick connect (M1-07) → new tab.
- `leader 1..9` go to tab N. `leader n`/`N` next/previous (wrapping).
- `leader -` / `leader |` → split the focused pane. The new pane opens **the same kind of session**: same host for
  SSH (a new channel on the same connection when multiplexing lands in M3-07; a new connection until then), or local for local.
  Alternative `leader c` inside a split picks a different host? Keep it simple: splitting duplicates the session target, and
  "connect in split" from the Hosts view (M1-07 `v`) splits the current tab with the chosen host.
- Focus: `leader ←↑→↓` / `leader hjkl` (§8.3; `h`/`l` are focus only, per `03-KEYBINDINGS.md` §4.1).
- `leader x` → close the pane (also on disconnected or exited panes), `leader X` → close the tab, with a confirm if the session is alive (`Connected`/connecting). Closing the last pane closes the
  tab. Closing the last tab returns the main area to the Hosts view.
- Mouse: click a pane to focus it, click a tab to switch, click `+` to open the host picker.

### 2.4 Resize propagation (§8.4)
On terminal resize or layout change, compute pane rects. For panes whose inner size changed, send
`SessionCmd::Resize{cols, rows, px_w, px_h}` **debounced by 50 ms** per pane (a timer effect, M0-09), so dragging the outer
window doesn't spam `window_change`.

### 2.5 Rendering
Each pane is rendered with `TerminalPane` (M1-10) in its rect. The focused pane gets a focused border, and the terminal cursor
is placed only for the focused pane of the active tab. Background tabs aren't rendered, but their sessions keep running and set
the activity marker on `Dirty`.

## 3. Codebase changes
- **Create** `sverb-core::layout` (pure + serde, for M3-03).
- **Create** the sessions view modules. Implement the actions in the reducer.

## 4. Test cases to implement

### Layout (pure)
**T-01 (property)** After any random sequence of split/remove operations, the invariants hold (≥ 2 children, ratios
sum to 1 ± 1e-6, no same-direction nesting).

**T-02 (unit)** `rects()` for a 3-way vertical split of width 100 → widths 33/33/34 (minus borders), with no gaps or overlaps
(the union equals the area).

**T-03 (property)** The rects of all leaves tile the area exactly, for random trees and sizes ≥ 20×10.

**T-04 (unit, table)** `neighbor()` in a 2×2 grid built by splits: right of top-left = top-right, down of top-left
= bottom-left, left of top-left = None.

**T-05 (unit)** `remove()` of one child in a 2-child split collapses it to the sibling leaf.

### Reducer
**T-06** `leader c` + pick a host → `OpenSession` + a new tab focused, with the title = host label.

**T-07** `leader -` → focused pane split, new pane focused, `OpenSession` for the same target.

**T-08** `leader l` / `leader h` focus moves per geometry.

**T-09** `leader x` on a live session → confirm. Confirm → `CloseSession`, the layout collapses. Last pane → the tab is removed.

**T-10** `leader 3` with 2 tabs → no-op. `leader N` on the first tab wraps to the last.

**T-11** Output on a background tab → `●` marker. Focusing the tab clears it. BEL → bell marker.

**T-12** `use_osc_title = true` + a `Title` event → the tab shows the OSC title (≤ 256 chars, truncated in the bar with `…`).

**T-13** Resize debounce: 10 terminal resize events within 40 ms → exactly one `Resize` cmd per pane, after 50 ms.

### Snapshots
**T-14** 3 tabs (one with a 2×2 split, one disconnected, one with activity) at 160×48 and 80×24, with tab overflow at 40 columns.

### e2e
**T-15** Open two SSH tabs and one split. Run `htop` in one and `vim` in another (M1 exit criterion: vim, htop and tmux run
correctly). Snapshot-check that the grids are sane after a resize.

## 5. Passing functional characteristics
- [ ] Tabs hold a layout tree per §8.4. Panes hold SSH or local sessions.
- [ ] Splitting, focusing (direction-aware), closing (with confirm) and tab navigation work via the §8.3 keys and the mouse.
- [ ] Tab titles and activity, bell, disconnected and auth markers are correct.
- [ ] Pane resizes propagate to the remote, debounced by 50 ms.
- [ ] The layout tree is pure, serializable, invariant-preserving and lives in `sverb-core`.
- [ ] M1 exit criterion: vim, htop and tmux run correctly in remote sessions inside tabs and splits.
