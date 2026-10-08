# M3-01 — Split resizing, zoom, tab rename and reorder

| | |
|---|---|
| **Milestone** | M3 — Advanced sessions |
| **Touches** | `crates/sverb-core/src/layout.rs` (resize ops), `crates/sverb-tui/src/views/sessions/{panes.rs, tabs.rs}` |
| **Spec refs** | §8.3 (`leader H J K L`, `leader z`), `tasks/03-KEYBINDINGS.md` §4.1/§4.4 (`leader r` resize mode, `leader X`), §8.4 (rename `leader ,`, reorder `leader <`/`>`, resize debounce 50 ms) |
| **Depends on** | M1-17 |
| **Blocks** | M3-02, M3-03 |

---

## 1. Current state in the codebase
The layout tree supports split, remove, neighbor and rects with equal ratios (M1-17). There's no resizing, zoom, rename or reorder.

## 2. Detailed description
- **Resize** (`leader H/J/K/L` = grow/shrink toward left/down/up/right): find the nearest ancestor split whose direction matches the axis (H/L →
  vertical split = side-by-side panes, J/K → horizontal split), and move the boundary adjacent to the focused pane by **one step = 5% of
  the split's extent, minimum 1 cell**. Ratios are clamped so that no child gets fewer than 2 rows or 5 columns of content. Each `leader H/J/K/L`
  is **one** step. There is no timed repeat, because it would steal arrows and letters meant for the shell (`03-KEYBINDINGS.md` §3.1
  A6).
- **Resize mode** (`leader r`): an explicit pane-overlay state. `h j k l`/arrows = one step, `H J K L` = three steps, `=` = equalize,
  `Esc`/`Enter` = exit, auto-exit after 10 s idle. While it is active the status bar shows `RESIZE` in the accent color, and **all
  other keys are swallowed**: never sent to the session.
- **Mouse drag** of split borders (when mouse is enabled): dragging the border line adjusts the ratio live, with the remote resize debounced
  (50 ms, M1-17).
- **Zoom** (`leader z`): toggle the focused pane to full tab area. The other panes keep their sessions (and receive no resize, so their size
  stays the pre-zoom size; **document** that remote apps in hidden panes see no `SIGWINCH`). The tab bar shows a `Z` marker. Focusing another pane
  (`leader hjkl`) while zoomed **unzooms** first. Closing the zoomed pane unzooms.
- **Rename tab** (`leader ,`): an inline prompt prefilled with the current title. An empty string clears the override (back to the host or OSC title).
- **Reorder** (`leader <` / `leader >`): move the current tab left or right (no wrap). Tab numbers (`leader 1..9`) follow the new order.
- **Equalize** (an extra action `equalize_panes`, unbound by default, available in the palette): reset all ratios in the tab to equal.

## 3. Codebase changes
- Pure layout ops `resize(pane, direction, step) -> Layout`, `equalize() -> Layout` in core. Reducer handling and the status-bar `RESIZE` segment.

## 4. Test cases to implement

**T-01 (unit) Resize vertical split.** 2 panes 50/50, focus left, `L` (grow right) → 55/45.

**T-02 (unit) Clamp.** Repeated grows never shrink the sibling below 5 columns of content at width 40.

**T-03 (unit) Nested.** In a V split whose right child is an H split, focus the bottom-right pane, `K` → the H-split ratio changes, and the V-split ratio doesn't change.

**T-04 (unit) No matching axis** (single pane, or only H splits for an H/L request) → no-op.

**T-05 (property)** Invariants (ratio sum = 1, minimum sizes) hold after random resize sequences.

**T-06 (reducer) Resize mode.** `leader L` → exactly one step, and the next `L` goes to the session. `leader r` then `l l =` → two steps
then equalize, with no `SendToSession` at any point. `Esc` exits. 10 s idle → exits. In the mode, `x` is swallowed (K-06).

**T-07 (reducer) Zoom toggle.** The zoomed pane's rect equals the tab area. Other sessions get no Resize cmd. Unzoom → resize to the restored rects.

**T-08 (reducer) Focus move while zoomed** unzooms.

**T-09 (reducer) Rename.** Set "db" → the title is "db". An empty string → reverts.

**T-10 (reducer) Reorder.** Tabs [a,b,c], on b, `>` → [a,c,b]. `leader 3` → b.

**T-11 (reducer) Mouse border drag** updates the ratio, and exactly one debounced Resize per affected pane.

**T-12 (snapshot)** Zoomed pane with the `Z` marker, and the `RESIZE` status at 80×24.

## 5. Passing functional characteristics
- [ ] `leader H/J/K/L` resize the focused pane one 5% step along the correct split axis, with clamps. `leader r` enters an explicit resize mode that never leaks keys to the session.
- [ ] Mouse dragging split borders resizes, and remote sizes update with a 50 ms debounce.
- [ ] `leader z` zooms and unzooms, and focus changes unzoom automatically.
- [ ] Tabs can be renamed (`leader ,`) and reordered (`leader <`/`>`).
