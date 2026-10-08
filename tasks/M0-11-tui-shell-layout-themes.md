# M0-11 — TUI shell: layout, sidebar, tab bar, status/top bar, UI themes, toasts, log pane

| | |
|---|---|
| **Milestone** | M0 — Skeleton (exit criterion: "`sverb` opens and quits cleanly. Snapshot tests run.") |
| **Touches** | `crates/sverb/src/components/home.rs` (deleted); new `crates/sverb-tui/src/{views/shell.rs, views/sidebar.rs, widgets/{tabbar,statusbar,topbar,toast,which_key,log_pane}.rs, theme/{mod.rs, builtin.rs}}`; config Styles removed (see M0-06) |
| **Spec refs** | §8.1, §8.5 (section list), §8.7, §8.8, §18 (`leader D` log pane), §21 M0 |
| **Depends on** | M0-09, M0-10 |
| **Blocks** | M1-06, M1-07, M1-10, M1-17 and all views |

---

## 1. Current state in the codebase
- `components/home.rs:43-50` renders a bordered "Hello World / press `q` to quit!" paragraph
  over the whole frame.
- Styling: `config.rs:325-452` parses free-form style strings into `Styles(HashMap<Mode,
  HashMap<String, Style>>)`. Nothing uses them (the `.config/config.json` `"styles"` map is empty). The
  parser has the `bright` bug noted in M0-06. There's no notion of a theme, `NO_COLOR` or monochrome.
- No sidebar, tabs, status bar, notifications or log pane.

## 2. Detailed description

### 2.1 Layout (§8.1)
```
┌ sverb ─ Personal ▾ ─────────────────────────── ⟳ synced · 🔒 ┐   top bar (1 row)
│ ┌ sidebar ┐ ┌ tab bar ─────────────────────────────────────┐ │
│ │ ▸ Hosts │ │ main area: section view OR session area      │ │
│ │   …     │ │                                               │ │
│ └─────────┘ └───────────────────────────────────────────────┘ │
│ NORMAL │ session info │ forwards │ REC │ sync │ ^\ ? help    │   status bar (1 row)
└───────────────────────────────────────────────────────────────┘
```
- **Top bar**: app name, vault selector (shows `Personal` until vaults exist; `▾` hints that it's
  clickable/selectable), sync indicator (hidden in local-only mode, §1.1), lock icon (🔒 when locked,
  with an ASCII fallback `[L]` when the terminal can't render the glyph width, detected with
  `unicode-width`).
- **Sidebar**: sections `Hosts, Keychain, Forwards, Snippets, Known, Logs, Settings` (§8.5). The
  selection marker is `▸`. Toggled with `leader s`. With `ui.sidebar = auto` it's hidden under 100 columns;
  `always`/`never` force it.
- **Main area**: either the active section's view (placeholder text per section until its task lands)
  or the session area (tab bar + panes, M1-17). Toggle with `leader v` (`03-KEYBINDINGS.md` §4.1. This replaces
  §8.1's `leader h`/`leader t`, which collided with pane focus and the local tab).
- **Status bar** segments, left to right: mode (`TERMINAL|NORMAL|COPY|INSERT`), focused session info
  (`user@host · ssh · 23ms`, empty for now), active forwards summary, `REC ●`, `BROADCAST ×N`, sync
  status (hidden in local-only), and key hint `^\ ? help` (rendered from the actual leader chord). Segments are
  dropped right-to-left (lowest priority first) when space is short. The priority order is documented.
- **Responsive rules**:
  - width < 100 and `sidebar=auto` → hidden
  - width < 80 → the sidebar, when toggled on, renders as an **overlay** over the main area
  - height < 24 → the status bar merges into the tab bar row (status segments on the right side of the tab
    bar)
  - minimum supported size 40×10. Below that, render a centered "Terminal too small (W×H)"
    message and nothing else.

### 2.2 Focus model
`Focus { Sidebar, Main, Detail }`, cycled with `tab` in Normal mode (§8.3). The focused region's border
uses the theme's accent style, and the others use the dim border. When a session pane is focused, mode is Terminal.

### 2.3 UI themes (§8.8)
- `UiTheme` struct with named roles: `bg`, `fg`, `dim`, `border`, `border_focused`, `accent`,
  `selection`, `sidebar_bg`, `status_bg`, `status_fg`, `ok`, `warn`, `error`, `info`,
  `broadcast_border`, `toast_bg`, plus a modifier for selection (default reverse).
- Built-ins: `default-dark`, `default-light`, `high-contrast`. User UI themes are **not** in the
  spec (only terminal color schemes are, §7.4). Theme names are validated by `ThemeCatalog` (M0-06).
- **`NO_COLOR`** (any non-empty value): every role resolves to `Color::Reset`. Focus and selection are
  shown with **reverse video + bold** only (§8.8). The UI must remain fully usable, and snapshot tests at the
  monochrome level verify it.
- **Color depth**: if `ui.truecolor = off` or auto-detect fails (`COLORTERM` not `truecolor`/`24bit`),
  theme RGB colors are downsampled to the 256-color palette (nearest in a perceptual
  space). The function is shared with M1-10's pane color downsampling and lives in
  `sverb-tui::theme::color`.
- Theme changes apply live on config reload.
- **Delete** the template `Styles` and `parse_style` machinery.

### 2.4 Toasts and notification history (§8.7)
- Toasts appear top-right, stacked, at most 3 visible, each ≤ 50 columns wide and wrapped to ≤ 3 lines.
- Levels: info, success, warning (fade after 4 s via `ScheduleTimer`), and error (sticky until dismissed
  with `leader !` → history, or `Esc` when the toast stack is focused).
- History: the last 100 notifications, viewable with `leader !` as a list overlay with timestamps
  (`ui.date_format`), level, short message and expandable detail chain (`ErrorReport`).
- Duplicate toasts (same level and message within 2 s) are coalesced with a counter `(×3)`.

### 2.5 Which-key popup and help
- Render the which-key popup (M0-10) bottom-right, above the status bar, as a multi-column list of
  `key → description` grouped by category.
- `leader ?` opens a full-screen help overlay listing the effective keymap (`Keymap::effective`),
  searchable with `/`.

### 2.6 Debug log pane (§18)
With `--debug`, `leader D` toggles a bottom split (30% height) showing the M0-04 debug ring, auto-scrolling,
with `PageUp/PageDown` scrolling when focused and a level color per line. Without `--debug` the action is
unbound and absent from which-key.

### 2.7 Quit and empty state
On first launch (before vault work exists), the Hosts section shows an empty state: "No hosts yet ·
`a` add · `leader o` quick connect". Quit works via `leader q` (and `q` in Normal mode).

## 3. Codebase changes
- **Delete** `crates/sverb/src/components/home.rs` (already moved by M0-08; delete it now).
- **Create** the files listed in the header. `views/shell.rs` computes layout `Rect`s through a pure function
  `layout(area, &ShellState, &Config) -> ShellRects`, unit-testable without rendering.
- **Create** `sverb-tui/src/theme/color.rs` (downsampling) and `theme/builtin.rs`.

## 4. Test cases to implement

### Layout (pure function)
**T-01 (unit, table)** `layout()` for sizes (40×10, 79×24, 80×24, 99×30, 100×30, 160×48, 300×100) with
`sidebar=auto` produces the expected sidebar visibility, overlay mode, and status-bar merge (height 23 vs 24).

**T-02 (unit)** `sidebar = always` at 60 columns → overlay sidebar visible. `never` at 200 → hidden.

**T-03 (unit)** Below 40×10 → the "too small" state.

### Snapshots (`insta`, `TestBackend`)
**T-04** Initial screen at 80×24 and 160×48 (§19 sizes) with `default-dark`.

**T-05** The same with `NO_COLOR=1`: the snapshot shows no color attributes, and the selection is reverse+bold
(assert on buffer cell modifiers, not just text).

**T-06** `default-light` and `high-contrast` at 80×24.

**T-07** The which-key popup open at 80×24 and 160×48.

**T-08** The help overlay at 80×24.

**T-09** Three toasts (info, warn, error) at 80×24, and the error toast is still present after 4 s of virtual time
while the others are gone.

**T-10** Status bar truncation at 60 columns: low-priority segments are dropped first, and the mode and help hint
stay.

**T-11** Height 20: the status segments render inside the tab-bar row.

### Behavior (reducer)
**T-12** `leader s` toggles the sidebar. `tab` cycles focus Sidebar → Main → Detail → Sidebar.

**T-13** Selecting a sidebar section with `j/k` + `enter` (or arrows) switches the main view.

**T-14** Duplicate toasts within 2 s coalesce into `(×2)`.

**T-15** With `--debug`, `leader D` shows the log pane with ring contents. Without `--debug` the action is
unbound.

**T-16** A config reload changing `ui.theme` re-renders with the new theme (the snapshot differs).

### Color
**T-17 (unit)** Downsampling: pure red `#ff0000` → index 196, `#808080` → nearest gray in 232–255, and
the 16 base ANSI colors map to themselves.

**T-18 (unit)** `COLORTERM=truecolor` + `auto` → truecolor. Unset → 256.

### Integration
**T-19 (PTY)** `sverb` launches, shows the shell (look for "Hosts" in the PTY output), and `ctrl-\ q` exits 0
with the terminal restored. This is the M0 exit criterion.

## 5. Passing functional characteristics
- [ ] The shell renders the top bar, sidebar, main area and status bar as in §8.1, with responsive rules at 100, 80
      and 24 boundaries and a "too small" state.
- [ ] The sidebar lists the 7 sections, toggles with `leader s`, and honors `ui.sidebar`.
- [ ] Three built-in UI themes exist, switch live, and `NO_COLOR` gives a fully usable monochrome UI.
- [ ] Colors downsample correctly without truecolor.
- [ ] Toasts follow §8.7: 4 s fade, sticky errors, history under `leader !`.
- [ ] The which-key popup, help overlay and debug log pane work.
- [ ] Snapshot tests exist for 80×24 and 160×48 and pass in CI.
- [ ] The template `Home` and `Styles` code is gone. The M0 exit criterion holds: `sverb` opens and quits
      cleanly.
