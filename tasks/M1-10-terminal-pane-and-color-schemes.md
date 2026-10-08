# M1-10 — `TerminalPane` widget rendering and terminal color schemes

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-term/src/render.rs` (Emulator::render impl), `crates/sverb-term/src/scheme/{mod.rs, builtin/*.toml, import_alacritty.rs, import_kitty.rs}`, `crates/sverb-tui/src/widgets/terminal_pane.rs`, `crates/sverb-tui/src/theme/color.rs` (shared downsampling from M0-11) |
| **Spec refs** | §7.2, §7.4, §4.2 (`color_scheme` per host), §15 (`terminal.color_scheme`, `ui.truecolor`), §19 (perf: 300×100 frame < 2 ms) |
| **Depends on** | M1-09, M0-11 |
| **Blocks** | M1-17, M3-04, M3-05, M6-03 |

---

## 1. Current state in the codebase
M0-11 implemented UI themes and RGB→256 downsampling in `sverb-tui::theme::color`. M1-09 provides the emulator.
Nothing renders terminal content yet.

## 2. Detailed description

### 2.1 Render path (§7.2)
`Emulator::render(&self, area: Rect, buf: &mut Buffer, view: &ViewState)`:
- `ViewState` holds the scroll offset (lines up into scrollback; 0 = live), `focused: bool`,
  selection (M3-04), search matches, hovered hyperlink, the color scheme, color depth
  (`TrueColor | Ansi256 | Ansi16 | Mono`), and `broadcast_highlight` (border is drawn by the pane widget, not here).
- Walk the visible rows of `alacritty_terminal::Term::grid()` at the display offset and write each cell into `buf`:
  - **Flags → `Modifier`:** BOLD, DIM, ITALIC, UNDERLINE (all underline styles map to UNDERLINED; curly
    and dotted need the outer terminal to support them, so fall back to underline), INVERSE → REVERSED,
    HIDDEN → HIDDEN, STRIKEOUT → CROSSED_OUT.
  - **Wide chars:** write the char to the first cell and skip the `WIDE_CHAR_SPACER` cell (ratatui handles
    the width, so leave the spacer cell untouched or set it to an empty symbol per ratatui convention).
  - **Combining characters:** append zero-width chars to the cell symbol (`cell.zerowidth()`).
  - **Colors:** resolve `Named`/`Indexed`/`Spec(Rgb)` through the pane's `ColorScheme` (16 ANSI + fg/bg/cursor +
    the 256 palette, with indices 16–255 computed per xterm if the scheme doesn't define them). Then downsample by color
    depth: truecolor → `Color::Rgb`. 256 → nearest index (shared function). 16 → nearest of the 16. Mono →
    `Color::Reset`, keeping modifiers.
  - **`terminal` scheme (default, §7.4):** **no remapping**. Named and indexed colors are emitted as
    `Color::Indexed(n)` or `Color::Reset` (default fg/bg), so the outer terminal's own palette is used. Only RGB
    cells are downsampled when needed.
- **Cursor:**
  - Focused pane: the reducer sets `frame.set_cursor_position` to the pane-relative cursor when visible and the
    view is not scrolled back. The cursor shape is passed through with `DECSCUSR` (the runtime layer writes
    `ESC[n q` when the shape changes, from `TermModes.cursor_shape`).
  - Unfocused panes: draw a **hollow cursor** cell (reverse of the underline style, or a `▯`-style box via
    UNDERLINED+DIM). Document the choice and keep it consistent in snapshots.
- **Overlays**, drawn after cells: selection (REVERSED), search matches (theme `selection` bg), current match
  (accent), and URL hover (underlined + accent).
- **Scrolled back:** show a `[scroll: N/M]` indicator in the top-right corner of the pane.
- **Locking:** the render pass locks the emulator mutex briefly (copy cells into `buf`), never across `.await`
  (M1-08). Rendering is synchronous, so this is natural.
- **Performance target:** < 2 ms for a 300×100 grid (§19). Avoid per-cell allocations (reuse a `String` for
  symbols, and use `Buffer::cell_mut` directly).

### 2.2 Color schemes (§7.4)
- `ColorScheme { name, foreground, background, cursor, selection_bg?, ansi: [Rgb; 16], extended:
  Option<[Rgb; 240]> }`.
- **Built-ins** (TOML files embedded with `include_str!`): `sverb-dark`, `sverb-light`, `dracula`,
  `solarized-dark`, `solarized-light`, `gruvbox` (dark), `nord`, `catppuccin-latte`,
  `catppuccin-frappe`, `catppuccin-macchiato`, `catppuccin-mocha`, `tokyo-night`, `one-dark`, `monokai`,
  and `terminal` (a special marker with no palette). Use the canonical upstream palettes and cite the sources in file
  comments (all MIT-compatible).
- **User schemes:** `config_dir/themes/*.toml` (sverb format, documented in `docs/themes.md`), loaded at
  startup and on change (reuse the M0-06 watcher pattern).
- **Import** (§7.4): `sverb` imports **Alacritty** (`.toml`, and legacy `.yml` colors section) and **Kitty**
  (`.conf` `color0..15`, `foreground`, `background`, `cursor`) theme files into the sverb format. Where's the UI entry
  point? Settings → Appearance → "Import theme file…" (a file path prompt). Also a hidden CLI `sverb import theme <file>`.
  The spec doesn't list this command, so record it as an addition.
- **Scope:** a scheme applies to a host's **pane content** only (per-host `color_scheme`, falling back to
  `terminal.color_scheme`). sverb chrome uses the UI theme (M0-11). Panes re-render on config or scheme change.
- Implements the `ThemeCatalog` validation hook from M0-06 for `terminal.color_scheme` and the host field.

### 2.3 `TerminalPane` widget (`sverb-tui`)
Wraps the emulator render plus a border (focused/unfocused/broadcast styles), a title line (host label or OSC title
per `terminal.use_osc_title`), and state overlays: connecting spinner, disconnected banner (M1-16), lock overlay
(M1-04), and "session crashed". Its pixel size is computed from the outer terminal's cell size (crossterm
`window_size()`, or 0 if unknown) for `TextAreaSizeRequest` and `window_change` pixel params.

## 3. Codebase changes
- **Create** `sverb-term::render` and `sverb-term::scheme`, with the built-in TOML files.
- **Create** `sverb-tui::widgets::terminal_pane`.
- **Move** the downsampling function from `sverb-tui::theme::color` into `sverb-term::color` (sverb-term can't
  depend on sverb-tui), and re-export it from the TUI.
- **Docs:** `docs/themes.md`.

## 4. Test cases to implement

**T-01 (snapshot)** Render the fixtures from M1-09 (vim, htop, less) into a `TestBackend` at 80×24. The snapshot
includes styles (use `insta` with a buffer→styled-text serializer that encodes fg/bg/modifiers per cell run).

**T-02 (unit) Modifiers.** Every SGR attribute (1, 2, 3, 4, 4:3, 7, 8, 9) maps to the expected `Modifier`.

**T-03 (unit) Wide chars.** `a中b` → cells `a`, `中`, (spacer), `b`, and `b` is at column 3.

**T-04 (unit) Combining.** `e\u{301}` renders as one cell with the symbol `é` (decomposed).

**T-05 (unit) `terminal` scheme.** SGR 31 → `Color::Indexed(1)`. The default fg → `Color::Reset`. 24-bit
`38;2;255;0;0` with truecolor → `Rgb(255,0,0)`. With 256 → `Indexed(196)`.

**T-06 (unit) Named scheme remap.** With `dracula`, SGR 31 → Dracula red RGB (truecolor) or its nearest index (256).

**T-07 (unit) Mono.** With `NO_COLOR`, all colors are Reset, and bold and inverse are preserved.

**T-08 (unit) Cursor.** Focused → cursor position set, no hollow cell. Unfocused → a hollow cell at the cursor and
no terminal cursor. Scrolled back → no cursor shown.

**T-09 (unit) Scroll indicator** appears when the offset is > 0.

**T-10 (unit) Built-in schemes** all parse, and each defines 16 ANSI colors + fg + bg.

**T-11 (unit) Alacritty import.** A fixture `tests/fixtures/themes/alacritty_dracula.toml` → scheme equal
to the expected values. Same for the legacy YAML.

**T-12 (unit) Kitty import.** Fixture `kitty_nord.conf` → expected scheme.

**T-13 (unit) Invalid user scheme** (missing color4) → error naming the field. Other schemes still load.

**T-14 (reducer)** Changing the host's scheme in the form re-renders that pane only.

**T-15 (bench)** Render a full 300×100 grid with dense SGR in < 2 ms (criterion; the gate is enforced in M7-06).

## 5. Passing functional characteristics
- [ ] Terminal content renders with correct attributes, wide and combining chars, cursor (focused vs hollow) and
      overlays.
- [ ] Colors resolve through the pane's scheme and downsample correctly to 256, 16 or mono.
- [ ] The default `terminal` scheme leaves the outer terminal's palette untouched.
- [ ] All built-in schemes from §7.4 exist. User schemes load from `themes/*.toml`, and Alacritty/Kitty themes import.
- [ ] Schemes apply per host to pane content only, and the chrome uses the UI theme.
- [ ] Rendering a 300×100 grid takes < 2 ms.
