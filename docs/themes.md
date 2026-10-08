# Terminal color schemes

Terminal color schemes color the **content of session panes** (SPEC §7.4). The sverb chrome
(sidebar, borders, status bar) uses the separate UI theme (`ui.theme`).

## Choosing a scheme

- `terminal.color_scheme` in `config.toml` sets the default for every pane. It applies live.
- A host's `color_scheme` field overrides it for that host's panes.
- The default, `terminal`, does no remapping: named and indexed colors are sent as-is, so
  your outer terminal's own palette is used. Only 24-bit colors are downsampled when the
  outer terminal lacks truecolor.

## Built-in schemes

`terminal`, `sverb-dark`, `sverb-light`, `dracula`, `solarized-dark`, `solarized-light`,
`gruvbox`, `nord`, `catppuccin-latte`, `catppuccin-frappe`, `catppuccin-macchiato`,
`catppuccin-mocha`, `tokyo-night`, `one-dark`, `monokai`. Each built-in file cites the
upstream palette it comes from (`crates/sverb-term/src/scheme/builtin/`).

## User schemes

Put `*.toml` files in `<config dir>/themes/` (for example `~/.config/sverb/themes/`). They are
loaded at startup. A broken file is logged with the field at fault (for example
``missing `colors.color4` ``) and skipped; the other schemes still load. A user scheme cannot
reuse a built-in name.

```toml
name = "my-scheme"          # optional; defaults to the file name without .toml

[colors]
foreground = "#c0caf5"      # required
background = "#1a1b26"      # required
cursor = "#c0caf5"          # optional, defaults to the foreground
selection_bg = "#283457"    # optional
color0 = "#15161e"          # color0 … color15 are required
color1 = "#f7768e"
# … color2 to color15
# color16 … color255 are optional; missing ones use the xterm defaults
```

Colors are `#rrggbb`, `#rgb` or `0xrrggbb`. Unknown keys are rejected so a typo doesn't
silently fall back.

## Importing Alacritty and Kitty themes

sverb converts these formats to its own:

- Alacritty `.toml` (`[colors.primary]`, `[colors.cursor]`, `[colors.selection]`,
  `[colors.normal]`, `[colors.bright]`, `[[colors.indexed_colors]]`) and the legacy `.yml`
  `colors:` section,
- Kitty `.conf` (`foreground`, `background`, `cursor`, `selection_background`,
  `color0` … `color255`).

The library entry point is `sverb_term::scheme::import_into(file, themes_dir)`, which writes
`themes/<name>.toml` named after the file. The UI entry (Settings → Appearance → "Import theme
file…") and the hidden `sverb import theme <file>` command (an addition to the spec) are not
wired yet.

## Color depth

Pane content follows `ui.truecolor` and `COLORTERM` like the chrome: truecolor shows RGB,
otherwise colors map to the nearest xterm-256 entry (CIELAB distance). 16-color output maps to
the 16 base colors, and `NO_COLOR` drops all colors while keeping bold, reverse and the other
attributes.
