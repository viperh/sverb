# Accessibility

sverb is a full-screen terminal application. This page records the accessibility audit
done for 1.0 (task M7-07; SPEC §8.8, §21 M7). It also lists the settings that help, and
the limits of a TUI.

## Settings

| Setting | Effect |
|---|---|
| `NO_COLOR=1` (environment) | No colors anywhere. Focus and selection use reverse video and bold. |
| `ui.theme = "high-contrast"` | A high-contrast color theme. |
| `ui.ascii = "auto" \| "on" \| "off"` | ASCII glyphs instead of box drawing and symbols (`+ - \|` borders, `+` check, `x` cross, `*` bullet, `>` pointer, `!` warning, `L` lock). `auto` (the default) switches to ASCII when the locale (`LC_ALL`, `LC_CTYPE`, `LANG`) isn't UTF-8, or when `TERM=linux`. In ASCII mode, session content that isn't ASCII is shown as `?`. |
| `ui.reduce_motion = true` | Spinners show a static glyph. Nothing else in the UI animates: countdowns are numbers, and the cursor blink belongs to your terminal. |
| `ui.show_which_key`, `ui.which_key_delay_ms` | Show the which-key popup after the leader, and set how long it takes to appear. |
| `ui.mouse = false` | Leave the mouse to the terminal. sverb never needs the mouse. |
| `general.leader` | Pick a leader chord that is easy to reach (default `Ctrl-\`, or `ctrl-g`). |

## Audit results

**Keyboard.** Every action in the keymap registry has a default key or a command-palette
entry (`Ctrl-k`). The test `app::a11y_tests::t06_every_action_is_bound_or_in_the_palette`
enforces this. Five actions are listed in the palette only while a sync server is
connected (`share_pane`, `sync_status`, `sync_now`, `devices`, `team_keys`). Views have
their own keys, documented in [keybindings.md](keybindings.md#view-keys). Dialogs use
mnemonic letters, `Enter` and `Esc`.

**Color is never the only signal.** These indicators were checked with `NO_COLOR` and
ASCII output. They are covered by snapshots in
`crates/sverb-tui/src/app/snapshots/sverb_tui__app__a11y_tests__*` and by the existing
`NO_COLOR` snapshots of each view.

| Indicator | Text or glyph |
|---|---|
| Mode | `NORMAL`, `TERMINAL`, `COPY`, `INSERT`, `RESIZE` in the status bar |
| Broadcast input | `BROADCAST ×N` in the status bar, a bold border on receiving panes, and a marker on the tab |
| Recording | `REC ●` in the status bar |
| Sync state | Status text in the top bar (for example `synced`, `offline`, `error`); the color only repeats it |
| Toasts | A title with the level (`info`, `ok`, `warning`, `error`). Errors stay until dismissed, and `leader !` shows the history. |
| Focus and selection | Reverse video and bold |
| Locked vault | `🔒`, or `[L]` in ASCII mode, plus the unlock screen |
| Disconnected or exited panes | A banner with the reason and the keys to press |
| Host key changed | The full `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED` headline |
| Team keys | `✓` verified, or "key changed" spelled out |
| Pinned hosts and tags | Tag chips show `[name]` in monochrome |

**Tests.**
- `app::a11y_tests::t06_status_indicators_have_text_in_no_color_and_ascii` renders the
  Hosts view with toasts of every level, and a broadcast tab of three panes. It checks
  that the labels are there, that no cell has a color, and that every cell is ASCII.
- `ascii_auto_follows_the_environment` and `reduce_motion_freezes_the_spinner` cover the
  two new settings.
- `runtime::capabilities` tests cover the locale and `TERM=linux` detection.

## Screen readers

TUIs are hard for screen readers: the screen is redrawn in place, and there is no
accessibility tree. With that in mind:

- The status bar is the stable place for the current state: mode, broadcast, recording
  and hints. Reading the last screen line tells you where you are.
- Toasts appear at the top right, and errors stay until dismissed. `leader !` lists the
  last 100 notifications as text.
- Use `ui.reduce_motion = true` so a spinner doesn't trigger constant re-reads, and set
  `ui.show_which_key = false` if the popup is noisy (`leader ?` lists every binding
  instead).
- The headless commands (`sverb hosts list --json`, `sverb snippet run … --json`,
  `sverb sync --status`, `sverb doctor --ascii`) give the same information as plain,
  line-oriented output, which works well with screen readers and Braille displays.
- Terminal emulators with good screen-reader support (for example Windows Terminal with
  NVDA, or macOS Terminal with VoiceOver) read the session text. Results vary with the
  remote program, as with any TUI.
