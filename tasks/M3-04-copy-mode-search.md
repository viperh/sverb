# M3-04 — Copy mode, selection, scrollback search, hyperlinks

| | |
|---|---|
| **Milestone** | M3 |
| **Touches** | `crates/sverb-tui/src/views/sessions/copy_mode.rs`, `crates/sverb-term/src/{selection.rs, search.rs}`, `widgets/terminal_pane.rs` (overlays), mouse selection in `runtime/input` |
| **Spec refs** | §8.2 (Copy mode: vim motions, `/`/`?`, `v/V/Ctrl-v`, `y` OSC 52, `Esc`), §7.1 (selection, regex search, OSC 8), §7.3 (mouse selection when not captured by remote), §15 `terminal.word_separators`, §17 (hyperlink opening needs a keypress) |
| **Depends on** | M1-10, M1-11 |
| **Blocks** | — |

---

## 1. Current state in the codebase
The emulator exposes `search` and `grid_text` (M1-09). The renderer draws selection and match overlays from `ViewState` (M1-10). `leader [` is bound (M0-10) but does nothing.

## 2. Detailed description
- **Enter** with `leader [`: mode Copy (status bar `COPY`). A copy cursor starts at the terminal cursor. Output keeps flowing, but the view **freezes** at the current
  scroll offset (new output increments a "+N lines" indicator instead of scrolling).
- **Motions:** `h j k l`, arrows, `w b e` (word boundaries per `terminal.word_separators`), `W B E` (whitespace words), `0 ^ $`, `g g`/`G`
  (top of scrollback / bottom), `H M L` (screen top, middle, bottom), `ctrl-u/ctrl-d` half page, `ctrl-b/ctrl-f` page, counts (`5j`), `{`/`}`
  (blank-line paragraphs).
- **Selection:** `v` character-wise, `V` line-wise, `ctrl-v` block (rectangular). `o` swaps the anchor. Selection is rendered via `ViewState.selection`.
- **Yank:** `y` copies the selection text (trailing whitespace trimmed per line; wrapped lines joined without newline) via `Effect::CopyToClipboard`
  (OSC 52 / arboard, M1-11), then exits copy mode. `Y` yanks the current line.
- **Search:** `/` forward and `?` backward, with a regex (Rust `regex`; invalid regex → inline error, falling back to literal). `n`/`N` next/previous, with wrap-around and
  a "search wrapped" message. All visible matches are highlighted, and the current match is accented. The match count is shown when cheap (cap counting at 1,000).
- **Exit:** `Esc`, `q` or `ctrl-c` → back to Terminal mode and the live view.
- **Mouse** (when the remote hasn't captured it, or with Shift held): drag selects (character-wise), double-click selects a word, triple-click selects a line.
  The selection is copied on mouse release? **Decision:** copy on release (common terminal behavior), with a toast "Copied N chars".
  Wheel scrolls the scrollback in Terminal mode without entering copy mode.
- **Hyperlinks** (OSC 8 and auto-detected URLs): hovering (mouse) or putting the copy cursor on a link shows the URL in the status bar. **Opening requires an
  explicit key** (`o` in copy mode, or `ctrl-click`), and always shows the URL in a confirm dialog first (§17), then opens via the `open` crate.

## 3. Codebase changes
- `sverb-term::selection` (pure: selection model over grid coordinates, text extraction, block selection), `sverb-term::search` (regex across
  scrollback with line joining for wrapped rows), the copy-mode view and keymap table (`[keys.copy]` override table added to config, M0-06 schema update).

## 4. Test cases to implement

**T-01 (unit)** Word motions honor `word_separators` (e.g. `w` stops at `:` in `host:22`).

**T-02 (unit)** Selection text extraction: char-wise across a wrapped line → no newline inserted. Line-wise → trailing spaces trimmed. Block over 3 lines
→ columns 2–5 of each.

**T-03 (unit)** Wide chars inside a selection are extracted once.

**T-04 (unit)** Regex search backwards across scrollback finds the previous match, and `n` wraps with a flag.

**T-05 (unit)** An invalid regex `(` → error, then a literal search.

**T-06 (reducer)** `leader [` → Copy mode, `v` + motions + `y` → a `CopyToClipboard` effect with the expected text, and mode back to Terminal.

**T-07 (reducer)** New output while in copy mode doesn't move the view, and the indicator counts lines.

**T-08 (reducer)** Mouse drag selection plus release → copy effect. Shift-drag works even when the remote captures the mouse.

**T-09 (reducer)** `o` on a hyperlink → a confirm dialog with the URL. Confirm → an `OpenUrl` effect. There's no open without confirmation.

**T-10 (snapshot)** Copy mode with a selection and search highlights at 80×24.

**T-11 (unit)** Counts: `5j` moves 5 lines, `3w` moves 3 words.

## 5. Passing functional characteristics
- [ ] `leader [` enters a vim-style copy mode with motions, counts, `/`/`?` regex search with `n`/`N`, and `v`/`V`/`ctrl-v` selections.
- [ ] `y` yanks through OSC 52 / the local clipboard with correct line joining and trimming.
- [ ] Mouse selection works when the remote isn't capturing (or with Shift).
- [ ] Hyperlinks show the URL and open only after an explicit key plus confirmation.
