# M1-11 — Input encoding: keys, kitty protocol, mouse, paste, clipboard

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-term/src/input/{keys.rs, mouse.rs, paste.rs}`, `crates/sverb-tui/src/runtime/terminal.rs` (kitty flag detection and push), `crates/sverb-tui/src/services/clipboard.rs`, `crates/sverb-tui/src/views/sessions.rs` (routing) |
| **Spec refs** | §7.3, §4.2 (`backspace`), §9.8 (per-pane encoding for broadcast), §17 (OSC 52 policy), §19 (key → bytes table tests) |
| **Depends on** | M1-09, M0-10 |
| **Blocks** | M1-17, M3-02, M3-04 |

---

## 1. Current state in the codebase
- `crates/sverb/src/tui.rs` (now `sverb-tui::runtime`) never enables the kitty keyboard protocol, so
  `Ctrl-I` and `Tab` are indistinguishable.
- M0-10 delivers `KeyChord`s to the reducer. In Terminal mode, non-leader keys produce
  `Effect::SendToSession` with a placeholder raw encoding (`Char(c)` → UTF-8 only).
- Bracketed paste capture is on (M0-09), so `InputEvent::Paste(String)` arrives, but it isn't forwarded yet.

## 2. Detailed description

### 2.1 Outer terminal: kitty keyboard protocol
- At startup, query support with crossterm `supports_keyboard_enhancement()` (it sends `CSI ? u` and
  waits briefly). If supported, push `DISAMBIGUATE_ESCAPE_CODES | REPORT_ALTERNATE_KEYS` (§7.3), and record
  the `KITTY_FLAGS` bit (M0-05) so restore pops them. **Don't** enable `REPORT_EVENT_TYPES` (release events aren't needed) or
  `REPORT_ALL_KEYS_AS_ESCAPE_CODES`.
- Degrade gracefully when unsupported (§1 goals): legacy parsing, where `ctrl-i` == `tab`.

### 2.2 Key → bytes encoder (`sverb-term::input::keys`)
`encode_key(chord: KeyChord, modes: &TermModes, opts: &EncodeOpts{ backspace: Del|CtrlH }) ->
Option<Bytes>`. A pure function, encoded **per pane** using that pane's modes (§7.3). It's called in the session
actor (`SessionCmd::Key`), so broadcast targets encode with their own modes (§9.8).
Required encodings (minimum, table-tested):

| Key | Normal | DECCKM set |
|---|---|---|
| Up/Down/Right/Left | `ESC [ A/B/C/D` | `ESC O A/B/C/D` |
| Home/End | `ESC [ H` / `ESC [ F` | `ESC O H` / `ESC O F` |
| Ctrl-Up (any modified arrow) | `ESC [ 1 ; 5 A` (mod param: 2 shift, 3 alt, 4 shift+alt, 5 ctrl, 6 ctrl+shift, 7 ctrl+alt, 8 all) | same (modified keys ignore DECCKM) |
| Enter | `\r` | `\r` |
| Backspace | `\x7f` (or `\x08` if host `backspace = CtrlH`) | same |
| Alt-x | `ESC x` | same |
| F1–F4 | `ESC O P/Q/R/S` | same |
| F5 / F6–F12 | `ESC [ 1 5 ~` / `17~ 18~ 19~ 20~ 21~ 23~ 24~` | same |
| Shift-Tab | `ESC [ Z` | same |
| Tab | `\t` | same |
| Esc | `\x1b` | same |
| Insert/Delete/PgUp/PgDn | `ESC[2~` `ESC[3~` `ESC[5~` `ESC[6~` | same |
| Ctrl-a … Ctrl-z | `0x01 … 0x1a` | same |
| Ctrl-space / Ctrl-@ | `0x00` | same |
| Ctrl-[ \ ] ^ _ | `0x1b 0x1c 0x1d 0x1e 0x1f` | same |
| Ctrl-? / Ctrl-Backspace | `0x7f` / `0x08` | same |
| Keypad keys | normal digits | `ESC O p…y` when DECKPAM |

- **modifyOtherKeys** (when the remote set `CSI > 4 ; 2 m`): encode ambiguous ctrl combos as `CSI 27 ; mod ; code ~`.
- **Kitty protocol, remote side:** if the remote app pushed kitty flags (`CSI > flags u`), tracked by the
  emulator in `TermModes`, encode keys per the kitty spec (`CSI code ; mods u`) for disambiguation.
- Unicode chars: UTF-8, then charset-encode (M1-09 §2.3) in the write path.
- Leader handling stays in the reducer (M0-10): the encoder never sees the leader except for the literal double press.

### 2.3 Mouse (§7.3)
- If the remote enabled mouse reporting (1000/1002/1003) and the event is inside the pane and **Shift is not
  held**, translate to pane-relative 1-based coordinates and encode: SGR (1006) as `CSI < b ; x ; y M/m`,
  default X10 as `CSI M Cb Cx Cy` (coords capped at 223), 1015 urxvt if requested. 1000 sends press and release only.
  1002 adds drag. 1003 adds all motion.
- Otherwise the mouse drives sverb: click to focus a pane, wheel to scroll back (3 lines per notch), drag to
  select (M3-04), click a tab, click the sidebar. **Shift always gives the mouse to sverb** (§7.3).
- Wheel events when the remote has the alt screen and no mouse mode: send Up/Down arrow keys (3 per notch), as most
  terminals do (`alternateScroll`). Document this.

### 2.4 Paste (§7.3)
- `InputEvent::Paste(text)` to a pane:
  - remote bracketed paste on → send `ESC[200~` + text (with any `ESC[201~` inside the text **stripped**, to
    prevent paste injection) + `ESC[201~`,
  - off, and the text contains a newline, and `terminal.paste_confirm_multiline` → confirm dialog "Paste N lines
    into <host>?" with a preview of the first 5 lines,
  - newlines are normalized to `\r` when bracketed paste is off.
- Paste goes through broadcast (M3-02) when broadcast is active.

### 2.5 Clipboard (§7.3)
- **Copy** (from copy mode and actions such as "copy public key"): `Effect::CopyToClipboard(text)` →
  the clipboard service writes **OSC 52** to the outer terminal (`ESC]52;c;<base64>BEL`) when `clipboard.osc52 = true`
  (works over SSH), **and/or** `arboard` locally. Strategy: if `SSH_CONNECTION` or `SSH_TTY` is set (sverb itself runs
  over SSH), use OSC 52 only. Otherwise try `arboard`, plus OSC 52 if enabled. Cap OSC 52 payloads at 100 KB (many
  terminals reject larger), with a toast if truncated.
- **Remote OSC 52 writes** (from M1-09 `ClipboardWriteRequest`): policy `clipboard.allow_remote_write`:
  `never` → ignore (debug log), `always` → copy, `ask` → a dialog "<host> wants to set your clipboard (N chars)
  [a]llow once / allow [f]or this session / [d]eny", with a preview of the first 200 chars.
- Remote OSC 52 **reads** are always denied (M1-09).

## 3. Codebase changes
- **Create** `sverb-term::input` modules and the clipboard service. Deps: `base64`, `arboard` (optional on
  headless Linux; failure is non-fatal).
- **Modify** the runtime terminal setup for kitty detection.
- **Modify** the Terminal-mode reducer path to emit `SendToSession(Key(chord))` instead of raw bytes.

## 4. Test cases to implement

**T-01 (unit, table)** All rows of the table in §2.2 (≥ 60 rows), in both DECCKM states, with the backspace variants.

**T-02 (unit, table)** Modified arrows and function keys with all 7 modifier combos.

**T-03 (unit) Alt + Unicode.** `alt-é` → `ESC` + UTF-8 bytes of `é`.

**T-04 (unit) modifyOtherKeys.** With level 2, `ctrl-i` → `CSI 27;5;105~`, and `tab` → `\t`.

**T-05 (unit) Remote kitty mode.** With flags 1 pushed, `ctrl-i` → `CSI 105;5u`.

**T-06 (unit) Per-pane encoding.** The same `Up` chord to two sessions with different DECCKM → `ESC[A` vs `ESC OA`.

**T-07 (unit, table) Mouse SGR.** A click at pane (0,0) → `CSI <0;1;1M`, and release → `...m`. Wheel up → button 64.
Shift-click → not forwarded (routed to sverb).

**T-08 (unit) X10 coordinate cap.** Clicking at column 300 → no event, or a clamped one per xterm (document which).

**T-09 (unit) Mode 1000 drag** → not forwarded. 1002 → forwarded as motion with button.

**T-10 (unit) Alternate scroll.** Alt screen, no mouse mode, wheel down → 3× `ESC[B`.

**T-11 (unit) Bracketed paste.** Wrapped correctly, and an embedded `ESC[201~` is stripped.

**T-12 (reducer) Multi-line paste confirm** when not bracketed. Cancel → nothing sent. Confirm → newlines as `\r`.

**T-13 (unit) OSC 52 copy format** and the 100 KB cap.

**T-14 (reducer) Remote clipboard `ask`.** The dialog appears. "Allow for session" → subsequent requests from that pane
are copied silently. "Deny" → nothing.

**T-15 (integration, PTY)** With a fake outer terminal that answers the kitty query, the push sequence `CSI > 3 u`
(flags) is emitted and popped on exit.

**T-16 (fuzz stub)** `fuzz_targets/key_encoder.rs`: arbitrary chords and modes never panic.

## 5. Passing functional characteristics
- [ ] Keys are encoded per pane according to DECCKM, DECKPAM, modifyOtherKeys and remote kitty mode, and the reference table
      in §7.3 passes.
- [ ] The kitty keyboard protocol is used on the outer terminal when available and popped on exit. Without it, sverb degrades
      gracefully.
- [ ] The mouse goes to the remote when requested (SGR/X10/urxvt), otherwise to sverb. Shift always overrides.
- [ ] Paste respects bracketed paste, strips injection terminators, and confirms multi-line non-bracketed pastes.
- [ ] Copy uses OSC 52 and/or a local clipboard. Remote clipboard writes follow `never|ask|always`, and reads are never allowed.
- [ ] `backspace = CtrlH` per host is honored.
