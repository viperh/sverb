# M0-10 — Keymap, leader key, modes and which-key

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/config.rs:130-323` + tests `454-603` → `crates/sverb-tui/src/keymap/{chord.rs, action.rs, keymap.rs, leader.rs, whichkey.rs, dump.rs}`; `crates/sverb/src/app.rs:30-37,113-137` (Mode, key handling); `crates/sverb/src/cli/keys.rs` (`--dump`); `docs/keybindings.md` |
| **Spec refs** | §8.2, §8.3, §15 (`general.leader`, `ui.show_which_key`, `ui.which_key_delay_ms`, `[keys.*]`), §16 (`sverb keys --dump`) |
| **Depends on** | M0-06, M0-08 |
| **Blocks** | M0-11, M1-11 (terminal mode passthrough), every feature with a keybinding |

---

## 1. Current state in the codebase
- `app.rs:33-37`: `enum Mode { Normal }`, with only one mode.
- `app.rs:114-137`: looks up `vec![key]` in the keymap for the current mode, and otherwise appends to
  `last_tick_key_events` and looks up the whole buffer. The buffer is cleared **only on Tick**
  (app.rs:147), so:
  - a sequence that doesn't match keeps growing until the next tick,
  - after a sequence matches, the buffer isn't cleared, so a subsequent key in the same tick
    produces a 3-key buffer,
  - timing depends on `--tick-rate`.
- `config.rs:130-153`: `KeyBindings` deserializer, which `unwrap()`s parse errors.
- `config.rs:155-234`: `parse_key_event` handles `ctrl-`/`alt-`/`shift-` prefixes, named keys, single
  chars, and uppercases chars with shift. It doesn't support `space` combined with ctrl
  (`ctrl-space` → `Char(' ')` + CONTROL works, but terminals report it as `Char(' ')`/`Null`
  differently), `|`, `\`, `[`, or F-keys beyond 12.
- `config.rs:236-297`: `key_event_to_string` renders `F(5)` as `"f(5)"` (line 254), which
  `parse_key_event` can't read back. Modifier order is ctrl, shift, alt, while the parser accepts any order.
- `config.rs:299-323`: `parse_key_sequence` uses the `<a><b>` syntax. The spec's TOML keys are plain
  chords (`"p"`, `"ctrl-k"`), with sequences implied by the leader.
- Tests at `config.rs:522-602` cover simple keys, modifiers, case-insensitivity and invalid keys. Reuse
  them.
- `.config/config.json` binds `q`, `Ctrl-c`, `Ctrl-d` → Quit, `Ctrl-z` → Suspend, `Ctrl-h` → Help.
  In sverb, `Ctrl-c`/`Ctrl-d`/`Ctrl-z`/`Ctrl-h` must go **to the remote shell** in terminal mode, so
  these defaults are wrong for the product.

## 2. Detailed description

### 2.1 Key chords (`keymap::chord`)
- `KeyChord { code: KeyCode, mods: Mods }`, sverb's own type, converted from crossterm `KeyEvent` in
  the runtime layer. Normalization rules:
  - for `Char(c)` with SHIFT where `c` is a letter: store the uppercase char **without** SHIFT (`L`
    means shift-l), because terminals differ in whether they report SHIFT for uppercase,
  - `ctrl-space` is normalized from `Char(' ')+CONTROL`, `Null` or `Char('@')+CONTROL` (legacy encodings),
  - `BackTab` is normalized to `Tab + SHIFT`,
  - legacy control bytes for punctuation: crossterm reports `0x1C`–`0x1F` as `Char('4')`…`Char('7')` +
    CONTROL. Map `ctrl-4` ↔ `ctrl-\` (**the default leader**), `ctrl-5` ↔ `ctrl-]`, `ctrl-6` ↔ `ctrl-^`,
    and `ctrl-7`/`ctrl-/` ↔ `ctrl-_`. With the kitty protocol the real characters arrive, and both forms must compare equal.
- **Grammar** (case-insensitive modifiers, `-` separator): `[ctrl-][alt-][shift-][super-]<key>`, where
  `<key>` is a single printable char (including `-`, `|`, `\`, `[`, `,`, `<`, `>`, `?`, `!`, `/`),
  or one of `space`, `enter`, `esc`, `tab`, `backspace`, `delete`, `insert`, `home`, `end`,
  `pageup`, `pagedown`, `up`, `down`, `left`, `right`, `f1`…`f24`. Special case: a lone `-` is the minus key,
  and `ctrl--` is ctrl + minus.
- `Display` is the **canonical** form (modifier order ctrl, alt, shift, super), and it round-trips with
  `FromStr` (fixes the `f(5)` bug).
- Implements the `KeymapValidator` trait from M0-06, so config validation reports bad chords.

### 2.2 Modes (§8.2)
`enum Mode { Terminal, Normal, Copy, Insert }`:
- **Terminal**: focus is in a live session pane. Every key goes to the session encoder (M1-11) **except
  the leader**. Pressing the leader twice sends a literal leader to the remote. There is **no** Terminal-mode
  key table and no config for one. This is the pass-through guarantee from `tasks/03-KEYBINDINGS.md` §1.2, and
  it is enforced by tests K-01/K-02.
- **Pane overlays** (disconnected, exited, locked, resize mode) are pane states, not modes. Their few keys are
  defined in `03-KEYBINDINGS.md` §4.4 and implemented by M1-16, M1-12, M1-04 and M3-01.
- **Normal**: focus is in sverb views. Keys drive the UI (vim-style plus arrows). The leader also works
  here.
- **Copy**: entered via `leader [` (M3-04).
- **Insert**: a form field is focused (M1-06). Keys go to the field, `Esc` leaves. The leader still works
  so the user can't get trapped, except inside secret fields, where it is also honored.
- Mode is derived from focus by the reducer and isn't set ad hoc. The status bar shows it (M0-11).

### 2.3 Leader state machine (`keymap::leader`)
States: `Idle` → (leader pressed) → `Pending { since }` → next key → resolve → `Idle`.
- In `Pending`, the next chord is looked up in `keys.terminal` bindings (the "after leader" table,
  named `terminal` in §15 but **applies in every mode**). Document this naming.
- Leader + leader → literal leader to the focused session (Terminal mode). In Normal mode it does nothing.
- Leader + unbound key → toast "No binding for <leader> <key>" and back to Idle. The key is **not**
  forwarded to the session.
- **Timeout**: if no key arrives within **1.5 s**, return to Idle silently.
- **Which-key**: if `ui.show_which_key` and no key arrives within `ui.which_key_delay_ms` (400 ms), show
  the popup listing all after-leader bindings with descriptions (grouped: tabs/panes, sessions, views,
  tools). The popup stays until a key is pressed or the 1.5 s timeout fires. **Interpretation of the spec:**
  400 ms is the popup delay and 1.5 s is the leader timeout. While the popup is visible, the timeout
  is suspended, so the user can read it. Esc cancels.
- Timers are scheduled via `Effect::ScheduleTimer` (M0-09), so this is fully reducer-testable.
- `Esc` in Pending cancels.

### 2.4 Normal-mode bindings
Single-chord lookup in `keys.normal` (plus built-ins), with fallback to the focused view's own keys.
Multi-key Normal sequences (e.g. `gg`) are supported with a 1 s timeout, using the same state machine
generalized to a prefix trie. This replaces the template's tick-cleared buffer.

### 2.5 Default bindings: see `tasks/03-KEYBINDINGS.md` §4 (authoritative)
The binding tables were designed and then audited against what SSH sessions need (`03-KEYBINDINGS.md` §3).
That audit changed several spec defaults. Implement exactly §4.1 (after-leader) and §4.2 (Normal) of that document:
- **Default leader `ctrl-\`** (was `ctrl-g`, which collides with Emacs `keyboard-quit` and readline abort).
- After-leader changes vs SPEC §8.3: `t` = new local tab (was `l`, which collided with focus-right), `v` = toggle
  views/sessions (replaces §8.1's `leader h`/`leader t`), `ctrl-l` = lock (was `L`, which collided with resize-right),
  new `r` resize mode, `X` close tab, `i` session info, `Tab` accept ghost text, and `ctrl-z` suspend (Unix).
- Normal mode: `ctrl-k` palette plus the list keys in §4.2. `q` quits in Normal mode only.
- **Template defaults removed:** `q`, `Ctrl-c`, `Ctrl-d`, `Ctrl-z`, `Ctrl-h` are no longer global. In Terminal mode
  they reach the remote shell.
- Which-key groups: Sessions & tabs, Panes, Tools, UI, App (`03-KEYBINDINGS.md` §4.5).
- First-run leader notice (`03-KEYBINDINGS.md` §5.3), shown once and tracked in `meta.seen_leader_notice`.

### 2.6 Overrides (§15)
`[keys.terminal]` and `[keys.normal]` merge over the built-ins. Setting an action to `"none"` unbinds a
key. Two keys → same action is fine, and one key → two actions is impossible in TOML. Binding the leader chord
itself inside `[keys.terminal]` is an error. There's deliberately **no** table for unprefixed Terminal-mode keys.
**Leader validation** (`03-KEYBINDINGS.md` §5.2): must contain `ctrl` or `alt`. `ctrl-c`, `ctrl-d`, `ctrl-z`,
`ctrl-m`/`enter`, `ctrl-i`/`tab`, `ctrl-[`/`esc` are rejected. `ctrl-a`, `ctrl-b`, `ctrl-e`, `ctrl-k`, `ctrl-r`, `ctrl-u`,
`ctrl-w`, `ctrl-l` are accepted with a warning naming the programs they collide with.

### 2.7 `sverb keys --dump` (§8.3, §16)
Prints the effective keymap (built-ins + overrides) as a table: `MODE  KEYS  ACTION  DESCRIPTION
SOURCE(default|config)`. `--json` is available too. The reducer-independent function
`Keymap::effective(&Config) -> Vec<BindingRow>` is shared with the help screen (`leader ?`) and the
palette (M2-12).

### 2.8 `docs/keybindings.md`
Generated from the registry with an `xtask` or a test that regenerates and diffs, so the docs never drift.

## 3. Codebase changes
- **Move** the parser functions and tests from `crates/sverb/src/config.rs` to
  `crates/sverb-tui/src/keymap/chord.rs`. Rewrite them for the new grammar and normalization, and keep the existing test
  cases (adapted).
- **Delete** `KeyBindings` (config.rs:130-153), `parse_key_sequence` (299-323), `Mode` in app.rs.
- **Create** `keymap/{keymap.rs, leader.rs, whichkey.rs (popup widget), dump.rs, action.rs
  (registry)}`.
- **Implement** `sverb keys --dump` in `crates/sverb/src/cli/keys.rs`.
- **Generate** `docs/keybindings.md`.

## 4. Test cases to implement

### Chord parsing
**T-01 (unit, table)** Parse and canonical-display round-trip for ≥ 40 chords:
`ctrl-\`, `CTRL-A`, `alt-enter`, `ctrl-alt-shift-x`, `f5`, `f24`, `-`, `ctrl--`, `|`, `\`, `[`,
`space`, `ctrl-space`, `shift-tab`, `L`, `shift-l` (→ `L`), `?`, `!`, `,`, `<`, `>`.

**T-02 (unit) Display/parse round-trip property.** For all generated `KeyChord`s,
`parse(display(c)) == c` (proptest). This fixes the `f(5)` bug.

**T-03 (unit) Invalid.** `ctrl-`, `foo`, `ctrl-invalid`, `f25` and the empty string are errors with messages.

**T-04 (unit) Normalization.** crossterm `Char('4')+CONTROL` and raw `0x1C` → `ctrl-\` (K-05). `Char(' ')+CONTROL`, `Null` and `Char('@')+CONTROL` all
become `ctrl-space`. `BackTab` becomes `shift-tab`. `Char('L')+SHIFT` becomes `L`.

### Leader state machine (reducer tests via AppHarness)
**T-05** In Terminal mode, `a` → `SendToSession(bytes "a")`. The leader produces no bytes.

**T-06** `ctrl-\ ctrl-\` → `SendToSession(0x1C)` (literal leader). With `leader = "ctrl-g"`, `ctrl-g ctrl-g` → `0x07`.

**T-07** `ctrl-\ -` → `split_horizontal` dispatched, with no bytes sent.

**T-08** `ctrl-\` then 1.5 s timeout → Idle, and the next `a` goes to the session.

**T-09** `ctrl-\`, wait 400 ms → which-key popup visible (render snapshot at 80×24). Wait another
5 s → still visible (timeout suspended). Then `p` → palette and the popup is closed.

**T-10** `ui.show_which_key = false` → no popup ever.

**T-11** `ctrl-\ y` (unbound) → toast, and no bytes sent.

**T-12** `ctrl-\ esc` → Idle, and nothing is dispatched.

**T-13** In Normal mode, `q` → quit flow. In Terminal mode, `q` → bytes `q`.

**T-14** In Terminal mode, `ctrl-c` → bytes `0x03` (regression: the template mapped it to Quit).

**T-15** In Insert mode (a form field), the leader still opens which-key, and other keys go to the field.

### Config overrides
**T-16** `[keys.terminal] v = "split_vertical"` → `ctrl-\ v` splits vertically, and `ctrl-\ |` still
works (merge, not replace).

**T-17** `[keys.terminal] "-" = "none"` → `ctrl-\ -` is unbound.

**T-18** `general.leader = "ctrl-g"` (hot reload) → `ctrl-g` is now the leader and `ctrl-\` goes to the
session as `0x1C`.

**T-19** Binding the leader chord in `[keys.terminal]` → config validation error.

### Pass-through audit (from `03-KEYBINDINGS.md` §6)
**T-23 (property, K-01)** In Terminal mode with a live session focused, every generated chord except the leader → exactly
one `SendToSession(Key(chord))` and no other effect. Repeat for leaders `ctrl-\`, `ctrl-g`, `ctrl-a`, `ctrl-]`.

**T-24 (table, K-02)** The explicit must-pass list (`ctrl-a…z`, `ctrl-space`, `ctrl-[ ] ^ _`, `esc`, `alt-b/f/d/.`,
`f1…f12`, `tab`, `shift-tab`, arrows × modifiers, `home/end/pageup/pagedown/insert/delete/enter/backspace`, `q`) all reach
the session.

**T-25 (unit, K-03)** No key appears twice in the after-leader or Normal tables (built-ins, and built-ins + overrides).

**T-26 (unit)** Leader validation: `ctrl-c` is rejected, `ctrl-b` is accepted with a warning mentioning tmux, and `ctrl-\` is accepted silently.

**T-27 (reducer)** The first-run leader notice is shown once, then never again (`meta.seen_leader_notice`).

### Dump and docs
**T-20 (snapshot)** `sverb keys --dump` output (text and JSON).

**T-21 (unit)** `docs/keybindings.md` is up to date with the registry.

**T-22 (unit)** Every action in the registry has a description and appears in which-key groups.

## 5. Passing functional characteristics
- [ ] Four modes exist. Terminal mode passes every key to the session except the leader.
- [ ] The leader works in every mode, double leader sends it literally, there's a 1.5 s timeout, and which-key
      shows after `which_key_delay_ms`.
- [ ] Defaults match `03-KEYBINDINGS.md` §4 (leader `ctrl-\`), and the pass-through property test (K-01) passes for several leaders.
- [ ] `[keys.terminal]`/`[keys.normal]` overrides merge with the built-ins, support `"none"`, and hot-reload.
- [ ] Chords parse case-insensitively, normalize terminal quirks, and round-trip through their canonical form.
- [ ] Template issues are fixed: no tick-cleared buffer, no `unwrap` on bad keys, no `f(5)`
      mismatch, and `Ctrl-c`/`Ctrl-d`/`Ctrl-h` are no longer stolen from the remote.
- [ ] `sverb keys --dump` and `docs/keybindings.md` reflect the effective keymap.
