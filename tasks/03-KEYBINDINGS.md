# Keybinding plan: pass-through vs TUI keys

sverb is a terminal inside a terminal. Every key a user presses goes one of two ways. It either **passes through**
to the remote program (bash, zsh, fish, vim, emacs, nano, tmux, htop, less, mc, …) over SSH, or it's **consumed**
by sverb to drive its own UI. Any key sverb consumes is a key the remote side can't get. This document fixes the
rules, the bindings, and the result of auditing them against what SSH sessions need.

It supersedes the binding tables in SPEC §8.2/§8.3 and in the task files. The task files below were updated to match:
M0-06, M0-10, M0-11, M1-04, M1-12, M1-16, M1-17, M1-18, M3-01, M3-02, M7-01.

---

## 1. Rules

### 1.1 Input routing pipeline (in this order, first match wins)
1. **Modal dialog open** (host key, auth prompt, confirm, snippet vars, …): the dialog gets the key. Nothing reaches the session.
2. **Leader pending** (the leader was the previous key): the key is looked up in the *after-leader* table.
   - leader again → send the literal leader byte(s) to the focused session,
   - bound → run the action, and nothing is sent to the session,
   - unbound → toast "No binding for <leader> <key>", and the key is **discarded** (never forwarded, so a typo after the
     leader can't type into the remote shell).
3. **The key is the leader** → enter leader-pending (which-key popup after `ui.which_key_delay_ms`, timeout 1.5 s).
4. **Mode-specific table**:
   - **Terminal mode** (a live session pane has focus): **everything passes through.** There is no table. This is the
     core guarantee (§1.2).
   - **Pane state overlays** (disconnected, process exited, vault locked, resize mode): a tiny table, see §4.4.
   - **Copy mode**, **Insert mode** (form fields), **Normal mode** (sverb views): their own tables (§4.2, §4.3).
5. Unhandled in Normal, Copy or Insert mode → ignored. (Never forwarded: these modes have no session focus.)

### 1.2 Pass-through guarantee (Terminal mode)
While a live session pane has focus, sverb consumes **only**:
- the **leader chord**, and
- **mouse events** that the remote app didn't ask for, or that have **Shift** held (selection, focus, scroll; §7.3).

Every other key and chord reaches the remote, encoded for that pane's terminal modes (M1-11). That includes all of
`Ctrl-A…Z`, `Ctrl-Space`, `Ctrl-[ \ ] ^ _ /`, `Esc`, every `Alt-*`, `F1–F24`, `Tab`/`Shift-Tab`, arrows with any
modifiers, `Home/End/PgUp/PgDn/Ins/Del`, `Enter` and `Backspace`. Pastes are forwarded too. Only multi-line pastes
without bracketed-paste support ask for confirmation, and that never drops or changes the text.
**This is a tested invariant (§6, test K-01).** A new Terminal-mode binding can only be added by changing this document.

### 1.3 Keys sverb never relies on (owned by the outer terminal or the OS)
`Ctrl-Shift-C/V/T/W/N`, `Cmd-*` (macOS), `F11`, `Alt-Enter` (Windows Terminal fullscreen), `Ctrl-+/-/0` (zoom),
`Ctrl-Tab`, `Ctrl-Space` on macOS (the input-source switcher). Many terminals intercept these before sverb sees them, so
none of them is bound by default.

---

## 2. Phase 1: draft bindings (the spec as written)

Taken verbatim from SPEC §8.1–§8.4, §8.7, §9.8, §14.1, §18, plus the template's `.config/config.json`:
- **Leader:** `Ctrl-g`.
- **After leader:** `p` palette, `o` quick connect, `c` new tab (pick host), `l` new local tab, `1..9`/`n`/`N` tabs, `x` close
  pane, `-`/`|` split, `←↑→↓`/`h j k l` focus, `H J K L` resize, `z` zoom, `b` broadcast, `B` mark broadcast pane, `e` snippets,
  `[` copy mode, `Space` autocomplete, `R` recording, `s` sidebar, `L` lock, `?` help, `q` quit, `h` Hosts view and `t` sessions
  (§8.1), `,`/`<`/`>` tab rename and reorder, `S` share, `D` log pane, `!` notifications.
- **Normal mode:** `Ctrl-k` palette, `/` filter, `a e d y` add/edit/delete/duplicate, `Enter` open, `Tab` cycle focus.
- **Template defaults** (`.config/config.json`): `q`, `Ctrl-c`, `Ctrl-d` → quit, `Ctrl-z` → suspend, `Ctrl-h` → help, all
  active globally.
- **Additions from the earlier task drafts:** banner keys `r`/`c`/`l` on disconnected panes (M1-16), `x` on exited local panes (M1-12),
  a 1 s "resize repeat" where plain `H J K L`/arrows keep resizing after `leader H` (M3-01), and `Ctrl-f` to accept ghost text (M7-01).

---

## 3. Phase 2: audit against SSH use

Question asked for every binding: **is this key needed by programs that run over SSH, while sverb would be intercepting
it?** Bindings that are only active in sverb's own views (Normal, Copy, Insert, dialogs) can't steal from a remote and pass
automatically. The risky ones are the leader, anything active while a session pane has focus, and overlay keys typed by
a user who thinks they're still typing into the shell.

### 3.1 Findings

| # | Binding | Active while a session has focus? | Needed by remote programs? | Verdict |
|---|---|---|---|---|
| A1 | Leader `Ctrl-g` | yes | **Yes, heavily.** Emacs `keyboard-quit` (the most used Emacs key), readline/zsh abort (`Ctrl-r … Ctrl-g` to cancel history search), nano help, vim/less file info. Double-press would make Emacs users type `Ctrl-g Ctrl-g` dozens of times a session. | **Rewrite**: new default leader (§3.2) |
| A2 | Template `q`, `Ctrl-c`, `Ctrl-d`, `Ctrl-z`, `Ctrl-h` global | yes (template binds them in its only mode) | **Yes, critical**: interrupt, EOF/logout, job control, backspace on some terminals, and `q` quits less/htop/man. | **Rewrite**: removed from Terminal mode. `q` is Normal-only, and suspend is `leader Ctrl-z`. (Already in M0-10, confirmed here.) |
| A3 | Normal `Ctrl-k` palette | must **not** be | Yes: readline/emacs kill-line, nano cut, vim digraph. | **Keep, Normal-only.** Covered by the pass-through test. |
| A4 | Disconnected banner `r` / `c` / `l` (M1-16) | the pane just died while the user was typing | Not needed by the remote (it's dead), but **hazardous**: typing `cd …` as the link drops presses `c`, which **closes the pane and loses scrollback**. | **Rewrite**: `Enter` reconnect, `leader x` close, `leader i` details. Plain letters are swallowed with a hint. |
| A5 | Exited local pane `x` close (M1-12) | same as A4 | same hazard | **Rewrite**: `Enter` restart, `leader x` close. |
| A6 | Resize repeat: plain `H J K L`/arrows for 1 s after `leader H` (M3-01) | yes, for 1 s | **Yes**: arrows are history navigation, and typing `Hello` right after a resize would lose letters. | **Rewrite**: an explicit resize **mode** (`leader r`, exits on `Esc`/`Enter`, shown in the status bar), plus single steps with `leader H/J/K/L`. No timed key stealing. |
| A7 | Ghost-text accept `Ctrl-f` (M7-01) | yes, while ghost text is visible | **Yes**: readline/emacs forward-char, and fish's own autosuggestion accept. | **Rewrite**: `leader Tab`. |
| A8 | After-leader `l` = new local tab **and** `l` = focus right | n/a (after leader) | n/a | **Internal collision**: rewrite. Local tab → `leader t`. |
| A9 | After-leader `L` = lock **and** `L` = resize right | n/a | n/a | **Internal collision**: rewrite. Lock → `leader Ctrl-l`. |
| A10 | After-leader `h` = Hosts view (§8.1) **and** `h` = focus left (§8.3) | n/a | n/a | **Internal collision**: rewrite. Views ↔ sessions toggle → `leader v`, and `t` is freed for the local tab. |
| A11 | Shift + mouse → sverb | yes | Rarely: some remote apps read shift-click, but every major terminal reserves Shift for local selection too. | **Keep** (spec §7.3). |
| A12 | Mouse/wheel when the remote didn't request mouse | yes | No: the remote didn't ask for mouse input. Alternate-screen wheel → arrow keys mirrors xterm `alternateScroll`. | **Keep** |
| A13 | Multi-line paste confirmation | yes | Doesn't steal keys or alter text, and protects against accidental execution. | **Keep** (configurable, `terminal.paste_confirm_multiline`) |
| A14 | Leader + unbound key is discarded | yes | The discarded key was meant for sverb anyway. Forwarding it would type garbage into the shell. | **Keep** |
| A15 | Lock overlay blocks input | yes | Intentional (security, §5.3). | **Keep** |
| A16 | Leader inside nested sverb or remote tmux | yes | Remote tmux is the **recommended** setup (§1, flaky networks). The leader must not equal tmux's `Ctrl-b`, and preferably not screen's `Ctrl-a`. | Drives the choice in §3.2 |

### 3.2 Choosing the default leader
Candidates scored against what remote programs use. ✗ = conflicts with a commonly used binding, ~ = minor or rare use, ✓ = free.

| Chord | bash/zsh readline | fish | vim | emacs | nano | less/htop/man | remote tmux / screen | outer-terminal/OS issues | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| `Ctrl-g` (spec) | ~ abort i-search | ✓ | ~ file info | ✗ **keyboard-quit** | ~ help | ~ file info | ✓ | ✓ | rejected (Emacs) |
| `Ctrl-b` (tmux) | ~ back char | ~ | ~ page up | ~ back char | ✓ | ~ back page | ✗ **tmux prefix** | ✓ | rejected (nested tmux) |
| `Ctrl-a` (screen) | ✗ start of line | ✗ | ~ increment | ✗ start of line | ~ mark | ✓ | ✗ screen prefix | ✓ | rejected |
| `Ctrl-Space` | ~ set mark | ✓ | ~ | ✗ **set-mark** | ✓ | ✓ | ✓ | ✗ macOS input switcher; some terminals send NUL inconsistently | rejected |
| `Ctrl-]` | ~ char search | ✓ | ✗ **jump to tag** | ~ | ~ complete word | ✓ | ✓ | `]` needs AltGr on many EU layouts | runner-up |
| `Ctrl-q` | ~ XON / quoted insert | ✓ | ~ | ~ quoted-insert | ~ | ✓ | ✓ | flow control on some ttys | runner-up |
| **`Ctrl-\`** | ~ sends SIGQUIT (rarely intended; usually an accident) | ✓ | ~ (`Ctrl-\ Ctrl-n`, terminal-mode only) | ~ toggle input method | ~ replace (also `Alt-r`) | ✓ | ✓ | `\` needs AltGr on some EU layouts | **chosen** |

**Decision: the default leader is `Ctrl-\`.** It collides with nothing that is commonly used interactively. Its main
shell meaning, SIGQUIT (core-dump the foreground job), is something users usually *don't* want by accident. When needed it's still
available as `Ctrl-\ Ctrl-\`, and the same goes for nano's replace (or use nano's `Alt-r`). Users of keyboard layouts where `\`
needs AltGr (e.g. German, French, Nordic) should set `general.leader = "ctrl-g"`. That's the recommended fallback for non-Emacs users,
and the first-run notice says so (§5.3).

Implementation note: in the legacy keyboard encoding, `Ctrl-\` arrives as byte `0x1C`, which crossterm reports as
`Char('4') + CONTROL`. The chord normalizer must map `0x1C`/`ctrl-4` ↔ `ctrl-\`, `0x1D`/`ctrl-5` ↔ `ctrl-]`,
`0x1E`/`ctrl-6` ↔ `ctrl-^`, and `0x1F`/`ctrl-7`/`ctrl-/` ↔ `ctrl-_` (M0-10 §2.1).

---

## 4. Phase 3: final bindings

### 4.1 After leader (`Ctrl-\` by default), available in every mode

| Key | Action | Notes / origin |
|---|---|---|
| `Ctrl-\` (leader again) | `send_leader` | sends the literal leader to the focused session |
| **Sessions and tabs** | | |
| `c` | `new_tab_pick_host` | §8.3 |
| `t` | `new_local_tab` | **changed** from `l` (A8) |
| `o` | `quick_connect` | §8.3 |
| `1`…`9` | `go_to_tab_1` … `go_to_tab_9` | §8.3 |
| `n` / `N` | `next_tab` / `prev_tab` | §8.3 |
| `,` | `rename_tab` | §8.4 |
| `<` / `>` | `move_tab_left` / `move_tab_right` | §8.4 |
| `x` | `close_pane` (confirm if alive) | §8.3. Also closes disconnected or exited panes (A4/A5) |
| `X` | `close_tab` (confirm if any alive) | **new** |
| **Panes** | | |
| `-` / `\|` | `split_horizontal` / `split_vertical` | §8.3 |
| `h j k l`, `← ↓ ↑ →` | `focus_left/down/up/right` | §8.3 |
| `H J K L` | `resize_left/down/up/right` (one 5% step) | §8.3 |
| `r` | `resize_mode` | **new** (A6): explicit mode, see §4.4 |
| `z` | `zoom_pane` | §8.3 |
| `b` | `toggle_broadcast` | §8.3 |
| `B` | `mark_broadcast_pane` | §9.8 |
| `i` | `session_info` | M1-13. Also details on a disconnected pane (A4) |
| `S` | `share_pane` | §14.1 |
| **Tools** | | |
| `p` | `palette` | §8.3 |
| `e` | `snippet_picker` | §8.3 |
| `[` | `copy_mode` | §8.3 |
| `Space` | `autocomplete` | §8.3 |
| `Tab` | `accept_ghost_text` (only when ghost text is enabled and shown) | **changed** from `Ctrl-f` (A7) |
| `R` | `toggle_recording` | §8.3 |
| **UI** | | |
| `v` | `toggle_views` (switch the main area between section views and the session area) | **changed**: replaces `leader h`/`leader t` from §8.1 (A10) |
| `s` | `toggle_sidebar` | §8.3 |
| `!` | `notification_history` | §8.7 |
| `?` | `help` | §8.3 |
| `D` | `toggle_log_pane` (only with `--debug`) | §18 |
| **App** | | |
| `Ctrl-l` | `lock_vault` | **changed** from `L` (A9) |
| `Ctrl-z` | `suspend` (Unix) | template carry-over, now behind the leader (A2) |
| `q` | `quit` (confirm if sessions open) | §8.3 |
| `Esc` | cancel leader | |

No key appears twice in this table (enforced by test K-03).

### 4.2 Normal mode (sverb views focused; no session receives keys)
`Ctrl-k` palette · `/` filter · `j k`/arrows move · `g`/`G` top/bottom · `Ctrl-d`/`Ctrl-u` half page · `Space` mark · `s`/`S` sort ·
`h`/`l`/`←`/`→` collapse/expand tree · `Enter` connect/open · `Ctrl-Enter`/`v` connect in split · `a e d y` add/edit/delete/duplicate ·
`p` pin · `m` move to group · `t` tag · `c` copy `ssh` command · `i` full-screen detail · `Tab` cycle focus (sidebar → list → detail) ·
`?` help · `q` quit · `Ctrl-z` suspend.
(View-specific keys are defined in each view's task file. All of them live only in Normal mode.)

### 4.3 Copy, Insert, dialogs (no session receives keys)
- **Copy mode** (M3-04): vim motions, `v`/`V`/`Ctrl-v`, `y`/`Y`, `/`/`?`/`n`/`N`, `o` open link (confirm), and `q`/`Esc`/`Ctrl-c` exit.
- **Insert mode** (form fields, M1-06): text editing, `Tab`/`Shift-Tab` fields, `Ctrl-s` save, `Esc` cancel, `Ctrl-r` reveal secret.
  The leader still works.
- **Dialogs:** mnemonic letters, `Enter`, `Esc`.

### 4.4 Pane-state overlays (the pane has focus but there's no live session to receive keys)

| Overlay | Keys | Everything else |
|---|---|---|
| Disconnected banner (M1-16) | `Enter` reconnect · `leader x` close · `leader i` details | swallowed (never sent to anything), with a one-line hint flash |
| Auto-reconnect countdown | `Enter` reconnect now · `Esc` cancel auto-reconnect · `leader x` close | swallowed |
| Exited process (M1-12, M1-16 `Exited`) | `Enter` restart/reconnect · `leader x` close | swallowed |
| Vault locked (M1-04) | the unlock prompt gets the input · `leader q` quit | swallowed |
| Resize mode (`leader r`, M3-01) | `h j k l`/arrows step · `H J K L` 3 steps · `=` equalize · `Esc`/`Enter` exit. Auto-exit after 10 s idle | swallowed while the mode is shown (the status bar shows `RESIZE` in the accent color) |

The overlays are the only places where plain letters are interpreted while a pane has focus, and none of them is active
while a live session could have received the key.

### 4.5 Which-key popup
It appears `ui.which_key_delay_ms` (400 ms) after the leader, and the leader times out after 1.5 s (the timeout is suspended
while the popup is shown). The popup groups match §4.1: Sessions & tabs, Panes, Tools, UI, App. It shows the effective
(user-overridden) keys.

---

## 5. Configuration and discoverability

### 5.1 Config (§15)
```toml
[general]
leader = "ctrl-\\"      # TOML needs the backslash escaped. Alternatives: "ctrl-g" (non-US layouts), "ctrl-]", "ctrl-q"

[keys.terminal]          # after-leader table (applies in every mode, despite the name)
"p" = "palette"
"-" = "split_horizontal"
"|" = "split_vertical"

[keys.normal]
"ctrl-k" = "palette"
```
- Users may bind anything in `[keys.terminal]` because it's behind the leader.
- `[keys.normal]` and `[keys.copy]` can't affect sessions.
- **There's deliberately no config table for Terminal-mode keys without the leader.** That keeps the pass-through guarantee
  unbreakable by configuration.

### 5.2 Validation (M0-06/M0-10)
- The leader must include `ctrl` or `alt`, must not be a key whose loss breaks basic shell use, and gets a **warning** when set to a
  high-conflict chord: `ctrl-c`, `ctrl-d`, `ctrl-z`, `ctrl-m`/`enter`, `ctrl-i`/`tab`, `ctrl-[`/`esc` are **rejected**.
  `ctrl-a`, `ctrl-b`, `ctrl-e`, `ctrl-k`, `ctrl-r`, `ctrl-u`, `ctrl-w`, `ctrl-l` are accepted **with a warning** naming the
  conflicting programs.
- Binding the leader chord inside `[keys.terminal]` is an error.

### 5.3 First run
The first time the TUI starts (no `meta.seen_leader_notice`), a one-time info dialog says:
"sverb's command key is **Ctrl-\\**. Every other key goes to your SSH session. Press Ctrl-\\ then ? for help. Press it twice to
send Ctrl-\\ itself. If `\` is awkward on your keyboard layout, set `general.leader = "ctrl-g"` in config.toml."
The status bar always shows the hint rendered from the real leader (`^\ ? help`).

### 5.4 Nesting
- **sverb inside tmux (locally):** no conflict. tmux takes `Ctrl-b` first, and sverb gets `Ctrl-\`.
- **tmux on the remote (recommended for flaky links):** `Ctrl-b` passes straight through to the remote tmux.
- **sverb inside sverb (over SSH):** the inner sverb gets its leader with `Ctrl-\ Ctrl-\`, or the user sets a different leader on one
  side. Documented in `docs/keybindings.md`.

---

## 6. Tests that enforce this plan (owned by M0-10 unless noted)
- **K-01 Pass-through invariant (property test):** in Terminal mode with a live session focused, for every generated
  `KeyChord` other than the leader (all `KeyCode`s × all modifier combinations), `App::handle` returns exactly one
  `SendToSession(Key(chord))` effect and no other effect. Repeat with the leader configured as `ctrl-g`, `ctrl-a` and `ctrl-]`.
- **K-02 Explicit must-pass list (table test):** `ctrl-a … ctrl-z`, `ctrl-space`, `ctrl-[`, `ctrl-]`, `ctrl-^`, `ctrl-_`, `esc`,
  `alt-b`, `alt-f`, `alt-d`, `alt-.`, `f1…f12`, `tab`, `shift-tab`, every arrow × {none, ctrl, alt, shift}, `home`, `end`,
  `pageup`, `pagedown`, `insert`, `delete`, `enter`, `backspace`, and `q`. Each one reaches the session byte-exact per the M1-11 table.
- **K-03 No duplicate bindings** in any table (after merging user overrides, a duplicate is a config error).
- **K-04 Leader literal:** `ctrl-\ ctrl-\` sends `0x1C`. With `leader = "ctrl-g"`, `ctrl-g ctrl-g` sends `0x07`.
- **K-05 Normalization:** crossterm `Char('4')+CONTROL` and raw `0x1C` are both recognized as the leader.
- **K-06 Overlay safety** (M1-16/M1-12/M3-01): on a disconnected pane, typing `c d Enter` → the first two letters are swallowed and
  `Enter` reconnects. No `CloseSession` effect is emitted. In resize mode, letters never produce `SendToSession`.
- **K-07 Generated docs:** `docs/keybindings.md` is generated from the registry and includes this document's §1 rules and §3.2
  leader rationale (static text block).

---

## 7. SPEC.md changes (applied 2026-10-07)
Applied by the orchestrator after agent-M0-01 released SPEC.md:
1. §8.2: the default leader is `Ctrl-\` (was `Ctrl-g`). Add the pass-through guarantee (§1.2 here) and the rule that leader + unbound key is
   discarded.
2. §8.3: replace the table with §4.1/§4.2 here. Note the changed keys: `t` local tab, `v` views toggle, `Ctrl-l` lock, `r` resize
   mode, `X` close tab, `i` info, `Tab` ghost text.
3. §8.1: replace "reached with `leader h` and `leader t`" with "toggled with `leader v`".
4. §15: `leader = "ctrl-\\"`, with the comment about alternatives.
5. Decisions log: "2026-10-07: Default leader is Ctrl-\\. Ctrl-g conflicts with Emacs keyboard-quit and readline abort, and
   Ctrl-b/Ctrl-a with remote tmux/screen."
