<!-- Generated from crates/sverb-tui/src/keymap (registry + built-in tables). Do not edit:
     run `SVERB_BLESS=1 cargo test -p sverb-tui --test keybindings_doc` to regenerate. -->

# Keybindings

sverb is a terminal inside a terminal. Every key either **passes through** to the program in the
focused session (bash, vim, emacs, tmux, htop, …) or is **consumed** by sverb. sverb consumes as
little as possible: while a session pane has focus, only the **leader** (`ctrl-\` by default)
belongs to sverb. Press the leader, then a key from the tables below; press the leader twice to
send it to the session.

Modes (shown in the status bar):

- **TERMINAL**: a live session pane has focus. Every key except the leader goes to the session.
- **NORMAL**: sverb's own views have focus (hosts, lists, settings). Keys drive the UI.
- **COPY**: scrollback selection, entered with `leader [`.
- **INSERT**: a form field has focus. Keys go to the field, `esc` leaves, the leader still works.

## Rules

### Input routing pipeline (in this order, first match wins)
1. **Modal dialog open** (host key, auth prompt, confirm, snippet vars, …): the dialog gets the key. Nothing reaches the session.
2. **Leader pending** (the leader was the previous key): the key is looked up in the *after-leader* table.
   - leader again → send the literal leader byte(s) to the focused session,
   - bound → run the action, and nothing is sent to the session,
   - unbound → toast "No binding for <leader> <key>", and the key is **discarded** (never forwarded, so a typo after the
     leader can't type into the remote shell).
3. **The key is the leader** → enter leader-pending (which-key popup after `ui.which_key_delay_ms`, timeout 1.5 s).
4. **Mode-specific table**:
   - **Terminal mode** (a live session pane has focus): **everything passes through.** There is no table. This is the
     core guarantee (below).
   - **Pane state overlays** (disconnected, process exited, vault locked, resize mode): a tiny table of their own (e.g. `enter` reconnects a disconnected pane, plain letters are swallowed).
   - **Copy mode**, **Insert mode** (form fields), **Normal mode** (sverb views): their own tables (Normal mode: below).
5. Unhandled in Normal, Copy or Insert mode → ignored. (Never forwarded: these modes have no session focus.)

### Pass-through guarantee (Terminal mode)
While a live session pane has focus, sverb consumes **only**:
- the **leader chord**, and
- **mouse events** that the remote app didn't ask for, or that have **Shift** held (selection, focus, scroll).

Every other key and chord reaches the remote, encoded for that pane's terminal modes. That includes all of
`Ctrl-A…Z`, `Ctrl-Space`, `Ctrl-[ \ ] ^ _ /`, `Esc`, every `Alt-*`, `F1–F24`, `Tab`/`Shift-Tab`, arrows with any
modifiers, `Home/End/PgUp/PgDn/Ins/Del`, `Enter` and `Backspace`. Pastes are forwarded too. Only multi-line pastes
without bracketed-paste support ask for confirmation, and that never drops or changes the text.
This is a tested invariant: no configuration can add a Terminal-mode binding.

### Keys sverb never relies on (owned by the outer terminal or the OS)
`Ctrl-Shift-C/V/T/W/N`, `Cmd-*` (macOS), `F11`, `Alt-Enter` (Windows Terminal fullscreen), `Ctrl-+/-/0` (zoom),
`Ctrl-Tab`, `Ctrl-Space` on macOS (the input-source switcher). Many terminals intercept these before sverb sees them, so
none of them is bound by default.

## Why `ctrl-\` is the leader

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
and the first-run notice says so.

Implementation note: in the legacy keyboard encoding, `Ctrl-\` arrives as byte `0x1C`, which crossterm reports as
`Char('4') + CONTROL`. sverb maps `0x1C`/`ctrl-4` ↔ `ctrl-\`, `0x1D`/`ctrl-5` ↔ `ctrl-]`,
`0x1E`/`ctrl-6` ↔ `ctrl-^`, and `0x1F`/`ctrl-7`/`ctrl-/` ↔ `ctrl-_`.

## Nesting

- **sverb inside tmux (locally):** no conflict. tmux takes `Ctrl-b` first, and sverb gets `Ctrl-\`.
- **tmux on the remote (recommended for flaky links):** `Ctrl-b` passes straight through to the remote tmux.
- **sverb inside sverb (over SSH):** the inner sverb gets its leader with `Ctrl-\ Ctrl-\`, or the user sets a different leader on one
  side.

## After the leader (`ctrl-\`), in every mode

Press the leader, then one of these keys. The table is `[keys.terminal]` in `config.toml` (the name is historical: it applies in every mode). After the leader, an unbound key shows a toast and is discarded; `esc` cancels; the leader times out after 1.5 s; the which-key popup appears after `ui.which_key_delay_ms` (400 ms).

### Sessions & tabs

| Keys | Action | Description |
|---|---|---|
| `ctrl-\ c` | `new_tab_pick_host` | New host tab |
| `ctrl-\ t` | `new_local_tab` | New local tab |
| `ctrl-\ o` | `quick_connect` | Quick connect |
| `ctrl-\ 1` | `go_to_tab_1` | Go to tab 1 |
| `ctrl-\ 2` | `go_to_tab_2` | Go to tab 2 |
| `ctrl-\ 3` | `go_to_tab_3` | Go to tab 3 |
| `ctrl-\ 4` | `go_to_tab_4` | Go to tab 4 |
| `ctrl-\ 5` | `go_to_tab_5` | Go to tab 5 |
| `ctrl-\ 6` | `go_to_tab_6` | Go to tab 6 |
| `ctrl-\ 7` | `go_to_tab_7` | Go to tab 7 |
| `ctrl-\ 8` | `go_to_tab_8` | Go to tab 8 |
| `ctrl-\ 9` | `go_to_tab_9` | Go to tab 9 |
| `ctrl-\ n` | `next_tab` | Next tab |
| `ctrl-\ N` | `prev_tab` | Previous tab |
| `ctrl-\ ,` | `rename_tab` | Rename tab |
| `ctrl-\ <` | `move_tab_left` | Move tab left |
| `ctrl-\ >` | `move_tab_right` | Move tab right |
| `ctrl-\ x` | `close_pane` | Close pane |
| `ctrl-\ X` | `close_tab` | Close tab |

### Panes

| Keys | Action | Description |
|---|---|---|
| `ctrl-\ -` | `split_horizontal` | Split horizontal |
| `ctrl-\ \|` | `split_vertical` | Split vertical |
| `ctrl-\ h` | `focus_left` | Focus left |
| `ctrl-\ left` | `focus_left` | Focus left |
| `ctrl-\ j` | `focus_down` | Focus down |
| `ctrl-\ down` | `focus_down` | Focus down |
| `ctrl-\ k` | `focus_up` | Focus up |
| `ctrl-\ up` | `focus_up` | Focus up |
| `ctrl-\ l` | `focus_right` | Focus right |
| `ctrl-\ right` | `focus_right` | Focus right |
| `ctrl-\ H` | `resize_left` | Resize left |
| `ctrl-\ J` | `resize_down` | Resize down |
| `ctrl-\ K` | `resize_up` | Resize up |
| `ctrl-\ L` | `resize_right` | Resize right |
| `ctrl-\ r` | `resize_mode` | Resize mode |
| `ctrl-\ z` | `zoom_pane` | Zoom pane |
| `ctrl-\ b` | `toggle_broadcast` | Toggle broadcast |
| `ctrl-\ B` | `mark_broadcast_pane` | Mark broadcast |
| `ctrl-\ i` | `session_info` | Session info |
| `ctrl-\ S` | `share_pane` | Share pane |

### Tools

| Keys | Action | Description |
|---|---|---|
| `ctrl-\ p` | `palette` | Command palette |
| `ctrl-\ e` | `snippet_picker` | Snippets |
| `ctrl-\ [` | `copy_mode` | Copy mode |
| `ctrl-\ space` | `autocomplete` | Autocomplete |
| `ctrl-\ tab` | `accept_ghost_text` | Accept suggestion |
| `ctrl-\ R` | `toggle_recording` | Toggle recording |

### UI

| Keys | Action | Description |
|---|---|---|
| `ctrl-\ ?` | `help` | Help (all keys) |
| `ctrl-\ v` | `toggle_views` | Views / sessions |
| `ctrl-\ s` | `toggle_sidebar` | Toggle sidebar |
| `ctrl-\ !` | `notification_history` | Notifications |
| `ctrl-\ D` | `toggle_log_pane` | Toggle log pane |

### App

| Keys | Action | Description |
|---|---|---|
| `ctrl-\ ctrl-\` | `send_leader` | Send leader key |
| `ctrl-\ q` | `quit` | Quit sverb |
| `ctrl-\ ctrl-z` | `suspend` | Suspend to shell |
| `ctrl-\ ctrl-l` | `lock_vault` | Lock the vault |

## Normal mode (sverb views have focus)

No session receives keys in Normal mode. These are the global bindings (`[keys.normal]`); list and view keys (`/` filter, `j k`/arrows, `g`/`G`, `ctrl-d`/`ctrl-u`, `space` mark, `s`/`S` sort, `h`/`l` collapse/expand, `enter` open, `ctrl-enter`/`v` connect in split, `a e d y` add/edit/delete/duplicate, `p` pin, `m` move, `t` tag, `c` copy `ssh` command, `i` detail, `tab` cycle focus) are handled by the focused view after this table.

| Keys | Action | Description |
|---|---|---|
| `ctrl-k` | `palette` | Command palette |
| `?` | `help` | Help (all keys) |
| `q` | `quit` | Quit sverb |
| `ctrl-z` | `suspend` | Suspend to shell |

## View keys

Keys handled by one view, in Normal mode only. They are fixed (not in `[keys.*]`).

### Hosts view

On a host row (or the marked rows). Marks (`space`) apply the key to every marked host.

| Keys | Does |
|---|---|
| `enter` | connect (a new tab per host) |
| `ctrl-enter` `v` | connect in a split |
| `a` | add a host |
| `e` | edit the host |
| `y` | duplicate |
| `d` | delete (asks first) |
| `p` | pin / unpin |
| `m` | move to a group |
| `t` | tag |
| `c` | copy the `ssh` command |
| `A` | new group |
| `T` | manage tags |
| `D` | vault defaults (inherited settings) |
| `I` | import (ssh_config, known_hosts, CSV, PuTTY, backup) |
| `X` | export |
| `H` | clear the host's command history |
| `V` | next vault (personal, then each shared vault; the top bar shows it) |
| `M` | move to another vault (re-encrypts under its key) |
| `C` | copy to another vault |
| `O` | your credential override for a host in a shared vault |

### Hosts view, on a group row

Without marks.

| Keys | Does |
|---|---|
| `e` | edit the group |
| `d` | delete the group |
| `a` | add a host in the group |
| `A` | new subgroup |

### Settings → Vaults (sync builds, connected)

Shared vaults on the left, the selected vault's members on the right.

| Keys | Does |
|---|---|
| `j` `k` `↓` `↑` | move in the focused list |
| `tab` | switch between vaults and members |
| `n` | new shared vault (org owners and admins) |
| `u` | reload |
| `g` | grant `manage` to org admins who have no key yet |
| `R` | rotate the vault key, or resume an interrupted rotation (`manage`) |
| `r` `w` `m` | members: grant read / write / manage (`manage`) |
| `x` `delete` | members: revoke (asks; the key is rotated), or leave the vault |

## Copy mode (`leader [`)

Vim-style motions over the screen and the scrollback; output keeps flowing but the view stays frozen (the pane border counts the new lines). A count before a motion repeats it (`5j`, `3w`). `/` and `?` take a Rust regex (an invalid one is searched literally). `o` on a link asks before opening it. Bind keys with `[keys.copy]`.

| Keys | Action |
|---|---|
| `h` `left` | `move_left` |
| `j` `down` | `move_down` |
| `k` `up` | `move_up` |
| `l` `right` | `move_right` |
| `w` | `word_forward` |
| `b` | `word_backward` |
| `e` | `word_end` |
| `W` | `big_word_forward` |
| `B` | `big_word_backward` |
| `E` | `big_word_end` |
| `0` `home` | `line_start` |
| `^` | `line_first_non_blank` |
| `$` `end` | `line_end` |
| `g g` | `top` |
| `G` | `bottom` |
| `H` | `screen_top` |
| `M` | `screen_middle` |
| `L` | `screen_bottom` |
| `ctrl-u` | `half_page_up` |
| `ctrl-d` | `half_page_down` |
| `ctrl-b` `pageup` | `page_up` |
| `ctrl-f` `pagedown` | `page_down` |
| `{` | `paragraph_backward` |
| `}` | `paragraph_forward` |
| `v` | `select_char` |
| `V` | `select_line` |
| `ctrl-v` | `select_block` |
| `O` | `swap_anchor` |
| `y` | `yank` |
| `Y` | `yank_line` |
| `/` | `search_forward` |
| `?` | `search_backward` |
| `n` | `search_next` |
| `N` | `search_prev` |
| `o` | `open_link` |
| `q` `esc` `ctrl-c` | `exit` |

## Configuration

```toml
[general]
leader = "ctrl-\\"      # TOML needs the backslash escaped; "ctrl-g" for non-US layouts

[keys.terminal]          # after-leader table (applies in every mode, despite the name)
"v" = "split_vertical"   # override: merged over the built-ins
"-" = "none"             # unbind

[keys.normal]
"ctrl-k" = "palette"
```

- Overrides merge key by key over the built-ins; `"none"` unbinds a key.
- Binding the leader itself in `[keys.terminal]` is an error (press it twice to send it).
- Two spellings of one key in a table (`"L"` and `"shift-l"`) are an error.
- The leader must include `ctrl` or `alt`. `ctrl-c`, `ctrl-d`, `ctrl-z`, `ctrl-m`/`enter`, `ctrl-i`/`tab` and `ctrl-[`/`esc` are rejected; `ctrl-a b e k r u w l` are accepted with a warning.
- There is deliberately no table for Terminal-mode keys without the leader.
- `sverb keys --dump` (`--json`) prints the effective keymap including your overrides.

### Chord syntax

`[ctrl-][alt-][shift-][super-]<key>`: modifiers are case-insensitive, `<key>` is one character (`-`, `|`, `\`, `[`, `,`, `<`, `>`, `?`, `!`, `/` included) or `space enter esc tab backspace delete insert home end pageup pagedown up down left right f1…f24`. A lone `-` is the minus key and `ctrl--` is ctrl + minus. An uppercase letter means shift (`L`); after `ctrl-` letter case is ignored, so write `ctrl-shift-l` for the shifted chord. Separate chords with spaces for a multi-key sequence (`"g g"`).
