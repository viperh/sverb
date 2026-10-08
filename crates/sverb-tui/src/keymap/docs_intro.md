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
