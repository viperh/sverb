# M7-01 — Shell integration (OSC 133), command history, autocomplete overlay

| | |
|---|---|
| **Milestone** | M7 — Polish |
| **Touches** | `crates/sverb-term/src/osc133.rs`, `crates/sverb-core/src/history/{capture.rs, prompt_learn.rs, suggest.rs, static_commands.rs}`, `crates/sverb-tui/src/views/sessions/autocomplete.rs`, `crates/sverb-core/src/snippet/builtin/shell_integration.*` |
| **Spec refs** | §9.10, §4.12 (`HistoryEntry`), §15 `[history]`, §8.3 (`leader Space`) |
| **Depends on** | M1-09, M1-10, M2-09 (snippet source; install-integration snippet) |
| **Blocks** | — |

---

## 1. Current state in the codebase
The emulator surfaces `TermEvent`s (M1-09), and OSC 133 is listed as a future event. `leader Space` is bound to `autocomplete` (M0-10) but does nothing. The `HistoryEntry` view exists (M1-02).

## 2. Detailed description

### 2.1 Tier 1: shell integration (OSC 133)
- Parse `OSC 133 ; A` (prompt start), `B` (command start, i.e. the prompt end), `C` (command executed), `D [; exit]` (command finished) from the stream. Hook this into the alacritty
  processor if it exposes unknown OSCs, otherwise pre-scan the byte stream (a small state machine in the session read path, which must handle sequences split across chunks).
- Record grid positions: the prompt region and the command input region (B…C on the cursor line(s)). At `C`, capture the command text from the grid (B position → line end,
  joining wrapped rows). At `D;exit`, record the exit code. Create `HistoryEntry { command, host_id, executed_at, exit_code }`.
- **Install shell integration** (§9.10): a built-in snippet "Install sverb shell integration" for bash, zsh and fish that appends a small, idempotent hook (guarded by
  `# >>> sverb shell integration >>>` markers) to `~/.bashrc` / `~/.zshrc` / `~/.config/fish/conf.d/sverb.fish`. The hooks emit OSC 133 A/B/C/D. Ship the hook scripts as
  files in the repo (`assets/shell-integration/{bash,zsh,fish}`), and run via Exec with a preview. Uninstall removes the block.

### 2.2 Tier 2: heuristic
Without OSC 133 (never seen in this session), on `Enter` with the **alternate screen off**: capture the current cursor line, strip the learned **prompt prefix**, and record it as
**unverified** (the `HistoryEntry` gets a `verified: false` field: **spec addition**, mark it in data-model docs). Prompt learning: track the text left of the cursor at the moments
right after output settles (no output for 150 ms) and the cursor is at a line end. The longest common prefix over the last 5 observations (≥ 2 chars, ending with
`$`, `#`, `%`, `>`, or `❯` plus a space) becomes the prompt pattern. Secrets: skip capture when the remote has echo off? That isn't detectable directly. Use heuristics: skip if the
previous output line matches `/password|passphrase|token/i` and ends with `:`. Never capture while a sverb secret prompt is open.

### 2.3 Sources and suggestions (§9.10)
Per-host history (most recent first, frequency-weighted), global history, snippets (by name and script first line), and a **static completion set** of common commands (≈300
entries: coreutils, git, docker, kubectl, systemctl subcommands; shipped as a text file).

### 2.4 UX (§9.10)
- `leader Space` → an overlay **anchored at the cursor** (above it if there's no room below), with a fuzzy search over the sources, pre-filtered by the current line's **prefix when tier 1
  knows it** (the text between B and the cursor). Rows show a source icon (H history, G global, S snippet, C common), an unverified marker, and the exit code (red if ≠ 0).
- `Enter` types the **remainder** (the suggestion minus the existing prefix) and presses Enter? **The spec says** "Enter types the remainder into the pane, and Tab inserts without
  executing", so Enter = type the remainder + `\r`, and Tab = type the remainder only. For snippets: the run flow (variables).
- Optional inline **ghost text** (tier 1 only, off by default, a config `history.ghost_text = false`, spec addition): a dim suggestion after the cursor, accepted with `→` at line end.
  Accepted **only** with `leader Tab`. No unprefixed key is intercepted, because `ctrl-f`/`→` belong to readline and fish
  (`03-KEYBINDINGS.md` §3.1 A7, §1.2 pass-through guarantee).
- **Storage** (§9.10): HistoryEntry items, synced only when `history.sync = true`, capped at `history.max_entries_per_host` (5000; trim oldest), with `history.enabled = false`
  disabling capture. **Purge per host:** host detail action "Clear history".
- Secret snippet variables are never stored (M2-09).

## 3. Codebase changes
- The modules listed in the header, the assets, and the overlay view. Config additions: `history.ghost_text` (M0-06 table and schema).

## 4. Test cases to implement

**T-01 (unit)** OSC 133 parser: sequences split at every byte boundary are still recognized. A/B/C/D with exit codes.

**T-02 (integration, recorded stream)** A bash session with the integration installed → 3 commands captured with correct text and exit codes, including a wrapped long command.

**T-03 (unit)** Prompt learning from observations `user@h:~$ ` → the pattern is learned, and capturing `user@h:~$ ls -la` gives `ls -la` (unverified).

**T-04 (unit)** No capture on the alt screen. No capture after a "Password:" line.

**T-05 (unit)** Suggestion ranking: per-host history before global, frequency boost, prefix filter.

**T-06 (reducer)** `leader Space` overlay anchored at the cursor. Enter → remainder + `\r`. Tab → remainder only.

**T-07 (unit)** Cap per host at max_entries, with the oldest trimmed.

**T-08 (integration)** `history.sync = false` → no outbox rows for HistoryEntry.

**T-09 (e2e)** Run the install-integration snippet on the bash/zsh/fish container users → subsequent commands are captured as verified. Running it twice doesn't duplicate the block.
Uninstall removes it.

**T-10 (reducer)** Purge history for a host → entries tombstoned.

## 5. Passing functional characteristics
- [ ] With OSC 133, sverb captures exact commands and exit codes. A one-click snippet installs the integration for bash, zsh and fish.
- [ ] Without it, a heuristic captures commands as "unverified" using a learned prompt prefix, avoiding the alt screen and password prompts.
- [ ] `leader Space` opens a cursor-anchored fuzzy overlay over host and global history, snippets and common commands. Enter executes and Tab inserts.
- [ ] History respects `history.enabled/sync/max_entries_per_host` and can be purged per host. Optional ghost text is off by default.
