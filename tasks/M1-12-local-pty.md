# M1-12 — Local terminal transport (`portable-pty`)

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-conn/src/local.rs`, `crates/sverb-tui/src/services/sessions.rs` (`Local` spec), keybinding `leader t` |
| **Spec refs** | §6.2, §6 (Transport trait), §8.3 (`leader l` in the spec; **`leader t`** per `03-KEYBINDINGS.md` §4.1 because `l` is focus-right), §2.1 (blocking work) |
| **Depends on** | M1-08 |
| **Blocks** | M1-17 (local panes in layouts), M3-03 (workspace leaves `local`) |

---

## 1. Current state in the codebase
The session actor and `Transport` trait exist (M1-08), with `MockTransport` only. `leader t` is bound to
`new_local_tab` (M0-10) but has no implementation.

## 2. Detailed description
- `LocalTransport` implements `Transport` over `portable_pty::native_pty_system()`.
- **Shell selection:** Unix: `$SHELL`, falling back to `/bin/sh`, launched as a login shell? **Decision:** not a login
  shell by default, matching tmux defaults for new panes (`-l` is off). It's configurable via a future
  `terminal.local_shell_args`, so record it as an open question rather than add the config key now. Windows: `ComSpec`
  (`cmd.exe`), or `pwsh.exe` if found in PATH and preferred? **Decision:** `pwsh` if available, else `ComSpec`
  (§6.2 lists both).
- **cwd:** configurable per `LocalSpec { cwd: Option<PathBuf>, shell: Option<String>, env: Vec<(String,String)> }`.
  Default is the user's home directory (not sverb's cwd).
- **Environment:** inherit the process environment, set `TERM` = `terminal.term` (default `xterm-256color`), set
  `COLORTERM=truecolor` if sverb renders truecolor, and **remove** sverb-internal variables (`SVERB_*`) so
  child processes don't inherit test homes. Add `SVERB_PANE=<session id>` for scripts (document it).
- **I/O:** portable-pty readers and writers are **blocking**. Run a dedicated `std::thread` (or
  `spawn_blocking` with a long-lived loop) for reading, which forwards chunks over a `tokio::sync::mpsc`
  (bounded 32 × 64 KiB), adapted to `AsyncRead` for the trait's `reader()`. Writes go via `spawn_blocking` or
  a writer thread with a channel.
- **Resize:** `master.resize(PtySize{rows, cols, pixel_width, pixel_height})`.
- **Exit:** when the child exits, the reader hits EOF, `child.wait()` gives the exit code, and the state becomes
  `Disconnected{Exited(code)}` (no reconnect banner, §6.1.9). The pane shows "Process exited (code N) — [Enter] restart · leader x close". Plain letters are
  swallowed, never acted on, so typing `x…` into a just-exited shell can't close the pane (`03-KEYBINDINGS.md` §3.1 A5, §4.4).
- **Close:** kill the child (SIGHUP then SIGKILL after 1 s on Unix; `TerminateProcess` on Windows) and join the reader
  thread.
- Local terminals are regular tabs: splittable and broadcast-capable (§6.2).

## 3. Codebase changes
- **Create** `sverb-conn/src/local.rs`. Dep: `portable-pty`.
- **Wire** `Effect::OpenSession(SessionSpec::Local(..))` and the `new_local_tab` action.

## 4. Test cases to implement

**T-01 (integration) Echo.** Spawn `/bin/sh` (Unix) or `cmd /C` (Windows), write `echo hello\r`, and the emulator grid
contains `hello` within 2 s.

**T-02 (integration) TERM.** Run `echo $TERM` → `xterm-256color`. With `terminal.term = "xterm"` → `xterm`.

**T-03 (integration) No SVERB_ leak.** Run `env | grep SVERB_HOME` → empty. `SVERB_PANE` is present.

**T-04 (integration) Resize.** Resize to 100×30, then `stty size` → `30 100` (Unix).

**T-05 (integration) Exit code.** `exit 3` → state `Disconnected{Exited(3)}`.

**T-06 (integration) Close kills the child.** Spawn `sleep 1000`, close → the child PID is gone within 2 s.

**T-07 (integration) cwd.** `LocalSpec{cwd: /tmp}` + `pwd` → `/tmp`.

**T-08 (integration) Large output.** `yes | head -c 50000000` → completes, with no deadlock, and the UI receives ≤ (frames)
Dirty events (coalescing from M1-08 works with the threaded reader).

**T-09 (integration, Windows)** `cmd.exe` launches, `echo %COMSPEC%` works, and resize works.

**T-10 (reducer)** `leader t` → `OpenSession(Local)` and a new tab is created (after M1-17; until then, a single pane).

## 5. Passing functional characteristics
- [ ] `leader t` opens a local shell (`$SHELL`, `pwsh`/`ComSpec` on Windows) in a tab, behaving like any session.
- [ ] TERM and COLORTERM are set, and sverb-internal env vars are not leaked.
- [ ] Resize, exit codes and close (killing the child) work on Unix and Windows.
- [ ] Blocking PTY I/O never blocks the tokio runtime.
