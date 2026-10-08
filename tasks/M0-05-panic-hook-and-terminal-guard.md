# M0-05 — Panic hook, terminal guard and crash reports

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/errors.rs` → rename `panic.rs`; `crates/sverb/src/tui.rs:149-234` (`stop`, `enter`, `exit`, `Drop`); `crates/sverb/src/main.rs`; workspace deps (`human-panic`, `better-panic`, `libc` removed) |
| **Spec refs** | §18 (panic hook, error UX), §17 (no secrets in crash output), §7.3 (kitty flags to pop) |
| **Depends on** | M0-03, M0-04 |
| **Blocks** | M0-09 |

---

## 1. Current state in the codebase
`crates/sverb/src/errors.rs`:
- Lines 6-15: color-eyre `HookBuilder` with a "This is a bug" section pointing at
  `CARGO_PKG_REPOSITORY`. Keep that idea.
- Lines 16-21: the panic hook calls `crate::tui::Tui::new()` to restore the terminal. `Tui::new`
  (`tui.rs:57-70`) calls `tokio::spawn(async {})`, which **panics when there's no runtime
  context**, for example a panic on a `spawn_blocking` thread or after runtime shutdown. The result is
  a double panic and an abort with the terminal left in raw mode. `Tui::exit` (`tui.rs:179-193`) also
  only restores when `is_raw_mode_enabled()` is true, and it disables mouse and paste only if *that new
  instance's* `mouse`/`paste` flags are set. They're always `false` on a fresh `Tui`, so mouse capture
  and bracketed paste stay enabled after a crash.
- Lines 23-32: in release builds, `human-panic` writes a report to the OS temp dir and prints its
  own message. The spec wants the report in the **state dir**, with filtered logs.
- Lines 36-44: in debug builds `better-panic` prints a backtrace. That's fine for devs, but it's yet another hook.
- Line 46: `std::process::exit(EXIT_FAILURE)` skips destructors, so the non-blocking log writer
  (M0-04) is never flushed and the final log lines are lost.

`crates/sverb/src/tui.rs`:
- Lines 149-164: `stop()` busy-waits up to 100 ms with `std::thread::sleep` on the async runtime
  thread.
- Lines 230-234: `impl Drop for Tui { fn drop(&mut self) { self.exit().unwrap(); } }`. A failing
  `exit()` (e.g. stdout closed) **panics inside `Drop`**, and if that happens during unwinding it aborts.
- `enter()` (lines 166-177) hides the cursor and enters the alt screen. It doesn't push kitty keyboard
  flags (M1-11 adds them), so the restore sequence must already pop them if set.

## 2. Detailed description

### 2.1 Terminal state as a single source of truth
Introduce `TerminalModes` in `sverb-tui::runtime::terminal`: a process-global record (an
`AtomicU8` bitset, so no runtime and no allocation are needed) of which modes sverb has enabled:
`RAW`, `ALT_SCREEN`, `MOUSE`, `BRACKETED_PASTE`, `KITTY_FLAGS`, `CURSOR_HIDDEN`, `FOCUS_EVENTS`.
- Every enable operation sets its bit **after** succeeding. Every disable operation clears it.
- `restore_terminal()` is a free function that reads the bitset and undoes exactly the enabled modes,
  in reverse order: pop kitty flags → disable bracketed paste → disable mouse capture → disable focus
  events → show cursor → leave alt screen → disable raw mode. Each step is best-effort and errors are
  ignored. It writes directly to a fresh `std::io::stdout()` handle, does no tokio, takes no locks
  that could already be held (use `try_lock` on stdout, and fall back to raw `write` on a dup'd fd if
  locked), and never panics.
- `TerminalGuard` (RAII) calls `restore_terminal()` in `Drop`. It replaces `impl Drop for Tui`
  (`tui.rs:230-234`).

### 2.2 Panic hook (`crates/sverb/src/panic.rs`)
Installed as the very first thing in `main`, before logging (so even logging-init panics restore
the terminal):
1. `restore_terminal()`. This is safe from any thread, with or without a runtime.
2. Build the report text with color-eyre's `PanicHook::panic_report` (keep the "This is a bug, please
   report at …" section from `errors.rs:7-10`).
3. Print a **short** message to stderr: `sverb crashed: <message>` and
   `A crash report was written to <path>`. Print the full colored report only when
   `SVERB_LOG=debug` or in debug builds.
4. Write a crash report to `paths.crash_dir()/crash-<UTC yyyymmddThhmmssZ>-<pid>.txt` containing:
   sverb version (vergen describe), OS/arch, terminal (`TERM`, `TERM_PROGRAM`), the panic message and
   location, the thread name, a forced backtrace, the ANSI-stripped report, and the last 200 lines of
   the **info+** crash ring (M0-04 §2.1). No debug lines, so no hostnames. File mode `0600` on Unix.
5. Flush logging: the `LoggingGuard` is stored in a `OnceLock<Mutex<Option<WorkerGuard>>>`, so the hook can
   `take()` and drop it.
6. **Re-entrancy guard:** an `AtomicBool` `IN_PANIC_HOOK`. If set, a nested panic writes one line to
   stderr and calls `std::process::abort()`.
7. Exit: return from the hook and let the unwinding/runtime shutdown happen. For panics on non-main
   threads, the tokio runtime surfaces a `JoinError`. The app treats any panicked **UI** task as fatal
   and exits with code 101 after cleanup. Session tasks that panic are contained (M1-08), and the pane
   shows "session crashed" instead of crashing the app.
- **Remove** `human-panic`, `better-panic` and `libc` from the workspace and crate deps. Keep
  `strip-ansi-escapes` (used for the report).

### 2.3 Error reporting for the UI (`sverb-core::error_report`)
`ErrorReport { short: String, chain: Vec<String> }`, built from any `&dyn std::error::Error` by
walking `source()`. It's used by every toast and dialog that shows an error ("short message with
expandable detail chain", §18). Put it in core so the CLI uses the same formatting:
`error: <short>` then `  caused by: …` lines.

### 2.4 `Tui::stop` busy wait (`tui.rs:149-164`)
Replace with `async fn stop(&mut self)` that cancels the token and `await`s the task with a 100 ms
`tokio::time::timeout`, aborting on timeout. No `std::thread::sleep` on the runtime. (This moves into
the new runtime module in M0-09, but fix the hazard now.)

### 2.5 Suspend (`Ctrl-z`, `tui.rs:199-209`)
Keep SIGTSTP support, but route it through `restore_terminal()` before raising and re-enable the
recorded modes on resume (SIGCONT). On Windows, suspend is not available, so the keybinding is a no-op with a
toast.

### 2.6 Out of scope
- `prctl(PR_SET_DUMPABLE)` and `mlock` (M7-05).

## 3. Codebase changes
- **Rename** `crates/sverb/src/errors.rs` → `panic.rs` and rewrite it. Update `main.rs:16,22`.
- **Create** `crates/sverb-tui/src/runtime/terminal.rs` with `TerminalModes`, `restore_terminal` and
  `TerminalGuard`. Until M0-08 moves code into `sverb-tui`, put it in `crates/sverb/src/terminal.rs`
  and move it later.
- **Modify** `crates/sverb/src/tui.rs`: `enter`/`exit` set and clear mode bits; delete `impl Drop`;
  make `stop` async.
- **Create** `crates/sverb-core/src/error_report.rs`.
- **Remove** deps: `human-panic`, `better-panic`, `libc`.

## 4. Test cases to implement

**T-01 (integration, Unix PTY) Restore after panic in UI task.** Spawn the binary inside a
`portable-pty` PTY with a hidden test flag `--__panic-after-start` (compiled only with
`cfg(feature = "test-hooks")`). Read the PTY output and assert it contains `ESC[?1049l` (leave alt
screen), `ESC[?25h` (show cursor), `ESC[?1000l`/`ESC[?1006l` (mouse off, when mouse was enabled) and
`ESC[?2004l` (paste off). Assert the PTY termios has `ICANON|ECHO` set again.

**T-02 (integration) Panic on a non-runtime thread.** The test flag panics inside a `std::thread::spawn`.
The terminal is still restored, and there's no double panic (exit status is not SIGABRT).

**T-03 (integration) Panic during `spawn_blocking`.** Same as T-02 inside `spawn_blocking`.

**T-04 (integration) Crash report.** After T-01, exactly one `crash-*.txt` exists in
`SVERB_HOME/state/crash/`, contains the panic message and version, has mode `0600`, and contains no line
at `DEBUG` level even though debug lines were emitted before the panic.

**T-05 (integration) Logs flushed.** A `info!("last words")` emitted immediately before the panic is
present in the log file.

**T-06 (unit) Re-entrancy.** Simulate a nested invocation (set the guard, call the hook body). It
returns via the abort path. Test the decision function, not the actual abort.

**T-07 (unit) `restore_terminal` with nothing enabled** writes no bytes.

**T-08 (unit) Mode bookkeeping.** Enable raw + alt + paste through the wrapper functions (with a fake
writer), then call `restore_terminal`. The emitted sequences are in reverse order and only for those three.

**T-09 (unit) ErrorReport.** A 3-deep error chain gives `short` = the outermost message and `chain` of
length 3. The CLI formatting matches the snapshot.

**T-10 (integration) Drop never panics.** Close stdout (redirect to a closed pipe) before the app
exits normally. The process exits without "panicked while panicking".

**T-11 (unit) No `human-panic`/`better-panic`/`libc`.** `cargo tree -p sverb` doesn't contain them
(assert in the layering/metadata test from M0-01).

## 5. Passing functional characteristics
- [ ] Any panic, on any thread and with or without a runtime, leaves the terminal in cooked mode on the main
      screen with the cursor visible, mouse capture off, bracketed paste off and kitty flags popped.
- [ ] Every panic writes a private crash report into the state dir, without debug-level content.
- [ ] Log lines emitted before a panic are flushed to disk.
- [ ] Nested panics abort cleanly instead of looping.
- [ ] `Drop` never panics, and the async runtime is never blocked by busy-waits.
- [ ] Errors render consistently as short message plus detail chain in both the TUI and the CLI.
- [ ] `human-panic`, `better-panic` and `libc` are removed.
