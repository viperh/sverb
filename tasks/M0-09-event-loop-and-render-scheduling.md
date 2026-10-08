# M0-09 — Event loop and dirty-driven render scheduling

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/tui.rs` → `crates/sverb-tui/src/runtime/{mod.rs, terminal.rs, input.rs, timers.rs}`; `crates/sverb-tui/src/lib.rs` (`run`) |
| **Spec refs** | §2.1 (runtime model, backpressure, render scheduling, blocking work), §8.1 (resize), §18 (graceful exit) |
| **Depends on** | M0-05 (terminal guard), M0-08 (reducer) |
| **Blocks** | M0-11, M1-08 |

---

## 1. Current state in the codebase
`crates/sverb/src/tui.rs` and `app.rs:57-91`:
- A spawned task (`tui.rs:106-147`) multiplexes `tick_interval` (4 Hz), `render_interval`
  (60 Hz) and crossterm's `EventStream`, sending `Event`s over an **unbounded** channel.
- `App::run` handles **one** event per iteration (`handle_events`), then drains actions. A
  `Render` event redraws **unconditionally** 60 times per second, even when nothing changed, which
  burns CPU on idle and over SSH-in-SSH.
- Tick and render are `tokio::time::interval`s with the default `MissedTickBehavior::Burst`.
  After a stall, the loop fires a burst of catch-up renders.
- There's no input prioritization: a render can be drawn before already-queued keystrokes are applied.
- Key events are filtered to `KeyEventKind::Press` (tui.rs:129). That's correct, but repeat events
  are dropped too, so held-down keys don't repeat when the kitty protocol reports `Repeat`.
- Multi-key sequences rely on `Tick` to clear `last_tick_key_events` (app.rs:145-148), which ties
  keymap timing to the tick rate.
- Mouse and bracketed paste are off (`tui.rs:67-68`), and the mouse is commented out in `app.rs:59`.
- No signal handling for SIGTERM/SIGHUP. Suspend via SIGTSTP exists (tui.rs:199-204).
- `#[tokio::main]` (main.rs:20) builds the runtime implicitly.

## 2. Detailed description

### 2.1 Runtime
- The binary builds a `tokio` multi-thread runtime explicitly (M0-07 §2.5). `sverb_tui::run(intent,
  ctx)` runs on it as one task, and rendering happens inside that task (§2.1).
- Terminal setup through the M0-05 mode-tracking wrappers: raw mode, alt screen, hide cursor,
  **bracketed paste on**, **mouse capture on if `ui.mouse`**, focus events on, and kitty keyboard flags
  pushed if supported (detection lands in M1-11; the hook point is here).

### 2.2 Event sources and the main loop
- **Input task**: owns crossterm's `EventStream`, converts to `InputEvent`, and pushes into a
  **bounded** `mpsc` (capacity 1024). Accept key kinds `Press` **and** `Repeat`, and ignore `Release`.
- **Session events** (M1-08), **effect results**, **config events** and **sync events** each have their own
  receiver. The session channel carries coalesced `Dirty` notifications (§2.1).
- **Timers**: a `Timers` service owns a `tokio_util::time::DelayQueue<TimerKind>`. `ScheduleTimer`
  and `CancelTimer` effects drive it, and it yields `UiEvent::Timer`.
- **Frame tick**: `tokio::time::interval(16ms)` with `MissedTickBehavior::Skip`.
- Main loop, using `tokio::select! { biased; … }` with this priority:
  1. input receiver
  2. session events
  3. effect results, timers, config, sync
  4. frame tick
- **Input drain rule**: whenever the loop is about to draw (frame tick fired and something is
  dirty), it first drains **all** currently available input events with `try_recv` and feeds them to
  `App::handle`. Only then does it draw. Input is never starved by output floods (§2.1).
- **Dirty tracking**: draw only if `app.needs_redraw` or any session dirty flag is set. After drawing,
  clear `needs_redraw` and acknowledge each drawn session's dirty flag (`AtomicBool::store(false)`), which
  re-arms its next `Dirty` event (§2.1, M1-08).
- **Resize**: a terminal `Resize` event triggers `terminal.autoresize()` and sets `needs_redraw`. The
  frame tick still caps the draw rate.
- No `Tick` event exists any more. Anything time-based uses a scheduled timer.

### 2.3 Effects owned by the loop
- `Effect::Quit { code }`: stop the input task, call `SessionManager::shutdown(timeout = 2s)` (M1-08;
  a no-op now), flush the store, restore the terminal (guard drop), and return `code`.
- `Effect::Suspend` (Unix): restore the terminal, raise SIGTSTP, and on resume re-apply the recorded modes and
  force a full redraw (`terminal.clear()`). On Windows, show a toast "Suspend is not supported on Windows".
- `Effect::SetMouseCapture(bool)`: toggle capture live (config hot reload of `ui.mouse`).

### 2.4 Signals
- Unix: SIGTERM, SIGHUP and SIGINT (SIGINT only arrives when not in raw mode, e.g. while suspended) →
  `UiEvent::ShutdownRequested`. The reducer returns `Quit{code:0}` without confirmation. SIGCONT → force a
  redraw. SIGWINCH is already delivered through crossterm `Resize`.
- Windows: `tokio::signal::windows::ctrl_close` / `ctrl_shutdown` → the same path.

### 2.5 Backpressure contract (for M1-08)
- The session → UI channel is unbounded, but coalesced: at most one `Dirty` per session until acknowledged.
  Other session events (title, bell, state) are rare. Document this contract in the module docs.
- The UI must never `await` on a session's command channel while the session is blocked on the UI. Use
  `try_send` for `SessionCmd` from the UI, and handle a full queue by dropping resize/coalescing input
  with a warning. Input bytes are never dropped: the pane shows "input queue full", which is a bug indicator.

### 2.6 Out of scope
- Kitty keyboard detection (M1-11), the session manager (M1-08) and the layout (M0-11).

## 3. Codebase changes
- **Replace** `crates/sverb/src/tui.rs` with `crates/sverb-tui/src/runtime/` (`mod.rs` for the loop,
  `terminal.rs` for the guard from M0-05, `input.rs` for the input task, `timers.rs`, `signals.rs`).
- **Delete** `Tui`'s `tick_rate`/`frame_rate` builders and the `Event::{Tick, Render, Init, Error,
  Closed, Quit}` variants.
- **Delete** `App::run`, `handle_events`, `handle_actions`, `handle_resize` from the old `app.rs`
  (logic moves to the reducer and loop).
- **Modify** `crates/sverb/src/main.rs` to build the runtime explicitly.

## 4. Test cases to implement
All loop tests run with an injectable `Backend` (`TestBackend`) and fake input stream, under
`tokio::time::pause()` for determinism.

**T-01 (loop) Idle draws nothing.** After the initial frame, advance 10 s with no events: 0 additional draws.

**T-02 (loop) Frame cap.** Mark dirty continuously (a fake session sets dirty on every poll) for 1 s of
virtual time: ≤ 61 draws.

**T-03 (loop) Skip, not burst.** Make one draw take 100 ms of virtual time. The next draw happens on the next
16 ms boundary, with no burst of 6 draws.

**T-04 (loop) Input before draw.** Enqueue 500 key events and set dirty. At the moment of the first draw,
the reducer has processed all 500 (instrumented counter).

**T-05 (loop) Output flood doesn't starve input.** A fake session sets dirty continuously, and a key
event sent at t = 100 ms is handled before t = 117 ms (within one frame).

**T-06 (loop) Dirty ack.** The session's flag is false after a draw that included the pane, and a draw that
didn't include it (pane hidden) doesn't clear it.

**T-07 (loop) Repeat keys accepted, release ignored.** Feeding `Press`, `Repeat` and `Release` of `j`
produces two key events.

**T-08 (loop) Timers.** `ScheduleTimer{Toast, 4s}` delivers a `Timer(Toast)` exactly once at 4 s.
`CancelTimer` before it fires suppresses it.

**T-09 (integration, PTY) Quit restores terminal.** Launch the binary in a PTY, send the quit key
sequence, and assert exit 0 plus the restore sequences (shared assertion helper with M0-05 T-01).

**T-10 (integration, PTY, Unix) SIGTERM.** Exit 0 with the terminal restored, and no confirmation dialog shown.

**T-11 (integration, PTY, Unix) Suspend/resume.** `ctrl-z` → the process is stopped (check with
`waitpid(WUNTRACED)`) and the terminal is restored. `SIGCONT` → the alt screen is re-entered and the screen redrawn.

**T-12 (integration, PTY) Mouse capture follows config.** With `ui.mouse = false`, no `ESC[?1000h`
is emitted at startup.

**T-13 (bench, criterion; optional)** The loop overhead per idle tick is < 50 µs.

## 5. Passing functional characteristics
- [ ] Rendering is dirty-driven, capped at 60 fps, with skipped (not bursted) missed ticks.
- [ ] Queued input is always applied before a frame is drawn, and output floods can't delay keystrokes by
      more than one frame.
- [ ] There's no periodic `Tick`. Time-based behavior uses explicit timers.
- [ ] Bracketed paste is on, and mouse capture follows `ui.mouse` live.
- [ ] Quit, SIGTERM/SIGHUP, Windows console close and suspend/resume all leave the terminal correct.
- [ ] The template's `Tui` struct, tick/frame-rate options and unbounded event channel are gone.
- [ ] The session/UI backpressure contract is documented for M1-08.
