# Client UI architecture

The sverb client UI is a single-owner state machine (SPEC §2.1). All UI state lives in
one plain-data struct, `sverb_tui::app::App`. It changes in exactly one place:

```rust
impl App {
    pub fn handle(&mut self, ev: UiEvent) -> Vec<Effect>;
}
```

`handle` is synchronous and deterministic. It never reads the clock, because time arrives
inside events. It uses no randomness and does no I/O. Anything with a side effect is
returned as an `Effect`, executed elsewhere, and its result comes back as a new `UiEvent`.

## The loop

```
                 ┌──────────────────────────────────────────────┐
                 │                 runtime loop                 │
 crossterm ──────▶  UiEvent::Input ─┐                           │
 timers ─────────▶  UiEvent::Timer ─┤                           │
 services ───────▶  UiEvent::       │   ┌──────────────────┐    │
 (effect results)   EffectDone ─────┼──▶│  App::handle(ev) │    │
 sessions (M1-08) ▶ UiEvent::Session┘   │  (pure reducer)  │    │
                 │                      └────────┬─────────┘    │
                 │                     Vec<Effect>│              │
                 │        ┌───────────────────────┴────────┐    │
                 │        ▼                                ▼    │
                 │  Quit / Suspend /               Services::execute
                 │  SetMouseCapture                (timers, store, sessions,
                 │  (run by the loop)               clipboard, …) ──┐
                 │                                                  │
                 │  frame tick (≤ 60 fps, Skip): if app.needs_redraw │
                 │  → drain queued input → draw App::render (infallible)
                 └──────────────────────────────────────────────────┼─┘
                                     results as UiEvent ◀────────────┘
```

The client-wide picture from SPEC §2:

```
┌──────────────┐  UiEvent   ┌──────────────────┐  Cmd    ┌────────────┐
│ crossterm    ├──────────▶ │   App (state +   ├───────▶ │ Session    │
│ EventStream  │            │   reducer)       │         │ Manager    │
└──────────────┘            │                  │◀────────┤ (tasks)    │
                            │   ratatui render │ Session │            │
                            └───────┬──────────┘  Event  └─────┬──────┘
                                    │                          │
                       ┌────────────▼────────┐    ┌────────────▼──────┐
                       │ Vault (sverb-core)  │    │ Transports        │
                       │ SQLite + crypto     │    │ ssh (russh),      │
                       └─────────────────────┘    │ local pty         │
                                                  └───────────────────┘
```

## Modules (`crates/sverb-tui/src`)

| Module | What lives there |
|---|---|
| `app/event.rs` | `UiEvent`, `InputEvent`, `TimerKind`/`TimerFired`, `EffectResult` |
| `app/effect.rs` | `Effect`, `EffectId` |
| `app/state.rs` | plain-data state pieces: `Mode`, `Focus`, `Layout`, `Tabs`, `Toast`, `PendingKind` |
| `app/mod.rs` | `App`, `App::handle`, `App::render` |
| `views/` | the `View` trait, `Views` (one field per view), dialogs, the Hosts placeholder |
| `keymap/` | `KeyChord` parsing, the global `Keymap`, the `ActionName` registry |
| `services/` | `Services::execute`: the effect executor |
| `runtime/` | the event loop (`mod.rs`), terminal guard (`terminal.rs`), input task (`input.rs`), timer service (`timers.rs`), OS signals (`signals.rs`), session dirty tracking and the backpressure contract (`sessions.rs`) |
| `testing.rs` | `AppHarness`, `FakeSessionRegistry` (feature `test-util`) |

`app/`, `views/` and `keymap/` must not use the async runtime, the filesystem, the
network or the wall clock. A test (`testing::tests::t02_reducer_modules_import_no_io`)
scans their sources.

## Input dispatch

Key, mouse and paste input goes through three stages. The first one that returns
`Outcome::Consumed` wins:

1. the dialog on top of `App::dialogs` (dialogs are modal and consume everything),
2. the focused view,
3. the global keymap, which maps a `KeyChord` to an `ActionName` and applies it.

## Effects and their results

Effects that produce a result carry an `EffectId`, assigned monotonically by the
reducer. When the reducer issues one, it records a `PendingKind` in `App::pending`, which
says what the result is for (for example "the form dialog with id 3 is saving"). The
result arrives as `UiEvent::EffectDone { id, result }`. The reducer removes the pending
entry and routes the result. Unknown or duplicate ids are ignored. Errors carry a
`sverb_core::error_report::ErrorReport`, and its `short` message goes into an error toast.

`Quit`, `Suspend`, `SetMouseCapture`, `ScheduleTimer` and `CancelTimer` are executed by
the runtime loop itself.
Everything else goes to `Services`, which never touches `App`. Blocking work (Argon2,
SQLite, key generation) runs in `spawn_blocking`.

Timers are effects too: `ScheduleTimer { kind, after }` and `CancelTimer(kind)`. When a
timer fires, it is delivered as `UiEvent::Timer` with the `Instant` it fired at. There
is no periodic tick.

## The event loop (M0-09)

`runtime::EventLoop` waits on its sources with `tokio::select! { biased; … }`, in this
order: terminal input (bounded, 1024), session notifications (unbounded but coalesced:
at most one `Dirty` per session until it is drawn), then effect results / config /
timers / signals, and last the frame tick (1/60 s, `MissedTickBehavior::Skip`). On a
tick it first applies all queued input, then draws only if `App::needs_redraw`, a
visible session is dirty, or a full repaint is pending (resume after `SIGCONT`).
Visible sessions' dirty flags are acknowledged right before the draw. SIGTERM, SIGHUP
and SIGINT (Windows: console close/shutdown) become `UiEvent::ShutdownRequested`, which
quits with code 0 without confirmation. The UI → session backpressure rules for M1-08
are documented in `runtime/sessions.rs`.

## Why there is no ping-pong

The template's `Component`s each held an unbounded sender and could emit actions at any
time. Every component saw every action, so actions could bounce back and forth forever.
Views now have no sender. Inside one `handle` call a view can only push effects into the
`ViewCx` sink, request a redraw, or close itself if it is a dialog. Nothing is delivered
back to a view re-entrantly, so one event yields a bounded effect list. A test checks
that every single event yields fewer than 64 effects.

## Hotspot convention

`UiEvent`, `Effect`, the state enums, `Views`, `DialogKind` and the `ActionName`
registry are extended by almost every UI task. Add new variants and fields **at the
end**, in one block per change that starts with a short marker comment, so parallel
changes merge mechanically.

## How to add a view

1. Create `crates/sverb-tui/src/views/<name>.rs` with a plain-data struct
   (`#[derive(Debug, Default, Clone, PartialEq, Eq)]`). It must not hold channels,
   tokio types or closures.
2. Implement `View` for it:
   - `handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx) -> Outcome`: update your state,
     call `cx.request_redraw()` when the screen should change, push effects with
     `cx.push(..)`, or use `cx.issue(|id| Effect::…, PendingKind::…)` when you need the
     result. Return `Outcome::Ignored` for keys you don't handle, so they reach the
     global keymap.
   - `render(&self, frame, area, cx: &RenderCx)`: draw with ratatui. It must not fail
     or panic at any size. If there is not enough room, draw less or draw a short
     message instead.
3. Add a field for it at the end of `Views` (in your task's `// <task-id>` block), a
   `Focus` variant if it can take focus, and the matching arms in
   `Views::focused_mut` and `App::render`.
4. If results of your effects need routing, add a `PendingKind` variant and handle it in
   `App::on_effect_done`.
5. Test it through `AppHarness`: `.keys("j j enter")`, `.send(UiEvent::…)`,
   `.effects()`, `.advance(ms)` for timers, and `insta::assert_snapshot!(h.render(80, 24))`.
   Add it to the render-at-every-size test (`t08_every_view_renders_at_every_size`).
