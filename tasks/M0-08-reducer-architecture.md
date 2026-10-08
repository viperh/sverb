# M0-08 — Replace the Component/Action channel architecture with a pure reducer and effects

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/{app.rs, action.rs, components.rs, components/home.rs}` → moved and rewritten into `crates/sverb-tui/src/{app/, views/, services/, keymap/action.rs}`; `crates/sverb-core/src/lib.rs` (`Core` placeholder removed) |
| **Spec refs** | §2, §2.1 ("The App is a single-owner state machine"), §2.2, §19 (TUI row: reducer tests, `TestBackend` snapshots) |
| **Depends on** | M0-01 (crate `sverb-tui` exists) |
| **Blocks** | M0-09, M0-10, M0-11, every UI feature |

---

## 1. Current state in the codebase
The template architecture (`crates/sverb/src/app.rs`, `components.rs`, `action.rs`):
- `App` (app.rs:16-29) holds `components: Vec<Box<dyn Component>>`, an **unbounded**
  `mpsc` `action_tx`/`action_rx`, `should_quit`, `should_suspend`, `mode`,
  `last_tick_key_events`, plus `tick_rate`/`frame_rate`, and a `core: Core` placeholder.
- `Component` (components.rs:15-122) has `register_action_handler(tx)` (components keep a
  sender and can emit actions **asynchronously, from anywhere**), `register_config_handler`,
  `init`, `handle_events`, `handle_key_event`, `handle_mouse_event`, `update(action) ->
  Option<Action>`, and a **fallible** `draw(...) -> Result<()>`.
- `App::handle_actions` (app.rs:139-167) drains the channel. Each action is applied by `App`
  **and** broadcast to every component's `update`, which can enqueue more actions. Ordering and
  termination aren't guaranteed (an action can ping-pong forever), and every component sees every
  action, including `Tick`/`Render` 64 times a second.
- `Action` (action.rs:9-20) mixes **internal events** (`Tick`, `Render`, `Resize`, `Error`,
  `ClearScreen`, `Resume`) with **user commands** (`Quit`, `Suspend`, `Help`). It derives
  `Deserialize`, so `"Render"` could be bound to a key from the config.
- Draw errors are turned into `Action::Error` and only logged (app.rs:175-186).
- `Home` (components/home.rs) renders "Hello World".
- `sverb-core::Core` (lib.rs:26-50) is a tick counter that `App` advances on every `Tick`.

Problems vs. §2.1: the state is spread across components with interior senders, which isn't a
single-owner state machine. Nothing is deterministic or testable without a terminal and runtime,
because `App::new` builds channels and `run` needs a real `Tui`. There's no notion of side effects being
requested and executed separately.

## 2. Detailed description

### 2.1 New core types (`sverb-tui::app`)
- **`UiEvent`** (`#[non_exhaustive]` enum): everything the reducer can react to.
  - `Input(InputEvent)`: key, mouse, paste, focus gained/lost, terminal resize (from crossterm,
    converted in the runtime layer).
  - `Session(SessionId, SessionEvent)` (M1-08).
  - `EffectDone { id: EffectId, result: EffectResult }`.
  - `Timer(TimerKind)`: which-key timeout, toast expiry, auto-lock check, leader timeout, resize
    debounce. Each carries the `Instant` it fired.
  - `Config(ConfigEvent)` (M0-06).
  - `Sync(SyncEvent)` (behind `cfg(feature = "sync")`).
  - `Launch(LaunchIntent)` (M0-07).
- **`Effect`** (`#[non_exhaustive]`): side-effect requests, for example `Quit { code }`,
  `Suspend`, `ScheduleTimer { kind, after }`, `CancelTimer(kind)`, `SetMouseCapture(bool)`,
  `CopyToClipboard(..)`, `OpenSession{..}`, `SendToSession{id, cmd}`, `CloseSession(id)`,
  `SaveItem{id, ..}`, `DeleteItem{..}`, `Lock`, `Unlock{..}`, `Log(LevelMsg)`. Later tasks add
  variants.
- **`EffectId(u64)`**: monotonically assigned by the reducer, so results correlate with requests.
- **`App`**: owns all UI state as **plain data**: `mode`, `focus`, `layout` (sidebar,
  sections), `views: Views` (a struct with one field per view, not a `Vec<Box<dyn …>>`), `tabs`,
  `toasts`, `dialogs` (a stack), `keymap`, `config: Arc<Config>`, `pending: HashMap<EffectId,
  PendingKind>`, `needs_redraw: bool`, `next_effect_id`.
  It holds no channels, no tokio types and no `Box<dyn Fn>`. It's `Clone + Debug`, so snapshot and diff
  tests are possible.
- **`App::handle(&mut self, ev: UiEvent) -> Vec<Effect>`**: synchronous and deterministic. It never
  reads the clock (time arrives inside events), uses no randomness and does no I/O. Unknown events are
  ignored.

### 2.2 Views (successor of `Component`)
- **`View` trait** (`sverb-tui::views`):
  - `fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx) -> Outcome`. `ViewEvent` is the subset
    of input relevant to a focused view (key, mouse, paste). `ViewCx` gives read access to the config
    and an `effects: &mut Vec<Effect>` sink plus `request_redraw()`. `Outcome` is `Consumed` or
    `Ignored`, so unhandled keys bubble to the global keymap.
  - `fn render(&self, frame: &mut Frame, area: Rect, cx: &RenderCx)` is **infallible**. Rendering
    must not fail. Any "can't render" condition is drawn as an inline message.
- There's no `register_action_handler`. Views can't emit anything asynchronously, so there are no more
  hidden senders.
- There's no `register_config_handler`. Config comes through `cx`.
- Dispatch order for input: open dialog (top of stack) → focused view → global keymap (M0-10). The
  first `Consumed` wins.
- `Home` is replaced by the M0-11 shell, which keeps a placeholder "Hosts" section until M1-07.

### 2.3 Keymap actions (successor of `Action`)
`crates/sverb/src/action.rs` becomes `sverb-tui::keymap::action::ActionName`: **only user-bindable
commands**, `snake_case` names (`quit`, `suspend`, `help`, `palette`, `split_horizontal`, …), with
`FromStr`/`Display` via `strum`, and a static registry with a description per action, used by which-key,
help and the palette. Internal events (`Tick`, `Render`, `Resize`, `ClearScreen`, `Resume`,
`Error`) are **removed** from it. M0-10 owns the full list. This task migrates the existing three
(`Quit`, `Suspend`, `Help`).

### 2.4 Services (effect executor)
- `sverb-tui::services::Services` holds handles: store (later), session manager (M1-08),
  clipboard, timers, config watcher. `Services::execute(effect, ev_tx)` spawns or performs the effect
  and later sends the result as a `UiEvent` on the bounded event channel. Blocking work (Argon2,
  SQLite, keygen) uses `spawn_blocking` (§2.1).
- `Effect::Quit` and `Effect::Suspend` are executed by the runtime loop itself (M0-09), not by services.
- Services **never** touch `App`.

### 2.5 Domain placeholder
Delete `sverb-core::Core` (lib.rs:26-50) and its tests (52-71). `App` no longer has `core`. Domain
state arrives in M1 through the store and services. Keep `sverb_core::Error`/`Result` if useful,
otherwise replace them with per-module errors.

### 2.6 Test harness (`sverb-tui::testing`, behind feature `test-util`)
- `AppHarness::new(config)` builds an `App` with a fixed `Instant` origin.
- `.send(ev)`, `.keys("ctrl-\\ q")` (default leader is `ctrl-\`, see `03-KEYBINDINGS.md`) (parsing chord strings via the M0-10 parser), `.effects()` (the
  accumulated effects).
- `.render(w, h) -> String` draws into `ratatui::backend::TestBackend` and returns the buffer as
  text for `insta::assert_snapshot!`.
- `.advance(ms)` delivers due timer events, which the harness tracks from `ScheduleTimer` effects.
- A `FakeSessionRegistry` provides canned grids for rendering session panes (used from M1-10).

### 2.7 Out of scope
- The event loop and terminal I/O (M0-09), keymap parsing and leader logic (M0-10), and the shell layout (M0-11).

## 3. Codebase changes
- **Move and rewrite** `crates/sverb/src/app.rs` → `crates/sverb-tui/src/app/{mod.rs, event.rs,
  effect.rs, state.rs}`.
- **Move and rewrite** `components.rs` + `components/home.rs` → `crates/sverb-tui/src/views/{mod.rs,
  …}`.
- **Move and rename** `action.rs` → `crates/sverb-tui/src/keymap/action.rs`.
- **Create** `crates/sverb-tui/src/services/mod.rs` and `crates/sverb-tui/src/testing.rs`.
- **Modify** `crates/sverb/src/main.rs` to call `sverb_tui::run(...)`. The binary no longer has
  `mod app; mod action; mod components;`.
- **Delete** `sverb-core::Core`.
- **Docs:** add `docs/architecture.md` describing `UiEvent → App::handle → Effect → Services →
  UiEvent`, with the diagram from §2 of the spec, and a "how to add a view" guide (replacing the
  template's "copy home.rs" advice in README line 26).

## 4. Test cases to implement

**T-01 (unit) Determinism.** Clone an `App`, feed both copies the same 200-event script (randomly
generated via `proptest` from a small event alphabet), and assert equal resulting state (`Debug` string
or `PartialEq`) and identical effect vectors.

**T-02 (unit) No I/O in reducer.** A compile-level guard: `sverb-tui::app` must not import
`tokio`, `std::fs`, `std::net` or `std::time::SystemTime`. Implement it as a test that greps the module
sources, or as a clippy `disallowed_types`/`disallowed_methods` configuration scoped to the module.

**T-03 (unit) Quit without sessions.** `quit` action → `[Effect::Quit{code:0}]`.

**T-04 (unit) Quit with open sessions and `confirm_quit = true`.** A dialog is pushed and there are no effects.
`y` → `[Quit]`. `n` and `Esc` → the dialog is popped and there are no effects.

**T-05 (unit) Quit with `confirm_quit = false`** → `[Quit]` immediately.

**T-06 (unit) Effect correlation.** The reducer issues `SaveItem` with `EffectId(n)`. Feeding
`EffectDone{n, Err(e)}` adds an error toast containing `ErrorReport.short`. `EffectDone{n, Ok}` closes the
originating form. An unknown `EffectId` is ignored.

**T-07 (unit) Dispatch order.** With a dialog open, a key consumed by the dialog never reaches the focused
view. An `Ignored` key in the view reaches the global keymap.

**T-08 (unit) Render is infallible.** Rendering every view at sizes 1×1, 10×3, 80×24 and 300×100 never
panics (loop over the size list).

**T-09 (snapshot) Harness.** `AppHarness` renders the initial state at 80×24 and 160×48, and
`insta` snapshots exist.

**T-10 (unit) Action registry.** `ActionName::from_str("quit")` is OK. `"Render"` and `"tick"` are
errors (internal events can't be bound anymore). Every registry entry has a non-empty description.

**T-11 (regression) No ping-pong.** There's no API through which a view can enqueue events to itself.
Document this, and add a test that the effects vector returned from `handle` for any single input is bounded
(< 64 effects).

## 5. Passing functional characteristics
- [ ] All UI state mutation goes through `App::handle(UiEvent) -> Vec<Effect>`, which is synchronous,
      deterministic and I/O-free.
- [ ] Views have no senders and render infallibly. Input is dispatched dialog → view → keymap.
- [ ] Side effects run only in `Services`, and results come back as `UiEvent::EffectDone`.
- [ ] Internal events can no longer be bound as keymap actions.
- [ ] The template `Component`, `Action` channel, `Home` and `Core` placeholder are gone.
- [ ] An `AppHarness` drives the app with scripted events and snapshots it with `TestBackend`.
- [ ] `docs/architecture.md` explains the event → reducer → effect flow.
