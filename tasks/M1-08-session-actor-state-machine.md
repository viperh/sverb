# M1-08 — Session actor, session manager, state machine, dirty coalescing

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-conn/src/{transport.rs, session/{mod.rs, actor.rs, state.rs, cmd.rs, event.rs}, manager.rs}`, `crates/sverb-tui/src/services/sessions.rs` |
| **Spec refs** | §2.1 (each session is an actor; channels; 64 KiB lock chunks; backpressure), §2.1.1 (state machine), §6 (Transport trait), §6.1.9 (DisconnectReason) |
| **Depends on** | M0-09 (loop contract), M1-09 (Emulator trait; can be developed in parallel against a stub) |
| **Blocks** | M1-12, M1-13, M1-16, M1-17 |

---

## 1. Current state in the codebase
There are no sessions. M0-09 defined the UI side: a bounded input channel, unbounded-but-coalesced session events, the
dirty acknowledgement via an `AtomicBool`, and `try_send` from the UI. `Effect::{OpenSession, SendToSession,
CloseSession}` exist as placeholders (M0-08).

## 2. Detailed description

### 2.1 `Transport` trait (§6), in `sverb-conn::transport`
Methods `write`, `resize`, `reader`, `close` and `kind` exactly as in §6. Implementations: SSH (M1-13), local PTY (M1-12),
and a `MockTransport` (in-memory duplex) for tests, exported under `test-util`.

### 2.2 Session actor
One tokio task per session, which owns:
- the `Box<dyn Transport>` (after connect),
- `Arc<parking_lot::Mutex<Box<dyn Emulator>>>` (M1-09), shared read-only-ish with the renderer,
- the dirty flag `Arc<AtomicBool>`,
- `cmd_rx: mpsc::Receiver<SessionCmd>` (**bounded, capacity 256**, §2.1),
- `ev_tx: mpsc::UnboundedSender<(SessionId, SessionEvent)>`.

**SessionCmd** (§2.1): `Input(Bytes)`, `Resize{cols,rows,px_w,px_h}`, `Close`, `StartRecording`,
`StopRecording`, `HostKeyDecision(Decision)`, `AuthAnswer(AuthAnswer)`, `Reconnect`, plus
`Key(KeyChord)` (encoded by the session with its own modes, needed for broadcast, §7.3; added in M1-11).

**SessionEvent** (§2.1): `Dirty`, `Title(String)` (≤ 256 chars, §17), `Bell`, `State(SessionState)`,
`Prompt(AuthPrompt)`, `HostKey(Verification)`, `Exit{code}`, `Latency(Duration)`, `Error(ErrorReport)`.

**Read loop:**
- Read from the transport into a 64 KiB buffer. For each chunk (≤ 64 KiB), lock the emulator, `feed`, drain
  `take_responses()`, unlock, and write the responses back to the transport (§7.1: DA/DSR replies must reach the
  remote). **Never hold the mutex across `.await`** (clippy `await_holding_lock` is denied, M0-01).
- After feeding: if `dirty.swap(true)` was `false`, send `SessionEvent::Dirty` (at most one outstanding Dirty,
  §2.1).
- Title and bell events from the emulator are forwarded (coalesced: a title is sent only when it changed).
- The SSH channel window is never blocked on rendering (§2.1 backpressure). The read loop never waits on the UI.

**Command loop:** `select!` between transport readable, `cmd_rx.recv()`, keepalive and latency ticks (SSH), and the
cancellation token.
- `Input` → `transport.write`.
- `Resize` → `emulator.resize` + `transport.resize`. The 50 ms debounce lives in the UI (M1-17), and the actor
  applies immediately.
- `Close` → graceful close → state `Closed` → the task ends.
- **Panic containment:** the actor body runs inside a `tokio::spawn`, and the manager observes the
  `JoinHandle`. If it panics, the UI receives `State(Disconnected{reason: Internal})` and the pane shows "session crashed (see
  log)". The app keeps running (M0-05 §2.2).

### 2.3 State machine (§2.1.1)
`SessionState { Resolving, Connecting{hop, of}, AwaitingHostKey(Verification),
Authenticating{method}, AwaitingUser(AuthPrompt), Connected{since}, Disconnected{reason, at}, Closed }`.
- `fn transition(&self, ev: StateInput) -> Result<SessionState, IllegalTransition>` as a pure function.
  `StateInput` is an enum of things that happen: `Resolved`, `TcpConnected{hop}`, `HostKeyNeeded`,
  `HostKeyAccepted`, `HostKeyRejected`, `AuthStarted(method)`, `PromptNeeded`, `PromptAnswered`,
  `AuthSucceeded`, `AuthFailed`, `ChannelOpened`, `RemoteExit(code)`, `TransportError(reason)`,
  `KeepaliveTimeout`, `UserClose`, `ReconnectRequested`.
- **Allowed transitions table**, the ground truth to encode and test exhaustively:

| From | Input | To |
|---|---|---|
| Resolving | Resolved | Connecting{1,n} |
| Resolving | TransportError | Disconnected |
| Connecting | TcpConnected (more hops) | Connecting{hop+1,n} |
| Connecting | HostKeyNeeded | AwaitingHostKey |
| Connecting | AuthStarted | Authenticating |
| Connecting | TransportError | Disconnected |
| AwaitingHostKey | HostKeyAccepted | Connecting (same hop) → continues |
| AwaitingHostKey | HostKeyRejected / timeout | Disconnected{HostKey} |
| Authenticating | PromptNeeded | AwaitingUser |
| Authenticating | AuthStarted (next method) | Authenticating |
| Authenticating | AuthSucceeded (intermediate hop) | Connecting{hop+1} |
| Authenticating | AuthSucceeded (final) + ChannelOpened | Connected |
| Authenticating | AuthFailed (no methods left) | Disconnected{Auth} |
| AwaitingUser | PromptAnswered | Authenticating |
| AwaitingUser | UserClose | Closed |
| Connected | RemoteExit(code) | Disconnected{Exited(code)} |
| Connected | TransportError / KeepaliveTimeout | Disconnected |
| Disconnected | ReconnectRequested | Resolving |
| any non-Closed | UserClose | Closed |
| Closed | anything | **illegal** |

- An illegal transition is logged at `error` and the session moves to `Disconnected{Internal}` (§2.1.1).
- `DisconnectReason { Resolve, Connect, Negotiation, HostKey, Auth, Timeout, Exited(i32), Internal,
  Closed }` with user messages per §6.1.9 (in M1-13).
- Local PTY sessions use a subset: Resolving → Connected → Disconnected{Exited}/Closed.

### 2.4 Session manager (`sverb-conn::manager`)
- `open(spec: SessionSpec) -> SessionHandle { id, cmd_tx, term: Arc<Mutex<..>>, dirty: Arc<AtomicBool> }`,
  `close(id)`, `get(id)`, and `shutdown(timeout)`, which sends Close to all sessions, waits up to the timeout, and then aborts
  the rest (used by Quit, M0-09).
- `SessionSpec` is an enum `Ssh(ResolvedHost)` (M1-13), `Local(LocalSpec)` (M1-12), or `Mock(..)`.
- The UI side (`services/sessions.rs`) implements `Effect::OpenSession`/`SendToSession`/`CloseSession`
  through the manager. `SendToSession` uses `try_send`. If the queue is full, log a warning. For `Input`, retry via a small
  per-session overflow `VecDeque` (input bytes are never dropped, §M0-09 §2.5), with an error toast if the overflow
  exceeds 1 MiB.
- `SessionRegistry` (read-only view for rendering) provides the emulator handle and dirty flag by `SessionId`.

### 2.5 Out of scope
SSH specifics (M1-13…16), the PTY (M1-12), the emulator implementation (M1-09), and pane layout (M1-17).

## 3. Codebase changes
- **Create** the modules listed in the header in `sverb-conn` and the UI service in `sverb-tui`.
- `sverb-conn` depends on `sverb-term` for the `Emulator` trait. Alternatively, define the trait in `sverb-core` to avoid
  the dependency. **Decision:** the `Emulator` trait lives in `sverb-term`, and `sverb-conn` depends on `sverb-term`
  (allowed by the layering, since neither is UI).

## 4. Test cases to implement

**T-01 (unit, exhaustive) Transition table.** For every `(state, input)` pair (product of all variants),
assert the result matches the table: allowed → expected state, otherwise `IllegalTransition`.

**T-02 (unit) Illegal transition handling.** The actor receiving an illegal input logs at error (captured by a
test subscriber) and ends in `Disconnected{Internal}`.

**T-03 (integration, MockTransport) Dirty coalescing.** The remote writes 10,000 small chunks quickly, and the UI never
acknowledges: exactly **1** `Dirty` event is received. After the ack (flag = false) and one more chunk → exactly one more.

**T-04 (integration) 64 KiB lock chunks.** Feed 1 MiB in one transport read. An instrumented emulator records
the slice lengths passed to `feed`, and none exceeds 64 KiB.

**T-05 (integration) Responses written back.** The remote sends `ESC[c` (DA1). The mock transport
receives the emulator's reply bytes (with a stub emulator returning a fixed reply).

**T-06 (integration) No lock across await.** Covered by clippy `await_holding_lock = deny`. Also run a stress test
with a render thread locking the mutex at 1 kHz while 50 MB is fed, and assert no deadlock within 10 s.

**T-07 (integration) Command channel capacity.** Fill 256 commands without the actor reading (paused). `try_send`
returns Full, and the overflow buffer holds the input bytes, delivered in order once the actor resumes.

**T-08 (integration) Panic containment.** A mock transport that panics on read → the UI gets
`Disconnected{Internal}`, and other sessions keep working.

**T-09 (integration) Shutdown.** 5 sessions, `shutdown(2s)`: all close. One session ignoring Close is aborted
after 2 s (virtual time).

**T-10 (integration) Title cap and coalescing.** A 1,000-char OSC title becomes ≤ 256 chars. The same title twice → one event.

**T-11 (unit) Remote exit.** `Connected` + `RemoteExit(0)` → `Disconnected{Exited(0)}`, and no reconnect banner is
flagged (§6.1.9).

## 5. Passing functional characteristics
- [ ] Each session is an isolated actor owning its transport and emulator, communicating via a bounded command channel (256) and
      coalesced events.
- [ ] Output floods produce one `Dirty` per render cycle, and parsing continues regardless of UI speed.
- [ ] The emulator lock is held per ≤ 64 KiB chunk and never across `.await`.
- [ ] Terminal query responses are written back to the transport.
- [ ] The state machine matches §2.1.1, is exhaustively tested, and illegal transitions degrade to `Disconnected`.
- [ ] Session panics are contained. Shutdown is bounded in time.
- [ ] Input bytes are never silently dropped under backpressure.
