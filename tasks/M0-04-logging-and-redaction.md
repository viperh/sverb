# M0-04 — Logging rewrite: state dir, daily rotation, `SVERB_LOG`, debug ring buffer, secret redaction

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/logging.rs` (rewrite), `crates/sverb/src/errors.rs:51-77` (`trace_dbg!`), new `crates/sverb-core/src/secret.rs`, `crates/sverb/src/app.rs:121,132,142` (log statements) |
| **Spec refs** | §11.5, §17 (secrets in logs; no hostnames at info+), §18 |
| **Depends on** | M0-03 |
| **Blocks** | M0-05 (crash report uses the ring buffer), M0-11 (log pane), all later tasks (logging policy) |

---

## 1. Current state in the codebase
`crates/sverb/src/logging.rs`:
- Line 13: logs go to the **data** dir. The spec wants the **state** dir.
- Line 16: `std::fs::File::create(log_path)` **truncates** `sverb.log` on every start. Previous
  sessions' logs are lost (bad for "why did my session drop yesterday" debugging). There is no rotation.
- Lines 8-9, 21-23: the level comes from `RUST_LOG`, then `SVERB_LOG_LEVEL`. The spec names
  the variable `SVERB_LOG`.
- Line 17: default directive `INFO`. That's correct.
- Lines 24-30: the file layer has `with_file(true)`, `with_line_number(true)`, `with_ansi(false)`. That's fine.
- Lines 31-34: the `ErrorLayer` from `tracing-error` is installed. Keep it (color-eyre span traces).
- No `--debug` flag, no in-memory buffer, no non-blocking writer (synchronous file writes on the
  UI task).
- `app.rs:121,132` log `info!("Got action: {action:?}")` on every keypress-bound action.
  That's harmless now, but the same pattern for future actions would log hostnames/commands at `info`,
  which §17 forbids.
- No secret types exist yet.

## 2. Detailed description

### 2.1 Subscriber layout
`logging::init(paths: &Paths, opts: LogOptions) -> Result<LoggingGuard>`. `LogOptions` holds
`debug: bool` (from `--debug`) and `headless: bool`. Layers:
1. **File layer**: `tracing_appender::rolling::Builder` with `Rotation::DAILY`,
   `filename_prefix("sverb")`, `filename_suffix("log")` and `max_log_files(7)`, wrapped in
   `tracing_appender::non_blocking`. The returned `WorkerGuard` lives in `LoggingGuard`, and it must be
   dropped (flushed) on exit and in the panic hook. Format: no ANSI, RFC 3339 UTC timestamps,
   target and level, plus file and line.
2. **Ring-buffer layer** (only with `debug = true`): keeps the last 5,000 formatted lines in a
   `parking_lot::Mutex<VecDeque<LogLine>>`, behind a cloneable `LogRing` handle that the TUI log pane
   (M0-11) reads. `LogLine { at, level, target, message }`.
   **Even without `--debug`**, keep a small ring (200 lines, `info`+ only) for crash reports (M0-05).
   That's two ring instances, or one ring with a per-entry level and a reader-side filter. Document the choice.
3. **ErrorLayer** (keep).
4. **Filter**: `EnvFilter` from `SVERB_LOG`, with default `info`, or `debug` when `--debug`. **Drop
   `RUST_LOG` support**, so the filter is never set implicitly by an unrelated environment (spec names one variable).
   An invalid `SVERB_LOG` directive must not abort startup: fall back to the default and record a warning
   that's logged right after init (the current code returns `Err` at line 23, which kills the app).

### 2.2 Logging policy (§17), enforced by convention, review checklist and tests
- At `info` and above, **never** log hostnames, addresses, usernames, commands, snippet bodies,
  item labels or file paths inside the user's home. Use opaque IDs (`ItemId`, `SessionId`,
  `ConnId`).
- `debug` may include hostnames. When `--debug` is on, the TUI shows a one-time warning toast:
  "Debug logging is on: log files may contain hostnames." For headless commands, print it to stderr.
- Add a `docs/logging.md` section describing the policy, and link it from `CONTRIBUTING.md`.
- Change `app.rs:121,132` to `debug!`.

### 2.3 Secret types (`sverb-core::secret`)
- `Secret<T>`, a newtype over `secrecy::SecretBox<T>` with aliases `SecretString` and `SecretBytes`.
- `Debug` and `Display` both write `[REDACTED]`, regardless of content.
- **No** `Serialize`, `Clone` or `PartialEq` by default. Explicit methods:
  - `expose(&self) -> &T` (named so it is grep-able in review),
  - `expose_for_envelope()` used only by the item serializer (M1-02),
  - `ct_eq(&self, other)` for constant-time comparison using `subtle`.
- Zeroized on drop (secrecy does this).
- Provide a `tracing::Value`-friendly path: recording `?secret` prints `[REDACTED]`, because of
  `Debug`.

### 2.4 `trace_dbg!` macro (`errors.rs:51-77`)
Keep it but move it to `sverb-core::trace_dbg` (so all crates can use it), and keep the default
level `DEBUG`. Add a doc note that it must never be used on values that contain user data at `info`+.

### 2.5 Headless commands
CLI subcommands use the same file logging. User-facing output goes to stdout/stderr through normal
printing, never through tracing.

### 2.6 Out of scope
- The log pane UI (M0-11). The CI canary grep over all test logs is M7-05, which builds on T-08 here.

## 3. Codebase changes
- **Rewrite** `crates/sverb/src/logging.rs` as described. Add `tracing-appender` and `parking_lot` to the
  workspace dependencies.
- **Create** `crates/sverb-core/src/secret.rs`, and add `secrecy`, `zeroize` and `subtle` to sverb-core's deps.
- **Move** `trace_dbg!` from `crates/sverb/src/errors.rs` to `crates/sverb-core/src/lib.rs`.
- **Edit** `crates/sverb/src/app.rs:121,132` from `info!` to `debug!`.
- **Edit** `.envrc` (`SVERB_LOG=debug`) and the README "Logging" section (`README.md:65-68`).

## 4. Test cases to implement

**T-01 (integration) File location.** With a temp `SVERB_HOME`, init and emit `info!`. A file
`state/sverb.<date>.log` exists and contains the message. Nothing is created in `data/`.

**T-02 (integration) No truncation across runs.** Init and log "A" in child process 1, then init and
log "B" in child process 2 on the same day. The log file contains both A and B (this fixes the
`File::create` truncation).

**T-03 (integration) Retention.** Pre-create 10 files `sverb.2026-09-2X.log`, init and write.
At most 7 dated files remain (the oldest are deleted).

**T-04 (unit) Level from `SVERB_LOG`.** `SVERB_LOG=warn` drops `info`. `SVERB_LOG=sverb_conn=debug`
enables debug only for that target. `RUST_LOG=trace` alone has **no** effect.

**T-05 (unit) Invalid `SVERB_LOG`.** `SVERB_LOG="=[[["`: init succeeds, with the default `info`, and a
warning line about the bad directive appears in the log.

**T-06 (unit) Debug ring.** With `debug = true`, 6,000 lines are emitted and the ring holds exactly the
last 5,000 in order. Concurrent writer and reader threads don't deadlock (run 10k iterations).

**T-07 (unit) Crash ring filters.** Without `--debug`, `debug!` lines are absent from the crash ring
and `info!` lines are present.

**T-08 (integration) Redaction canary.** Log `info!(pw = ?SecretString::from("CANARY-1b9f"), "x")`
and `debug!("{:?}", secret)`. Flush through the guard. The log file contains `[REDACTED]` and does
**not** contain `CANARY-1b9f`.

**T-09 (unit) Secret API.** `format!("{}", s)` and `format!("{:?}", s)` both equal `[REDACTED]`.
`s.expose()` returns the inner value, and `ct_eq` works.

**T-10 (compile-fail, trybuild)** `serde_json::to_string(&secret)` and `secret.clone()` don't compile.

**T-11 (integration) Non-blocking flush.** Emit 10k lines, drop the guard, and all 10k lines are in the file.

**T-12 (unit) Stdout is clean.** In a child process with logging initialized, emit logs at every
level. Captured stdout and stderr are empty.

## 5. Passing functional characteristics
- [ ] Logs are written to the state dir, rotated daily, with 7 files kept. Restarts never wipe history.
- [ ] `SVERB_LOG` alone controls the filter (default `info`), and invalid values degrade gracefully.
- [ ] `--debug` enables debug level plus a 5,000-line ring, and a small `info`+ ring always exists for
      crash reports.
- [ ] Logging never writes to stdout or stderr.
- [ ] `Secret` values can't be printed, logged, cloned or serialized accidentally, and they're zeroized on drop.
- [ ] The logging policy (no hostnames, users or commands at `info`+) is documented, and the existing
      action logs are downgraded to `debug`.
