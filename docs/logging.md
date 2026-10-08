# Logging

How sverb logs (SPEC §17, §18). The implementation is `sverb_core::logging`; the
binary calls `sverb_core::logging::init` once, right after the CLI is parsed.

## Where logs go

- One file per UTC day in the **state** directory: `<state>/sverb.YYYY-MM-DD.log`
  (`~/.local/state/sverb/` on Linux, `$SVERB_HOME/state/` when `SVERB_HOME` is set;
  `sverb --version` prints the directory). Seven files are kept; older ones are
  deleted when a new file is opened. Files are appended to, so restarts never wipe
  earlier runs.
- Lines are written by a background thread (`tracing-appender` non-blocking writer),
  so the UI never waits on the disk. The `LoggingGuard` returned by `init` flushes the
  file when it is dropped; keep it alive in `main`, and drop it before
  `std::process::exit`.
- Format: RFC 3339 UTC timestamp, level, target, `file:line`, message and fields. No
  ANSI colors.
- **Logging never writes to stdout or stderr.** stdout belongs to the TUI. Messages for
  the user (CLI output, errors) are printed directly, never through `tracing`.

## Choosing the level

- `SVERB_LOG` is the only variable that controls the filter. It takes
  [`EnvFilter` directives](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html):
  `SVERB_LOG=warn`, `SVERB_LOG=sverb_conn=debug`, `SVERB_LOG=info,sverb_store=trace`.
  `RUST_LOG` is ignored.
- The default level is `info`, or `debug` with `sverb --debug`. Directives that only
  name targets (`sverb_conn=debug`) keep the default level for everything else.
- An invalid `SVERB_LOG` does not stop sverb: the default is used and a warning naming
  the problem is the first line logged.

## In-memory rings

- **Crash ring**: the last 200 `info`+ lines, always on. Crash reports (M0-05) include
  it; it never holds `debug` or `trace` lines.
- **Debug ring**: the last 5,000 lines that pass the file filter, only with `--debug`
  in the TUI. The log pane (`leader D`, M0-11) shows it.

They are two separate rings so debug chatter can't push `info` lines out of the crash
ring, and so debug lines (which may contain hostnames) never reach a crash report.

## Policy: what may be logged

At `info`, `warn` and `error`, **never** log:

- hostnames, IP addresses, ports tied to a host, usernames,
- commands, snippet bodies, terminal input or output,
- item labels, tags, notes,
- file paths inside the user's home directory,
- secrets of any kind (passwords, passphrases, keys, tokens), at any level.

Use opaque IDs instead (`ItemId`, `SessionId`, `ConnId`): `info!(%session_id,
"session connected")`, not `info!("connected to {host}")`.

`debug` and `trace` may include hostnames and usernames to make debugging possible.
`sverb --debug` warns the user that log files may then contain hostnames ("Debug logging
is on: log files may contain hostnames."), as a toast in the TUI or on stderr for
headless commands. Secrets are never logged, even at `trace`.

### Secrets are redacted by type

Hold secret values in `sverb_core::secret::{Secret, SecretString, SecretBytes}`:

- `Debug` and `Display` print `[REDACTED]`, so `info!(pw = ?secret)` and
  `debug!("{secret:?}")` are safe. Structs that contain a `Secret` can derive `Debug`.
- There is no `Clone`, `PartialEq` or `Serialize`. Compare with `ct_eq` (constant time).
- `expose()` returns the value. Every call is a review point: never pass its result to
  `tracing`, `format!` or `println!`. `expose_for_envelope()` is reserved for the
  encrypted item serializer.
- Values are zeroized on drop.

A test logs a canary secret and asserts the log file contains `[REDACTED]` and not the
canary (`crates/sverb-core/tests/logging.rs`, T-08); M7-05 extends this to a grep over
all test logs in CI.

### `trace_dbg!`

`sverb_core::trace_dbg!(expr)` is `dbg!` for `tracing`: it logs `expr` with `Debug` at
`DEBUG` (or `level: …`) and returns it. Never use it on values containing user data at
`info` or above.

## Review checklist

- [ ] No hostname, address, username, command, snippet body, label or home path in an
      `info!`/`warn!`/`error!` (including inside `?value` fields and error messages
      formatted into them).
- [ ] Secrets are `Secret*` types, not `String`/`Vec<u8>`; no new `expose()` result
      reaches a formatter.
- [ ] No `println!`/`eprintln!` for diagnostics; user-facing output only.
- [ ] New `info!` lines identify things by opaque ID.
