# M0-03 — Platform paths and `SVERB_HOME`

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | new `crates/sverb-core/src/paths.rs`; `crates/sverb/src/config.rs:17-128` (remove path code); `crates/sverb/src/cli.rs:3,26-41`; `crates/sverb/src/logging.rs:13`; `.envrc` |
| **Spec refs** | §5.1, §6.1.6 (agent socket dir `0700`), §17 |
| **Depends on** | M0-01 |
| **Blocks** | M0-04, M0-05, M0-06, M1-03, M2-07, M3-05 |

---

## 1. Current state in the codebase
- `crates/sverb/src/config.rs:19-20`: `APP_QUALIFIER = "me"` and `APP_ORGANIZATION = "viperh"`, used in
  `project_directory()` (`config.rs:126-128`) as `ProjectDirs::from("me","viperh","sverb")`.
  Results per OS:
  - Linux: `~/.config/sverb`, `~/.local/share/sverb`. These match the spec, by luck.
  - macOS: `~/Library/Application Support/me.viperh.sverb`. **The spec wants
    `~/Library/Application Support/sverb/`.**
  - Windows: `config_local_dir` → `%LOCALAPPDATA%\viperh\sverb\config`. **The spec wants
    `%APPDATA%\sverb\` (roaming) for config and `%LOCALAPPDATA%\sverb\` for data.**
- `config.rs:42-53`: env overrides `SVERB_CONFIG` and `SVERB_DATA` (prefix derived from
  `CARGO_CRATE_NAME`). The spec has a single `SVERB_HOME`.
- `config.rs:106-124`: `get_data_dir()` / `get_config_dir()` fall back to `./.data` / `./.config`
  relative to the **current working directory** when `ProjectDirs` fails. That silently
  writes a database and logs into whatever directory the user ran sverb from.
- There is no **state** dir (logs and recordings currently go to the data dir, `logging.rs:13`) and no
  **runtime** dir.
- `.envrc:6-8` exports `SVERB_CONFIG`, `SVERB_DATA` and `SVERB_LOG_LEVEL` for in-repo development.
- `cli.rs:30-31` prints config and data dirs in `--version`.
- Path code lives in the binary crate. The spec requires it to be reusable and UI-agnostic, so it belongs in `sverb-core`.

## 2. Detailed description

### 2.1 `Paths` type (in `sverb-core::paths`)
A value object resolved **once** at startup and passed explicitly. Do not use `LazyLock`
globals: they make tests that need different homes impossible in one process. Fields and accessors:

| Accessor | Linux | macOS | Windows |
|---|---|---|---|
| `config_dir()` | `$XDG_CONFIG_HOME/sverb` or `~/.config/sverb` | `~/Library/Application Support/sverb` | `%APPDATA%\sverb` |
| `config_file()` | `config_dir/config.toml` | same | same |
| `themes_dir()` | `config_dir/themes` | same | same |
| `data_dir()` | `$XDG_DATA_HOME/sverb` or `~/.local/share/sverb` | `~/Library/Application Support/sverb` | `%LOCALAPPDATA%\sverb` |
| `db_file()` | `data_dir/sverb.db` | same | same |
| `state_dir()` | `$XDG_STATE_HOME/sverb` or `~/.local/state/sverb` | `~/Library/Logs/sverb` | `%LOCALAPPDATA%\sverb\state` |
| `log_dir()` | `state_dir` | same | same |
| `recordings_dir()` | `state_dir/recordings` | same | same |
| `crash_dir()` | `state_dir/crash` | same | same |
| `runtime_dir()` | `$XDG_RUNTIME_DIR/sverb` | `$TMPDIR/sverb` | n/a |
| `agent_endpoint()` | `runtime_dir/agent.sock` | same | `\\.\pipe\sverb-agent` (named pipe name) |

- Use `directories::BaseDirs` (not `ProjectDirs`, whose qualifier/org naming produced the macOS and
  Windows mismatch) and append `sverb` manually. `directories` doesn't provide a state dir on every OS,
  so apply the table explicitly.
- **`SVERB_HOME=P`** overrides everything: `P/config`, `P/data`, `P/state`, `P/run`. On
  Windows the agent pipe becomes `\\.\pipe\sverb-agent-<first 8 hex of sha256(P)>`, so test instances
  never collide.
- **Linux without `XDG_RUNTIME_DIR`:** fall back to `$TMPDIR/sverb-<uid>` or `/tmp/sverb-<uid>`, and
  return a warning value that the caller logs once logging is up (logging isn't initialized yet when
  paths are resolved).
- **No home directory at all** (`BaseDirs::new()` returns `None`): return an error that tells the user
  to set `SVERB_HOME`. **Never** fall back to the CWD (this fixes `config.rs:112,122`).
- **Environment injection:** `Paths::resolve(env: &dyn EnvSource)`, where `EnvSource` is a trait with
  `var(&str) -> Option<OsString>`, `home_dir`, and `uid` (Unix). Production uses the real
  environment, and tests use a map. This makes the per-OS table testable on one OS for the
  Linux/XDG logic.
- Paths are `PathBuf`. **Never** convert to `&str` with `unwrap` (fixes `config.rs:61-62`).
  Non-UTF-8 paths must work.

### 2.2 Directory creation
`Paths::ensure(&self, which: DirKind) -> io::Result<()>` creates a directory lazily:
- Unix: `config`, `data`, `state`, `run` are created with mode `0700` (`DirBuilderExt::mode`).
  If the **runtime** dir already exists with looser permissions or a different owner, refuse with
  an error, because §6.1.6 needs a private socket dir. For the other dirs, log a warning only.
- Windows: rely on the inherited profile ACLs.
- Never chmod a user-provided `SVERB_HOME` root itself.

### 2.3 Migration from template locations
On Linux the template paths equal the new ones. On macOS and Windows, the template (never released)
wrote to `me.viperh.sverb` / `viperh\sverb`. No migration is needed, because no users exist. Note
this in the changelog.

### 2.4 Development workflow (`.envrc`)
Replace the three exports with `export SVERB_HOME="$(pwd)/.sverb-home"` and
`export SVERB_LOG=debug` (renamed variable, see M0-04). Add `/.sverb-home` to `.gitignore`.
Remove `/.data` from `.gitignore` once no code writes there.

### 2.5 `--version` output
`cli.rs:26-41` currently prints config and data dirs. Keep that, but print all four roots
(config, data, state, runtime) and say whether `SVERB_HOME` is in effect. This moves into the
CLI rework (M0-07), and this task supplies `Paths::describe()`.

### 2.6 Out of scope
- Log file handling (M0-04), config parsing (M0-06), DB opening (M1-03).

## 3. Codebase changes
- **Create** `crates/sverb-core/src/paths.rs` (+ `pub mod paths;` in `lib.rs`). Add `directories`
  to `sverb-core`'s dependencies (remove it from `crates/sverb` once unused).
- **Delete** from `crates/sverb/src/config.rs`: `APP_QUALIFIER`, `APP_ORGANIZATION`, `PROJECT_NAME`,
  `DATA_FOLDER`, `CONFIG_FOLDER`, `get_data_dir`, `get_config_dir`, `project_directory`
  (lines 17-20, 40-53, 106-128), and the `data_dir`/`config_dir` fields of `AppConfig` (22-28).
- **Modify** `crates/sverb/src/main.rs`: resolve `Paths` first and pass it to logging, config and
  the app.
- **Modify** `crates/sverb/src/logging.rs:13`: take `&Paths` (the full rework is in M0-04).
- **Modify** `.envrc`, `.gitignore`, the README "Configuration"/"Logging" sections (`README.md:54-68`).

## 4. Test cases to implement

**T-01 (unit) `SVERB_HOME` overrides everything.** With env `{SVERB_HOME: /h}`, the roots are
`/h/config`, `/h/data`, `/h/state`, `/h/run`, and `db_file() == /h/data/sverb.db`.

**T-02 (unit) Linux defaults.** Env `{HOME: /home/u}` (no XDG) gives config `/home/u/.config/sverb`,
data `/home/u/.local/share/sverb`, state `/home/u/.local/state/sverb`.

**T-03 (unit) XDG overrides.** `XDG_CONFIG_HOME=/c`, `XDG_DATA_HOME=/d`, `XDG_STATE_HOME=/s` and
`XDG_RUNTIME_DIR=/r` give `/c/sverb`, `/d/sverb`, `/s/sverb`, `/r/sverb`.

**T-04 (unit) Missing runtime dir.** No `XDG_RUNTIME_DIR` and uid 1000 give runtime `/tmp/sverb-1000` plus
a warning value.

**T-05 (unit) No home.** An env without `HOME` and without `SVERB_HOME` gives an error whose message mentions
`SVERB_HOME`. Assert that no path is relative.

**T-06 (unit, macOS-gated)** The real resolution ends in `Library/Application Support/sverb` for
config and data and `Library/Logs/sverb` for state.

**T-07 (unit, Windows-gated)** Config is under `%APPDATA%\sverb` and data under `%LOCALAPPDATA%\sverb`.
The agent endpoint starts with `\\.\pipe\sverb-agent`.

**T-08 (unit, Windows-gated)** Two different `SVERB_HOME`s yield different pipe names.

**T-09 (integration, Unix)** `ensure(Data)` on a fresh temp home creates the dir with mode `0700`.

**T-10 (integration, Unix)** A pre-existing runtime dir with mode `0755` makes `ensure(Run)`
error out. With `0700` it succeeds.

**T-11 (unit) Non-UTF-8 path.** `SVERB_HOME` set to a path containing invalid UTF-8 bytes (Unix
`OsString::from_vec`) resolves without panicking.

**T-12 (regression)** Running the binary from an arbitrary CWD with `SVERB_HOME` set creates nothing
in the CWD (the template's `./.data` fallback is gone).

## 5. Passing functional characteristics
- [ ] Paths on Linux, macOS and Windows match §5.1 exactly.
- [ ] `SVERB_HOME` alone relocates config, data, state and runtime. `SVERB_CONFIG` and `SVERB_DATA` are gone.
- [ ] There is no silent fallback to the working directory. A missing home is a clear error.
- [ ] Private directories are `0700` on Unix, and an insecure runtime dir is refused.
- [ ] The path code lives in `sverb-core`, is injectable, and is unit-tested for each platform's rules.
- [ ] `.envrc` and the README reflect the new variables.
