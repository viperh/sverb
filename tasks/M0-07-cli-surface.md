# M0-07 — Full CLI surface (`clap`) and headless-command conventions

| | |
|---|---|
| **Milestone** | M0 — Skeleton (subcommand bodies are filled in by their feature tasks) |
| **Touches** | `crates/sverb/src/cli.rs` → `crates/sverb/src/cli/{mod,hosts,keys,import,export,…}.rs`; `crates/sverb/src/main.rs` |
| **Spec refs** | §16, §1.1, §17.1 (`sverb approve`), §18 (`--debug`) |
| **Depends on** | M0-03, M0-04, M0-06 |
| **Blocks** | features that add subcommand implementations |

---

## 1. Current state in the codebase
`crates/sverb/src/cli.rs`:
- Lines 5-15: `Cli { tick_rate: f64 (default 4.0), frame_rate: f64 (default 60.0) }`. Both
  flags are template knobs. The spec has neither: render scheduling is fixed at ≤ 60 fps and
  dirty-driven (M0-09), and there's no tick-driven logic.
- Lines 17-24: `VERSION_MESSAGE` = pkg version + `VERGEN_GIT_DESCRIBE` + build date. Keep it, and
  add enabled features.
- Lines 26-41: `version()` prints authors and dirs. Its directory functions are removed in M0-03.
- `main.rs:25-27`: parse → `App::new(tick_rate, frame_rate)` → `run()`. There are no subcommands.
- The workspace `clap` features (`Cargo.toml:32-39`) include `unstable-styles`, which is unnecessary on
  clap 4.6 (styles are stable). Remove it.

## 2. Detailed description

### 2.1 Command tree (exactly §16)
```
sverb [--debug] [--workspace <name>]                          launch TUI
sverb connect <target>                                        TUI + session (fuzzy host or user@host:port)
sverb join <share-link>                                       [sync]
sverb hosts list [--json] [--tag <t>]... [--group <g>]
sverb hosts add <address> [--label] [--user] [--port] [--group] [--tag]...
sverb hosts rm <host>
sverb keys list | generate [--type <alg>] [--label] | import <file> | export <key> [--public]
sverb keys --dump                                             effective keymap
sverb forward <rule> [--detach]
sverb snippet run <snippet> --on <host|#tag|group>... [--json]
sverb import ssh-config [path] | known-hosts [path] | putty | csv <file> | backup <file>  [--dry-run]
sverb export backup <file> | ssh-config <file> | csv <file> | recording <id> <out.cast>
sverb approve <host>
sverb agent [--socket <path>]
sverb lock | unlock
sverb login [--server <url>] | logout [--keep-local] | register     [sync]
sverb sync [--now] [--status]                                       [sync]
sverb devices list | revoke <id>                                    [sync]
sverb team list | invite <email> | verify <user>                    [sync]
sverb config --check | --print-default | --path   (+ hidden --schema)
sverb doctor [--algos]
```
- `--type` values: `ed25519` (default), `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`,
  `rsa-3072`, `rsa-4096` (`ValueEnum`).
- `[sync]` commands exist only with `cfg(feature = "sync")`. In local-only builds an external-subcommand
  catch matches those names and prints "this build of sverb was compiled without sync support" (exit 2).
- `--tick-rate` and `--frame-rate` are removed.
- `--version`: `sverb <semver>-<git describe> (<build date>) features: sync`, followed by the four
  path roots and whether `SVERB_HOME` is set (via `Paths::describe()` from M0-03).

### 2.2 Module structure
- `cli/mod.rs`: `Cli`, `Command` enum, global flags and `dispatch(cli, ctx) -> ExitCode`.
- One module per command group: `hosts.rs`, `keys.rs`, `forward.rs`, `snippet.rs`, `import.rs`,
  `export.rs`, `approve.rs`, `agent.rs`, `vault.rs` (lock/unlock), `account.rs` (login/logout/register,
  sync), `devices.rs`, `team.rs`, `config.rs`, `doctor.rs`.
- Each body is a stub returning `CliError::NotImplemented { milestone: "M2" }` until its task lands.
  Exceptions done here: `config` (all three flags, using M0-06), `keys --dump` (wired in M0-10).

### 2.3 Conventions
- **Exit codes** (`cli::exit` constants, documented in `--help` `after_long_help`):
  0 ok · 1 failure · 2 usage · 3 vault locked/unlock failed · 4 not found · 5 approval required
  (§17.1, message points to `sverb approve <host>`) · 6 network/server · 7 partial failure.
- **Errors** are printed with `ErrorReport` (M0-05) as `error: …` / `  caused by: …`. color-eyre's
  fancy report is used only for unexpected internal errors (exit 1).
- **JSON output** (`--json`) is wrapped as `{"version":1,"data":…}`, documented in
  `docs/cli-json.md`, and snapshot-tested.
- **Vault access** for headless commands, via `cli::vault::require_unlocked()`:
  keyring unlock (if enabled) → TTY prompt (stdin and stderr are TTYs; no echo; backoff from M1-04)
  → otherwise exit 3: `vault is locked and no terminal is available to enter the master password`.
  The commands never hang reading a non-TTY stdin.
- **Host argument resolution** (`sverb-core::resolve_host_arg`): exact label → exact address →
  unique fuzzy (nucleo, M1-05) → ambiguity error listing ≤ 5 candidates (exit 4).
- Headless commands never enter raw mode or the alternate screen.

### 2.4 TUI launch
`sverb`, `connect`, `--workspace` and `join` all build a `LaunchIntent { Plain | Connect(String) |
Workspace(String) | Join(String) }`, handed to `sverb_tui::run(intent, ctx)`. The intent is delivered
as the first `UiEvent` after unlock. If stdout isn't a TTY, exit 1 with "sverb's TUI needs an
interactive terminal" before touching the terminal.

### 2.5 `main.rs` shape
`main` becomes: install panic hook (M0-05) → resolve `Paths` (M0-03) → parse CLI → init logging
(M0-04, with `--debug` and the headless flag) → load config (M0-06) → build the tokio runtime **manually**
(replacing `#[tokio::main]` at `main.rs:20`, so the panic hook and logging exist before the runtime and
the runtime can be shut down with a timeout) → `dispatch`.

## 3. Codebase changes
- **Replace** `crates/sverb/src/cli.rs` with the `crates/sverb/src/cli/` directory.
- **Modify** `crates/sverb/src/main.rs` as described in §2.5.
- **Modify** `Cargo.toml:32-39`: drop `unstable-styles`.
- **Remove** the tick/frame-rate plumbing in `app.rs:20-21,40,58-61` (finished by M0-09).
- **Docs:** `docs/cli-json.md` and a README usage section.

## 4. Test cases to implement

**T-01 (unit)** `Cli::command().debug_assert()` passes.

**T-02 (unit, table) Every documented form parses.** One row per §16 line, e.g.
`hosts add 10.0.0.1 --user root --port 2222 --tag a --tag b` → `{address, user, port: 2222,
tags: [a,b]}`. Include `import csv f.csv --dry-run`, `snippet run s --on h1 --on #web --json`,
`keys generate --type rsa-4096`, `export recording 0190… out.cast`, `logout --keep-local`.

**T-03 (unit) Invalid forms.** `hosts add` without an address, `keys generate --type dsa` and
`hosts add x --port 70000` all exit 2 with clap usage text.

**T-04 (unit, cfg not sync)** Help omits `login/logout/register/sync/devices/team/join`, and
`sverb login` prints the compiled-without-sync message with exit 2.

**T-05 (snapshot)** `insta` snapshots of `sverb --help` and every subcommand's `--help`, for both
feature sets.

**T-06 (unit) Version** contains semver, git describe and the feature list. `--tick-rate` is rejected.

**T-07 (unit, table) Host resolution.** Hosts `{prod-web-1 (10.0.0.1), prod-web-2, db}`: `db` → label,
`10.0.0.1` → address, `web-2` → fuzzy unique, `web` → ambiguous (2 listed), `zzz` → not found (code 4).

**T-08 (integration, enabled after M1-04)** `sverb hosts list < /dev/null` with a locked vault and
no keyring exits 3 with the exact message, and finishes in < 2 s (no hang).

**T-09 (integration)** `sverb > file.txt` exits 1 with the TTY message, and the file contains no escape bytes.

**T-10 (integration)** `sverb config --check` on a valid file exits 0 with `OK`. On an invalid file it exits 1
with `path:line:col`. `--print-default` output equals the embedded file. `--path` honors `SVERB_HOME`.

**T-11 (unit)** Each `CliError` variant maps to its documented exit code.

**T-12 (unit)** Every stub returns `NotImplemented` naming a milestone. Guard with a test that iterates
all commands.

## 5. Passing functional characteristics
- [ ] Every command and flag in §16 parses as written, and the template's `--tick-rate`/`--frame-rate` are gone.
- [ ] Sync-only commands are absent from local-only builds, and calling them gives a clear message.
- [ ] Exit codes are stable, documented and tested.
- [ ] Headless commands never hang without a TTY and never touch terminal modes.
- [ ] Host arguments resolve the same way in every command.
- [ ] `sverb config …` is fully functional, and other commands are clearly marked stubs.
- [ ] `main` initializes panic hook → paths → CLI → logging → config → runtime, in that order.
- [ ] Help output is snapshot-tested for both feature sets.

## 6. Notes and spec questions
- §16 uses `sverb keys` both for SSH keys and `--dump` (keybindings). Implement as specified and add
  a hidden alias `sverb keymap --dump`. Raise this with the spec owner (see `00-README.md` §4).
