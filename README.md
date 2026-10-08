# sverb

[![CI](https://github.com/viperh/sverb/workflows/CI/badge.svg)](https://github.com/viperh/sverb/actions)

sverb is a terminal SSH client with a [ratatui](https://ratatui.rs) user interface:
an encrypted local vault of hosts, identities, keys and snippets, tabs and split
panes with a built-in terminal emulator, port forwarding, and optional end-to-end
encrypted sync through a self-hostable server. The full product specification is
in [SPEC.md](SPEC.md).

> Status: early development. The UI runs on the reducer architecture described in
> [docs/architecture.md](docs/architecture.md) (with a placeholder Hosts screen) while
> the crates below are filled in milestone by milestone (see `tasks/`).

## Crate map

```
Cargo.toml              workspace manifest: dependency versions, lints, release profile
SPEC.md                 product specification
crates/
  sverb/                client binary (clap CLI -> TUI or subcommands)
  sverb-tui/            ratatui app: views, widgets, keymap, theme
  sverb-core/           domain model, vault, settings resolution, importers (no UI)
  sverb-crypto/         key hierarchy, envelopes, HPKE, OPAQUE wrappers (no I/O)
  sverb-proto/          API DTOs, sync/share wire types (serde), versioned
  sverb-store/          SQLite persistence for the client (rusqlite + migrations)
  sverb-conn/           transports: ssh, local pty; forwarding; agent
  sverb-term/           terminal emulator wrapper, key/mouse encoding, recording
  sverb-sync/           client sync engine (HTTP + WS), optional
  sverb-server/         axum sync backend (lib + bin `sverb-server`)
  sverb-e2e/            docker-based integration tests and workspace checks (not published)
migrations/{client,server}/   SQLite and PostgreSQL migrations
deploy/                 server deployment files
docs/                   architecture, keybindings, threat model, self-hosting
tests/fixtures/         sample ssh configs, keys, known_hosts
```

Dependency direction is enforced by `crates/sverb-e2e/tests/workspace_metadata.rs`:
business logic (`sverb-core`, `sverb-proto`, `sverb-crypto`) never depends on
ratatui or crossterm, `sverb-crypto` does no I/O, and `sverb-server` shares only
`sverb-proto` and `sverb-crypto` with the client. Every crate inherits the
workspace lints, including `unsafe_code = "forbid"`.

## Local-only vs synced builds

Sync is a cargo feature of the binary, on by default:

```sh
cargo build -p sverb                          # with sync (default)
cargo build -p sverb --no-default-features    # local-only: no sync code linked in
```

The local-only build (SPEC §1.1) contains no `sverb-sync` code at all;
`cargo tree -p sverb --no-default-features -e normal` shows no `sverb-sync`.

## Running

```sh
cargo run -p sverb
cargo run -p sverb -- --version    # vergen-stamped version and resolved directories
```

`q`, `Ctrl-c` and `Ctrl-d` quit; `Ctrl-z` suspends.

### Command line

<!-- M0-07 -->
`sverb` with no subcommand launches the TUI (it needs a terminal on stdout). The full
tree (SPEC §16) is in `sverb --help`; commands marked `[sync]` exist only in builds
with the `sync` feature.

```text
sverb [--debug] [--workspace <name>]        launch the TUI
sverb connect <host|user@host:port>         TUI with a session open
sverb hosts list [--json] [--tag t]... [--group g] | add <address> … | rm <host>
sverb keys list | generate [--type ed25519] | import <file> | export <key> [--public]
sverb keys --dump                           effective keymap
sverb forward <rule> [--detach]
sverb snippet run <snippet> --on <host|#tag|group>... [--json]
sverb import ssh-config|known-hosts|putty|csv|backup … [--dry-run]
sverb export backup|ssh-config|csv <file> | recording <id> <out.cast>
sverb approve <host>    sverb agent [--socket <path>]    sverb lock | unlock
sverb join | login | logout | register | sync | devices | team     [sync]
sverb config --check | --print-default | --path
sverb doctor [--algos]
```

Headless commands never touch terminal modes and never wait on a non-terminal
stdin. Exit codes: 0 ok, 1 failure, 2 usage, 3 vault locked, 4 not found or
ambiguous host, 5 approval required (`sverb approve <host>`), 6 network/server,
7 partial failure. `--json` output is described in [`docs/cli-json.md`](docs/cli-json.md).
Subcommands that are not implemented yet say which task implements them.

### Managing hosts

<!-- M1-07 -->
In the TUI the **Hosts** section lists your hosts: pinned first, then the ones you
use most (frecency, kept on this device only), then alphabetically, with a
collapsible **Recent** group of the last 10 connections on top. `/` filters
(`#tag`, `@vault` and fuzzy text); `Space` marks hosts for bulk actions.

| Key | Action |
|---|---|
| `Enter` | connect (every marked host opens in its own tab) |
| `a` / `e` / `y` / `d` | add / edit / duplicate / delete (asks "Delete N hosts?") |
| `p` | pin or unpin |
| `c` | copy the equivalent `ssh …` command line |
| `i` | full-screen details (the detail pane shows at ≥ 100 columns) |
| `leader o` | quick connect: `user@host:port`, `[v6addr]:port`, `ssh://user@host:port`, or a saved host |

After a quick connection to an unsaved target succeeds, sverb offers to save it
(`s` opens the host form prefilled). Every change is encrypted with the vault key
and queued for sync, also in local-only builds.

From the command line (the vault is unlocked with the keyring, or the master
password on a terminal):

```sh
sverb hosts add 10.0.0.1 --label web-1 --user deploy --port 2222 --tag web
sverb hosts add db.internal --group prod --create-group   # unknown groups exit 4 without it
sverb hosts list [--json] [--tag web] [--group prod]      # never prints secrets
sverb hosts rm web-1 [--yes]                               # --yes is required without a terminal
sverb connect web-1          # a saved host (label, address or unique fuzzy match)…
sverb connect root@10.0.0.9:2200                           # …or any user@host:port
```

Missing tags are created by `hosts add`. Invalid addresses (`root@x`, `host:22`,
spaces) exit with code 2; an ambiguous `<host>` exits with 4 and lists the matches.

### `.envrc`

<!-- M0-03 -->
The repository ships a [direnv](https://direnv.net) `.envrc` that keeps config,
data, logs and the agent socket inside the checkout while developing: it sets
`SVERB_HOME=$PWD/.sverb-home` (git-ignored) and `SVERB_LOG=debug`. Run
`direnv allow` once.

### Logging

<!-- M0-04 -->
Logs go to one file per day in the state directory (`sverb.YYYY-MM-DD.log`, 7 days
kept), never to the terminal. `SVERB_LOG` sets the filter (`info` by default; e.g.
`SVERB_LOG=debug` or `SVERB_LOG=sverb_conn=trace`); `RUST_LOG` is ignored.
`sverb --debug` logs at `debug` and keeps recent lines for the in-TUI log pane;
debug logs may contain hostnames. See [`docs/logging.md`](docs/logging.md) for the
policy on what may be logged.

### Files and directories

<!-- M0-03 -->
sverb resolves its directories once at startup (`sverb_core::paths`, SPEC §5.1);
`sverb --version` prints them.

| Purpose | Linux | macOS | Windows |
|---|---|---|---|
| Config (`config.toml`, `themes/`) | `$XDG_CONFIG_HOME/sverb` or `~/.config/sverb` | `~/Library/Application Support/sverb` | `%APPDATA%\sverb` |
| Data (`sverb.db`) | `$XDG_DATA_HOME/sverb` or `~/.local/share/sverb` | `~/Library/Application Support/sverb` | `%LOCALAPPDATA%\sverb` |
| State (logs, recordings, crash reports) | `$XDG_STATE_HOME/sverb` or `~/.local/state/sverb` | `~/Library/Logs/sverb` | `%LOCALAPPDATA%\sverb\state` |
| Runtime (agent socket) | `$XDG_RUNTIME_DIR/sverb` | `$TMPDIR/sverb` | named pipe `\\.\pipe\sverb-agent` |

Set `SVERB_HOME=<dir>` to relocate everything to `<dir>/config`, `<dir>/data`,
`<dir>/state` and `<dir>/run` (useful for tests and portable installs). Without a
home directory and without `SVERB_HOME`, sverb exits with an error instead of
writing into the working directory. Directories are created with mode `0700` on
Unix, and a runtime directory that is group/world-accessible or owned by another
user is refused. If `XDG_RUNTIME_DIR` is unset on Linux, the runtime directory
falls back to `$TMPDIR/sverb-<uid>` (or `/tmp/sverb-<uid>`) with a logged warning.

<!-- M1-12 -->
Local shells (`leader t`) start in your home directory with sverb's environment,
minus every `SVERB_*` variable, plus `TERM` (`terminal.term`), `COLORTERM=truecolor`
and `SVERB_PANE=<session id>`, so scripts can tell which sverb pane they run in.

### Configuration

<!-- M0-06 -->
sverb reads one file, `config.toml` in the config directory above (SPEC §15). Every
key is optional; the commented defaults are in
[`crates/sverb-core/src/config/default_config.toml`](crates/sverb-core/src/config/default_config.toml).
For example:

```toml
[general]
leader = "ctrl-g"        # default "ctrl-\\"; ctrl-g suits layouts where \ needs AltGr

[ssh]
keepalive_secs = 10

[keys.terminal]          # bindings after the leader
"|" = "split_vertical"
```

- Unknown keys, wrong types and out-of-range values are reported with
  `key:line:col` and a hint (e.g. "did you mean `keepalive_secs`?"). A file with
  any error is never partially applied: at startup the defaults are used, and on a
  live reload the last good config stays in effect.
- Changes are picked up while sverb runs. Keys that only affect new sessions or
  connections (e.g. `terminal.term`, `ssh.*`) say so in a toast.
- Server URLs and tokens never go in this file; they are set with `sverb login`
  and stored encrypted in the database. AI keys are read from the environment
  variable named by `ai.api_key_env`.
- A JSON schema for editor completion is in
  [`docs/config.schema.json`](docs/config.schema.json).

## Toolchain

- Development uses the latest stable Rust (`rust-toolchain.toml`, with `rustfmt` and `clippy`).
- **MSRV: Rust 1.95** (`rust-version` in `Cargo.toml`). It is the highest
  `rust-version` declared by the pinned dependency set (`rusqlite_migration`
  2.6, `vergen-gix` 10.0.1).

## Checks

The gates CI runs:

```sh
cargo test --locked --all-features --workspace
cargo fmt --all --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace
```

`Cargo.lock` is committed on purpose — CI builds with `--locked`.

## License

MIT — see [LICENSE](LICENSE).
