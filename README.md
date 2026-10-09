# sverb

[![CI](https://github.com/viperh/sverb/workflows/CI/badge.svg)](https://github.com/viperh/sverb/actions)

sverb is a terminal-native SSH client and server manager with a
[ratatui](https://ratatui.rs) interface. It keeps hosts, identities, keys, port
forwards and snippets in an encrypted local vault, and it has tabs and split panes
with a built-in terminal emulator. Sync between devices, team vaults and terminal
sharing go through an optional self-hosted server with end-to-end encryption.
Everything else works offline, with no account. The product specification is
[SPEC.md](SPEC.md).

> Status: **1.0 release candidate.** [CHANGELOG.md](CHANGELOG.md) lists what is in it.
> [docs/release.md](docs/release.md) lists what still has to happen before 1.0.

```text
 sverb ─ Personal ▾ ────────────────────────────────────────────────────────────
 no sessions · ^\ o quick connect · ^\ v views/sessions
┌ Hosts ───────────────────────────────────────────────────────────────────────┐
│›   alpha  10.0.0.1                                                           │
│    bravo  10.0.0.2                                                           │
│    charlie  10.0.0.3                                                         │
│                                                                              │
└───────────────────────────────────────────────────────────────────────── 3/3 ┘
 NORMAL                                                      ^\ ? help · q quit
```

## Features

- **Hosts:** groups with inherited settings, tags, identities, pinned and frecent
  hosts, fuzzy filter, and quick connect (`user@host:port`).
- **SSH:** connects through `russh` with password, key, agent, keyboard-interactive and
  certificate auth. It has strict known-hosts with TOFU, jump-host chains, SOCKS5, HTTP
  CONNECT and ProxyCommand proxies, connection sharing, and auto-reconnect.
- **Keychain:** generate, import and export keys (OpenSSH, PEM, PKCS#8, PuTTY `.ppk`) and
  certificates. Install a key on a host. A built-in agent can forward vault keys.
- **Terminal:** tabs, splits, resize, zoom, broadcast input, workspaces, copy mode with
  search, OSC 52 clipboard, encrypted session recording, and asciicast export.
- **Port forwarding:** local, remote and dynamic (SOCKS) forwards, in the TUI or headless
  with `sverb forward`.
- **Snippets:** variables, run modes, and runs on many hosts (`sverb snippet run --on
  #tag`).
- **Shell history and autocomplete:** OSC 133 shell integration, with a heuristic
  fallback.
- **Import and export:** `~/.ssh/config`, `known_hosts`, CSV, PuTTY sessions, and
  encrypted `.sverb-backup` files.
- **Sync (optional):** end-to-end encrypted with OPAQUE login. You get devices, a recovery
  key, team vaults with safety numbers and key rotation, and terminal sharing.
- **Command palette:** `Ctrl-k` (or `leader p`). Every action is reachable from the
  keyboard.
- **Accessibility:** works in monochrome (`NO_COLOR`) and has an ASCII glyph mode
  (`ui.ascii`) and reduced motion. See [docs/accessibility.md](docs/accessibility.md).
- **Diagnostics:** `sverb doctor` checks the terminal, the agent, the keyring and sync.

## Install

| Channel | Command |
|---|---|
| Cargo | `cargo install sverb` (Rust 1.95+; add `--no-default-features` for a local-only build without sync) |
| Prebuilt | [GitHub releases](https://github.com/viperh/sverb/releases): static Linux x86_64/aarch64 (musl), universal macOS, and Windows x86_64. Each archive includes the man page and shell completions. Check them against `SHA256SUMS`. |
| Arch Linux (AUR) | `paru -S sverb` (built from source) or `paru -S sverb-bin` (prebuilt) |
| Homebrew | `brew install viperh/sverb/sverb` |
| Nix | `nix run github:viperh/sverb` or `nix profile install github:viperh/sverb` |
| Scoop | `scoop bucket add sverb https://github.com/viperh/scoop-sverb` then `scoop install sverb` |

The sync server is published as the image `ghcr.io/viperh/sverb-server` (amd64 and
arm64) and as static Linux binaries. See [docs/self-hosting.md](docs/self-hosting.md).

macOS binaries that aren't notarized need one extra step:
[docs/faq.md](docs/faq.md#macos-gatekeeper-says-the-binary-cant-be-opened).

## Quick start (local only)

```sh
sverb                      # first run: choose a master password (or store it in the OS keyring)
```

1. Press `a` in **Hosts** to add a host, or `I` to import `~/.ssh/config`.
2. Press `Enter` to connect. `Ctrl-\` is the **leader**: use `leader -` / `leader |` to
   split, `leader t` for a local shell, `leader [` for copy mode and `leader ?` for every
   binding.
3. Press `Ctrl-k` to open the command palette for anything else.

From scripts:

```sh
sverb hosts add 10.0.0.1 --label web-1 --user deploy --tag web
sverb connect web-1
sverb snippet run uptime --on '#web' --json
sverb forward db-tunnel --detach
sverb doctor
```

Headless commands unlock the vault with the OS keyring, or ask for the master password
on the terminal. Without a terminal they exit with code 3. The exit codes and `--json`
output are stable ([docs/cli-json.md](docs/cli-json.md), `man sverb`).

## Enabling sync

Sync needs a server you run yourself. There is no hosted service and no default URL.

```sh
sverb register --server https://sync.example.com   # first account: use the setup token from the server log
sverb login --server https://sync.example.com      # on each other device
sverb sync --status
```

Your master password is also the account password. It never leaves the device: login
uses OPAQUE. Keep the recovery key that registration shows you. Teams (`sverb team
create`, `sverb team invite <email>`), shared vaults and terminal sharing (`leader S`,
`sverb join <link>`) need sync.

## Security model in short

- The vault is encrypted at rest (XChaCha20-Poly1305 under an Argon2id-derived key, or
  the OS keyring). Locking clears decrypted caches. Auto-lock is on by default.
- The server only stores ciphertext and OPAQUE records. Public keys of team members are
  pinned on first sight and can be checked with safety numbers. Revoking a member
  rotates the vault key.
- Host keys are checked strictly, and a changed key is blocked.
- Synced settings that would run something locally (ProxyCommand, non-loopback
  forwards, agent forwarding) need approval on each device (`sverb approve`).
- Secrets are redacted from logs by type, and CI greps for planted canary secrets.
- No `unsafe` code outside two documented, audited modules.

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Documentation

| Topic | File |
|---|---|
| Keybindings (generated) | [docs/keybindings.md](docs/keybindings.md) |
| Configuration reference (generated) | [docs/config.md](docs/config.md), schema [docs/config.schema.json](docs/config.schema.json) |
| FAQ and troubleshooting | [docs/faq.md](docs/faq.md) |
| Accessibility | [docs/accessibility.md](docs/accessibility.md) |
| Self-hosting the server | [docs/self-hosting.md](docs/self-hosting.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| CLI JSON output | [docs/cli-json.md](docs/cli-json.md) |
| Themes and color schemes | [docs/themes.md](docs/themes.md) |
| Terminal emulator | [docs/emulator.md](docs/emulator.md) |
| Logging policy | [docs/logging.md](docs/logging.md) |
| Performance targets | [docs/performance.md](docs/performance.md) |
| Architecture, data model | [docs/architecture.md](docs/architecture.md), [docs/data-model.md](docs/data-model.md) |
| Releasing | [docs/release.md](docs/release.md) |

### Files and directories

| Purpose | Linux | macOS | Windows |
|---|---|---|---|
| Config (`config.toml`, `themes/`) | `~/.config/sverb` | `~/Library/Application Support/sverb` | `%APPDATA%\sverb` |
| Data (`sverb.db`) | `~/.local/share/sverb` | `~/Library/Application Support/sverb` | `%LOCALAPPDATA%\sverb` |
| State (logs, recordings, crash reports) | `~/.local/state/sverb` | `~/Library/Logs/sverb` | `%LOCALAPPDATA%\sverb\state` |

The XDG variables are honoured. `SVERB_HOME=<dir>` moves everything under `<dir>`, and
`sverb --version` prints the resolved paths. Logs never go to the terminal: `SVERB_LOG`
sets the filter and `--debug` turns on the in-TUI log pane.

## Building from source

```sh
cargo build -p sverb                          # client with sync (default)
cargo build -p sverb --no-default-features    # local-only client: no sync code linked in
cargo build -p sverb-server                   # sync server
```

The workspace has one binary crate (`crates/sverb`), the server (`crates/sverb-server`)
and libraries: `sverb-core` (domain, no UI), `sverb-crypto` (no I/O), `sverb-proto`,
`sverb-store`, `sverb-conn`, `sverb-term`, `sverb-sync` and `sverb-tui`. The layering
rules are enforced in CI ([docs/architecture.md](docs/architecture.md)).

The gates CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
SVERB_KEYRING=off cargo test --workspace
cargo test -p sverb --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
python3 scripts/check-layering.py && python3 scripts/check-unsafe.py && scripts/canary-scan.sh --self-test
```

The MSRV is Rust 1.95. `Cargo.lock` is committed and CI builds with `--locked`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
