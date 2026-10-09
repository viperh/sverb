# Changelog

All notable changes to sverb are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) for the CLI, `config.toml` and the vault format;
the sync protocol is versioned separately (`/v1`, `Sverb-Proto: 1`).

Release PRs (release-plz) add a section per release from conventional commits.

## [1.0.1] - 2026-10-09

The first release candidate for 1.0: everything below is new. SPEC.md (v0.4) describes the
product; its decisions log and Appendix B list what changed from the draft.

### Added

- **Foundation:** a workspace of eleven crates with enforced layering; a pure reducer with
  effects and a dirty-driven render loop; platform paths with `SVERB_HOME`; daily-rotated
  logs with secret redaction (`SVERB_LOG`); a panic hook that restores the terminal and
  writes a crash report; a typed `config.toml` with hot reload, validation, `sverb config
  --check/--print-default/--path` and a JSON schema.
- **Keyboard model:** the `Ctrl-\` leader with a pass-through guarantee, Terminal / Normal /
  Copy / Insert modes, a which-key popup, user keymaps (`[keys.*]`), the command palette.
- **Vault:** an encrypted SQLite store (XChaCha20-Poly1305, Argon2id), OS keyring unlock,
  auto-lock, a decrypted in-memory index with fuzzy search.
- **Hosts and organization:** hosts, groups with inherited settings and provenance, tags,
  identities, vault defaults, quick connect, pinning and frecency.
- **SSH:** russh transport with keepalive and algorithm policy; password, key, certificate,
  keyboard-interactive and agent authentication; known hosts with TOFU and hashed entries;
  reconnect with backoff (`ssh.auto_reconnect`); jump hosts; SOCKS5, HTTP CONNECT and
  ProxyCommand proxies; connection sharing; exec channels and install-key-on-host.
- **Keychain:** key generation, import (OpenSSH, PEM, PKCS#8, PuTTY `.ppk`), export,
  certificates; a built-in agent with forwarding control and per-use confirmation.
- **Terminal:** an `alacritty_terminal`-based emulator with color schemes, key, mouse and paste
  encoding (kitty keyboard protocol), local PTY tabs, tabs and split panes with resize and zoom,
  broadcast input, workspaces, copy mode with search, OSC 52 clipboard, encrypted session
  recording and asciicast export, the Logs view, OSC 133 shell integration with history,
  autocomplete and optional ghost text.
- **Port forwarding** (local, remote, dynamic) in the UI and headless (`sverb forward`), and
  **snippets** with variables and multi-host runs (`sverb snippet run`).
- **Approval** of synced settings that act locally (`sverb approve`).
- **Import and export:** `ssh_config`, `known_hosts`, CSV, PuTTY sessions, encrypted
  `.sverb-backup` files (`SVERB_EXPORT_PASSWORD` for scripts).
- **Sync (optional):** `sverb-server` (axum, PostgreSQL) with OPAQUE login, TOTP, devices,
  refresh-token rotation, the vault and item API, WebSocket notifications with LISTEN/NOTIFY,
  rate limits, metrics and an admin CLI; the client sync engine with an outbox, field-level
  merge and tombstones; account registration, login, password change and the recovery key.
- **Teams:** orgs, invites, roles and an audit log; shared vaults with signed HPKE key grants,
  TOFU key pinning and safety numbers (`sverb team verify`); credential overrides; key rotation
  on revoke that resumes after a crash.
- **Terminal sharing:** an end-to-end-encrypted share relay with host approval and view or
  control mode (`leader S`, `sverb join`).
- **Diagnostics:** `sverb doctor` (terminal capabilities, agent, keyring, sync; `--algos`).
- **Hardening:** no core dumps and no same-user ptrace on Linux, best-effort `mlock`, canary
  secret scans in CI, fuzz targets for every parser of untrusted input.
- **Performance:** criterion benchmarks with CI gates (emulator throughput, render time,
  index build and search, envelope sealing, unlock, key encoding) and a startup budget.
- **Accessibility:** no status conveyed by color alone, `ui.ascii` (ASCII glyph fallback,
  automatic on non-UTF-8 locales and the Linux console), `ui.reduce_motion`, and a test that
  every action has a key or a palette entry.
- **Packaging:** release automation with release-plz; static musl Linux, universal macOS and
  Windows archives with a man page and bash, zsh, fish and PowerShell completions
  (`sverb generate`); reproducible builds; a multi-arch distroless server image; AUR,
  Homebrew, Nix and Scoop packages; `cargo install sverb`.
- **Documentation:** a generated configuration reference (`docs/config.md`) and keybinding
  list, FAQ and troubleshooting, accessibility notes, the release process.

### Removed

- The optional AI assistant planned in the draft spec (§9.11) was dropped before release.
