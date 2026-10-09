# sverb — Specification

> **sverb** is a terminal-native SSH client and server manager, delivered as a TUI written in Rust
> with [ratatui](https://ratatui.rs), plus a
> self-hosted, end-to-end-encrypted sync backend (`sverb-server`). The backend is optional, and
> sverb is fully functional without it.

| | |
|---|---|
| Status | v0.4, 1.0 release candidate (the decisions and spec additions made during implementation are recorded below and in Appendix B) |
| Date | 2026-10-09 |
| License | MIT (all crates, client and server) |
| Language | Rust (edition 2024) |
| Client UI | ratatui + crossterm |
| Async runtime | tokio |
| Server | axum + PostgreSQL. Optional and self-hosted only. |

### Decisions log

| Date | Decision |
|---|---|
| 2026-10-07 | **One password.** The local master password and the sync account password are the same secret (§5.3, §11.2). |
| 2026-10-07 | **Local-only is a first-class mode.** No server is needed for any feature except sync, teams and terminal sharing (§1.1). |
| 2026-10-07 | **Self-hosted only.** There is no official hosted service, and the client ships with no default server URL. |
| 2026-10-07 | **License:** MIT for the whole repository, including `sverb-server`. |
| 2026-10-07 | **SSH only.** Every remote shell and command goes through `russh`. Mosh, Telnet and Serial are out of scope. |
| 2026-10-07 | **No file transfer.** sverb has no SFTP, SCP or file manager. |
| 2026-10-07 | **Default leader is `Ctrl-\`.** `Ctrl-g` conflicts with Emacs `keyboard-quit` and readline abort, and `Ctrl-b`/`Ctrl-a` with remote tmux/screen. A pass-through guarantee is added to §8.2, and the §8.3 key collisions (`h`, `l`, `L`) are resolved. See `docs/keybindings.md`. |
| 2026-10-07 | **The client binary stays at `crates/sverb/`** (not `bin/sverb/`): the `crates/*` workspace glob picks it up and `cargo install sverb` is unaffected (§3). |
| 2026-10-08 | **No AI assistant.** §9.11 is removed; there are no `ai.*` config keys and no `leader a` binding. |
| 2026-10-08 | **Field-level LWW for lists (§22 Q1).** `tags`, `env`, `jump_chain`, `broadcast_groups` and every other list field are whole-value LWW registers in v1 (§12.4). No OR-sets: concurrent tag edits on two devices keep the later list. Revisit after 1.0 if users lose tag edits in practice. |
| 2026-10-08 | **Shared-vault grants pin unseen keys (M5-02).** Granting access to a member whose key was never seen pins it (TOFU, §13.3); only a key that **changed** since it was pinned is refused until it is verified. |
| 2026-10-08 | **Rotation never drops a member silently (M5-04, §13.2).** A remaining member whose key changed, or whose key can't be fetched or verified, blocks the rotation commit. The rotation stays open (pushes stay paused) until the key is accepted in Settings → Team and the rotation is resumed, or it is abandoned after 15 minutes. Org admins that never held a grant are optional and are skipped. |
| 2026-10-09 | **`unsafe_code = "deny"`, not `forbid` (§17).** `forbid` can't be lifted by an inner `allow`, and two documented modules need one: process hardening (`sverb-core/src/hardening/`: `prctl`, `setrlimit`, `mlock`, and the Windows equivalents) and the Windows agent pipe DACL (`sverb-conn/src/agent/dacl_windows.rs`). `scripts/check-unsafe.py` fails CI if `allow(unsafe_code)` appears anywhere else. |
| 2026-10-09 | **`read_ssh_config` live mode is post-1.0 (§22 Q2).** The parser is reusable (`sverb_core::importers::ssh_config`), but 1.0 only imports (`sverb import ssh-config`, Hosts → `I`). The key `ssh.read_ssh_config` is accepted and warns that it has no effect yet. |
| 2026-10-09 | **No web share viewer in 1.0 (§22 Q3).** Viewers join with `sverb join <link>`; a browser viewer is post-1.0. The share protocol (§14.2) needs no change for it. |
| 2026-10-09 | **Emulator: `alacritty_terminal` stays (§22 Q4).** 0.26 behind the `sverb-term` wrapper, so a switch touches one crate. Known workaround: split UTF-8 sequences across reads are re-joined before `vte` 0.15. Re-evaluate at each alacritty_terminal release; `wezterm-term` or vendoring remain the fallbacks. |
| 2026-10-09 | **Accessibility (§8.8).** `ui.ascii` (ASCII glyph fallback) and `ui.reduce_motion` (static spinners) are added; every status indicator has a text label, so monochrome is complete. |
| 2026-10-09 | **Packaging (§20).** Releases are cut by pushing a tag `vX.Y.Z`, which produces static musl Linux, universal macOS and Windows archives (with man page and completions), static server archives, a multi-arch distroless image, `SHA256SUMS` and an SBOM, and updates the AUR, Homebrew, Scoop and Nix channels. All library crates are published with the `sverb-` prefix so `cargo install sverb` works. |

---

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [System architecture](#2-system-architecture)
3. [Repository layout](#3-repository-layout)
4. [Data model](#4-data-model)
5. [Local storage and encryption at rest](#5-local-storage-and-encryption-at-rest)
6. [Connection layer](#6-connection-layer)
7. [Terminal emulation and rendering](#7-terminal-emulation-and-rendering)
8. [TUI design](#8-tui-design)
9. [Feature specifications](#9-feature-specifications)
10. [Sync backend (`sverb-server`)](#10-sync-backend-sverb-server)
11. [Cryptography and key hierarchy](#11-cryptography-and-key-hierarchy)
12. [Sync protocol](#12-sync-protocol)
13. [Teams and shared vaults](#13-teams-and-shared-vaults)
14. [Terminal sharing](#14-terminal-sharing)
15. [Configuration](#15-configuration)
16. [CLI interface](#16-cli-interface)
17. [Security model](#17-security-model)
18. [Observability, errors and logging](#18-observability-errors-and-logging)
19. [Testing strategy](#19-testing-strategy)
20. [Packaging and distribution](#20-packaging-and-distribution)
21. [Milestones](#21-milestones)
22. [Open questions](#22-open-questions)
23. [Appendix: dependency shortlist](#appendix-a-dependency-shortlist)
24. [Appendix: spec additions made during implementation](#appendix-b-spec-additions-made-during-implementation)

---

## 1. Goals and non-goals

### Goals

- **A complete SSH workbench in the terminal.** It covers hosts, groups, tags, identities,
  keychain, known hosts, port forwarding, snippets, multi-session tabs/splits, broadcast
  input, autocomplete and history, session logs, teams and terminal sharing. Everything is built
  on plain SSH via `russh`.
- **Keys and credentials follow you.** Hosts, identities, passwords and keys sync end-to-end
  encrypted across your devices through your own server.
- **Local-only by default.** sverb works fully offline with no server and no account. Sync is
  opt-in, and can be turned on (or off) at any time without losing data (§1.1).
- **Zero-knowledge sync.** The server stores only ciphertext. It never sees passwords, keys,
  hostnames or snippet contents.
- **Self-hosted backend only.** `sverb-server` ships as one static binary plus PostgreSQL, with a
  Docker Compose file. Users run their own instance, and the project operates no hosted
  service.
- **Fast and keyboard-first.** Startup takes under 100 ms to an interactive host list when the vault
  unlocks via the OS keyring. Master-password unlock adds the Argon2id cost, about 0.5–1 s by
  design (§5.3). Any action is reachable from the keyboard, and mouse support is a bonus.
- **Works anywhere a terminal works.** That includes Linux, macOS, Windows (Windows Terminal) and
  SSH-in-SSH. It degrades gracefully without truecolor, mouse or the kitty keyboard protocol.

### Non-goals (v1)

- A GUI or web client. A read-only web viewer for terminal sharing is listed as a stretch goal.
- Font selection. The outer terminal emulator owns fonts. Per-host *color themes* are supported.
- X11 forwarding. It is technically possible but meaningless inside a TUI, so it's deferred.
- An official hosted sync service, billing or subscriptions.
- Mobile clients.
- **Any protocol other than SSH:** no Mosh, Telnet, Serial, RDP or VNC. All remote sessions and
  commands run over plain SSH via `russh`. Flaky networks are handled by SSH keepalive plus
  auto-reconnect with preserved scrollback (§6.1.2). Pairing it with tmux on the remote host
  keeps the remote shell alive across reconnects.
- **File transfer (SFTP/SCP).** sverb is about shells, commands, keys and credentials.

### 1.1 Operating modes

| | **Local-only** (default) | **Synced** |
|---|---|---|
| Setup | First run asks for a master password. Nothing else. | `sverb login --server <url>` (or Settings → Sync) against your own `sverb-server` |
| Network use | Only the SSH connections you open | Plus HTTPS/WebSocket to your server |
| Hosts, keychain, snippets, forwards, splits, broadcast, workspaces, history, logs, import/export | ✅ | ✅ |
| Multi-device sync | ❌ (use the encrypted backup export to move data by hand) | ✅ |
| Teams and shared vaults | ❌ | ✅ |
| Terminal sharing | ❌ (it needs a relay) | ✅ |

Rules that follow from this:
- **No code path in the client may require a server.** `sverb-sync` is a feature-gated crate
  (`--features sync`, enabled by default in release builds), and a build without it must pass the
  full test suite except the sync and sharing tests.
- Sync, Team and Share UI is hidden in local-only mode. In its place, Settings → Sync shows
  "Not connected · Connect to a server".
- The local data format is identical in both modes, so connecting uploads the existing personal
  vault as-is and disconnecting (`sverb logout --keep-local`) keeps every item locally.
- The client never phones home: no telemetry, update checks or default server URL.

---

## 2. System architecture

```
┌──────────────────────────── sverb (client) ─────────────────────────────┐
│                                                                          │
│  ┌──────────────┐  UiEvent   ┌──────────────────┐  Cmd    ┌────────────┐ │
│  │ crossterm    ├──────────▶ │   App (state +   ├───────▶ │ Session    │ │
│  │ EventStream  │            │   reducer)       │         │ Manager    │ │
│  └──────────────┘            │                  │◀────────┤ (tasks)    │ │
│                              │   ratatui render │ Session │            │ │
│                              └───────┬──────────┘  Event  └─────┬──────┘ │
│                                      │                          │        │
│                         ┌────────────▼────────┐    ┌────────────▼──────┐ │
│                         │ Vault (sverb-core)  │    │ Transports        │ │
│                         │ SQLite + crypto     │    │ ssh (russh),      │ │
│                         └────────────┬────────┘    │ local pty         │ │
│                                      │             └───────────────────┘ │
│                         ┌────────────▼────────┐                          │
│                         │ Sync engine         │                          │
│                         └────────────┬────────┘                          │
└──────────────────────────────────────┼───────────────────────────────────┘
                                       │ HTTPS + WebSocket (ciphertext only)
                         ┌─────────────▼──────────────┐
                         │ sverb-server (axum)        │
                         │  auth (OPAQUE) · sync API  │
                         │  teams · share relay       │
                         └─────────────┬──────────────┘
                                       │
                                ┌──────▼──────┐
                                │ PostgreSQL  │
                                └─────────────┘
```

### 2.1 Client runtime model

- **One tokio multi-thread runtime.** The UI loop runs as a task on it, and rendering happens
  inside that task.
- **The App is a single-owner state machine.** All mutations go through
  `App::handle(event) -> Vec<Effect>`. Effects such as "open session", "save host" or "start
  forward" are executed by services, and their results come back as events. Because the reducer
  is pure, it can be tested without a terminal.
- **Each session is an actor.** It is a tokio task that owns its transport and its terminal
  emulator, and it communicates over channels:
  - `SessionCmd` (UI → session, bounded `mpsc`, capacity 256): `Input(Bytes)`,
    `Resize{cols,rows}`, `Close`, `StartRecording`, `HostKeyDecision(..)`, `AuthAnswer(..)`, …
  - `SessionEvent` (session → UI, unbounded but coalesced): `Dirty(SessionId)`, `Title(String)`,
    `Bell`, `State(SessionState)`, `Prompt(AuthPrompt)`, `HostKey(Verification)`, …
    `Dirty` is sent at most once until the UI acknowledges it by rendering, which an
    `AtomicBool` per session enforces. That way a flood of output produces one event, not
    thousands.
  - The emulator grid sits behind `Arc<parking_lot::Mutex<Term>>`. The session task feeds bytes into
    it in chunks of at most **64 KiB per lock acquisition**, and the render pass locks it briefly
    to draw. Neither side ever holds the lock across an `.await`.
- **Backpressure.** If the UI falls behind, the session keeps parsing, because the emulator state
  must stay correct, but it skips intermediate frames. SSH flow control (channel window) is never
  blocked on rendering.
- **Render scheduling.** The UI redraws only when something is dirty, at no more than 60 fps
  (a 16 ms frame budget, driven by a `tokio::time::interval` with `MissedTickBehavior::Skip`).
  Output bursts such as `cat bigfile` are coalesced, so a busy session cannot starve input
  handling. Input events are always drained before a frame is drawn.
- **Blocking work** like Argon2, SQLite writes and key generation runs in `spawn_blocking`.

#### 2.1.1 Session state machine

```rust
enum SessionState {
    Resolving,                         // settings resolution, DNS
    Connecting { hop: usize, of: usize },
    AwaitingHostKey(Verification),     // modal shown, handshake suspended
    Authenticating { method: AuthMethod },
    AwaitingUser(AuthPrompt),          // password / kbd-interactive / passphrase prompt
    Connected { since: Instant },
    Disconnected { reason: DisconnectReason, at: Instant },  // reconnect banner (§6.1.2)
    Closed,
}
```

Allowed transitions are encoded in a `transition(&self, ev) -> Result<SessionState>` function and
unit-tested exhaustively. An illegal transition is a bug: it is logged at `error`, and the session
moves to `Disconnected`.

### 2.2 Crate boundaries

Business logic never depends on ratatui. That means the server and future clients can reuse
`sverb-core`, `sverb-proto` and `sverb-crypto`.

---

## 3. Repository layout

```
sverb/
├── Cargo.toml                 # workspace
├── SPEC.md
├── crates/
│   ├── sverb-crypto/          # key hierarchy, envelopes, HPKE, OPAQUE wrappers (no I/O)
│   ├── sverb-proto/           # API DTOs, sync/share wire types (serde), versioned
│   ├── sverb-core/            # domain model, vault, settings resolution, importers
│   ├── sverb-store/           # SQLite persistence for the client (rusqlite + migrations)
│   ├── sverb-conn/            # transports: ssh, local pty; forwarding; agent
│   ├── sverb-term/            # terminal emulator wrapper, key/mouse encoding, recording
│   ├── sverb-sync/            # client sync engine (HTTP + WS)
│   ├── sverb-tui/             # ratatui app: views, widgets, keymap, theme
│   ├── sverb-server/          # axum backend (lib + bin)
│   ├── sverb-e2e/             # docker-based openssh integration tests (publish = false)
│   └── sverb/                 # client binary (clap CLI → TUI or subcommands)
├── migrations/
│   ├── client/                # SQLite migrations (links into crates/sverb-store/migrations/)
│   └── server/                # PostgreSQL migrations (links into crates/sverb-server/migrations/)
├── assets/shell-integration/  # OSC 133 snippets (links into crates/sverb-core/assets/)
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile.server          # image built from source
│   └── Dockerfile.server.release  # published image, from the release binaries
├── packaging/                 # AUR (sverb, sverb-bin), Homebrew formula, Scoop manifest
├── flake.nix                  # Nix packages sverb, sverb-server and a dev shell
├── CHANGELOG.md
├── fuzz/                      # cargo-fuzz targets (own workspace, nightly)
├── scripts/                   # CI helpers: layering, unsafe, canary scan, bench gate, release
├── tests/
│   └── fixtures/              # sample ssh configs, keys, known_hosts
└── docs/
    ├── keybindings.md         # generated from the keymap registry
    ├── config.md              # generated from the config schema
    ├── threat-model.md
    ├── self-hosting.md
    └── …                      # architecture, data model, CLI JSON, themes, FAQ, accessibility
```

Files that crates embed with `include_str!` (migrations, shell-integration snippets) live
inside the crate, so `cargo package` includes them; the top-level paths are symlinks.

---

## 4. Data model

Each synced entity is an **Item**. Items live in exactly one **Vault**. On disk and on the server,
an item's whole body is encrypted (§11.4). The plaintext structures are listed below.

All IDs are **UUIDv7**, so they sort by time. Timestamps are UTC. Every mutable field carries a
**Hybrid Logical Clock (HLC)** stamp, which is what field-level merging uses (§12.4).

### 4.1 Item envelope (plaintext, before encryption)

```rust
struct ItemBody {
    kind: ItemKind,          // Host | Group | Identity | Key | Certificate | KnownHost
                             // | PortForward | Snippet | Workspace | Tag | HistoryEntry | ConnLog
    schema_version: u16,
    fields: BTreeMap<String, Stamped<ciborium::Value>>, // field-level LWW
    deleted: Option<Stamped<bool>>,                      // tombstone carries its own HLC (§12.4)
}

struct Stamped<T> { value: T, hlc: Hlc, device: DeviceId }
```

- **Typed views.** `Host::try_from(&ItemBody)` and similar provide the strongly typed structs
  below. Writes go through `ItemBody::set(field, value, hlc)`, so every change is stamped.
- **Unknown fields** are preserved untouched, so an older client cannot erase data written by a
  newer one.
- **Nested structs are flattened** into dotted keys, for example `defaults.port` and
  `proxy.addr`. Concurrent edits to different sub-fields then merge instead of overwriting each
  other.
- **`schema_version`** bumps only for breaking changes. Migrations are pure functions
  `fn(ItemBody) -> ItemBody` that run on read. A client that sees a newer `schema_version` than
  it understands opens the item **read-only** and shows "Update sverb to edit this item".

### 4.2 Host

| Field | Type | Notes |
|---|---|---|
| `label` | String | Display name. Defaults to `address`. |
| `address` | String | Hostname, IPv4 or IPv6. |
| `port` | `Option<u16>` | Defaults to 22. |
| `group_id` | `Option<ItemId>` | |
| `tags` | `Vec<ItemId>` | |
| `identity_id` | `Option<ItemId>` | Reusable credentials. |
| `username` | `Option<String>` | Inline credential. Overrides the identity. |
| `password` | `Option<Secret>` | Inline credential. |
| `key_id` | `Option<ItemId>` | Inline credential. |
| `jump_chain` | `Vec<ItemId>` | Ordered list of hosts to hop through. |
| `proxy` | `Option<Proxy>` | `Socks5{addr,auth}`, `Http{addr,auth}`, `Command(String)` |
| `agent_forwarding` | `Option<bool>` | |
| `agent_source` | `Option<Builtin \| System \| Both>` | Which agent answers forwarded requests (§6.1.6). Default `Builtin`. |
| `env` | `Vec<(String,String)>` | Sent via `env` requests. |
| `startup_snippet_id` | `Option<ItemId>` | Runs after the shell opens. |
| `keepalive_secs` | `Option<u32>` | |
| `charset` | `Option<String>` | Defaults to UTF-8. Other charsets use `encoding_rs`. |
| `backspace` | `Option<Del \| CtrlH>` | |
| `color_scheme` | `Option<String>` | Theme name. |
| `port_forwards` | `Vec<ItemId>` | Rules auto-started with this host. |
| `notes` | `Option<String>` | Markdown. |
| `pinned` | bool | Pinned to the top as a favorite. |
| `algorithms` | `Option<AlgoOverrides>` | Per-host opt-in to legacy algorithms (§6.1.8). |
| `request_pty_for_exec` | `Option<bool>` | Request a PTY for exec runs (needed for `sudo` prompts). |

Every `Option` that is `None` falls through to the group chain and then to global defaults (§4.3).
`last_connected_at` and frecency are **not** item fields. They live in the device-local
`device_local` table (§5.2) and are never synced.

**Validation** runs on save:
- `address` is a valid DNS name (IDNA-normalized), IPv4 or IPv6 literal, without brackets.
- `port` is between 1 and 65535.
- `env` names match `[A-Za-z_][A-Za-z0-9_]*`.
- `jump_chain` must not contain the host itself, and a depth-first search over the resolved
  chain must find no cycles.

### 4.3 Group and settings inheritance

```rust
struct Group {
    name: String,
    parent_id: Option<ItemId>,   // nesting; cycles rejected on write
    defaults: HostDefaults,      // same optional fields as Host (minus label/address)
    icon: Option<String>,
}
```

**Resolution order** for any setting: `Host` → `Group` → parent `Group` → … → vault defaults →
global config (`config.toml`). This is implemented as
`resolve(host: &Host, store: &Store) -> ResolvedHost`, with a provenance map so the UI can show
where each value came from (for example `port: 2222 (from group "prod")`).

### 4.4 Identity

`label`, `username`, `password: Option<Secret>`, `key_id: Option<ItemId>`. An identity can be
referenced by many hosts, so changing it updates every host that uses it.

### 4.5 Key

| Field | Type |
|---|---|
| `label` | String |
| `algorithm` | `ed25519 \| ecdsa-p256 \| ecdsa-p384 \| ecdsa-p521 \| rsa-2048/3072/4096 \| sk-ed25519 \| sk-ecdsa` |
| `private_key` | `Secret<String>`, in OpenSSH format, optionally passphrase-encrypted |
| `public_key` | String, OpenSSH format |
| `passphrase` | `Option<Secret>`, stored so the user isn't prompted |
| `certificate_ids` | `Vec<ItemId>` |
| `agent_forwardable` | bool. Defaults to `false`. |
| `confirm_on_use` | bool. Prompts before the built-in agent signs with this key. |

### 4.6 Certificate

`label`, `cert: String` (OpenSSH cert), `key_id`. Parsed fields (principals, validity, CA
fingerprint) are derived and never stored.

### 4.7 KnownHost

`host_pattern` (`[host]:port` form, hashed or unhashed), `key_type`, `public_key`, `added_at`,
`comment`, `marker: None | CertAuthority | Revoked`.

### 4.8 PortForward

```rust
enum ForwardKind { Local, Remote, Dynamic }
struct PortForward {
    label: String,
    kind: ForwardKind,
    host_id: ItemId,            // connection that carries the tunnel
    bind_addr: String,          // default 127.0.0.1
    bind_port: u16,
    dest_host: Option<String>,  // None for Dynamic
    dest_port: Option<u16>,
    auto_start: bool,           // start when host connects
}
```

### 4.9 Snippet

`name`, `script` (multiline), `description`, `tags`, `variables: Vec<VarDef { name, default,
secret: bool }>`, `run_mode: Paste | PasteAndExecute | Exec`. Variables use `{{name}}` or
`{{name:default}}` syntax.

### 4.10 Workspace

`name` plus a serialized layout tree (§8.4) whose leaves reference `host_id` (or `local`). Also
`broadcast_groups`.

### 4.11 Tag

`name`, `color`.

### 4.12 HistoryEntry and ConnLog

- `HistoryEntry`: `command`, `host_id`, `executed_at`, `exit_code: Option<i32>`. Synced only if
  the user opts in.
- `ConnLog`: `host_id`, `started_at`, `ended_at`, `result: Ok | AuthFailed | HostKeyRejected |
  NetworkError(String)`, `bytes_in/out`. It is synced only if `logs.sync = true`. The path to
  a session recording is device-local, stored in `device_local`, because recordings never leave
  the device.

Tags, identities, keys and the other items are **per vault**. A host can reference only items in
its own vault, with the one exception described in §13.4.

### 4.13 Vault

```rust
struct Vault { id, name, kind: Personal | Shared { org_id }, key_version: u32, defaults: HostDefaults }
```

Every user has exactly one Personal vault and can be a member of any number of Shared vaults. The
UI can show all vaults merged or filter to one.

---

## 5. Local storage and encryption at rest

### 5.1 Paths (via the `directories` crate)

| Purpose | Linux | macOS | Windows |
|---|---|---|---|
| Config | `~/.config/sverb/config.toml` | `~/Library/Application Support/sverb/` | `%APPDATA%\sverb\` |
| Data (DB) | `~/.local/share/sverb/sverb.db` | same as config | `%LOCALAPPDATA%\sverb\` |
| State (logs, recordings) | `~/.local/state/sverb/` | `~/Library/Logs/sverb/` | `%LOCALAPPDATA%\sverb\state\` |
| Runtime (agent socket) | `$XDG_RUNTIME_DIR/sverb/` | `$TMPDIR/sverb/` | named pipe `\\.\pipe\sverb-agent` |

The `SVERB_HOME` environment variable overrides all of them, which is useful for tests and
portable installs.

### 5.2 SQLite schema (client)

```sql
CREATE TABLE meta        (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE vaults      (id BLOB PRIMARY KEY, kind INTEGER, org_id BLOB, key_version INTEGER,
                          wrapped_key BLOB NOT NULL, sync_cursor INTEGER NOT NULL DEFAULT 0);
CREATE TABLE items       (id BLOB PRIMARY KEY, vault_id BLOB NOT NULL REFERENCES vaults(id),
                          revision INTEGER NOT NULL DEFAULT 0,  -- server revision, 0 = never synced
                          key_version INTEGER NOT NULL,
                          envelope BLOB NOT NULL,               -- encrypted ItemBody
                          deleted INTEGER NOT NULL DEFAULT 0,
                          dirty INTEGER NOT NULL DEFAULT 0,     -- pending push
                          updated_at INTEGER NOT NULL);
CREATE TABLE outbox      (item_id BLOB PRIMARY KEY,          -- one row per item: coalesced
                          vault_id BLOB NOT NULL,
                          base_revision INTEGER NOT NULL,     -- server revision the edit is based on
                          queued_at INTEGER NOT NULL,
                          attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE device_local(item_id BLOB PRIMARY KEY, last_connected_at INTEGER, frecency REAL,
                          recording_dir TEXT);
CREATE TABLE sync_state  (id INTEGER PRIMARY KEY CHECK (id = 1),
                          server_url TEXT, device_id BLOB,
                          tokens_enc BLOB);                   -- access+refresh tokens, AEAD under LMK

-- created at unlock time, never on disk:
PRAGMA temp_store = MEMORY;
CREATE TEMP TABLE item_index (item_id BLOB PRIMARY KEY, vault_id BLOB, kind INTEGER,
                              label TEXT, search TEXT);
```

- WAL mode, `synchronous=NORMAL`, `foreign_keys=ON` and a single writer connection behind a
  `tokio::sync::Mutex`. Readers use a small pool (`r2d2`-style, 4 connections).
- Item bodies are always encrypted. `item_index` is a **TEMP** table created at unlock time, and
  with `temp_store = MEMORY` decrypted labels are never written to disk (not even to temp files).
- `outbox` has **one row per item**. Editing an item that is already queued updates its row
  but keeps the original `base_revision`, so ten local edits produce one push.
- Search uses `nucleo` fuzzy matching on in-memory decrypted labels, addresses, tags and group
  paths. The index is rebuilt incrementally on every item write, and in full on unlock. For
  scale, decrypting 10,000 items takes about 50 ms on a modern CPU.
- **Migrations:** `rusqlite_migration` runs versioned SQL from `migrations/client/` at startup,
  inside a transaction. A database written by a newer schema refuses to open with a clear error
  instead of corrupting it.

### 5.3 Unlock and auto-lock

- **Local Master Key (LMK):** 256 random bits generated on first run. It wraps the per-vault keys
  stored in `vaults.wrapped_key`, the sync tokens, and the per-device key that encrypts
  recordings (§7.5). Wrapping uses XChaCha20-Poly1305 with
  `aad = "sverb-lmk-wrap-v1" || purpose`.
- `meta` holds `kdf = {alg:"argon2id", m_kib, t, p, salt(16 B)}` and `lmk_wrapped_pw`, plus
  `lmk_wrapped_keyring` if keyring unlock is on. A wrong password is detected by AEAD tag
  failure, with no separate verifier stored. Five consecutive failures add an increasing delay
  (1 s, 2 s, 4 s, …, capped at 30 s), persisted in `meta` so restarting doesn't reset it.
- The LMK is always wrapped by the **master password**, and optionally also by the OS keyring:
  1. **Master password** (always present).
     `Argon2id(password, local_salt, m=256 MiB, t=3, p=1)` → KEK → AEAD-wraps the LMK. Parameters
     are stored in `meta` and can be upgraded. **This is the same password as the sync account
     password** whenever sync is enabled (§11.2). There is only ever one password to remember.
  2. **OS keyring** (`keyring` crate: Secret Service, macOS Keychain, Windows Credential
     Manager), as an optional convenience unlock. This is the "biometric" equivalent, because the
     OS can gate it with Touch ID / Windows Hello. The master password always remains a valid way
     to unlock.
- **Auto-lock** after N idle minutes (default 15, 0 disables), on `sverb lock`, or on system
  suspend where detectable. When locked:
  - Decrypted caches are zeroized and `item_index` is dropped.
  - **Open sessions stay connected.** Their panes are covered by a lock overlay, and input is
    blocked until unlock. This can be configured to disconnect instead.
  - Built-in agent signing requests are refused.
- Local unlock **never contacts the server**. It works offline in both modes, even when the
  password was changed on another device and this device hasn't heard about it yet (§11.2.1).

---

## 6. Connection layer

All transports implement one trait so that the session actor doesn't care what's underneath:

```rust
#[async_trait]
trait Transport: Send {
    async fn write(&mut self, data: &[u8]) -> Result<()>;
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<()>;
    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send);
    async fn close(&mut self) -> Result<()>;
    fn kind(&self) -> TransportKind;
}
```

### 6.1 SSH (`russh`)

#### 6.1.1 Connection flow

`russh` API names below refer to the version pinned in `Cargo.lock`. The `sverb-conn` crate wraps
them, so an upstream rename touches only one module.

1. **Resolve** settings (§4.3) to get `ResolvedHost`. DNS uses `tokio::net::lookup_host`, and
   the result is never cached across connections.
2. **Build the underlying stream** (`Box<dyn AsyncRead + AsyncWrite + Unpin + Send>`):
   - Direct TCP: `tokio::net::TcpStream`, with happy-eyeballs (RFC 8305: IPv6 first, IPv4
     250 ms later, first success wins), `TCP_NODELAY` on, and `connect_timeout_secs` (default
     15).
   - Through a proxy (§6.1.5).
   - Through a jump chain (§6.1.4): a `direct-tcpip` channel on the previous hop, converted to a
     stream with `Channel::into_stream()`.
3. **SSH handshake** with `russh::client::connect_stream(config, stream, handler)`. Algorithm
   preferences are in §6.1.8. The `client::Handler::check_server_key` callback verifies the host
   key against KnownHosts (§9.5). For an unknown or changed key, the handler sends
   `SessionEvent::HostKey` with a `oneshot::Sender<Decision>` and **awaits** it, which suspends
   the handshake until the user decides. A 120 s timeout counts as `reject`.
4. **Authentication.** Methods are tried in this order, skipping any the server didn't list in its
   `USERAUTH_FAILURE` continuation:
   1. `publickey` with a certificate, if one is attached (`authenticate_openssh_cert`).
   2. `publickey` with the configured key (`authenticate_publickey`). For RSA keys sverb picks
      `rsa-sha2-512`, then `rsa-sha2-256`, based on the server's `server-sig-algs`
      (RFC 8308). It never uses SHA-1 `ssh-rsa` unless legacy algorithms are enabled for the host.
   3. `publickey` via the system agent (`SSH_AUTH_SOCK`, or the OpenSSH/Pageant named pipe on
      Windows), with `authenticate_publickey_with` and an agent signer. This is how FIDO/`sk-*`
      and hardware tokens are supported. **If a key is configured for the host, agent keys are
      not offered** (OpenSSH `IdentitiesOnly` semantics). This avoids hitting the server's
      `MaxAuthTries` (default 6) with irrelevant keys.
   4. `password`, with the stored value or an interactive prompt.
   5. `keyboard-interactive`. Each prompt becomes an overlay dialog, so 2FA/OTP works. If a
      password is stored and exactly one non-echo prompt matches `/password/i`, it is answered
      automatically **once**. Every other prompt is always shown to the user.

   Total attempts are capped at 5 per connection. An encrypted private key with no stored
   passphrase triggers a passphrase prompt, with an optional "save passphrase to vault" checkbox.
5. **Session channel:** `channel_open_session`, then:
   - `set_env` for each `env` pair. Servers often reject these because of `AcceptEnv`. A
     rejection is logged at `debug` and not shown as an error.
   - `agent_forward(true)`, if enabled (§6.1.6).
   - `request_pty("xterm-256color" or config term, cols, rows, px_w, px_h, modes)`, where
     `modes` sets `VERASE` from the host's `backspace` setting and `IUTF8 = 1`.
   - `request_shell`.
6. Start auto-start port forwards (§9.6) and run the startup snippet, if any. The snippet is sent
   as typed input once the first output arrives, or after 500 ms.
7. **Keepalive:** `russh::client::Config { keepalive_interval: keepalive_secs, keepalive_max: 3 }`
   (sends `keepalive@openssh.com`). After 3 missed replies the session moves to `Disconnected`.
   The keepalive round-trip time feeds the latency shown in the status bar.
8. **Data path:** `channel.wait()` yields `ChannelMsg::Data` (to the emulator),
   `ExtendedData{ext:1}` (stderr, also to the emulator), `ExitStatus`, `ExitSignal`, `Eof` and
   `Close`. Writes use `channel.data(&bytes[..])`, and resize uses
   `channel.window_change(cols, rows, px_w, px_h)`.

#### 6.1.2 Reconnect

When a session disconnects, its pane shows a banner:
`Disconnected (reason) — [r] reconnect  [c] close  [l] view log`. Optional auto-reconnect uses
exponential backoff (1s → 30s, max 10 tries). Scrollback is kept across reconnects.

#### 6.1.3 Connection sharing

Several tabs to the same `ResolvedHost` (same address, port, user and jump chain) can share one
SSH connection, with one channel per tab, much like OpenSSH `ControlMaster`. Port forwards and
exec channels reuse it too. This is on by default (`ssh.multiplex = true`).

#### 6.1.4 Jump hosts

`jump_chain = [A, B]` means: connect to A, open `direct-tcpip` to B, run SSH over that channel,
then open `direct-tcpip` to the target. Each hop resolves its own credentials and host key.
Host keys are recorded under each hop's **own** `address:port`, as seen from the previous hop,
matching OpenSSH `ProxyJump` behavior. Hop connections are shared through the multiplexer.
Cycles are detected and rejected. Jump hosts' own `jump_chain`s are expanded recursively, with
a depth limit of 8. A failure is reported with the hop index ("hop 2/3 (bastion-eu): auth
failed").

#### 6.1.5 Proxies

- **SOCKS5** (with optional user/password) via `tokio-socks`.
- **HTTP CONNECT** with optional basic auth, implemented in-house (about 100 lines).
- **ProxyCommand:** spawn the command via `sh -c` (or `cmd /C` on Windows) with `%h`, `%p`, `%r`
  and `%%` substituted, and use its stdin/stdout as the stream. stderr goes to the session log.
  The child is killed when the session closes. Because a ProxyCommand runs **locally**, a
  ProxyCommand that arrives through sync needs per-device approval before it can run (§17.1).

#### 6.1.6 Agent forwarding and the built-in agent

- **Requesting forwarding:** sverb sends `auth-agent-req@openssh.com` on the session channel.
  The server then opens `auth-agent@openssh.com` channels back to the client, which russh
  surfaces through `client::Handler::server_channel_open_agent_forward`.
- **Which agent answers** is decided per host, by `agent_source = builtin | system | both`
  (default `builtin`):
  - **System agent passthrough:** the channel is spliced byte-for-byte to `SSH_AUTH_SOCK` (or the
    Windows named pipe).
  - **Built-in agent:** an agent server (`russh::keys::agent::server`) answers from keychain keys
    with `agent_forwardable = true`. Certificates attached to those keys are served too.
  - `both`: built-in first, and requests for keys it doesn't hold go to the system agent.
- **Local socket.** `sverb agent --socket <path>` exposes the built-in agent locally, so plain
  `ssh` and `git` can use vault keys. The socket lives in a `0700` directory under the runtime dir
  and is created with mode `0600`. On Windows it's a named pipe with an owner-only DACL. Peer
  credentials are checked with `SO_PEERCRED` / `getpeereid`, and connections from other UIDs
  are refused.
- Signing with a `confirm_on_use` key shows a modal naming the requesting host, or the local
  peer process for the socket. A locked vault refuses all signing with `SSH_AGENT_FAILURE`.

#### 6.1.7 Non-interactive exec

`exec` channels are used for multi-host snippet runs and "install key on host". They return
`ExecResult { stdout: Bytes, stderr: Bytes, exit: Option<u32>, signal: Option<String>, truncated: bool }`.
- Output is capped at 1 MiB per stream, and `truncated` is set when the cap is hit.
- There's a per-run timeout (default 60 s). On timeout, the client sends `signal("TERM")` and
  then closes the channel.
- No PTY is requested unless `request_pty_for_exec` is set, in which case stdout and stderr are
  merged, as with `ssh -t`.

#### 6.1.8 Algorithms

sverb uses russh's secure defaults, with the following preferences. Only algorithms actually
implemented by the pinned russh version are offered, and `sverb doctor --algos` lists them.

| Category | Preferred (in order) | Disabled by default (per-host opt-in via `algorithms`) |
|---|---|---|
| Key exchange | `mlkem768x25519-sha256` (if available), `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group16/18-sha512` | `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1` |
| Host key | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256`, plus their `-cert-v01@openssh.com` variants | `ssh-rsa` (SHA-1), `ssh-dss` |
| Cipher | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes128-ctr` | `aes*-cbc`, `3des-cbc` |
| MAC (non-AEAD ciphers) | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` | `hmac-sha1` |
| Compression | `none` | `zlib@openssh.com` (opt-in) |

The negotiated algorithms are logged at `debug` and shown in the session info panel. When a
connection fails because there are no common algorithms, the error names the server's offer and
the per-host setting that would enable it.

#### 6.1.9 Error mapping

Transport errors are mapped to a small user-facing enum, and the raw error chain is kept for the
detail view:

| Condition | `DisconnectReason` | Message |
|---|---|---|
| DNS failure | `Resolve` | "Could not resolve `host`" |
| TCP refused/timeout | `Connect` | "Connection refused / timed out (`addr`)" |
| No common algorithms | `Negotiation` | "No common key exchange: server offers …" |
| Host key rejected or changed | `HostKey` | "Host key verification failed" |
| All auth methods failed | `Auth` | "Permission denied (methods tried: …)" |
| Keepalive timeout | `Timeout` | "Connection lost (no response for N s)" |
| Remote closed with exit status | `Exited(code)` | "Session ended (exit N)". No reconnect banner. |

### 6.2 Local terminal

`portable-pty` spawns `$SHELL` (or `ComSpec`/`pwsh` on Windows) with a configurable cwd. A local
terminal is a regular tab, splittable and broadcast-capable.

---

## 7. Terminal emulation and rendering

### 7.1 Emulator

**Choice: `alacritty_terminal`**, the core of Alacritty without its renderer. It provides:
- a correct VT/xterm parser (via `vte`)
- alternate screen, scroll regions, DEC modes and mouse modes
- scrollback with configurable size (default 10,000 lines per pane)
- selection model, search (regex), hyperlinks (OSC 8) and title changes
- damage tracking

The alternative is the `vt100` crate (used by `tui-term`). It is simpler but less complete,
and it's kept as a fallback if `alacritty_terminal`'s API churn becomes a problem. The
emulator is hidden behind a `sverb-term::Emulator` trait so it can be swapped.

```rust
trait Emulator: Send {
    fn feed(&mut self, bytes: &[u8]);                 // parse remote output
    fn resize(&mut self, cols: u16, rows: u16);
    fn modes(&self) -> TermModes;                     // DECCKM, DECKPAM, mouse, bracketed paste, …
    fn render(&self, area: Rect, buf: &mut Buffer, view: &ViewState); // §7.2
    fn take_responses(&mut self) -> Vec<Bytes>;       // replies the terminal owes the remote
    fn scrollback_len(&self) -> usize;
    fn search(&self, re: &Regex, dir: Direction, from: Point) -> Option<Match>;
    fn snapshot_vt(&self) -> Bytes;                   // §14.2
}
```

**Integration details for `alacritty_terminal`:**
- The parser is `vte::ansi::Processor`, and `processor.advance(&mut term, bytes)` is called from
  `feed`.
- An `EventListener` impl collects events into a queue drained after each `feed`:
  - `PtyWrite(String)`: replies to terminal queries (DA1/DA2, DSR cursor position report,
    DECRQM, XTVERSION, OSC 10/11 color queries). **These must be written back to the SSH channel**
    via `take_responses()`, or remote apps like vim and fish hang or misdetect the terminal.
  - `Title` / `ResetTitle`: tab title.
  - `Bell`: tab marker and visual bell.
  - `ClipboardStore`: OSC 52 write, gated by policy (§7.3).
  - `ClipboardLoad`: OSC 52 **read**, which is always denied (§17).
  - `ColorRequest`: answered from the pane's color scheme.
  - `TextAreaSizeRequest`: answered with the pane size in cells and pixels.
- **Charsets.** The emulator always consumes UTF-8. When a host's `charset` isn't UTF-8, a
  streaming `encoding_rs::Decoder` converts remote bytes to UTF-8 before `feed`. A matching
  `Encoder` converts input on the way out, so multi-byte sequences split across reads decode
  correctly.

### 7.2 Rendering into ratatui

A custom `TerminalPane` widget walks visible grid cells and writes them into the ratatui `Buffer`:
- It maps cell flags (bold, italic, underline styles, inverse, dim, strikethrough, hidden) to
  `ratatui::style::Modifier`.
- It handles wide chars (the spacer cell is skipped) and combining characters.
- Colors are resolved through the pane's color scheme (§7.4). When the outer terminal lacks
  truecolor (detected through `COLORTERM`, or configured), RGB is downsampled to xterm-256 or 16.
- The cursor is drawn by setting the real terminal cursor position for the focused pane, with the
  cursor shape (block/bar/underline) set via `DECSCUSR` passthrough. Unfocused panes draw a hollow
  cursor cell.
- Selection, search matches and URL hover are drawn as overlays.

### 7.3 Input encoding

- sverb enables crossterm's kitty keyboard protocol flags (`DISAMBIGUATE_ESCAPE_CODES`,
  `REPORT_ALTERNATE_KEYS`) when the outer terminal supports them. This lets it tell `Ctrl-I` from
  `Tab`, etc.
- `KeyEvent` is encoded to bytes, respecting the emulator's current modes (DECCKM application
  cursor keys, DECKPAM keypad, modifyOtherKeys and kitty protocol if the *remote* app requested it).
  Reference encodings, which are covered by table tests:

  | Key | Normal mode | DECCKM set |
  |---|---|---|
  | `Up` | `ESC [ A` | `ESC O A` |
  | `Ctrl-Up` | `ESC [ 1 ; 5 A` | `ESC [ 1 ; 5 A` |
  | `Enter` | `\r` | `\r` |
  | `Backspace` | `\x7f` (or `\x08` if host `backspace = CtrlH`) | same |
  | `Alt-x` | `ESC x` | `ESC x` |
  | `F5` | `ESC [ 1 5 ~` | `ESC [ 1 5 ~` |
  | `Shift-Tab` | `ESC [ Z` | `ESC [ Z` |

- **Encoding is per pane.** In broadcast mode (§9.8), each target pane encodes the `KeyEvent`
  with **its own** modes, rather than receiving a copy of the focused pane's bytes. Otherwise
  arrow keys would break in panes running different programs.
- **Mouse:** when the remote app enables mouse reporting (1000/1002/1003/1006), events inside the
  pane are translated to pane-relative coordinates and forwarded. Otherwise the mouse drives
  sverb (selection, focus, scrolling). Holding `Shift` always gives the mouse to sverb.
- **Paste:** bracketed paste is forwarded when the remote enabled mode 2004. Multi-line pastes into
  a session without bracketed paste ask for confirmation (configurable).
- **Clipboard:** copying writes to the outer terminal via OSC 52 (works over SSH) with `arboard`
  as a local fallback. When remote apps send OSC 52, sverb relays it, gated by the config
  `clipboard.allow_remote_write` (default `ask`).

### 7.4 Color schemes

- Built-in schemes: sverb-dark, sverb-light, Dracula, Solarized Dark/Light, Gruvbox, Nord,
  Catppuccin (4 flavors), Tokyo Night, One Dark, Monokai, plus `terminal` (use the outer terminal's
  own palette, no remapping; this is the default).
- User schemes live in `~/.config/sverb/themes/*.toml`, and Alacritty/Kitty theme files can be
  imported.
- Scope: a scheme applies to the **terminal pane content** of a host. The sverb chrome (sidebar,
  borders) uses the separate **UI theme** from config.

### 7.5 Session recording

When recording is on (globally, per host, or toggled with `leader R`), raw output plus resize
events are captured in **asciicast v2** format. Input is *not* recorded by default, because it
may contain passwords.

- **Encrypted at rest.** Terminal output routinely contains secrets, so recordings are stored as
  `<conn_id>.cast.sv`: a sequence of independently sealed chunks.
  - Each chunk holds 64 KiB of asciicast lines.
  - Chunks use XChaCha20-Poly1305 under a recording key derived from the LMK (`HKDF(LMK,
    info="sverb/recording/v1")`), with `aad = conn_id || chunk_index || is_last`.
  - The final chunk is flagged, so truncation is detected. A crash leaves a readable prefix.
- Recordings are replayed inside sverb (Logs view). `sverb export recording <id> out.cast`
  writes plain asciicast for `asciinema play`, after a confirmation.

---

## 8. TUI design

### 8.1 Layout

```
┌ sverb ─ Personal ▾ ─────────────────────────────────────────── ⟳ synced · 🔒 ┐
│ ┌─────────────┐ ┌ 1 prod-web-1 ┬ 2 db-primary ● ┬ 3 local ┬ + ───────────────┐ │
│ │ ▸ Hosts     │ │                                                          │ │
│ │   Keychain  │ │  ubuntu@prod-web-1:~$ systemctl status nginx             │ │
│ │   Forwards  │ │  ● nginx.service - A high performance web server         │ │
│ │   Snippets  │ │       Loaded: loaded (/lib/systemd/system/nginx.service) │ │
│ │   Known     │ │       Active: active (running) since Tue 2026-10-06      │ │
│ │   Logs      │ │                                                          │ │
│ │   Settings  │ ├──────────────────────────────┬───────────────────────────┤ │
│ │             │ │ db-primary                   │ local                     │ │
│ │             │ │ postgres=# \dt               │ ~/Work $                  │ │
│ └─────────────┘ └──────────────────────────────┴───────────────────────────┘ │
│ NORMAL │ prod-web-1 · ssh · 23ms │ ⇄ L:5432→db:5432 │ REC ● │ ^g ? help      │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **Sidebar** (toggle with `leader s`, auto-hidden under 100 columns) is the section switcher.
- **Main area** shows either the active section's view or the session area (tabs + panes).
  `leader v` toggles between the section views and the session area.
- **Status bar:** mode, focused session info (`user@host`, latency from keepalive RTT), active
  forwards, recording indicator, sync status, lock state and a key hint.
- **Top bar:** vault selector, sync indicator and lock icon.

Responsive behavior: under 80 columns the sidebar becomes an overlay. Under 24 rows the status bar
merges into the tab bar.

### 8.2 Modes and the leader key

sverb has to coexist with remote apps that use every key, so it uses a **leader key**, like tmux:

- **Terminal mode** (focus is in a session pane): all keys go to the remote side except the
  leader. The default leader is `Ctrl-\`, configurable. `Ctrl-g` is the recommended alternative on
  keyboard layouts where `\` needs AltGr. It isn't the default because it is Emacs `keyboard-quit` and
  the readline abort key. `Ctrl-b` and `Ctrl-a` collide with tmux and screen on the remote. Pressing the leader
  twice sends a literal leader to the remote. After the leader, an unbound key is discarded with a hint
  and never forwarded.
- **Pass-through guarantee.** While a live session pane has focus, sverb consumes only the leader
  and mouse events the remote didn't request (or that have Shift held). Every other key, including all
  `Ctrl`, `Alt` and function keys, reaches the remote. There is no configuration for unprefixed
  Terminal-mode bindings, so this can't be broken by a config file.
- **Pane overlays** (disconnected, exited, locked, resize mode) accept only `Enter`, `Esc` and leader
  combinations. Plain letters are swallowed, so typing into a pane that just dropped can't trigger actions.
- **Normal mode** (focus is in sverb views): keys drive the UI directly, vim-style with arrow
  equivalents.
- **Copy mode** (`leader [`): vim motions over scrollback, `/` and `?` search, `v`/`V`/`Ctrl-v`
  selection, `y` to yank (OSC 52), `Esc` to exit.
- **Insert/form mode:** when editing fields in dialogs.

After the leader, a which-key popup listing the available next keys appears after
`ui.which_key_delay_ms` (400 ms). The leader times out after 1.5 s unless the popup is open. This is
how the app stays discoverable.

### 8.3 Default keybindings

| Keys | Action |
|---|---|
| `leader p` / `Ctrl-k` (normal) | Command palette (fuzzy over every action, host and snippet) |
| `leader o` | Quick connect (`user@host:port`, or fuzzy-pick host) |
| `leader c` | New tab: pick host |
| `leader t` | New local terminal tab |
| `leader 1..9`, `leader n`/`N` | Go to tab / next / previous |
| `leader ,` / `leader <` / `leader >` | Rename tab / move tab left / right |
| `leader x` / `leader X` | Close pane / close tab (confirm if sessions alive) |
| `leader -` / `leader \|` | Split horizontal / vertical |
| `leader ←↑→↓` / `leader hjkl` | Focus pane |
| `leader H J K L` | Resize pane (one step) |
| `leader r` | Resize mode (`hjkl`/arrows, `=` equalize, `Esc` exit) |
| `leader z` | Zoom pane (toggle fullscreen) |
| `leader b` / `leader B` | Toggle broadcast for current tab / mark pane for broadcast (§9.8) |
| `leader i` | Session info (also details on a disconnected pane) |
| `leader S` | Share pane (§14) |
| `leader e` | Snippet picker → run in current pane |
| `leader [` | Copy mode |
| `leader Space` | Autocomplete/history overlay (§9.10) |
| `leader Tab` | Accept ghost-text suggestion (when enabled, §9.10) |
| `leader R` | Toggle recording |
| `leader v` | Toggle section views / session area |
| `leader s` | Toggle sidebar |
| `leader !` | Notification history |
| `leader ?` | Help / keybinding reference |
| `leader D` | Debug log pane (`--debug` only) |
| `leader Ctrl-l` | Lock vault |
| `leader Ctrl-z` | Suspend sverb (Unix) |
| `leader q` | Quit (confirm if sessions open) |
| Normal: `/` | Filter current list |
| Normal: `a` / `e` / `d` / `y` | Add / edit / delete / duplicate item |
| Normal: `Enter` | Connect / open |
| Normal: `Tab` | Cycle focus between sidebar, list and detail |
| Normal: `q` | Quit |
| Disconnected/exited pane: `Enter` | Reconnect / restart (`leader x` closes) |

Keymaps are overridable in `config.toml` (§15), and `sverb keys --dump` prints the effective
keymap.

### 8.4 Tabs and panes

- A **tab** holds a **layout tree**:
  `enum Layout { Leaf(PaneId), Split { dir: H|V, ratio: Vec<f32>, children: Vec<Layout> } }`.
- A **pane** holds a session (SSH or local shell).
- Pane resizes propagate to the remote side, debounced by 50 ms.
- Tabs show an activity marker (`●`) for output in a background tab, a bell marker and a
  disconnected marker. A tab's title is the host label, or the OSC title if `tabs.use_osc_title`
  is set.
- Tabs can be renamed (`leader ,`) and reordered (`leader <` / `leader >`).

### 8.5 Views (sidebar sections)

Every list view uses one shared component: a fuzzy filter, multi-select (`Space`), sorting, grouping
and a detail pane on the right when width allows.

| View | Content | Actions |
|---|---|---|
| **Hosts** | Tree of groups and hosts. Filter by tag (`#tag`) and vault. Pinned and recent on top. | connect, connect in split, edit, duplicate, move to group, tag, delete, copy `ssh` command |
| **Keychain** | Keys, certificates and identities, in sub-tabs | generate, import (file/paste), export public key, copy public key, install on host, change passphrase, attach cert |
| **Forwards** | Saved rules plus a live tunnel status table (bytes, connections) | start, stop, add, edit, start without terminal |
| **Snippets** | List with preview | run here, run on hosts…, paste, edit, duplicate |
| **Known Hosts** | Entries with fingerprints | delete, edit, import from `~/.ssh/known_hosts`, export |
| **Logs** | Connection history plus recordings | reconnect, replay recording, export, clear |
| **Settings** | Global config editor, account/sync, devices, team, appearance | |

### 8.6 Forms and dialogs

Host, key, snippet and other editors are full-screen forms, with:
- typed field widgets: text, secret (masked, `Ctrl-r` reveals), number, select, multiselect,
  reference picker (e.g. pick identity), key-value list, multiline text (`tui-textarea`)
- inline validation and an inherited value placeholder (`22 (default)`)
- `Ctrl-s` to save and `Esc` to cancel (with a confirm if the form is dirty)

Modal dialogs cover host-key verification, auth prompts, confirmations, snippet variables and agent
signing confirmation.

### 8.7 Notifications

Toasts appear in the top-right and fade after 4 s. Errors stay until dismissed. A history of them
is under `leader !`.

### 8.8 UI themes

The chrome is styled through a `UiTheme` struct (sidebar, borders, accent, selection, status
colors). It ships `default-dark`, `default-light` and `high-contrast`. sverb respects `NO_COLOR`
and is fully usable in monochrome: focus and selection are shown with reverse video and bold.

Accessibility (M7, decisions log 2026-10-09):
- No information is conveyed by color alone. Every status indicator has text or a glyph: the
  mode segment, `BROADCAST ×N`, `REC ●`, the sync status text, toast titles (`info`,
  `warning`, `error`, `ok`), host-key and certificate warnings.
- `ui.ascii = "auto" | "on" | "off"` (spec addition): ASCII stand-ins for box drawing and
  symbols (`+ - |`, `*`, `>`, `!`). `auto` picks ASCII when the locale isn't UTF-8 or
  `TERM=linux`.
- `ui.reduce_motion = false` (spec addition): spinners show a static glyph.
- Every action is reachable from the keyboard: it has a default binding or a command
  palette entry (enforced by a test).
- See `docs/accessibility.md` for screen-reader notes.

---

## 9. Feature specifications

### 9.1 Hosts

- CRUD via form. Required: `address`. Everything else is optional or inherited.
- **Quick connect** parses `[user@]host[:port]` and the `ssh://user@host:port` URL. It offers
  "Save as host" after a successful connection.
- **Ordering:** pinned, then frecency (local), then alphabetical. A "Recent" pseudo-group shows
  the last 10.
- **Bulk actions** on multi-selected hosts: move to group, add/remove tag, delete, connect all
  (each in a new tab, or as splits in one tab), and run a snippet on all of them.
- **Copy as command:** generates the equivalent `ssh -J … -p … user@host` line.

### 9.2 Groups

- Nested to any depth. The tree is collapsible (`←`/`→` or `h`/`l`).
- Each group has a defaults editor. Its detail pane shows "N hosts inherit these settings".
- Deleting a group asks whether to move its hosts to the parent group or delete them.

### 9.3 Identities

Create, edit and delete. A host form's credentials section can pick an identity or inline
credentials. On delete, the dialog warns how many hosts reference the identity.

### 9.4 Keychain

- **Generate:** Ed25519 (default), ECDSA P-256/384/521 or RSA 2048/3072/4096, with an optional
  passphrase and a comment. Uses the `ssh-key` crate with `OsRng`.
- **Import:**
  - file picker or paste
  - formats: OpenSSH, PEM (PKCS#1, SEC1), PKCS#8, and PuTTY `.ppk` v2/v3 (in-house parser)
  - encrypted keys prompt for the passphrase
- **Export:** public key (OpenSSH format) to clipboard or file, and the private key to a file
  (with confirmation and an optional passphrase re-encrypt).
- **Install on host:** pick hosts, then for each one run this over `exec`, where `<pub>` is the
  public key line passed through POSIX single-quote escaping (`'` → `'\''`):
  `umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '<pub>' ~/.ssh/authorized_keys || printf '%s\n' '<pub>' >> ~/.ssh/authorized_keys)`.
  It requires a POSIX `sh` login shell on the remote. Windows OpenSSH servers are detected
  (`uname` fails) and reported as unsupported. A results table shows the outcome per host
  (`installed` / `already present` / `error: …`).
- **Certificates:** import an OpenSSH certificate and attach it to a key. The UI shows principals,
  validity window (warns if expired or expiring within 7 days) and the CA fingerprint.
- **Hardware / FIDO keys:** used through the system agent (§6.1.1). A key item can be a
  "reference" with only a public key, telling sverb to ask the agent for it.

### 9.5 Known hosts

- **Unknown host key:** a modal shows the host, key type, SHA256 fingerprint and randomart, with
  the choices `[a]ccept & save`, `[o]nce` and `[r]eject`.
- **Changed host key:** a red full-screen warning with old and new fingerprints. Only
  `reject` is offered by default. Replacing the key requires typing the hostname to confirm.
- `@cert-authority` entries are supported: host certificates signed by a trusted CA are accepted.
  The certificate's validity window, its principals (which must include the hostname) and its
  key type are checked as well.
- `@revoked` entries always reject, even if a CA would accept.
- **Lookup key** is `host` for port 22 and `[host]:port` otherwise. For jump chains, see §6.1.4.
- **Hashed entries** (`|1|base64(salt)|base64(HMAC-SHA1(salt, host))`) are imported and kept
  hashed. Lookup computes the HMAC with each entry's salt. New entries are stored unhashed by
  default (`ssh.hash_known_hosts = false`). They're encrypted in the vault anyway.
- **Multiple keys per host** (one per key type) are allowed. During the handshake, sverb orders
  its host-key algorithm preference to put types it already has a key for first, as OpenSSH does.
  This avoids spurious "unknown key" prompts when the server offers several key types.
- **Verification mode** per host or globally: `strict` (unknown keys are rejected), `ask`
  (default) or `accept-new` (unknown keys are saved automatically, changed keys are still
  rejected).

### 9.6 Port forwarding

- **Local (`-L`):** a `tokio::net::TcpListener` on `bind_addr:bind_port`. Each accepted
  connection opens `channel_open_direct_tcpip(dest_host, dest_port, peer_ip, peer_port)`, and
  the two streams are spliced with `tokio::io::copy_bidirectional`. Half-close is propagated in
  both directions (TCP FIN becomes channel `eof`, and vice versa).
- **Remote (`-R`):** `tcpip_forward(bind_addr, bind_port)`. A `bind_port` of 0 means the
  server allocates a port, which is shown in the UI. The server opens `forwarded-tcpip` channels,
  surfaced through `client::Handler::server_channel_open_forwarded_tcpip`. These are matched to
  the rule by `(connected_address, connected_port)`, then connected to `dest_host:dest_port`
  locally. Stopping the rule sends `cancel_tcpip_forward`.
- **Dynamic (`-D`):** a local SOCKS5 server (RFC 1928): no-auth method, `CONNECT` only (`BIND`
  and `UDP ASSOCIATE` are refused with reply `0x07`), and IPv4, IPv6 and domain address types.
  Domain names are resolved **on the remote side** by passing them to `direct-tcpip`, so DNS
  doesn't leak locally. SOCKS4a is accepted too.
- **Lifecycle:** each rule runs as its own task, with a `CancellationToken` that's a child of the
  connection's token. A dropped connection stops all its rules, and reconnecting restarts the
  auto-start ones. Each rule allows at most 256 concurrent channels, and further accepts are
  refused while at the cap.
- Rules can run **with a terminal session** (auto-start) or **standalone** (a tunnel-only
  connection, with no shell channel and no tab).
- The live status table shows rule, state (`listening` / `error: address in use` / `stopped`),
  active connections, and bytes in and out.
- Binding to a non-loopback address asks for confirmation the first time.
- `sverb forward <rule>` runs a rule headlessly from the CLI (§16).

### 9.7 Snippets

- **Variables:** `{{name}}` / `{{name:default}}`. Before running, a form asks for the values.
  Secret variables are masked and never saved to history.
- Built-in variables: `{{host.label}}`, `{{host.address}}`, `{{host.user}}`, `{{date}}`.
- **Variable substitution** is literal text substitution, with no shell escaping, because the
  user sees the final text in a preview before it runs. In *Exec on hosts* mode, values can
  optionally be shell-quoted with the `{{name|q}}` filter.
- **Run modes:**
  - *Paste:* type the text into the focused pane without a trailing newline. If the remote side
    enabled bracketed paste (mode 2004), the text is wrapped in `ESC[200~ … ESC[201~`.
  - *Paste & execute:* each line is sent followed by `\r`, **without** bracketed paste, so the
    shell runs it.
  - *Exec on hosts:* pick hosts, tags or groups, then run via `exec` channels concurrently
    (default concurrency 10). A results view shows per-host status, exit code and expandable
    stdout/stderr, and can export results as JSON/Markdown.
- Snippet picker: `leader e` opens a fuzzy list with preview.
- Snippets can be organized by tags. Startup snippets are snippets referenced by a host.

### 9.8 Broadcast input

- `leader b` toggles broadcast for **all panes in the current tab**. Alternatively, mark specific
  panes with `leader B` to build a custom broadcast set.
- While broadcast is active, input to the focused pane is duplicated to every pane in the set.
  Every pane in the set gets a highlighted border, and the status bar shows `BROADCAST ×N`.
- Paste and snippet runs are broadcast too.
- Resize is never broadcast.

### 9.9 Workspaces

- `Save workspace` captures every tab's layout tree with the host references and broadcast sets.
- `Open workspace` recreates the tabs and connects every pane, in parallel with bounded
  concurrency.
- Workspaces are synced items. `sverb --workspace <name>` opens one at startup.

### 9.10 Autocomplete and command history

Commands can't be observed reliably inside a raw terminal stream, so there are three tiers:

1. **Shell integration (best).** When the remote shell emits **OSC 133** prompt/command markers
   (supported by fish, zsh and bash setups), sverb knows exactly where the prompt is, what command
   ran and its exit code. sverb offers a one-click "install shell integration" snippet that adds a
   small hook to `~/.bashrc` / `~/.zshrc` / fish config.
2. **Heuristic.** Without OSC 133, sverb captures the current cursor line on `Enter` when the
   alternate screen is off. The prompt is stripped using a learned prompt prefix. History entries
   from this tier are marked "unverified".
3. **Sources for suggestions:** per-host history, global history, snippets, and a static completion
   set of common commands.

**UX:** `leader Space` opens an overlay anchored at the cursor. It contains a fuzzy search over
those sources, filtered by the current line's prefix (when tier 1 knows it). `Enter` types the
remainder into the pane, and `Tab` inserts without executing. There is an optional inline "ghost
text" suggestion, which requires tier 1 and is off by default.

History is stored as `HistoryEntry` items. It is synced only when `history.sync = true`, and it
can be purged per host.

### 9.11 (removed)

This section described an optional AI assistant. It was dropped from the product on 2026-10-08. The
number is kept so the references to §9.12 and later stay valid.

### 9.12 Logs

- `ConnLog` entries for each connection attempt, sorted newest first and filterable by
  host/result.
- Each entry offers reconnect, view error details, and replay recording, if one exists.
- **Replay player:** play/pause (`Space`), speed `1/2/4x` (`+`/`-`), seek (`←`/`→` 5s), and idle
  time capped at 2 s.
- Retention: logs 90 days, recordings until deleted. Both are configurable.

### 9.13 Import and export

| Source | Notes |
|---|---|
| `~/.ssh/config` | Parses `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, `ProxyCommand`, `LocalForward`, `RemoteForward`, `DynamicForward`, `ForwardAgent`, `SetEnv`, `ServerAliveInterval` and `Include`. Wildcard `Host` blocks become group defaults where expressible and are otherwise reported as skipped. Identity files are imported into the keychain after confirmation. |
| `~/.ssh/known_hosts` | §9.5 |
| PuTTY sessions | `~/.putty/sessions/*` on Linux/macOS, and the registry `HKCU\Software\SimonTatham\PuTTY\Sessions` on Windows |
| CSV | Columns: `label,address,port,username,group,tags` |
| sverb backup | Encrypted JSON (`.sverb-backup`), Argon2id + XChaCha20-Poly1305 with an export password |

Exports: sverb backup, `ssh_config` (lossy, with a warning about secrets not exported) and CSV.

Every import runs as a **dry run first**, with a preview table (new / duplicate / conflict). The
user then picks a target vault and group.

---

## 10. Sync backend (`sverb-server`)

### 10.1 Stack

- `axum` HTTP server and `tokio-tungstenite`/axum WebSockets
- `sqlx` with PostgreSQL 15+
- `tower-http` for tracing, compression, CORS (for a future web viewer) and request limits
- `governor` for rate limiting
- TLS via `rustls` built-in (optional `--tls-cert/--tls-key`), or terminated at a reverse proxy
- Config via environment variables or `sverb-server.toml`

### 10.2 Responsibilities

The server **never** decrypts user data. It does the following:

1. Account registration and login (OPAQUE, §11.2). Optional TOTP as a second factor.
2. Storing the encrypted account key bundle.
3. Storing encrypted items per vault, with revisions.
4. Holding membership and wrapped vault keys for shared vaults.
5. Push notifications to connected devices over WebSocket.
6. Relaying terminal-sharing streams (§14).
7. Device registry and session revocation.
8. A metadata-only audit log for orgs.

### 10.3 Database schema (PostgreSQL)

```sql
CREATE TABLE server_secrets (
  name TEXT PRIMARY KEY,                  -- 'opaque_server_setup'
  value_enc BYTEA NOT NULL                -- AEAD under key derived from SVERB_SERVER_SECRET
);
CREATE TABLE users (
  id UUID PRIMARY KEY, email CITEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  is_instance_admin BOOLEAN NOT NULL DEFAULT false,
  opaque_record BYTEA NOT NULL,           -- OPAQUE registration record
  totp_secret_enc BYTEA,                  -- encrypted with server KMS key
  disabled BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE account_keys (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  x25519_pub BYTEA NOT NULL, ed25519_pub BYTEA NOT NULL,
  private_bundle_enc BYTEA NOT NULL,      -- encrypted under AKEK (client-side)
  recovery_bundle_enc BYTEA,              -- encrypted under recovery key
  version INT NOT NULL
);
CREATE TABLE devices (
  id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), name TEXT, platform TEXT,
  created_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ
);
CREATE TABLE auth_tokens (
  token_hash BYTEA PRIMARY KEY,           -- SHA-256 of the 256-bit random token
  device_id UUID REFERENCES devices(id),
  kind TEXT CHECK (kind IN ('access','refresh')), expires_at TIMESTAMPTZ NOT NULL,
  family UUID NOT NULL,                   -- refresh-token rotation family
  used_at TIMESTAMPTZ                     -- set when a refresh token is rotated
);
CREATE TABLE orgs (id UUID PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ);
CREATE TABLE org_members (
  org_id UUID REFERENCES orgs(id), user_id UUID REFERENCES users(id),
  role TEXT CHECK (role IN ('owner','admin','member')), PRIMARY KEY (org_id, user_id)
);
CREATE TABLE vaults (
  id UUID PRIMARY KEY,                    -- client-generated (UUIDv7), so local ids survive upload
  kind TEXT CHECK (kind IN ('personal','shared')) NOT NULL,
  owner_user_id UUID, org_id UUID REFERENCES orgs(id),
  key_version INT NOT NULL DEFAULT 1, head_revision BIGINT NOT NULL DEFAULT 0,
  gc_floor_revision BIGINT NOT NULL DEFAULT 0,  -- tombstones at or below this were purged
  rotation JSONB,                         -- non-NULL while a key rotation is in progress (§13.2)
  name_enc BYTEA NOT NULL,                -- vault name encrypted under vault key
  CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL AND org_id IS NULL))
);
CREATE TABLE vault_members (
  vault_id UUID REFERENCES vaults(id), user_id UUID REFERENCES users(id),
  permission TEXT CHECK (permission IN ('read','write','manage')),
  key_version INT NOT NULL, wrapped_vault_key BYTEA NOT NULL,   -- HPKE to member's x25519
  wrapped_by UUID NOT NULL,               -- granting user (for signature verification)
  signature BYTEA NOT NULL,               -- ed25519 by granter over (vault, member, key_version, wrapped key)
  PRIMARY KEY (vault_id, user_id, key_version)
);
CREATE TABLE items (
  vault_id UUID REFERENCES vaults(id), id UUID NOT NULL,
  revision BIGINT NOT NULL, key_version INT NOT NULL,
  envelope BYTEA NOT NULL,                -- always present; tombstones carry a tiny encrypted
                                          -- body with the delete HLC (§12.4)
  deleted BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL, updated_by_device UUID,
  PRIMARY KEY (vault_id, id)
);
CREATE UNIQUE INDEX items_vault_rev ON items (vault_id, revision);
CREATE TABLE items_rotation_staging (     -- re-encrypted items uploaded during key rotation
  vault_id UUID, id UUID, key_version INT, envelope BYTEA NOT NULL,
  PRIMARY KEY (vault_id, id)
);
CREATE TABLE invites (
  id UUID PRIMARY KEY, org_id UUID, email CITEXT, role TEXT, token_hash BYTEA,
  created_by UUID, expires_at TIMESTAMPTZ, accepted_at TIMESTAMPTZ
);
CREATE TABLE share_sessions (
  id UUID PRIMARY KEY, owner_user_id UUID, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
  mode TEXT CHECK (mode IN ('view','control')), max_viewers INT, closed_at TIMESTAMPTZ
);
CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY, org_id UUID, actor_user_id UUID, kind TEXT, target UUID,
  at TIMESTAMPTZ NOT NULL, meta JSONB    -- never contains plaintext item data
);
```

### 10.4 HTTP API (v1)

All bodies are JSON (`sverb-proto`, `serde`), and binary fields (envelopes, OPAQUE messages,
keys) are base64url without padding. Auth is via `Authorization: Bearer <access token>`.

- **Tokens.** Access and refresh tokens are opaque random 256-bit values, stored as SHA-256
  hashes. Access tokens have a 15-minute TTL. Refresh tokens have a 30-day TTL, rotate on every
  use and are bound to a device.
- **Reuse detection.** Presenting an already-rotated refresh token (`used_at IS NOT NULL`)
  revokes the whole token `family`, so the device must log in again. This catches stolen
  refresh tokens.
- **Error format** (all endpoints):
  `{ "error": { "code": "conflict|forbidden|not_found|rate_limited|invalid|gone|rotating|auth_required|internal", "message": "...", "retry_after_s"?: n } }`.
  `429` responses carry `Retry-After`. `internal` (5xx, unexpected server failure) is a spec
  addition; clients treat it as transient.
- **Request IDs.** Each request gets an `x-request-id` (generated if absent), which is echoed in
  responses and logs.
- **Account enumeration resistance.** For an unknown email, `login/start` returns a
  syntactically valid KE2 computed from a dummy record (`ServerLogin::start` with
  `None`), so unknown and known emails are indistinguishable until `finish`, which fails the same
  way for both.
- **OPAQUE configuration:** `opaque-ke` with the cipher suite `{ OPRF: Ristretto255, KE:
  TripleDh<Ristretto255, Sha512>, KSF: Argon2id(m=64 MiB, t=3, p=1) }`. The KSF runs client-side,
  so the server's CPU cost per login stays small. The `ServerSetup` is generated on first start
  and stored in `server_secrets`.

**Auth and account**

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/auth/register/start` | OPAQUE registration step 1 |
| POST | `/v1/auth/register/finish` | Step 2. Also uploads the account key bundle and creates the personal vault. |
| POST | `/v1/auth/login/start` | OPAQUE login KE1 → KE2 |
| POST | `/v1/auth/login/finish` | KE3 (+ TOTP) → tokens + encrypted key bundle |
| POST | `/v1/auth/refresh` | Rotate tokens |
| POST | `/v1/auth/logout` | Revoke the current device's tokens |
| POST | `/v1/account/password/start` | Password change step 1: OPAQUE registration start for the new password (needs a fresh `reauth_token`) |
| POST | `/v1/account/password` | Password change: new OPAQUE record + re-wrapped bundle (atomic) |
| POST | `/v1/account/recovery/code` | Recovery step 1: mail a one-time code (with SMTP; otherwise the operator issues it with `sverb-server admin user recovery-code`) |
| POST | `/v1/account/recovery/start` | Recovery step 2: code + OPAQUE registration request → `recovery_bundle_enc` + registration response |
| POST | `/v1/account/recovery` | Recovery step 3: code + signature with the account key; replaces record and bundle, revokes every device |
| GET/DELETE | `/v1/devices`, `/v1/devices/{id}` | List and revoke devices |
| POST/DELETE | `/v1/account/totp` | Enable or disable TOTP |
| DELETE | `/v1/account` | Delete account (requires re-auth) |

**Vaults and sync**

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/vaults` | Vaults the user belongs to, with wrapped keys, permission and head revision |
| POST | `/v1/vaults` | Create a shared vault (org admin+) |
| GET | `/v1/vaults/{id}/changes?since=&limit=` | Pull (§12.2) |
| POST | `/v1/vaults/{id}/changes` | Push batch (§12.3) |
| POST | `/v1/vaults/{id}/rotate` | Key rotation: new wrapped keys + re-encrypted items, chunked |
| GET | `/v1/ws` | WebSocket: change notifications, share signalling |

**WebSocket protocol (`/v1/ws`).** The access token isn't put in the URL, where it would end up in
proxy logs. The first client message must be
`{"type":"auth","token":"…"}` within 5 s, or the socket is closed with code `4401`.

| Direction | Message |
|---|---|
| server → client | `{"type":"vault_changed","vault_id","head_revision"}` |
| server → client | `{"type":"vault_access","vault_id","change":"granted\|revoked\|rotated"}` |
| server → client | `{"type":"account_changed","key_version"}` (password change elsewhere) |
| server → client | `{"type":"share_join_request","share_id","viewer"}` |
| both | `{"type":"ping"}` / `{"type":"pong"}` every 30 s; 2 missed pongs close the socket |

The server closes the socket with `4401` when the token expires, and the client re-authenticates
after refreshing. Notifications are hints only, because correctness comes from pull (§12.2), so a
missed message is harmless.

**WebSocket close codes** (`/v1/ws` and the share streams). Only `4401` was named above; the
rest are spec additions (M4-05, M6-01):

| Code | Meaning |
|---|---|
| `4401` | Authentication missing, invalid or expired, device revoked, account disabled; or the share requires an account |
| `4403` | Not allowed to host this share (not the owner) |
| `4404` | No such share (viewer stream) |
| `4408` | Ping timeout (2 missed pongs), or a share viewer too slow to keep up |
| `4409` | Replaced by a newer host connection for the same share |
| `4410` | The share ended (deleted, host gone past the grace period, or expired) |
| `4411` | Kicked by the share host |
| `4429` | The share already has `max_viewers` viewers |

**Orgs and members**

| Method | Path | Purpose |
|---|---|---|
| POST/GET | `/v1/orgs` | Create or list orgs |
| GET | `/v1/orgs/{id}/members` | Members with roles (spec addition, M5-01) |
| GET | `/v1/orgs/{id}/vaults` | The org's shared vaults (spec addition, M5-02) |
| GET | `/v1/vaults/{id}/members` | A vault's members with permission and key version (spec addition, M5-02) |
| POST | `/v1/orgs/{id}/invites` | Invite by email or link |
| POST | `/v1/invites/{token}/accept` | Accept an invite |
| GET | `/v1/users/{id}/public-keys` | Fetch member public keys, used for wrapping |
| PUT/DELETE | `/v1/vaults/{id}/members/{user}` | Grant (with wrapped key + signature) or revoke |
| PATCH/DELETE | `/v1/orgs/{id}/members/{user}` | Change role or remove |
| GET | `/v1/orgs/{id}/audit` | Audit log |

**Sharing**

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/shares` | Create a share session |
| DELETE | `/v1/shares/{id}` | End a share |
| GET (WS) | `/v1/shares/{id}/host` | Host stream |
| GET (WS) | `/v1/shares/{id}/join` | Viewer stream. Auth optional, depending on share policy. |

**Ops**

`GET /healthz`, `GET /readyz` and `GET /metrics` (Prometheus, behind an admin token or bind
address).

### 10.5 Limits and abuse controls

- Login: 5 attempts per minute per email, and 50 per minute per IP.
- Item envelope: 1 MiB max. Push batch: 500 items or 8 MiB max.
- Per-user storage quota, configurable (default 100 MiB).
- Share sessions: max 10 viewers and a 24 h default TTL, both configurable.

### 10.6 Admin CLI

```
sverb-server serve
sverb-server migrate
sverb-server admin user create|disable|list
sverb-server admin registration open|invite-only|closed
sverb-server admin gc            # purge expired tokens, tombstones > horizon, closed shares
```

**Bootstrap for a fresh instance.** Registration starts as `invite-only`. On first start the
server prints a one-time **setup token** to its log, and the first account registered with that
token becomes the instance admin. After that, new accounts need an invite (from an org admin or
`sverb-server admin invite <email>`), unless the operator switches registration to `open`.

### 10.7 Deployment

- Ships as a single static binary (musl) and a distroless Docker image.
- `deploy/docker-compose.yml` brings up `sverb-server` and `postgres` with volumes.
- Environment:
  - `DATABASE_URL`, `SVERB_BIND`, `SVERB_PUBLIC_URL`
  - `SVERB_SERVER_SECRET`, 32+ random bytes. It encrypts `server_secrets` (the OPAQUE
    `ServerSetup`) and TOTP secrets at rest.
  - optional `SMTP_*` for invite emails. Without SMTP, invites are copy-paste links.
- **Back up the database and `SVERB_SERVER_SECRET` together.** Losing either one invalidates
  every login, because the `ServerSetup` can't be decrypted. User data stays safe, because it's
  E2EE and recoverable on any logged-in device, but every user would have to re-register and
  re-upload.
- **Multiple instances.** The server is stateless except for WebSockets and share relays.
  Running more than one replica requires sticky routing for `/v1/shares/*` and Postgres
  `LISTEN/NOTIFY` for `vault_changed` fan-out. That fan-out is implemented from the start, so
  scaling out is a deployment choice.

---

## 11. Cryptography and key hierarchy

All primitives come from audited RustCrypto / dalek crates. Secrets are wrapped in
`secrecy::SecretBox` and zeroized on drop.

### 11.1 Primitives

| Purpose | Primitive |
|---|---|
| Password hashing (local) | Argon2id |
| Password authentication (server) | OPAQUE (`opaque-ke`, ristretto255, Argon2id KSF) |
| Symmetric AEAD | XChaCha20-Poly1305 (24-byte random nonces) |
| Key derivation | HKDF-SHA256 |
| Public-key encryption | HPKE (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 |
| Signatures | Ed25519 |
| Random | `OsRng` |

**Canonical encodings.** Every byte string that feeds into AAD, HKDF `info`, HPKE `info` or a
signature is built as a concatenation of **fixed-width or length-prefixed** fields, never
ambiguous strings:
- UUIDs are 16 raw bytes.
- Integers are big-endian (`key_version: u32`, `seq: u64`).
- Variable-length fields are prefixed with their length as `u32` BE.
- Domain-separation labels are ASCII constants such as `"sverb/vk/v1"`.

`sverb-crypto` exposes these only through typed builder functions, and known-answer test vectors
cover each one.

### 11.2 Account keys

```
password ──OPAQUE──▶ export_key (64 B, stable per password, never sent)
export_key ──HKDF("sverb/akek/v1")──▶ AKEK (Account Key-Encryption Key)

Account keypairs (generated on device at registration):
  X25519 (enc)   Ed25519 (sign)
private_bundle = AEAD(AKEK, {x25519_sk, ed25519_sk})        → stored on server
recovery_key   = 256-bit random, shown once as 24-word BIP39 phrase
recovery_bundle= AEAD(HKDF(recovery_key), {x25519_sk, ed25519_sk})
```

- **Login on a new device:** OPAQUE yields `export_key`, which derives AKEK, which decrypts
  `private_bundle`, which gives the account private keys, which unwrap the vault keys.
- **Forgotten password:** recovery key → decrypt `recovery_bundle` → set a new password. Without
  the recovery key **and** without any logged-in device, data is unrecoverable. This is by
  design, and the UI must say so clearly at signup. A local-only user who forgets the password
  has no recovery path unless they enabled the OS keyring unlock, which can be used to set a new
  password.

#### 11.2.1 One password, two derivations

The master password (§5.3) and the account password are the same secret. It is used in two
independent ways, and the password itself never leaves the device:

```
                 ┌── Argon2id(local_salt) ──▶ local KEK ──▶ wraps LMK      (device only, offline)
password ────────┤
                 └── OPAQUE ──▶ export_key ──▶ AKEK ──▶ wraps account keys (server stores ciphertext)
```

The two derivations use different salts and constructions, so neither output reveals the other.
The local KEK lets the vault unlock offline, and OPAQUE means the server never sees the password
or anything it can brute-force without running an online attack.

**Flows:**

- **Local-only → enable sync (new account).** The user picks a server URL and email. sverb
  asks for the **current master password** (not a new one) and uses it for OPAQUE registration.
  The existing personal vault becomes the account's personal vault: same vault id, same VK and
  same item ids. Its VK is self-granted (§11.3), and every item is pushed with
  `base_revision = 0`.
- **Local-only → log in to an existing account.** The user enters the account password, and OPAQUE
  login succeeds. If it differs from the current local password, sverb shows a warning
  ("Your local master password will be changed to your account password"), then re-wraps the LMK
  under a KEK from the account password. The local personal vault has a **different VK** from the
  account's personal vault, so its items are imported: each one is decrypted, re-encrypted under
  the account vault's VK with a **new** item id, and pushed. Then the old local vault is deleted.
  Likely duplicates (same `address:port:user`) are shown in a dry-run preview first, with keep
  both, keep local or keep account.
- **Password change (online).** This must happen with the server reachable:
  1. Run OPAQUE login with the old password to prove knowledge.
  2. Register a new OPAQUE record and re-encrypt `private_bundle` under the new AKEK. Upload both
     atomically.
  3. Re-wrap the LMK locally under the new KEK.
  4. The server bumps `account_keys.version` and notifies the other devices over WebSocket.
- **Password changed on another device.** This device still unlocks locally with the **old**
  password, because its LMK wrap hasn't changed. On its next server login, OPAQUE fails or the
  server reports a newer key version. sverb then shows "Your password was changed on another
  device", and the user enters the new password. OPAQUE login succeeds, and the LMK is re-wrapped
  with the new password. Old access tokens are revoked server-side when the password changes, so
  sync stops on stale devices until this happens.
- **Password change in local-only mode.** Only the LMK is re-wrapped, with no server involved.
- **Disable sync** (`sverb logout --keep-local`). Tokens are revoked and shared vaults are
  removed from the device, because they belong to the org. The personal vault and the password
  stay as they are.

**Password strength:** because the same password protects the server-side bundle, sverb enforces
a minimum strength at creation (`zxcvbn` score ≥ 3), in both modes. Local-only users get the same
rule, so they don't have to change their password when they enable sync later.

### 11.3 Vault keys

- Each vault has a random 256-bit **Vault Key** (VK) with a `key_version`.
- **Personal vaults use the same mechanism.** The owner is the only `vault_members` row, a
  **self-grant** wrapped to their own X25519 key and signed with their own Ed25519 key. That's how
  a new device obtains the personal VK after login. There is no separate code path.
- For each member: `wrapped_vault_key = HPKE.Seal(member_x25519_pub, info="sverb/vk/v1"||vault_id||key_version, VK)`,
  in HPKE base mode, single-shot.
- The granter signs `(vault_id, member_user_id, key_version, wrapped_vault_key)` with Ed25519.
  Clients verify the signature against a granter key they trust (§13.3) before using a VK.
- Locally, VKs are re-wrapped under the LMK (§5.3), so normal unlock doesn't need the account
  password.

### 11.4 Item encryption

```
item_key  = HKDF-SHA256(ikm=VK, salt=item_id, info="sverb/item/v1")   // per-item subkey
nonce     = random 24 B (fresh for every write)
aad       = "sverb-item-v1" || vault_id || item_id || key_version
plaintext = pad256(zstd(cbor(ItemBody)))
envelope  = 0x01 (format version) || key_version (u32 BE) || nonce || XChaCha20Poly1305(item_key, nonce, aad, plaintext)
```

`pad256` appends `0x80` followed by zero bytes up to the next multiple of 256 (ISO/IEC 7816-4
style), so it can be removed unambiguously.

- The AAD binds the ciphertext to its vault and item, so the server can't swap or move items
  undetected.
- The item **kind** is inside the ciphertext, so the server learns only counts, sizes (to 256 B
  granularity) and change timing.
- Random 192-bit nonces make collisions negligible, even at billions of writes per key, so no
  nonce counter state is needed.

### 11.5 Local secrets

Passwords, private keys and passphrases are just fields in an encrypted ItemBody, with no
separate storage. In memory they are held as `SecretString` and only exposed at the point of use
(auth, signing).

---

## 12. Sync protocol

### 12.1 Model

- The server keeps one monotonically increasing `head_revision` per vault. Every accepted change
  gets `revision = ++head_revision`.
- **Gap-free ordering.** A push transaction first runs
  `UPDATE vaults SET head_revision = head_revision + $n WHERE id = $1 RETURNING head_revision`,
  which takes the vault row lock and holds it until commit. Pushes to the same vault are
  therefore serialized, and revisions become visible in the order they were assigned. Without
  this, a reader could see revision 12 committed before 11, advance its cursor past 11, and miss
  it forever. Rejected changes in the batch don't consume revisions, because `$n` is the number
  of accepted changes, computed before the update inside the same transaction.
- Each client stores a `sync_cursor` per vault, which is the highest revision it has applied.
- Local edits set `dirty = 1` and append to `outbox`.

### 12.2 Pull

`GET /v1/vaults/{id}/changes?since=<cursor>&limit=500` returns
`{ items: [{id, revision, key_version, envelope, deleted}], head_revision, more: bool }`,
ordered by `revision ASC`.

The client:
1. Decrypts each item.
2. If the local copy is **not dirty**, it replaces the local copy.
3. If the local copy **is dirty**, it does a field-level merge (§12.4), keeps the item dirty, and
   rebases the outbox base revision to the incoming revision.
4. Advances the cursor and repeats while `more` is true.

Each page is applied in one SQLite transaction, together with the cursor update, so a crash
mid-pull never leaves the cursor ahead of the data.

**Tombstone GC.** `sverb-server admin gc` purges tombstones older than the horizon (default
90 days) and raises `vaults.gc_floor_revision` to the highest purged revision. If a client's
`since` is below `gc_floor_revision`, the server returns `410 Gone`. The client then does a
**full resync**:
1. It pulls everything from `since=0`.
2. Any local item that is clean (not dirty) and absent from the server is deleted locally.
3. Any local dirty item that is absent from the server is pushed again as a new item.

### 12.3 Push

`POST /v1/vaults/{id}/changes` with
`{ changes: [{id, base_revision, key_version, envelope, deleted}] }`. Every change must carry
`key_version == vaults.key_version`. During a rotation the server answers `409 rotating`
(§13.2), and the client retries after the rotation completes, re-encrypting under the new VK.

The server, in one transaction per batch:
- for each change, accepts it if `items.revision == base_revision` (or the item is absent and
  `base_revision == 0`), assigning a new revision
- otherwise rejects the change with `conflict`, returning the current server item

The response is `{ results: [{id, status: ok|conflict|forbidden|too_large, revision?, current?}] }`.

On conflict, the client merges and retries, at most 5 rounds before surfacing an error.

### 12.4 Merge

- Each field in `ItemBody.fields` carries an HLC stamp. Merging takes the field with the higher
  `(hlc, device_id)`. This is a deterministic, commutative, idempotent per-field LWW register,
  so every replica converges regardless of order.
- **HLC.** Each device keeps an HLC (`uhlc`: 64-bit NTP-style physical time plus a logical
  counter) and updates it on every received stamp. To limit damage from a device with a wildly
  wrong clock, stamps more than **5 minutes ahead** of local physical time are clamped on
  receipt, and the device is warned ("Clock skew detected on device X").
- **Deletion** is the item-level `deleted` stamp. Tombstones are pushed as a normal envelope
  whose body contains only `deleted = Stamped(true, hlc)`. At merge time, an item is deleted
  if `deleted.hlc` is greater than the highest field HLC. An edit newer than the delete
  resurrects the item, and the user sees a toast about it.
- List fields (`tags`, `port_forwards`, `env`) are LWW as whole values in v1. Using OR-sets is an
  open question.
- Referential integrity: references to deleted items, such as a host whose group was deleted, are
  resolved at read time by treating the missing reference as `None`, and are cleaned up lazily.

### 12.5 Triggering

- Push is debounced 2 s after a local change.
- Pull happens on startup, on WebSocket notification `{type:"vault_changed", vault_id, head}`, and
  every 5 minutes as a fallback.
- The WebSocket reconnects with exponential backoff. Offline edits queue in the outbox
  indefinitely.
- The status bar shows the sync state (`synced` / `syncing` / `offline (3 pending)` / `error`).

### 12.6 Device-local data

`last_connected_at`, frecency, recordings, window state and
`config.toml` are **never** synced. `config.toml` is meant for dotfiles management.

---

## 13. Teams and shared vaults

### 13.1 Concepts

- An **Org** has members with an org role: `owner` (one or more), `admin` or `member`.
- **Shared vaults** belong to an org. Membership is per vault, with permission `read`, `write` or
  `manage` (can grant and revoke). Org owners and admins implicitly have `manage` on all of the
  org's vaults.
- Items can be moved or copied between personal and shared vaults. A move re-encrypts the item
  under the target vault key and tombstones the source.

### 13.2 Membership flows

- **Invite:** an admin creates an invite (email or link with a token). The invitee registers or
  logs in, then accepts.
- **Grant vault access:** a `manage` user's client fetches the invitee's public keys, verifies
  them (§13.3), HPKE-wraps the VK, signs it and `PUT`s the membership. The server cannot grant
  access by itself, because it never holds the VK.
- **Revoke:** the server deletes the membership immediately, so the revoked user can't pull
  anymore. The revoking client then **rotates** the vault key:
  1. `POST /rotate {action:"begin", new_key_version}` sets `vaults.rotation =
     {by, new_key_version, started_at}`. From now on, pushes are answered `409 rotating`, and pulls
     keep working.
  2. The client generates VK′, pulls everything up to `head_revision`, and re-encrypts each item
     under VK′. Items keep their ids, but the AAD now includes the new `key_version`.
  3. `POST /rotate {action:"upload", items:[…]}` in chunks of up to 500 items, written to
     `items_rotation_staging`.
  4. `POST /rotate {action:"commit", wrapped_keys:[{user, wrapped, signature}…]}`. In one
     transaction, the server checks that staging covers **every** item in the vault, moves the
     staged envelopes into `items` with fresh revisions, inserts the new `vault_members` rows,
     bumps `key_version`, clears `rotation`, and notifies members with `vault_access: rotated`.
  5. If the rotating client disappears, the rotation is abandoned after 15 minutes: staging is
     discarded, `rotation` is cleared, and the next `manage` client to connect is prompted to
     restart it.

  Old `vault_members` rows for previous key versions are kept, so that items not yet rotated can
  still be decrypted by remaining members during the window. They are deleted at commit. The
  revoked user keeps any data they had already synced, which is unavoidable. Rotation only
  protects **future** changes.

  **Decision (M5-04):** before step 4 the rotating client fetches every remaining member's
  public keys and checks them against its pins (§13.3). A member whose key **changed**, or whose
  key can't be fetched or verified, **blocks the commit**: the client stops with an error naming
  those members, the rotation stays open (pushes stay paused), and it is resumed after the new
  keys are accepted in Settings → Team, or abandoned after 15 minutes (step 5). A member is never
  silently dropped from the vault because of a key change. Org admins who never held a grant are
  optional: an untrusted one is skipped and granted later by the §13.1 reconcile. A crashed
  rotation **resumes** on the same device (VK′ and the uploaded ids are kept, wrapped under the
  LMK) instead of restarting.
- **Read-only enforcement:** the server rejects pushes from `read` members (`forbidden`).
  Clients hide edit actions.

### 13.3 Public key trust

A malicious server could substitute public keys. Mitigations:
- **TOFU pinning:** each client pins every org member's key fingerprint on first sight and warns
  loudly if it changes.
- **Safety numbers:** each member has a short fingerprint (`sverb team verify <user>`), comparable
  out of band. Verified members show a ✓.
- **Granter signatures:** every wrapped VK is signed by its granter, and clients verify that the
  granter is a pinned member with `manage` permission.

### 13.4 Credentials in shared vaults

Shared hosts commonly reference shared identities and keys. A host in a shared vault **must not**
reference an item in a personal vault, because other members could not resolve it. The UI enforces
this, with one exception. A per-user **credential override** can be stored in the user's personal
vault, keyed by `(shared_host_id)`. That lets teams share host definitions while each member uses
their own key.

### 13.5 Audit log

The server records metadata events: member added/removed, vault created/rotated, invite
sent/accepted, share started/ended, and device added/revoked. Item-level events record only
`item_id` and the actor, never content. The log is visible to org admins in Settings → Team.

---

## 14. Terminal sharing

The goal is to give someone a live view of (and optionally control over) one of your sessions
through a link, with the server acting as a blind relay.

### 14.1 Flow

1. The host user presses `leader S` on a pane and chooses mode (`view` / `control`), expiry and
   whether viewers must have a sverb account.
2. The client creates the share: `POST /v1/shares` returns `share_id`. The client generates a
   256-bit `share_key` locally.
3. The link is `sverb://join/<server>/<share_id>#<base64url(share_key)>`, plus the equivalent
   `https://<server>/s/<share_id>#<key>` for a future web viewer. The fragment never reaches the
   server.
4. The host opens WS `/v1/shares/{id}/host` and streams frames.
5. A viewer runs `sverb join <link>` (or pastes it into the palette) and opens WS
   `/v1/shares/{id}/join`.
6. **The host approves each viewer.** A modal shows the viewer's name, or "anonymous", and an IP
   hint from the server. Approval can be skipped with an option.
7. On approval, the host sends a **snapshot frame** (the serialized visible grid, cursor and
   modes), followed by live output frames.

### 14.2 Keys and frames

A single key shared by every viewer would let any viewer forge another viewer's input. Instead,
the link key only authenticates the join, and each viewer gets its own channel key:

1. **Join handshake.** The viewer generates an ephemeral X25519 key pair and sends
   `Hello { viewer_eph_pub, name, mac }` through the relay, where
   `mac = HMAC-SHA256(HKDF(share_key, info="sverb/share/join/v1"), share_id || viewer_eph_pub || name)`.
   The host verifies the MAC, which proves the viewer has the link, and replies with
   `Welcome { host_eph_pub, mac' }`, MAC'd the same way over the full transcript.
2. **Channel key.** Both sides compute
   `k_viewer = HKDF(X25519(eph, eph'), salt=share_key, info="sverb/share/chan/v1" || share_id || viewer_eph_pub || host_eph_pub)`,
   then split it into `k_h2v` and `k_v2h`. This gives forward secrecy per viewer, and a viewer
   cannot impersonate another viewer.
3. **Frames** are `XChaCha20Poly1305(k_dir, nonce = seq (u64 BE, zero-padded to 24 B), aad =
   share_id || viewer_id || dir || seq)`. Per-direction counters make nonces unique without
   randomness. A frame with `seq` that isn't exactly `last + 1` closes the channel, which
   prevents replay, reordering and dropping.

```rust
enum ShareFrame {
    Snapshot { cols: u16, rows: u16, vt: Bytes },  // emulator.snapshot_vt(): VT byte stream that
                                                    // redraws the screen (SGR, cursor, modes)
    Output(Bytes),
    Resize { cols: u16, rows: u16 },
    Input(Bytes),                                  // viewer→host; honored only if this viewer has control
    ControlGranted(bool),
    Bye { reason: String },
}
```

- **Snapshot.** The snapshot is a VT byte stream, not a custom cell format, so the viewer just
  feeds it to its own emulator. It contains: clear screen, the visible grid with full SGR
  attributes, the cursor position and shape, and active modes (alternate screen, DECCKM,
  bracketed paste, mouse). Scrollback isn't shared.
- **Relay framing.** Each WebSocket message carries a binary `RelayEnvelope { viewer_id: u32,
  payload }`. The server sees only that routing header.

### 14.3 Rules

- The viewer renders the stream in a pane sized to the host's dimensions, letterboxed or clipped
  as needed.
- In `control` mode, viewer input is injected into the host session. The host sees a
  `⚠ shared · control` banner and can revoke control or kick viewers at any time (`leader S`).
- Sharing ends when the host closes it, the session ends, or the expiry passes.
- **Stretch goal:** a read-only web viewer (xterm.js plus WebCrypto) served by `sverb-server` at
  `/s/<id>`.

---

## 15. Configuration

`~/.config/sverb/config.toml`. Every key is optional, and these are the defaults:

```toml
[general]
leader = "ctrl-\\"               # Ctrl-\ ; "ctrl-g" recommended where \ needs AltGr
confirm_quit = true
auto_lock_minutes = 15
lock_disconnects_sessions = false
default_vault = "personal"

[ui]
theme = "default-dark"          # UI chrome theme
sidebar = "auto"                # auto | always | never
mouse = true
truecolor = "auto"              # auto | on | off
show_which_key = true
which_key_delay_ms = 400
date_format = "%Y-%m-%d %H:%M"

[terminal]
term = "xterm-256color"
scrollback = 10000
color_scheme = "terminal"       # default for hosts without one
bell = "visual"                 # none | visual | audible
paste_confirm_multiline = true
use_osc_title = false
word_separators = " ,│`|:\"'()[]{}<>"

[clipboard]
osc52 = true
allow_remote_write = "ask"      # never | ask | always

[ssh]
multiplex = true
keepalive_secs = 30
host_key_policy = "ask"         # strict | ask | accept-new
use_system_agent = true
read_ssh_config = false         # also resolve hosts from ~/.ssh/config live (read-only)
hash_known_hosts = false        # store new known_hosts entries hashed
exec_timeout_secs = 60
max_auth_attempts = 5
connect_timeout_secs = 15

[recording]
enabled = false
include_input = false

[history]
enabled = true
sync = false
max_entries_per_host = 5000

[sync]
# Server URL, device id and tokens are set by `sverb login` and stored encrypted in the
# database (§5.2), not in this file. These are tuning knobs only.
push_debounce_ms = 2000
poll_fallback_secs = 300

[logs]
retention_days = 90
sync = false

[keys.terminal]                 # bindings after leader
"p" = "palette"
"-" = "split_horizontal"
"|" = "split_vertical"

[keys.normal]
"ctrl-k" = "palette"
```

**Spec additions** (all optional, defaults shown; the generated reference with types and
descriptions is `docs/config.md`):

```toml
[ui]
ascii = "auto"                  # auto | on | off: ASCII glyphs (auto: non-UTF-8 locale or TERM=linux)
reduce_motion = false           # no animated spinners

[ssh]
auto_reconnect = false          # reconnect dropped sessions (backoff 1 s → 30 s, 10 tries); hosts can override

[recording]
retention_days = 0              # delete recordings after N days; 0 = keep until deleted

[history]
ghost_text = false              # inline suggestion after the cursor (needs OSC 133); leader Tab accepts

[keys.copy]                     # copy-mode bindings (leader [)
"y" = "yank"
```

`ssh.read_ssh_config = true` and `terminal.bell` values other than `"visual"` are accepted
but have no effect in 1.0 (a warning says so; decisions log 2026-10-09).

- The config is hot-reloaded on change (`notify` crate). Invalid config is reported as a toast
  and the last good config stays in effect.
- `sverb config --check` validates the file. `sverb config --print-default` prints the defaults.
- A JSON schema is generated with `schemars`, for editor completion.

---

## 16. CLI interface

`clap` derive. Running `sverb` with no subcommand launches the TUI.

```
sverb                                 Launch TUI
sverb connect <host|user@host:port>   Launch TUI with a session open (fuzzy host match)
sverb --workspace <name>              Launch TUI and open a workspace
sverb join <share-link>               Join a shared terminal

sverb hosts list [--json] [--tag t] [--group g]
sverb hosts add <address> [--label] [--user] [--port] [--group] [--tag]...
sverb hosts rm <host>
sverb keys list | generate [--type ed25519] [--label] | import <file> | export <key> [--public]
sverb forward <rule> [--detach]       Run a port-forward rule headless
sverb snippet run <snippet> --on <host|#tag|group>... [--json]
sverb import ssh-config [path] | known-hosts [path] | putty | csv <file> | backup <file> [--dry-run]
sverb export backup <file> | ssh-config <file> | csv <file> | recording <id> <out.cast>
sverb approve <host>                  Review and approve locally-acting fields from sync (§17.1)

sverb agent [--socket <path>]         Run built-in agent exposing forwardable vault keys
sverb lock | unlock
sverb login [--server url] | logout | register
sverb sync [--now] [--status]
sverb devices list | revoke <id>
sverb team list | invite <email> | verify <user>
sverb team create <name> | accept <link>                     (spec addition, M5-01)
sverb config --check [--file f] | --print-default | --path
sverb keys --dump [--json]            Print effective keymap
sverb doctor [--algos] [--json] [--ascii]  Diagnose terminal capabilities, agent, sync; list SSH algorithms
```

Hidden commands (not in `--help`; spec additions): `sverb keymap` (alias of `keys --dump`) and
`sverb generate man [--out-dir d] | completions <bash|zsh|fish|powershell>` (M7-07, used by
packagers). Exit codes are stable: 0 ok, 1 failure,
2 usage, 3 vault locked, 4 not found or ambiguous, 5 approval required, 6 network or server,
7 partial failure. `--json` output is wrapped as `{"version":1,"data":…}` (`docs/cli-json.md`).

Environment (spec additions): `SVERB_HOME` (relocate every directory, §5.1), `SVERB_LOG`
(§18), `SVERB_KEYRING=off` (never use the OS keyring), `SVERB_EXPORT_PASSWORD` (backup
password for `export backup` / `import backup` in scripts, §9.13), `NO_COLOR` (§8.8).

Headless commands that need vault access prompt for the master password on the TTY, or use the
keyring. They exit non-zero with a clear message when the vault is locked and no TTY is
available.

---

## 17. Security model

Full detail goes in `docs/threat-model.md`. The summary:

| Threat | Mitigation |
|---|---|
| Server compromise / malicious operator | E2EE. The server holds only ciphertext and OPAQUE records, so it can't learn passwords. Key substitution is countered by TOFU pinning, safety numbers and signed grants (§13.3). |
| Stolen laptop, sverb not running | Vault encrypted at rest with Argon2id-derived KEK or the OS keyring. No plaintext on disk (`item_index` is TEMP). |
| Stolen laptop, sverb unlocked | Auto-lock, and the lock clears decrypted caches. OS disk encryption is recommended. |
| Memory scraping | `zeroize`/`secrecy`. Best-effort `mlock` of key material where supported. Core dumps disabled via `prctl(PR_SET_DUMPABLE, 0)` on Linux. |
| Secrets in logs | `tracing` fields for secret types are redacted by type (`Debug` prints `[REDACTED]`). A CI test greps log output for planted canary secrets. |
| MITM on SSH | Strict host-key verification. Changed keys are blocked by default. |
| Malicious remote output | Emulator-level: OSC 52 writes gated and OSC 52 **reads always denied**, no OSC that executes or opens anything without confirmation, title length capped at 256 chars, hyperlink opening requires a keypress and shows the URL, and query responses (DA/DSR) are generated by the emulator, never echoed from remote input. |
| Malicious synced item runs local code | See §17.1. |
| Recordings and logs on disk | Recordings are encrypted under an LMK-derived key (§7.5). `tracing` never logs hostnames, usernames or commands at `info` level or above. `debug` logs may contain hostnames, and `--debug` warns about this. |
| Agent-forwarding abuse | Per-key `agent_forwardable` (off by default), `confirm_on_use`, and refusal when locked. |
| Shared-terminal hijack | Key only in the URL fragment, host approval of each viewer, view mode by default, AEAD with sequence numbers. |
| Supply chain | `cargo-deny` (licenses, advisories, bans), `cargo-vet` for crypto deps, pinned `Cargo.lock`, reproducible release builds. |

The project avoids `unsafe` outside vetted dependencies: every sverb crate inherits the workspace
lint `unsafe_code = "deny"`. Exactly two documented modules lift it with `allow(unsafe_code)`:
process hardening (`sverb-core/src/hardening/`: `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit`,
`mlock`, and `SetErrorMode`/`VirtualLock` on Windows) and the Windows agent pipe DACL
(`sverb-conn/src/agent/dacl_windows.rs`). `deny` rather than `forbid` because `forbid` can't be
lifted by an inner `allow`; `scripts/check-unsafe.py` fails CI if `allow(unsafe_code)` appears
anywhere else (decisions log 2026-10-09).

### 17.1 Synced items that act locally

Most synced data only affects what's sent to remote hosts. Some fields, though, cause actions **on
the local machine**, and a teammate (or a compromised teammate account) could plant them in a
shared vault. These fields are:
- `proxy = Command(..)`, which runs a local process
- `Remote` port forwards whose `dest_host` isn't loopback, which expose the local network
- `Local`/`Dynamic` forwards binding non-loopback addresses
- `agent_forwarding = true` combined with `agent_source` including `system`

**Rule:** the first time a device is about to act on such a field, and whenever its value changes,
sverb shows the exact value ("This host runs a local command: `…`. Allow?") and records
`(item_id, field, sha256(value))` in a device-local allowlist. Values the user typed on this
device are pre-approved. Unapproved values are never acted on silently, and headless CLI
commands fail with an error pointing to `sverb approve <host>`.

---

## 18. Observability, errors and logging

- `tracing` with `tracing-subscriber` writes **to a file only** (stdout belongs to the TUI), at
  `~/.local/state/sverb/sverb.log`. The file rotates daily and 7 days are kept. The level comes
  from `SVERB_LOG` (`info` by default).
- `sverb --debug` turns on `debug` level plus a hidden in-TUI log pane (`leader D`).
- Errors use `thiserror` in libraries and `anyhow`/`color-eyre` at the binary edge. Every error
  shown in the UI has a short message and an expandable detail chain.
- A panic hook restores the terminal (leaves the alt screen, disables raw mode and mouse) before
  printing the panic, and writes a crash report to the state dir.
- The server emits structured JSON logs and Prometheus metrics (requests, latency, active WS
  connections, sync push/pull volume, share relays).

---

## 19. Testing strategy

| Layer | Approach |
|---|---|
| Crypto | Known-answer tests, round-trip property tests (`proptest`), AAD tamper tests, cross-version envelope fixtures |
| Merge/sync | Property tests: random concurrent edit sequences across N simulated devices converge to an identical state, with tombstone/resurrection cases. A concurrency test runs parallel pushers against Postgres while a puller asserts that it never misses a revision (§12.1). Another test kills a rotation mid-way and asserts recovery (§13.2). |
| Session state machine | Exhaustive transition table tests (§2.1.1) |
| Emulator integration | Recorded byte streams from vim, htop, tmux and less, replayed with an assertion on the final grid. Query-response tests (DA1, DSR) check that replies reach the transport. |
| Port forwarding | SOCKS5 conformance (domain, IPv4, IPv6, refused commands), half-close propagation, 256-channel cap |
| Settings resolution | Table tests over nested group chains |
| Importers | Fixture files (`tests/fixtures/ssh_config/*`) with `insta` snapshot of the parsed result |
| Terminal input encoding | Table tests for key → bytes across modes |
| TUI | ratatui `TestBackend` + `insta` snapshot tests of every view at 80×24 and 160×48. Reducer tests drive `App::handle` with scripted events. |
| Transports (e2e) | `testcontainers`: OpenSSH server (password, key, cert, keyboard-interactive, jump host chain, `MaxAuthTries 2`, legacy-only algorithm server for negative tests). Tests cover connect, PTY, resize, env, forwards L/R/D, agent forwarding (`ssh-add -l` on the remote lists forwarded keys) and exec timeouts. |
| Server | `sqlx::test` per-test DB, HTTP-level tests via `axum::Router` + `tower::ServiceExt`, plus multi-client sync scenarios against a real server |
| Fuzzing | `cargo-fuzz` targets: ssh_config parser, ppk parser, known_hosts parser, SOCKS5 request parser, share frame decoding, envelope decoding, key-event encoder |
| Performance | `criterion` benches: emulator throughput (target ≥ 100 MB/s parse), render frame time for a 300×100 grid (target < 2 ms) |

CI (GitHub Actions) runs fmt, clippy (`-D warnings`), tests on Linux/macOS/Windows, e2e on Linux,
cargo-deny and an MSRV check.

---

## 20. Packaging and distribution

- **Client:**
  - `cargo install sverb` (every library crate is published as `sverb-*`; `sverb-e2e` is not)
  - GitHub releases with prebuilt binaries for x86_64/aarch64 Linux (musl), macOS (universal) and
    Windows: `sverb-<v>-linux-{x86_64,aarch64}.tar.gz`, `sverb-<v>-macos-universal.tar.gz`,
    `sverb-<v>-windows-x86_64.zip`. Each archive holds the binary, `LICENSE`, `README.md`,
    `CHANGELOG.md`, the man page `man/sverb.1` and completions for bash, zsh, fish and PowerShell
    (generated by `sverb generate`).
  - AUR (`sverb`, `sverb-bin`), Homebrew tap (`<org>/homebrew-sverb`), Nix flake (`flake.nix`,
    packages `sverb` and `sverb-server`), Scoop (`<org>/scoop-sverb`, with `autoupdate`)
  - macOS binaries are signed and notarized when the signing secrets are configured; otherwise
    `docs/faq.md` documents the Gatekeeper workaround.
- **Server:** Docker image `ghcr.io/<org>/sverb-server:<v>` and `:latest` (linux/amd64 and
  linux/arm64, distroless, non-root, built from the release binaries), static binary releases
  `sverb-server-<v>-linux-{x86_64,aarch64}.tar.gz`, and a Helm chart (stretch goal, not in 1.0).
- **Checksums and builds:** every release has `SHA256SUMS` and a CycloneDX SBOM. Release builds
  are reproducible: `--locked`, `SOURCE_DATE_EPOCH` from the tagged commit, `-C strip=symbols`,
  `--remap-path-prefix` for the checkout and the cargo home, deterministic archives; CI builds the
  Linux musl binaries twice from different directories and compares them.
- **Versioning:** SemVer. The sync protocol is versioned separately (`/v1`), and the client sends
  `Sverb-Proto: 1`. The server supports N and N-1.
- Releases are made only by pushing a tag `vX.Y.Z` after bumping every crate's version together
  and adding the `CHANGELOG.md` section. The tag starts `cd.yml` (binaries, image, GitHub release,
  package channels). `docs/release.md` has the checklist, including the manual install test per
  channel.
- **License:** MIT for the whole repository. A single `LICENSE` file sits at the root, and every
  crate sets `license = "MIT"` in `Cargo.toml`. `cargo-deny` rejects dependencies with licenses
  that aren't compatible with MIT distribution of the binaries (for example GPL), with
  case-by-case exceptions for permissive and weak-copyleft licenses like MPL-2.0.

---

## 21. Milestones

Each milestone ends with a usable build.

| # | Name | Scope | Exit criteria |
|---|---|---|---|
| **M0** | Skeleton | Workspace, CI, config loading, logging, panic hook, empty TUI shell with sidebar/tabs/status bar, keymap + leader + which-key | `sverb` opens and quits cleanly. Snapshot tests run. |
| **M1** | Core terminal & SSH | Local storage + unlock (master password and keyring), Host CRUD, quick connect, local PTY tabs, `alacritty_terminal` rendering, input encoding, SSH (password/key/agent/kbd-interactive), known hosts + TOFU, reconnect, tabs, basic splits | vim, htop and tmux run correctly in a remote SSH session. Daily-driver for a single user. |
| **M2** | Organization & power features | Groups + inheritance, tags, identities, keychain (generate/import/export/install/certs), jump hosts, proxies, agent forwarding + built-in agent, port forwarding L/R/D + standalone, snippets (vars, paste, multi-host exec), per-host color schemes, `ssh_config`/known_hosts/CSV import, command palette | Usable for day-to-day work against a real fleet. |
| **M3** | Advanced sessions | Split layouts and resize, broadcast input, workspaces, copy mode + search, recording + replay, Logs view, connection multiplexing | E2e suite passes. Workspace of 8 panes reopens in under 3 s on LAN. |
| **M4** | Sync (personal) | `sverb-server` with OPAQUE auth, setup token, devices, vault/item API, WS notifications; client sync engine, outbox, merge, recovery key, backup export; local-only → synced upgrade and password flows (§11.2.1) | Two devices edit offline, reconnect and converge. A local-only vault with 500 items upgrades to synced without loss. Server DB contains no plaintext (verified by test). |
| **M5** | Teams | Orgs, invites, shared vaults, permissions, key wrap/sign, TOFU + safety numbers, rotation on revoke, credential overrides, audit log | 3-member org scenario passes, including revocation + rotation. |
| **M6** | Terminal sharing | Share relay, host approval, view/control modes, `sverb join` | Remote pair-debugging session works across NAT through the server. |
| **M7** | Polish | Autocomplete + history (OSC 133 integration), PuTTY/ppk import, `sverb doctor`, docs, packaging for all channels, accessibility pass | 1.0 release candidate |

---

## 22. Open questions

All four were resolved before 1.0; the answers are in the decisions log.

1. **List merge semantics.** Is whole-value LWW for `tags`/`env`/`jump_chain` good enough, or do
   we need OR-sets for `tags` in v1? `env` and `jump_chain` are ordered, so LWW is the right
   choice for them either way. **Resolved (2026-10-08):** whole-value LWW for every list in v1.
2. **`read_ssh_config` live mode.** Should `~/.ssh/config` hosts appear read-only in the Hosts list
   without importing, for people who manage SSH config via dotfiles? **Resolved (2026-10-09):**
   post-1.0; 1.0 imports only, and the config key warns.
3. **Web viewer** for shares. Is it in scope for M6 or post-1.0? **Resolved (2026-10-09):**
   post-1.0.
4. **Emulator choice.** Track `alacritty_terminal` API stability. If it churns too much, consider
   `wezterm-term` or vendoring. **Resolved (2026-10-09):** keep `alacritty_terminal` behind
   `sverb-term`; re-evaluate per release.

---

## Appendix A: dependency shortlist

| Area | Crates |
|---|---|
| TUI | `ratatui`, `crossterm`, `tui-textarea`, `nucleo` (fuzzy), `unicode-width` |
| Async/runtime | `tokio`, `tokio-util`, `futures`, `async-trait`, `bytes` |
| SSH | `russh`, `ssh-key`, `ssh-encoding`, `tokio-socks` |
| Terminal | `alacritty_terminal` (alt: `vt100`), `portable-pty`, `encoding_rs` |
| Storage | `rusqlite` (bundled), `rusqlite_migration`, `directories` |
| Serialization | `serde`, `serde_json`, `ciborium`, `toml`, `zstd`, `schemars` |
| Crypto | `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hpke`, `opaque-ke`, `x25519-dalek`, `ed25519-dalek`, `rand_core`, `zeroize`, `secrecy`, `bip39`, `zxcvbn` |
| OS integration | `keyring`, `arboard`, `notify`, `open` |
| IDs/time | `uuid` (v7), `time`, `uhlc` (HLC) |
| CLI/errors/logging | `clap`, `thiserror`, `anyhow`/`color-eyre`, `tracing`, `tracing-subscriber`, `tracing-appender` |
| Sync client | `reqwest` (rustls), `tokio-tungstenite` |
| Server | `axum`, `tower`, `tower-http`, `sqlx` (postgres), `governor`, `totp-rs`, `rustls`, `metrics`, `metrics-exporter-prometheus` |
| Testing | `insta`, `proptest`, `testcontainers`, `criterion`, `cargo-fuzz` |
| Recording | asciicast v2 writer (in-house, trivial) |

---

## Appendix B: spec additions made during implementation

Things the implementation needed that this spec did not name. Each was marked "spec addition"
in its task and is part of the 1.0 contract. Details are in the linked docs.

| Area | Addition | Where |
|---|---|---|
| Config | `ssh.auto_reconnect = false` (M1-16), `recording.retention_days = 0` (M3-06), `history.ghost_text = false` (M7-01), `ui.ascii = "auto"`, `ui.reduce_motion = false` (M7-07), the `[keys.copy]` table (M3-04) | §15, `docs/config.md` |
| Host / group defaults | `auto_reconnect: Option<bool>` (M1-16) and `record_sessions: Option<bool>` (M3-05), inheritable like the other settings | `docs/data-model.md` |
| HistoryEntry | `verified` (false for heuristic captures without OSC 133) (M7-01) | `docs/data-model.md` |
| ConnLog | optional `host_id`; `label`, `target`, `error_detail` (M3-06) | `docs/data-model.md` |
| Workspace | the `layout` / `broadcast_groups` encoding (M3-03) | `docs/data-model.md` |
| Backup file | items stored as `{ id, vault, body }`, vaults as `{ id, name, kind, defaults }`; the password from `SVERB_EXPORT_PASSWORD` in scripts (M2-11) | §9.13, `docs/data-model.md` |
| CredentialOverride | fields `shared_host_id`, `username`, `password`, `key_id`, `identity_id` (M5-02) | §13.4, `docs/data-model.md` |
| HTTP API | `GET /v1/orgs/{id}/members` (M5-01); `GET /v1/vaults/{id}/members`, `GET /v1/orgs/{id}/vaults` (M5-02); `POST /v1/account/password/start`, `/v1/account/recovery/code`, `/v1/account/recovery/start` (M4-02); error code `internal` | §10.4 |
| WebSocket | close codes `4403`, `4404`, `4408`, `4409`, `4410`, `4411`, `4429` (M4-05, M6-01) | §10.4 |
| CLI | `team create`, `team accept` (M5-01); `config --check --file`; `doctor --json --ascii` (M7-04); hidden `keymap` and `generate` (M7-07) | §16 |
| Environment | `SVERB_HOME`, `SVERB_KEYRING=off`, `SVERB_EXPORT_PASSWORD`; `SVERB_PANE` set in local shells (M1-12); `SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1` (development only, M1-13) | §16, README |
| Keys | Hosts view `A T D I X H V M C O` and group-row keys; Settings → Vaults keys (M2-01, M2-11, M5-02, M5-04, M7-01) | `docs/keybindings.md` "View keys" |
| Lints | `unsafe_code = "deny"` with two exception modules (M7-05) | §17 |
