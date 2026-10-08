# sverb — task breakdown

These tasks turn the current repository (`~/Projects/sverb`, which is the ratatui async template
renamed to `sverb`) into the product described in `SPEC.md` (Draft v0.3, kept at
`~/Work/sverb/SPEC.md`; copy it to the repo root as part of M0-01).

Every task file has the same sections:

1. **Header table:** milestone, crates/files touched, spec references, dependencies.
2. **Current state in the codebase:** what exists today, with `file:line` references, and what is
   wrong or missing relative to the spec. (Later-milestone tasks describe the code that will exist
   once their dependencies are done.)
3. **Detailed description:** target behavior, design, data shapes (described, not coded), edge
   cases, and out-of-scope items.
4. **Codebase changes:** files and modules to create, modify, move or delete.
5. **Test cases to implement:** numbered, typed (unit / property / integration / snapshot / e2e /
   CLI), each with setup, action and expected result.
6. **Passing functional characteristics:** the acceptance checklist. The task is done when every
   box can be ticked and CI is green.
7. **Notes, risks and spec questions.**

No task contains implementation code. Names of types and functions are given so tasks stay
consistent with each other.

---

## 1. Audit of the current codebase (as of 2026-10-07)

The repository has **no commits yet** (`git status` shows everything untracked on `master`).

| Area | Current state | Gap vs SPEC |
|---|---|---|
| Workspace (`Cargo.toml`) | `members = ["crates/*"]`, two crates: `crates/sverb` (bin) and `crates/sverb-core` (lib). Edition 2024, MSRV 1.85, MIT. Release profile `opt-level = "s"`, `lto = true`. | Spec §3 needs 9 library crates + binary. No `[workspace.lints]`, no `forbid(unsafe_code)`, no feature flags (`sync`). |
| Binary architecture (`crates/sverb/src/app.rs`, `components.rs`, `action.rs`) | Template "Component" architecture: `Vec<Box<dyn Component>>`, components push `Action`s into an unbounded `mpsc` channel, the App drains it, and every component sees every action. | Spec §2.1 requires a pure reducer `App::handle(event) -> Vec<Effect>`, effect executor, testable without a terminal. |
| Event loop (`crates/sverb/src/tui.rs`) | Separate task emits `Tick` (4 Hz) and `Render` (60 Hz) unconditionally, plus crossterm events, over an unbounded channel. One event is handled per loop iteration. `Drop` calls `exit().unwrap()`. `stop()` busy-waits with `std::thread::sleep` inside async code. Mouse and bracketed paste off. | Spec §2.1: dirty-driven rendering capped at 60 fps, `MissedTickBehavior::Skip`, input drained before draw, no tick-driven logic. Bracketed paste and mouse on by default. |
| Keybindings (`crates/sverb/src/config.rs:130-323`, `.config/config.json`) | JSON5 keymap keyed by `Mode` → `"<ctrl-a>"` sequences → `Action` variant names. Multi-key sequences are buffered in `last_tick_key_events` and cleared on every 250 ms tick. Parse errors `unwrap()` (panic). `key_event_to_string` renders F-keys as `f(5)`, which the parser can't read back. | Spec §8.2–8.3: leader key (spec says `ctrl-g`; changed to `ctrl-\` by `03-KEYBINDINGS.md`), Terminal/Normal/Copy/Insert modes, which-key popup, `[keys.terminal]`/`[keys.normal]` tables in TOML, named actions (`split_horizontal`), `sverb keys --dump`. |
| Config (`crates/sverb/src/config.rs:13-128`) | `config` crate layering json5/json/yaml/toml/ini from the config dir over an embedded `.config/config.json`. Only `data_dir`, `config_dir`, `keybindings`, `styles`. `to_str().unwrap()` on paths. Logs an **error** when no config file exists. | Spec §15: one TOML file, fully typed with defaults, `deny_unknown_fields`, validation, hot reload, `--check/--print-default/--path`, JSON schema. Must live in `sverb-core` (UI-agnostic). |
| Paths (`config.rs:40-128`, `.envrc`) | `ProjectDirs::from("me", "viperh", "sverb")`, env overrides `SVERB_CONFIG` / `SVERB_DATA`. On macOS this gives `~/Library/Application Support/me.viperh.sverb`, on Windows `%LOCALAPPDATA%\viperh\sverb\…`. | Spec §5.1 paths (`…/Application Support/sverb/`, `%APPDATA%\sverb\`), a separate **state** dir and **runtime** dir, and a single `SVERB_HOME` override. |
| Logging (`crates/sverb/src/logging.rs`) | `File::create` truncates `<data dir>/sverb.log` on every start. Env `SVERB_LOG_LEVEL` or `RUST_LOG`. | Spec §18: state dir, daily rotation, 7 files kept, `SVERB_LOG`, `--debug` ring buffer + log pane, secret redaction. |
| Panic handling (`crates/sverb/src/errors.rs`) | color-eyre + human-panic (release) + better-panic (debug). The hook builds a **new** `Tui` (which calls `tokio::spawn` in `Tui::new`, which panics outside a runtime) to restore the terminal, then `process::exit(1)` without flushing logs. | Spec §18: always restore terminal (incl. kitty flags, mouse, paste), crash report in the state dir with filtered logs, no secrets. |
| CLI (`crates/sverb/src/cli.rs`) | `--tick-rate`, `--frame-rate`, `--version` (prints dirs). | Spec §16: full subcommand tree. |
| Domain (`crates/sverb-core/src/lib.rs`) | Placeholder `Core { ticks }`. | Everything in §4–§13. |
| CI (`.github/workflows/ci.yml`) | Ubuntu only: test, fmt, clippy, docs. | Spec §19: Linux/macOS/Windows, e2e, cargo-deny, MSRV, plus the local-only build check (§1.1). |
| CD (`.github/workflows/cd.yml`) | Tag-triggered build of gnu/i686/macOS x86+arm/Windows tarballs. | Spec §20: musl Linux, macOS universal, server Docker image, release-plz, package channels. |
| README | Describes the template. | Must describe sverb. |

Useful pieces to **keep**: the workspace dependency-pinning pattern, the `sverb-core`
must-not-depend-on-UI rule (already stated in `crates/sverb-core/Cargo.toml:11-12` and README),
`vergen-gix` version stamping (`crates/sverb/build.rs`), the CI `--locked` discipline, the
docs job with `-D warnings`, and the key-chord parsing tests in `config.rs:454-603` as a starting
point for the new keymap parser.

---

## 2. Target architecture (decisions all tasks follow)

### 2.1 Crate layout
The `crates/*` glob in the workspace stays. New crates are added next to the existing two:

```
crates/
  sverb/          BINARY (package name `sverb`, required for `cargo install sverb`)
                  main.rs, cli/ (clap tree + one module per subcommand group),
                  panic.rs (was errors.rs), logging.rs, build.rs
  sverb-tui/      ratatui app: app/ (reducer, Effect, UiEvent), runtime/ (event loop,
                  terminal guard — was tui.rs), views/ (was components/), widgets/,
                  keymap/, theme/, services/ (effect executor)
  sverb-core/     config/, paths, secret, error_report, model/ (ItemBody, Host, …),
                  hlc, resolve, validation, importers/, search
  sverb-crypto/   no I/O
  sverb-proto/    serde DTOs
  sverb-store/    rusqlite
  sverb-conn/     russh, pty, forwarding, agent
  sverb-term/     emulator wrapper, key encoding, recording
  sverb-sync/     optional (feature `sync`)
  sverb-server/   axum backend (lib + bin `sverb-server`)
  sverb-e2e/      publish = false, docker-based tests (spec §3 `tests/e2e`)
migrations/{client,server}/   deploy/   docs/   tests/fixtures/
```

**Deviation from SPEC §3:** the spec puts the binary at `bin/sverb/`. The existing binary is at
`crates/sverb/`, so we keep it there. That avoids churn, and the `crates/*` glob already picks it up.
M0-01 updates SPEC §3 to match.

### 2.2 Runtime architecture
- The template's `Component` trait and `Action` channel are **replaced** (M0-08) by:
  - `UiEvent`: everything that can happen (terminal input, session events, effect results,
    timers, config reload, sync notifications).
  - `App::handle(&mut self, UiEvent) -> Vec<Effect>`: pure and synchronous.
  - `Effect`: side-effect requests executed by `Services` in `sverb-tui/src/services/`, whose
    results return as `UiEvent`s.
  - `View` trait (successor to `Component`): `handle(&mut self, &ViewEvent, &mut Ctx) -> Vec<Effect>`
    and an **infallible** `render(&self, &mut Frame, Rect, &RenderCtx)`.
- `Action` (`crates/sverb/src/action.rs`) is renamed into the **keymap action registry**
  (`sverb-tui/src/keymap/action.rs`): user-bindable named commands only (`palette`,
  `split_horizontal`, …), with no `Tick`/`Render`/`Resize`.

### 2.3 Conventions
- `#![forbid(unsafe_code)]` everywhere, except the documented `mlock`/`prctl` module (M7-05).
- Libraries use `thiserror`. The binary uses `color-eyre`.
- No `unwrap()`/`expect()` outside tests and provably infallible spots (with a comment).
- Each crate keeps unit tests in-module and integration tests in `tests/`.
- Snapshot tests use `insta`. Property tests use `proptest`.
- `SVERB_HOME` is set to a temp dir in every test that touches the filesystem.

---

## 3. Task index

### M0 — Skeleton (refactor the template into the sverb foundation)
| ID | Title | Depends on |
|---|---|---|
| [M0-01](M0-01-workspace-restructure.md) | Workspace restructure, lints, crate skeletons | — |
| [M0-02](M0-02-ci-hardening.md) | CI hardening (3 OS, deny, vet, MSRV, local-only, layering) | M0-01 |
| [M0-03](M0-03-paths-and-sverb-home.md) | Platform paths and `SVERB_HOME` | M0-01 |
| [M0-04](M0-04-logging-and-redaction.md) | Logging rewrite, rotation, secret redaction | M0-03 |
| [M0-05](M0-05-panic-hook-and-terminal-guard.md) | Panic hook, terminal guard, crash reports | M0-04 |
| [M0-06](M0-06-configuration-toml.md) | `config.toml` model replacing the `config` crate | M0-03 |
| [M0-07](M0-07-cli-surface.md) | Full clap CLI surface | M0-06 |
| [M0-08](M0-08-reducer-architecture.md) | Replace Component/Action with reducer + effects | M0-01 |
| [M0-09](M0-09-event-loop-and-render-scheduling.md) | Event loop and dirty-driven rendering | M0-08, M0-05 |
| [M0-10](M0-10-keymap-leader-modes.md) | Keymap, leader key, modes, which-key | M0-06, M0-08 |
| [M0-11](M0-11-tui-shell-layout-themes.md) | TUI shell layout, UI themes, toasts, log pane | M0-09, M0-10 |

### M1 — Core terminal and SSH
| ID | Title | Depends on |
|---|---|---|
| [M1-01](M1-01-crypto-primitives.md) | `sverb-crypto` primitives and canonical encodings | M0-01 |
| [M1-02](M1-02-item-model-and-hlc.md) | Item model, `Stamped` fields, HLC | M1-01 |
| [M1-03](M1-03-sqlite-store.md) | `sverb-store` SQLite schema and migrations | M1-02 |
| [M1-04](M1-04-vault-unlock-autolock.md) | LMK, master password, keyring, auto-lock | M1-03 |
| [M1-05](M1-05-search-index.md) | In-memory decrypted index and fuzzy search | M1-04 |
| [M1-06](M1-06-list-form-components.md) | Shared list view, forms, modal dialogs | M0-11 |
| [M1-07](M1-07-hosts-crud-quick-connect.md) | Host model, validation, Hosts view, quick connect | M1-05, M1-06 |
| [M1-08](M1-08-session-actor-state-machine.md) | Session actor, state machine, dirty coalescing | M0-09 |
| [M1-09](M1-09-emulator-wrapper.md) | `sverb-term` emulator wrapper | M0-01 |
| [M1-10](M1-10-terminal-pane-and-color-schemes.md) | TerminalPane rendering and color schemes | M1-09, M0-11 |
| [M1-11](M1-11-input-encoding.md) | Key/mouse/paste encoding and clipboard | M1-09, M0-10 |
| [M1-12](M1-12-local-pty.md) | Local PTY transport | M1-08 |
| [M1-13](M1-13-ssh-transport-core.md) | SSH connection flow, keepalive, algorithms, errors | M1-08 |
| [M1-14](M1-14-ssh-authentication.md) | SSH authentication chain and prompts | M1-13 |
| [M1-15](M1-15-known-hosts.md) | Known hosts and host-key verification | M1-13 |
| [M1-16](M1-16-reconnect.md) | Disconnect banner and auto-reconnect | M1-13 |
| [M1-17](M1-17-tabs-and-panes.md) | Tabs, layout tree, basic splits | M1-10 |
| [M1-18](M1-18-e2e-harness.md) | Docker/testcontainers e2e harness | M1-13 |

### M2 — Organization and power features
| ID | Title | Depends on |
|---|---|---|
| [M2-01](M2-01-groups-tags-resolution.md) | Groups, tags, settings resolution with provenance | M1-07 |
| [M2-02](M2-02-identities.md) | Identities | M2-01 |
| [M2-03](M2-03-keychain.md) | Keychain: generate, import, export, certificates | M1-07 |
| [M2-04](M2-04-exec-and-install-key.md) | Exec channels and install-key-on-host | M1-14, M2-03 |
| [M2-05](M2-05-jump-hosts.md) | Jump hosts | M1-14, M2-01 |
| [M2-06](M2-06-proxies.md) | SOCKS5, HTTP CONNECT, ProxyCommand | M1-13 |
| [M2-07](M2-07-agent.md) | Agent forwarding and built-in agent | M2-03 |
| [M2-08](M2-08-port-forwarding.md) | Port forwarding L/R/D, standalone, CLI | M1-13 |
| [M2-09](M2-09-snippets.md) | Snippets, variables, run modes, multi-host exec | M2-04 |
| [M2-10](M2-10-local-action-approval.md) | Approval of synced items that act locally | M2-06, M2-08 |
| [M2-11](M2-11-import-export.md) | ssh_config, known_hosts, CSV, backup import/export | M2-01, M2-03 |
| [M2-12](M2-12-command-palette.md) | Command palette | M1-05, M0-10 |

### M3 — Advanced sessions
| ID | Title | Depends on |
|---|---|---|
| [M3-01](M3-01-split-resize-zoom.md) | Split resize, zoom, tab rename/reorder | M1-17 |
| [M3-02](M3-02-broadcast-input.md) | Broadcast input | M3-01, M1-11 |
| [M3-03](M3-03-workspaces.md) | Workspaces | M3-02 |
| [M3-04](M3-04-copy-mode-search.md) | Copy mode, selection, scrollback search | M1-10 |
| [M3-05](M3-05-recording-replay.md) | Encrypted recording and replay | M1-04, M1-10 |
| [M3-06](M3-06-logs-view.md) | ConnLog and Logs view | M3-05 |
| [M3-07](M3-07-connection-multiplexing.md) | Connection sharing | M1-13 |

### M4 — Personal sync
| ID | Title | Depends on |
|---|---|---|
| [M4-01](M4-01-server-skeleton-ops.md) | `sverb-server` skeleton, config, admin CLI, deploy | M0-02 |
| [M4-02](M4-02-server-auth-tokens-devices.md) | OPAQUE auth, tokens, devices, TOTP | M4-01, M1-01 |
| [M4-03](M4-03-account-and-vault-keys.md) | Account key hierarchy, recovery key, vault-key grants | M1-01 |
| [M4-04](M4-04-server-sync-api.md) | Vault/item push-pull API, GC, limits | M4-02 |
| [M4-05](M4-05-websocket-notifications.md) | WebSocket notifications and LISTEN/NOTIFY | M4-04 |
| [M4-06](M4-06-merge-engine.md) | Field-level merge, tombstones, clock skew | M1-02 |
| [M4-07](M4-07-client-sync-engine.md) | Client sync engine | M4-04, M4-06 |
| [M4-08](M4-08-account-flows.md) | Register/login/password/recovery/logout flows | M4-03, M4-07 |
| [M4-09](M4-09-sync-ui-and-feature-gating.md) | Sync UI, status, devices, feature gating | M4-08 |

### M5 — Teams
| ID | Title | Depends on |
|---|---|---|
| [M5-01](M5-01-orgs-invites-audit.md) | Orgs, invites, roles, audit log | M4-04 |
| [M5-02](M5-02-shared-vaults.md) | Shared vaults, grants, permissions, credential overrides | M5-01, M5-03 |
| [M5-03](M5-03-public-key-trust.md) | TOFU pinning, safety numbers, grant signatures | M4-03 |
| [M5-04](M5-04-key-rotation.md) | Vault key rotation on revoke | M5-02 |

### M6 — Terminal sharing
| ID | Title | Depends on |
|---|---|---|
| [M6-01](M6-01-share-relay-server.md) | Share relay on the server | M4-05 |
| [M6-02](M6-02-share-crypto-frames.md) | Share handshake, channel keys, frames | M1-01 |
| [M6-03](M6-03-share-client.md) | Host/viewer UX, snapshot, control, `sverb join` | M6-01, M6-02, M1-10 |

### M7 — Polish
| ID | Title | Depends on |
|---|---|---|
| [M7-01](M7-01-autocomplete-history.md) | OSC 133, history, autocomplete overlay | M1-10 |
| [M7-02](M7-02-ai-assistant.md) | ~~Optional AI assistant~~ **DROPPED 2026-10-08** (user decision; see the task file) | — |
| [M7-03](M7-03-putty-import.md) | PuTTY sessions and `.ppk` import | M2-11 |
| [M7-04](M7-04-doctor.md) | `sverb doctor` | M1-13 |
| [M7-05](M7-05-security-hardening-fuzzing.md) | Hardening, canary tests, fuzzing | all |
| [M7-06](M7-06-performance.md) | Benchmarks and performance targets | M1-10 |
| [M7-07](M7-07-packaging-docs-accessibility.md) | Packaging, release, docs, accessibility | all |

---

## 4. Spec inconsistencies found while writing these tasks
Raise these with the spec owner. Each is also noted in the relevant task.
1. §8.2 says the which-key popup appears "after the leader … 1.5 s", while §15 sets
   `which_key_delay_ms = 400` (M0-10).
2. §6.1.1 says "Total attempts are capped at 5", but §15 has a configurable `max_auth_attempts` (M1-14).
3. §16 overloads `sverb keys` for SSH keys **and** `--dump` of key*bindings* (M0-07).
4. §10.6 lists admin commands without `admin invite <email>`, which the bootstrap paragraph uses (M4-01).
5. Several keybindings used in the text are missing from the §8.3 table: `leader S` (share),
   `leader D` (log pane), `leader B` (mark broadcast pane), `leader ,`/`<`/`>`
   (tabs), `leader !` (notification history) (M0-10).
6. §3 says `bin/sverb`, but the repo keeps `crates/sverb` (this README §2.1).
7. §5.3 "Five consecutive failures add an increasing delay (1 s, 2 s, 4 s …)": does the delay start
   *after* the 5th failure or apply from the 1st? (M1-04)
8. Keybindings: `leader h`, `leader l` and `leader L` each have two meanings in §8.1/§8.3, and the default leader `Ctrl-g` collides with
   Emacs and readline. Resolved in `03-KEYBINDINGS.md` (new default leader `Ctrl-\`, `t` local tab, `v` views, `Ctrl-l` lock).
9. Several tasks add config keys or fields the spec implies but doesn't name (`ssh.auto_reconnect`,
   `recording.retention_days`, `history.ghost_text`, …). Each is marked "spec addition" in its
   task and must be recorded in SPEC.md before 1.0 (M7-07 §2.7).

See also `01-DEPENDENCIES.md` (scheduling and file hotspots), `02-AGENT-PROTOCOL.md` (rules for parallel agents) and
`03-KEYBINDINGS.md` (authoritative keybinding plan and SSH pass-through audit).
