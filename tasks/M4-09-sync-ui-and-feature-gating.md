# M4-09 — Sync UI, `sverb sync`/`devices` CLI, and local-only feature gating

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-tui/src/views/settings/{sync.rs, devices.rs}`, `widgets/{topbar.rs, statusbar.rs}`, `crates/sverb/src/cli/{account.rs (sync), devices.rs}`, `cfg(feature = "sync")` boundaries across `sverb-tui` |
| **Spec refs** | §1.1 (Sync/Team/Share UI hidden in local-only; "Not connected · Connect to a server"; no phoning home), §8.1 (top bar sync indicator), §12.5 (status), §16 (`sverb sync`, `sverb devices`) |
| **Depends on** | M4-08 |
| **Blocks** | M5, M6 UI |

---

## 1. Current state in the codebase
Sync works (M4-07/08). Feature gating exists at the crate level (M0-01), but the UI shows sync elements whenever the feature is compiled in.

## 2. Detailed description
- **Two kinds of "off":** (a) **compiled without `sync`**: no sync code, UI or commands at all (M0-07 handles the CLI). (b) **compiled with sync but local-only mode**
  (no `sync_state` row): the Sync, Team and Share UI is **hidden**, and Settings → Sync shows exactly **"Not connected · Connect to a server"** with a button leading to the
  M4-08 wizards (§1.1). The top-bar sync indicator and status-bar sync segment are hidden. Palette actions for teams and sharing are disabled (`is_enabled` false).
- **Synced mode:** the top bar shows `⟳ synced` / `syncing` / `offline (N pending)` / `error` (§8.1, §12.5) with color plus a text label. Clicking it, or the palette action
  "Sync status", opens a panel with server URL, account email, last successful sync time, pending count per vault, recent errors (with ErrorReport detail), and
  buttons "Sync now" and "Disconnect".
- **Devices** (Settings → Devices): the list from `/v1/devices` (name, platform, created, last seen, "this device") with revoke (confirm). Revoking this device = logout.
- **Clock skew warnings** (M1-02/M4-06): a toast once per device per session "Clock skew detected on device X".
- **No phoning home** (§1.1): no telemetry, update checks or default server URL. Add a test asserting that a local-only run makes **zero** network connections (see T-08).
- **CLI:** `sverb sync [--now] [--status]`: `--status` prints the state, pending counts and last sync (with `--json`). `--now` runs one push+pull cycle headlessly and exits
  (0 ok, 6 network error). No flags → `--status`. `sverb devices list [--json]` and `sverb devices revoke <id>`.

## 3. Codebase changes
- The views and widgets above. Add a single `SyncUi` facade in `sverb-tui` that returns `None` in local-only mode (or when compiled out), so call sites don't sprinkle
  `cfg` everywhere: one `cfg` boundary in the facade.

## 4. Test cases to implement

**T-01 (snapshot)** Local-only mode: the top bar has no sync indicator, and Settings → Sync shows "Not connected · Connect to a server".

**T-02 (snapshot)** Synced mode in each status state (synced, syncing, offline (3 pending), error).

**T-03 (reducer)** Team and share palette actions are disabled in local-only mode.

**T-04 (build)** `--no-default-features` build: no `sync` strings in the binary's help, and the full test suite passes (CI job from M0-02).

**T-05 (reducer)** The devices view revoke flow, with revoking the current device → logout path.

**T-06 (CLI)** `sync --status --json` snapshot. `sync --now` with the server down → exit 6.

**T-07 (CLI)** `devices list` against TestServer shows 2 devices after two logins. `revoke` works.

**T-08 (integration)** Local-only network silence: run the TUI (PTY) in local-only mode for 10 s, opening a local shell, under a network namespace or a
monitored `connect()` (Linux: `strace -f -e trace=connect` or a seccomp/LD_PRELOAD-free approach via `ss` before and after). There are zero outbound connections.

## 5. Passing functional characteristics
- [ ] In local-only mode, every Sync/Team/Share element is hidden and Settings → Sync offers "Not connected · Connect to a server".
- [ ] In synced mode the top and status bars show the sync state, with a details panel, sync now and disconnect.
- [ ] Devices can be listed and revoked in the TUI and CLI. `sverb sync --now/--status` works.
- [ ] The client never makes network connections except the user's SSH sessions and their configured server.
