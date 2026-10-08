# M3-03 — Workspaces

| | |
|---|---|
| **Milestone** | M3 (exit criterion: "Workspace of 8 panes reopens in under 3 s on LAN") |
| **Touches** | `crates/sverb-core/src/model/workspace.rs`, `crates/sverb-core/src/layout.rs` (serde), `crates/sverb-tui/src/views/workspaces.rs`, `crates/sverb/src/cli/mod.rs` (`--workspace`) |
| **Spec refs** | §9.9, §4.10, §8.4, §16 (`sverb --workspace <name>`) |
| **Depends on** | M3-02, M1-17, M3-07 (multiplexing helps the 3 s target) |
| **Blocks** | — |

---

## 1. Current state in the codebase
The layout tree in `sverb-core::layout` is serializable (M1-17). The `Workspace` typed view exists (M1-02). The `--workspace` flag is parsed (M0-07) but ignored.

## 2. Detailed description
- `Workspace { name, tabs: Vec<WorkspaceTab { title_override, layout: Layout<LeafRef>, broadcast: BroadcastSpec }>,
  broadcast_groups }`. Leaves reference `host_id` or `local` (with an optional cwd) (§4.10). Ephemeral quick-connect panes and share
  viewer panes are **not** saveable: they're omitted, with a warning listing them. The pane ratio and focused pane are preserved.
- **Save** (`Save workspace` action in the palette and the Settings → Workspaces view): captures every tab's layout tree, host references and broadcast sets
  (§9.9). Prompts for a name (unique per vault; same name → confirm overwrite). Stored as a synced item (§9.9) in the vault of… **Decision:** the
  personal vault by default. If all referenced hosts are in one shared vault, offer that vault.
- **Open** (`Open workspace`, a fuzzy picker, or `sverb --workspace <name>`): recreates the tabs (appended after the existing tabs, or replacing them if
  the only tab is empty) and connects every pane **in parallel with bounded concurrency** (default 8; this could be a config key, but use a constant
  for now). Missing hosts (deleted) → a placeholder pane "Host missing" with a close action. Auth prompts queue normally (M1-14).
- Workspaces view: list, rename, delete, duplicate, and a "Preview" detail showing the ASCII layout.
- The `--workspace` launch intent runs right after unlock (M0-07 `LaunchIntent::Workspace`). An unknown name → error toast plus a list of the available names.

## 3. Codebase changes
- Model, view and reducer actions. The open path uses `SessionManager` with a `Semaphore` for bounded concurrency.

## 4. Test cases to implement

**T-01 (unit)** Layout + leaves serialize to CBOR and back identically (property test over random layouts).

**T-02 (reducer)** Save with 2 tabs (a 2×2 split and a local pane) → a SaveItem with the expected structure. A quick-connect pane is omitted, with a warning.

**T-03 (reducer)** Open → tabs and panes recreated with the same ratios, and `OpenSession` effects for each leaf.

**T-04 (unit)** Bounded concurrency: 20 leaves → never more than 8 connecting at once (fake manager).

**T-05 (reducer)** A deleted host → a placeholder pane.

**T-06 (reducer)** Broadcast sets are restored, with custom sets mapped to new pane ids.

**T-07 (CLI/PTY)** `sverb --workspace dev` opens the workspace after unlock. An unknown name → toast.

**T-08 (e2e, perf)** A workspace of 8 panes against 4 containers (2 panes per host, with multiplexing on) reopens with all panes `Connected` in < 3 s
(M3 exit criterion; measured on CI, with the threshold relaxed to 6 s on CI runners and the result recorded).

## 5. Passing functional characteristics
- [ ] Workspaces save every tab's layout, host references and broadcast sets as synced items.
- [ ] Opening recreates the tabs and connects all panes in parallel with bounded concurrency. Missing hosts are handled gracefully.
- [ ] `sverb --workspace <name>` opens one at startup.
- [ ] An 8-pane workspace reopens in under 3 s on a LAN.
