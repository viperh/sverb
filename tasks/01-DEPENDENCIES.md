# Task dependency and file-conflict analysis

This file is the scheduling input for fanning out agents. It has three parts:
1. **Functional dependencies:** which task must be finished before another can start.
2. **Parallel waves:** sets of tasks that can run at the same time.
3. **File hotspots:** files that several tasks modify. These are where agents would collide, so the
   lock protocol (`02-AGENT-PROTOCOL.md`, `/LOCKS.csv`) matters most there.

---

## 1. Functional dependency graph

`A ← B` means B needs A finished. The source of truth is each task file's "Depends on" row. Edges below are
the normalized set used for scheduling, and they include a few implicit edges found during analysis (marked *).

| Task | Depends on |
|---|---|
| M0-01 | — |
| M0-02, M0-03, M0-08, M1-01, M1-09 | M0-01 |
| M0-04 | M0-03 |
| M0-05 | M0-03, M0-04 |
| M0-06 | M0-03 |
| M0-07 | M0-03, M0-04, M0-06 |
| M0-09 | M0-05, M0-08 |
| M0-10 | M0-06, M0-08 |
| M0-11 | M0-09, M0-10 |
| M1-02 | M1-01 |
| M1-03 | M1-01, M1-02, M0-03 |
| M1-04 | M1-03, M0-11, M0-07* (`require_unlocked` lives in the CLI) |
| M1-05 | M1-04 |
| M1-06 | M0-11, M1-05 |
| M1-07 | M1-04, M1-05, M1-06 |
| M1-08 | M0-09, M1-09* (`Emulator` trait) |
| M1-10 | M1-09, M0-11 |
| M1-11 | M1-09, M0-10, M1-08* (`SessionCmd::Key`) |
| M1-12 | M1-08 |
| M1-13 | M1-08, M1-07 |
| M1-14, M1-15 | M1-13, M1-06 |
| M1-16 | M1-13, M1-10* (banner in `TerminalPane`) |
| M1-17 | M1-10, M1-11, M1-12, M1-13 |
| M1-18 | M0-02, M1-13 (fixtures and Dockerfile can start right after M0-02) |
| M2-01 | M1-07 |
| M2-02 | M2-01 |
| M2-03 | M1-07, M1-14 |
| M2-04 | M1-14, M2-03 |
| M2-05 | M1-14, M1-15, M2-01 |
| M2-06 | M1-13 |
| M2-07 | M2-03, M1-14 |
| M2-08 | M1-13, M1-16 |
| M2-09 | M2-04, M1-11 |
| M2-10 | M2-06, M2-07, M2-08 |
| M2-11 | M2-01, M2-03, M2-08, M1-15 |
| M2-12 | M1-05, M0-10, M2-09 |
| M3-01 | M1-17 |
| M3-02 | M3-01, M1-11, M2-09 |
| M3-03 | M3-02, M1-17, M3-07 |
| M3-04 | M1-10, M1-11, M1-17* |
| M3-05 | M1-04, M1-10, M1-08 |
| M3-06 | M3-05 |
| M3-07 | M1-13, M2-04, M2-05, M2-08 |
| M4-01 | M0-02, M1-01 |
| M4-02 | M4-01, M1-01 |
| M4-03 | M1-01 |
| M4-04 | M4-02 |
| M4-05 | M4-04 |
| M4-06 | M1-02 |
| M4-07 | M4-04, M4-05, M4-06, M2-10, M1-03 |
| M4-08 | M4-02, M4-03, M4-07, M1-04 |
| M4-09 | M4-08 |
| M5-01 | M4-04, M4-09 |
| M5-02 | M5-01, M5-03 |
| M5-03 | M4-03, M4-07* (pins live in the client store and are used by sync) |
| M5-04 | M5-02, M5-03, M4-05 |
| M6-01 | M4-05 |
| M6-02 | M1-01, M4-03* (X25519 helpers) |
| M6-03 | M6-01, M6-02, M1-10, M2-12, M4-09* |
| M7-01 | M1-09, M1-10, M2-09 |
| M7-02 | DROPPED 2026-10-08 (no dependents) |
| M7-03 | M2-11, M2-03 |
| M7-04 | M1-13, M1-11, M4-09 |
| M7-06 | M1-09, M1-10, M1-05, M1-04, M3-03 |
| M7-05 | all others (verification pass) |
| M7-07 | all others including M7-05 |

**Most depended-on tasks** (the critical path runs through these, so prioritize them and give them the best agents):
M1-13 (11 dependents), M1-10 (9), M1-01 (8), M1-11 (8), M0-01 (7), M0-03 (7), M1-04 (7), M1-09 (7), M1-05 (6), M1-08 (6), M1-14 (6), M2-03 (6).

---

## 2. Parallel waves

Waves are the longest-path depth in the graph. All tasks in a wave are functionally independent of each other.
**Schedule dynamically:** a task can start as soon as *its own* dependencies are done. It doesn't have to wait for
the whole previous wave. The waves show the maximum parallelism available.

| Wave | Tasks | Notes |
|---|---|---|
| W0 | M0-01 | Must run **alone**: it restructures the workspace and every later task builds on it. |
| W1 | M0-02, M0-03, M0-08, M1-01, M1-09 | M1-01 and M1-09 are isolated new crates (low conflict). M0-03 and M0-08 both touch `crates/sverb/src/main.rs` and `config.rs`. |
| W2 | M0-04, M0-06, M1-02, M4-01, M4-03 | The server track (M4-01) and crypto track (M4-03) run in parallel with the client. M0-04 and M0-06 both edit `main.rs`. |
| W3 | M0-05, M0-07, M0-10, M1-03, M4-02, M4-06, M6-02 | M0-05/M0-07/M0-10 all touch the binary entry point and keymap/config: a **hotspot wave**. |
| W4 | M0-09, M4-04 | |
| W5 | M0-11, M1-08, M4-05 | |
| W6 | M1-04, M1-10, M1-11, M1-12, M6-01 | |
| W7 | M1-05, M3-05 | |
| W8 | M1-06, M3-06 | |
| W9 | M1-07 | Bottleneck: Hosts CRUD gates all SSH work. |
| W10 | M1-13, M2-01 | Bottleneck: SSH core gates most of M1/M2/M3. |
| W11 | M1-14, M1-15, M1-16, M1-17, M1-18, M2-02, M2-06 | Largest wave. 5 of these touch `sverb-conn/src/ssh/*`. |
| W12 | M2-03, M2-05, M2-08, M3-01, M3-04 | |
| W13 | M2-04, M2-07, M2-11 | |
| W14 | M2-09, M2-10, M3-07, M7-03 | |
| W15 | M2-12, M3-02, M4-07, M7-01 | |
| W16 | M3-03, M4-08, M5-03 | M7-02 dropped 2026-10-08 |
| W17 | M4-09, M7-06 | |
| W18 | M5-01, M6-03, M7-04 | |
| W19 | M5-02 | |
| W20 | M5-04 | |
| W21 | M7-05 | Verification pass. Run alone. |
| W22 | M7-07 | Release. Run alone. |

**Independent tracks** that can progress side by side for long stretches:
- **Client UI track:** M0-03 → M0-04/06 → M0-05/07/10 → M0-09 → M0-11 → M1-04 … M1-07.
- **Terminal track:** M1-09 → (M1-08 after M0-09) → M1-10/11/12.
- **Server track:** M4-01 → M4-02 → M4-04 → M4-05 → M6-01. This only needs M0-02 and M1-01, and never touches client crates (enforced by layering).
- **Crypto track:** M1-01 → M1-02 / M4-03 / M6-02 → M4-06.

---

## 3. File hotspots (shared modification points)

These files or modules are modified by several tasks. When two tasks that share a hotspot run at the same
time, the second agent **must** follow the copy protocol in `02-AGENT-PROTOCOL.md`. When possible, the
orchestrator avoids running such pairs together. The table lists who creates each file and who extends it later.

| File / module | Created by | Extended by | Conflict risk |
|---|---|---|---|
| `Cargo.toml` (workspace deps, lints) | M0-01 | almost every task (new deps), M7-05 (lint level) | **Very high**: every new dependency. Mitigation: M0-01 pre-pins all Appendix A crates, and agents add deps only in their crate's `Cargo.toml` with `workspace = true`. |
| `crates/*/Cargo.toml` (per crate) | M0-01 | every task in that crate | High within one crate |
| `crates/sverb/src/main.rs` | template | M0-03, M0-04, M0-05, M0-07, M0-08, M0-09 | **Very high in W1–W4** |
| `crates/sverb/src/config.rs` | template | M0-03 (paths removed), M0-06 (split up), M0-10 (keymap moved out) | High in W1–W3 |
| `crates/sverb/src/tui.rs` → `sverb-tui/src/runtime/*` | template | M0-05, M0-08 (move), M0-09, M1-11 (kitty), M7-04 (capabilities) | High |
| `crates/sverb/src/cli/mod.rs` | M0-07 | M1-07 (`connect`), M3-03 (`--workspace`), M6-03 (`join`), all `cli/*.rs` siblings | Medium (siblings are separate files) |
| `crates/sverb-core/src/lib.rs` (module declarations) | template | M0-03, M0-04, M0-05, M0-06, M1-02, M1-05, M2-01, M2-11, M4-06, M7-01, M7-05 | Medium: one-line additions, easy to merge |
| `crates/sverb-core/src/config/model.rs` + `default_config.toml` + `docs/config.schema.json` | M0-06 | M1-16 (`ssh.auto_reconnect`), M3-06 (`recording.retention_days`), M7-01 (`history.ghost_text`), M2-07 (`agent.socket_in_tui`), M3-04 (`[keys.copy]`), M7-07 (`ui.ascii`, `ui.reduce_motion`) | Medium: additive |
| `crates/sverb-core/src/model/*` (typed views) | M1-02 | M1-16 (`auto_reconnect`), M3-05 (`record_sessions`), M3-06 (`error_detail`), M7-01 (`verified`), M5-02 (`CredentialOverride`) | Medium |
| `crates/sverb-core/src/resolve.rs` | M1-13 (minimal) | M2-01 (full), M2-05 (chains), M5-02 (overrides) | **High**: M2-01 and M2-05 are only one wave apart |
| `crates/sverb-tui/src/app/{event,effect,state}.rs` (UiEvent, Effect, App) | M0-08 | nearly every UI task adds variants or state | **Very high**. Mitigation: add variants at the **end** of enums, in one block per task with a `// <task-id>` comment, so merges are mechanical. |
| `crates/sverb-tui/src/keymap/action.rs` (action registry) | M0-08/M0-10 | every task with a new action (M1-*, M2-12, M3-*, M6-03) | High: same mitigation (append-only blocks) |
| `crates/sverb-tui/src/services/sessions.rs` | M1-08 | M1-12, M1-13, M1-17, M3-07 | High |
| `crates/sverb-conn/src/ssh/connect.rs` | M1-13 | M1-14, M1-15, M2-05, M2-06, M2-07, M2-08, M3-06, M3-07 | **Very high in W11–W14** |
| `crates/sverb-conn/src/session/actor.rs` | M1-08 | M1-11, M1-16, M3-05 (recording tap), M6-03 (share tap) | Medium |
| `crates/sverb-tui/src/widgets/terminal_pane.rs` | M1-10 | M1-04 (lock overlay), M1-16 (banner), M3-02 (broadcast border), M3-04 (overlays), M6-03 (banner) | Medium |
| `crates/sverb-tui/src/views/hosts/form.rs` | M1-07 | M2-01, M2-02, M2-05, M2-06, M2-07, M2-08, M2-09, M3-05 | High |
| `crates/sverb-tui/src/views/sessions/*` | M1-17 | M3-01, M3-02, M3-04, M6-03, M7-01 | Medium |
| `migrations/client/*.sql` | M1-03 (`0001`) | M2-10 (`0002`), M5-03 (`0003`) | Low if numbers are reserved up front (they are, in the task files) |
| `migrations/server/*.sql` | M4-01 (`0001`) | M4-02 (`0002`) | Low |
| `crates/sverb-proto/src/*` | M4-01 | M4-02, M4-04, M4-05, M5-01, M6-01, M6-02 (one module per area) | Low |
| `.github/workflows/ci.yml` | template | M0-02, M1-18, M4-01, M7-05, M7-06 | Medium |
| `docs/data-model.md` | M1-02 | every "spec addition" note | Low (append sections) |
| `README.md` | template | M0-01, M0-03, M0-04, M0-06, M0-07, M1-07, M7-07 | Medium |

### Pairs to avoid running concurrently (unless a copy/merge is acceptable)
- M0-03 ∥ M0-08: both rewrite `main.rs` and the `config.rs` region.
- M0-04 ∥ M0-06: both edit `main.rs` and README.
- M0-05 ∥ M0-07 ∥ M0-10: `main.rs`, `cli/`, `config.rs` and the keymap.
- M2-01 ∥ M2-05: `resolve.rs`.
- M1-14 ∥ M1-15 ∥ M2-06: `ssh/connect.rs` (each needs a hook into the handshake).
- M2-05 ∥ M2-08 (W12) and M2-07 (W13): `ssh/connect.rs`.

Where these pairs run anyway (to save wall-clock time), the second agent works in a copy and the orchestrator
merges. Because the hotspot edits are mostly **additive** (new enum variants, new match arms, new module
declarations, new config keys), those merges are expected to be mechanical.
