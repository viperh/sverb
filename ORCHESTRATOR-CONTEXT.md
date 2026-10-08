# Orchestrator context (temporary — delete when the project is done)

Snapshot taken 2026-10-08 after the user said "stop all agents". UPDATE 2: the orchestrator now runs as background session bde93869 (forked from d8490e3c). The other claude session (pid 16563) was killed at the user's request. The old agent ids are no longer resumable, so FRESH agents were started to continue M2-09, M3-07 and M2-10 from disk state: M2-09 aca15c7fde616b550, M3-07 ae90081d3b0890198, M2-10 a35f572e8120fb097.
Previous transcript: /home/viperh/.claude/projects/-home-viperh/d8490e3c-b2b8-4a26-b3b2-b109e1a3029e.jsonl

## User decision (2026-10-08)
- "merge when everything is done. before last check all": hold M2-09 + M2-11 (+ M3-07/M2-10 copies) merges until running agents finish; then merge in order M2-09 -> M2-11 -> M3-07 -> M2-10; run a full workspace check/test before the final step.
- M2-09 finished (fresh agent aca15c7fde616b550): 16 copies await merge; its old panic and clippy warnings were already gone.

## Update (2026-10-08, later)
- M2-09, M2-11, M3-07 and M2-10 are MERGED (53/71). Clippy is clean. The full test rerun after `cargo clean` of the workspace crates is in .orch/test-all.log.
- Stale test binaries came from an agent scratch build into the repo target/ (baked CARGO_MANIFEST_DIR). Agents are now told to use their own CARGO_TARGET_DIR.
- Running: M2-12 a549628ee29372648, M3-02 af2d0cc462f7fa3aa, M4-07 a505d5f6c4d731e90, M7-01 ab54000b3522ad619, M7-03 a2006ef71f2caa60e.

## State at hand-off (2026-10-08)
- 61/71 merged, M7-02 DROPPED (AI fully removed from code, SPEC and tasks), 9 not started: M4-09, M5-01, M5-02, M5-04, M6-03, M7-04, M7-06, then M7-05 and M7-07 (each alone at the end).
- No agents running, no locks held, .merge/ empty.
- Final check (no agents running): `cargo test --workspace` gave 1635 passed and 2 failed, both fixed afterwards: docs/keybindings.md regenerated; team_verify tests moved to services/team_verify_tests.rs because of the no-I/O scan. Then `cargo test -p sverb-tui --features sync` gave 507 passed and 0 failed, and `cargo test -p sverb --no-default-features` gave 73 passed and 0 failed. Clippy is clean with and without sync. 48 tests are ignored (Docker/PostgreSQL/manual).
- Follow-ups are listed per task in tasks/04-PROGRESS.md (notably M4-09 must render the M4-08 wizards and wire SyncService/TrustedKeySource; M5-01 must add GET /v1/users/{id}/public-keys).

## Cloud session progress (2026-10-08)
- Working directly in the cloud session (no sub-agents, so no locks), branch `claude/focused-tesla-e5wwcs`, committing per task.
- M4-09, M7-06 and M5-01 DONE (see tasks/04-PROGRESS.md). Stopped here at the user's request; the rest is for another session.
- Next: M5-02, M5-04, M6-03, M7-04, then M7-05 and M7-07 (each alone at the end).
- Full suite (all features, PostgreSQL on): see the last commit message for the counts.
- A local PostgreSQL 16 can be started in the container (binaries in /usr/lib/postgresql/16/bin; run as a non-root user, e.g. `pgtest`, port 55432) and DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres runs the *_pg server tests.
- Disk is tight here: build with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`.
- Pushing to GitHub works (access fixed by the user).

## User decision: moving to a cloud session (2026-10-08)
- "wait until they are done then do not create new agents afterwards. merge the changes. and tell me. i will commit"
- So: let M7-01, M3-03, M7-02, M4-08 and M5-03 finish. Start NO new agents. Merge everything, report, and the USER commits (I don't).
- After that, the user continues in a cloud session from this file. Next tasks: M4-09, M7-06, then M5-01, M5-02, M5-04, M6-03, M7-04, M7-05 and M7-07.

## Project / setup
- Repo: `/home/viperh/Projects/sverb`, Rust ratatui SSH client. Spec in `SPEC.md`. Tasks in `tasks/`:
  - `00-README.md`: index and architecture decisions. Spec inconsistencies are in §4.
  - `01-DEPENDENCIES.md`: dependency graph, waves and file hotspots.
  - `02-AGENT-PROTOCOL.md`: the lock protocol.
  - `03-KEYBINDINGS.md`: leader `Ctrl-\`. Terminal mode consumes only the leader and mouse.
  - `04-PROGRESS.md`: status table, the source of truth for per-task notes.
  - 71 task files, `M0-01`…`M7-07`.
- Locks: `LOCKS.csv` (append-only), handled by `scripts/lock.sh check|acquire|mark|mine`.
- Merge helper: `scripts/merge-agent.sh <task>`. It releases the agent's rows and takes orchestrator locks. Per file:
  - no base, or base == current: copy;
  - otherwise patch base→copy, reporting CONFLICT and leaving `.rej` on failure.
- `scripts/check-layering.py` allows `sverb-conn`→`sverb-term` and `sverb-term`→`sverb-crypto`.
- After merging a task: build and test, release locks (`orchestrator` row), delete `.merge/agent-X`, update `04-PROGRESS.md`.
- `Cargo.lock` is derived: never lock or copy it, use `--offline`, and never run `cargo update`.

## User instructions (verbatim intent)
- "no commits yet". No git commits, and agents must not run state-changing git commands.
- "fan out agents" (parallel background agents per task).
- When all tasks are done and green, recheck all the tests. If they all pass (or on an API limit), shut down the machine. **Confirm with the user before powering off.**
- "no need to reboot, ignore the watchdog for now". The watchdog is not running. Don't touch `scripts/watchdog-poweroff.sh`, `.watchdog.log` or `.orchestrator-heartbeat`.
- "don't run the curl anymore". Never run the ntfy curl, including any "project done" notification.
- "version string placeholder is okay for now" (vergen `VERGEN_IDEMPOTENT_OUTPUT`, because there are no commits).
- Latest: "stop all agents. make a temp file to keep context" (this file).

## Rules passed to every agent
- No commits. No curl or network notifications. Never open real URLs.
- Never read the real `~/.ssh`, the real `SSH_AUTH_SOCK` or the OS keyring in tests (`SVERB_KEYRING=off`).
- No sudo or package installs. Don't touch the watchdog files. Loopback-only binds.
- Never rustfmt a `lib.rs`/`mod.rs`; use `rustfmt --edition 2024 --config skip_children=true <file>`.
- No sub-agents. Scope verification per crate.
- Scratch copies plus CARGO_TARGET_DIR go under ~/.cache/sverb-agent-<task>/ and must be deleted afterwards. NEVER put them in the repo target/ (stale binaries with wrong baked paths) and NEVER in /tmp (6.8 GB tmpfs; filling it gives SIGBUS in ld.lld/rustc and test binaries).

## Environment limits
- No PostgreSQL. Docker is denied. rustc 1.98.1 without rustup; MSRV 1.95.
- DB server tests print "SKIPPED (needs PostgreSQL)". Docker e2e tests are `#[ignore]` (`SVERB_E2E=1`).

## Status: 49/71 merged
- **Merged:**
  - M0-01…M0-11, M1-01…M1-18
  - M2-01…M2-08 (M2-07 applied in place, locks released)
  - M3-01, M3-04, M3-05, M3-06
  - M4-01…M4-06, M6-01, M6-02

### Stopped mid-work. Resume via SendMessage to the agent id, or restart fresh.

**M2-11 import/export: DONE, merge pending.**
- Agent id `af9867b5e11f554b0` (finished). Full report in the transcript; summary in `04-PROGRESS.md`.
- New files are in the tree but not compiled until the `sverb-core/src/lib.rs` copy is merged.
- 18 copies are in `.merge/agent-M2-11/` (`_base` checked equal to the tree after the M2-04/M2-05 merges). Many overlap files that M2-09 also copied or modified.
- Merge with `scripts/merge-agent.sh M2-11`, ideally after M2-09 has merged.

**M2-09 snippets: IN PROGRESS, killed** at "Now in-tree verification on the real workspace". Agent id `a62865bd51e413162`.
- Modified in place:
  - `sverb-conn/src/ssh/exec.rs`, `exec/snippets*.rs`, `ssh/testing.rs`
  - `sverb-core/src/lib.rs`, `snippet/*`
  - `sverb/src/cli/snippet_tests.rs`
  - `sverb-tui` `app/shell.rs`, `views/mod.rs`, `views/snippets/*`
- Copies in `.merge/agent-M2-09/`:
  - `cli/{mod,snippet,tests}.rs` and help snaps
  - `sverb-tui` `app/{effect,event,input,mod,snippets,snippets_tests}.rs`
  - `services/{mod,sessions,snippets,ssh}.rs`, `views/dialogs.rs`
- Known bug: `cli::tests::stubs_return_not_implemented` panics at `crates/sverb/src/cli/snippet.rs:79` ("can call blocking only when running on the multi-threaded runtime"). I told the agent before it was stopped.
- Clippy: type complexity in `exec/snippets.rs` and sort_by in `views/snippets/mod.rs`.

**M3-07 connection multiplexing: IN PROGRESS, killed** at "Now wire the modules from jump.rs (free, mine) so they compile live". Agent id `adc6ef3d9d49c4894`.
- Modified in place:
  - `sverb-conn` `forward/ssh_glue.rs`, `session/{event,state}.rs`, `ssh/jump.rs`
  - new `ssh/mux{,_loopback,_ssh,_tests}.rs`
  - `sverb-tui/src/widgets/session_info.rs`
- Copies in `.merge/agent-M3-07/` (no MERGE-NOTES.md yet): `sverb-conn/src/ssh/{mod,connect,channel,exec}.rs`, `sverb-tui/src/services/ssh.rs`.
- The workspace may not compile until it is finished.

**M2-10 local action approval: JUST STARTED, killed** at "Now write the migration and store module". Agent id `ae27528995c421dbd`.
- Created `crates/sverb-store/migrations/0002_local_approvals.sql`, `crates/sverb-store/src/approvals.rs`, and the symlink `migrations/client/0002_local_approvals.sql`.
- Holds `locked` rows on:
  - `sverb-core/src/resolve.rs` and `resolve/approval.rs`
  - `sverb-store/src/{lib,schema}.rs`
  - `sverb-store/tests/{approvals,store}.rs`
- Must unify the M2-06 `StampApprovals`, the M2-08 `ApprovalStore`, the M2-07 "agent_forwarding" approval (`sverb approve <host>`) and the M2-11 `ApprovalNote`s.

### Not started (deps in `tasks/01-DEPENDENCIES.md`)
- M2-12 (needs M2-09)
- M3-02 (M2-09), M3-03 (M3-02, M3-07)
- M4-07 (M2-10), M4-08, M4-09
- M5-01…M5-04, M6-03
- M7-01 (M2-09), M7-02, M7-03 (M2-11), M7-04, M7-06
- M7-05 (verification, alone), M7-07 (release, alone)

## Suggested resume order
1. Resume M2-09 and finish it. Merge M2-09, then M2-11 (expect hunks to hand-apply in `app/*`, `cli/*`, `services/mod.rs`, `views/dialogs.rs`, the help snaps; regenerate the help snapshots).
2. Resume M3-07 and M2-10.
3. Then start M2-12, M3-02, M7-01 and M7-03, followed by M4-07 and so on.

## Known issues / follow-ups
- **Load-sensitive tests** (pass alone, flake under build load):
  - sverb-crypto `kat.rs`/`account_kat.rs`/`fixtures.rs` file reads
  - `t06_no_lock_across_await_stress`, `loopback_passphrase_prompt`
  - server `t06_rate_limit_per_ip`
  - `sverb/tests/vault.rs::t16_terminal_wrong_password_exits_3`
  - **The final green run must be done with no agents running.**
- `t07_render_10k_rows_under_2ms` (20 ms debug / 2 ms release, best of 20): re-verify.
- **Doc warnings under `-D warnings`:** `quick_connect.rs`, `dialogs.rs`, `hosts.rs`, `confirm.rs`, `auth_prompt.rs`, `remote_io.rs`, `render.rs`, `scheme/mod.rs`, `agent/confirm.rs`.
- **Final `cargo fmt` pass needed.** cargo-vet store is broken (`cargo vet fmt` plus exemptions). cargo-deny has not been run.
- **Crate-local pins to move to the workspace:** zxcvbn, keyring, tokio-socks, open, the M2-03 crypto crates, idna, tempfile, csv, glob, async-trait.
- **M1-15:** ignored `e2e_openssh_t14_to_t17` still calls `unimplemented!`.
- **M2-05:** move the `jump` mod declaration out of the `connect.rs` `#[path]` into `ssh/mod.rs`. Exec (M2-04) still rejects jump chains; M3-07 should route it.
- **M2-07 gaps:**
  - no Windows DACL (T-14) and no Docker T-09;
  - no `agent.socket_in_tui`, no `unlock --agent`;
  - russh `remove_all_identities` framing bug worked around.
- **SPEC.md additions for M7-07:** `recording.retention_days`, `ssh.auto_reconnect`, `history.ghost_text`, `ai.base_url`, extra close codes, the backup item format (M2-11), `SVERB_EXPORT_PASSWORD`.
