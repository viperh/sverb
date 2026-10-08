# Orchestration progress

Status per task: `todo` · `running` · `merged` (done, copies merged, build and tests green).
Updated by the orchestrator after every merge.

| Task | Status | Notes |
|---|---|---|
| M0-01 | merged | no copies; MSRV 1.95 |
| M0-02 | merged | no copies; T-01/T-07/T-08 need GitHub plus a first commit |
| M0-03 | merged | 12 copies merged; sverb, sverb-core, sverb-e2e tests green |
| M0-08 | merged | no copies. Interim keymap still binds ctrl-c/ctrl-d/ctrl-h (M0-10 removes them per 03-KEYBINDINGS); strum unused in crates/sverb |
| M1-01 | merged | crypto tests green; rand_core 0.10 + chacha20 rng; share labels guessed (M6-02 to confirm) |
| M1-09 | merged | no copies; vte 0.15 split-UTF-8 workaround; throughput ~99 MiB/s (M7-06 gate) |
| M0-04 | merged | merged jointly with M0-06 (main.rs conflict resolved by hand). Follow-ups: vet exemptions for new crates |
| M0-06 | merged | `.config/` deleted; ConfigWatcher not spawned yet (M0-07/M0-09) |
| M1-02 | merged | wired via M0-07; idna direct dep; open Qs: Unknown item kind, zeroize body secrets |
| M4-01 | merged | uses sqlx-core/sqlx-postgres (rusqlite links conflict); 5 DB tests SKIP without Postgres; vet exemptions pending |
| M4-03 | merged | bip39 workspace dep merged; OPAQUE suite left to M4-02; wrapped-key wire format `len||enc||len||ct` (confirm in M4-02/M5-03) |
| M0-05 | merged | test-hooks merged with M0-10. Open: panic msg not redacted; session panics vs hook (M1-08) |
| M0-07 | merged | no copies; keys --dump stub awaits M0-10; T-08 integration awaits M1-04 |
| M0-10 | merged | first-run leader notice needs UiEvent::Meta from store (M1-04); most leader actions toast until their tasks land |
| M6-02 | merged | wiring applied by M4-01 |
| M1-03 | merged | no copies; read-only marks in memory (M1-04 must set on unlock); tempfile direct dev-dep; migrations/client is a symlink |
| M4-06 | merged | no copies; open Q: distinguish remote restore vs resurrection toast (M4-07) |
| M0-09 | merged | no copies; frame 1/60 s; session seam placeholder in runtime/sessions.rs for M1-08; Windows paths uncompiled |
| M4-02 | merged | no copies; PG store compiled only (16 PG twins SKIP w/o DB); recovery flow design needs spec confirmation; vet exemptions pending |
| M0-11 | merged | runtime copy merged (patch fuzz 2); color downsampling in sverb-term::color; debug_ring() accessor |
| M1-08 | merged | UiEvent::Session wiring merged; hop-advance semantics question for M1-13 |
| M4-04 | merged | no copies; PG SQL unrun; body limit 12 MiB; shared-vault quota owner open (M5); possible delete_account vs push deadlock (M5); http t06 rate-limit test flaky under load |
| M1-11 | merged | copies merged after base64 + re-export landed; arboard unavailable offline -> CLI clipboard tools; mouse hit-testing waits M1-17 |
| M1-12 | merged | no copies; Windows test not run; Exited overlay generic for all transports (M1-16 may split); terminal.term not hot-reloaded |
| M1-04 | merged | TUI starts locked; SVERB_KEYRING=off for tests; zbus suspend not impl; Settings change-password entry later; zxcvbn/keyring crate-local pins |
| M1-10 | merged | runtime copy patched over M1-11; render 300x100 ~0.3 ms; themes not hot-reloaded; import CLI/Settings entry not done; pane titles hook App::set_pane_title |
| M4-05 | merged | no copies; PG fan-out twin SKIP; close code 4408 for ping timeout; layering script fixed (conn->term) |
| M6-01 | merged | no copies; extra close codes 4403/4404/4409/4411; share sockets check token at connect only; multi-replica DELETE limitation documented |
| M1-05 | merged | no copies; build 10k 56 ms, query 1.3 ms; index_upsert/remove must be called by M1-07/M4-07 writers; vault display names placeholder |
| M3-05 | merged | no copies; conn_id should be ConnLog id (M3-06); header TERM hard-coded; SSH auto_record hook for M1-07/M1-13; layering script updated (term->crypto) |
| M1-06 | merged | no copies; ratatui-textarea 0.9.2 instead of tui-textarea; Form returns FormRequest::Save (M1-07 builds effect); old dialogs not migrated |
| M3-06 | merged | copies merged clean (full re-test pending M1-07 WIP compile); Logs view uses own table (switch to ListView later); M1-13 must fill host_id in Attempt::from_spec; add recording.retention_days to SPEC §15 |
| M1-07 | merged | no copies; item service in services/vault/items.rs; fixed ListView set_rows panic; split connect/move/tag toast until M1-17/M2-01; hosts rm needs --yes w/o TTY |
| M1-13 | merged | no copies; in-process russh test server; host keys rejected until M1-15 (SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1 override); auth stub until M1-14; SshTarget in sverb-conn; vet exemptions for russh pending |
| M2-01 | merged | no copies; resolve(host, lookup, vault_defaults, config); vault defaults = group item flag; no Settings view yet (T/D keys in Hosts); FLAKY: widgets t07 2ms timing under load |
| M2-02 | merged | copies merged after M1-17 |
| M1-14 | merged | 3 hunks hand-applied (mod/dialogs/form); Key file field hidden in identity mode; Docker T-11..17 ignored |
| M1-15 | merged | 7 files resolved by the M1-15 agent post-merge; keys saved to Personal vault; global policy only |
| M1-16 | merged | no copies; countdown in UI (DialogTick ids) not actor; backoff at session::actor::backoff; reconnect countdown test fixed (jitter-tolerant assertion) |
| M1-17 | merged | no copies; PaneId == SessionId; rename/reorder/zoom left to M3-01 |
| M2-08 | merged | copies clean; ssh_glue in forward/ (russh outside ssh/); --detach via process_group; MemoryApprovals stub for M2-10 |

## Stopped: usage limit reached (resolved 2026-10-08 09:4x — M1-14, M1-15, M1-17, M2-08 resumed from saved transcripts; watchdog not restarted per user)
- Agents in flight when stopped (their partial edits are in the tree; see their non-released rows in LOCKS.csv):
  M1-14 (SSH auth), M1-15 (known hosts), M1-17 (tabs/panes), M2-08 (port forwarding). Re-run these tasks.
  Before re-running, check `scripts/lock.sh mine agent-<task>` and any `.merge/agent-<task>/` folders.
- M2-02 (identities) is done, but its TUI wiring copies are still in `.merge/agent-M2-02/` (with `_base/`). Merge them after M1-17
  using the base-aware approach (copy if `_base` == current, else `diff -u _base copy | patch`).
- The tree may not compile until the in-flight tasks are finished or their partial edits are reverted.
- Known flaky tests to stabilise before the final green run: server http t06_rate_limit_per_ip,
  sverb-tui widgets t07_render_10k_rows_under_2ms, the reconnect countdown in_secs test.
- Pending follow-ups: cargo-vet exemptions for new crates; cargo fmt pass; recording.retention_days and other
  "spec additions" into SPEC.md; PostgreSQL-backed tests only run in CI (no Postgres/Docker on this machine).
| M1-18 | merged | no copies; 17 Docker tests skip w/o SVERB_E2E/Docker (never run); PtyApp local tests pass; FOLLOW-UP: cargo-vet store broken (needs `cargo vet fmt` + exemptions), M1-15 e2e placeholder t14_to_t17 still unimplemented! (ignored) |
| M2-03 | merged | cli tests hunk hand-applied |
| M2-06 | merged | connect.rs hook patched; connector_tests mod line added |
| M3-01 | merged | no copies; resize mode swallows leader too; equalize_panes unbound (palette later) |
| M3-04 | merged | 4 hunks hand-applied (effect/event/mod/services) |
| M2-04 | merged | no copies; exec has own handshake loop (dedupe with connect.rs/M3-07); jump hosts rejected for exec until M2-05/M3-07; Docker variants ignored |
| M2-07 | merged | applied in place; T-09 docker half + T-14 Windows DACL not done; no agent.socket_in_tui, no `unlock --agent`; shell syntax from $SHELL; approval field "agent_forwarding"; russh remove_all_identities framing bug worked around |
| M2-05 | merged | no copies; FOLLOW-UP: move `jump` mod decl from connect.rs #[path] into ssh/mod.rs; exec still rejects chains; hop in error message not DisconnectReason |
| M2-11 | merged | 8 files hand-merged next to M2-09 arms; Host * -> "Imported defaults" group; no IdentityFile export; SVERB_EXPORT_PASSWORD env; IPv6 bind ApprovalNote lacks brackets (align preview.rs with resolve::approval::host_port) |
| M3-07 | merged | exec via pool (jump chains work), t07 un-ignored; pool key wider than spec; mux mods declared from jump.rs (cleanup -> ssh/mod.rs); OpenSSH mux e2e ignored (Docker); tunnel-only hop failure lacks hop label |
| M2-10 | merged | 2 hunks hand-applied; help snaps regenerated; NOT DONE: TUI connect approval dialog, "Needs approval" badges, Settings>Security approvals list (backend exists); no reload of device approvals before connect; SshConnector default still StampApprovals |
| M2-09 | merged | copies applied clean; T-09 via loopback not Docker; snippets mod is child of exec.rs |

### Load-sensitive tests (pass alone; failed once in a full run while 4 agents were building)
- sverb-crypto `tests/kat.rs`, `account_kat.rs`, `fixtures.rs`: fixture file reads failed (likely fd/IO pressure).
- sverb-conn `session::tests::t06_no_lock_across_await_stress`.
Final green run must be done with no agents running.
| M2-12 | merged | in place; is_enabled/category not in keymap registry (App::action_enabled match instead); join link is an M6-03 stub toast; no sync actions/settings pages yet; empty query shows only Recent+Actions |
| M3-02 | merged | in place; T-12 Docker e2e not done; N in BROADCAST xN = receivers; mouse click on confirm dialog closes without enabling; Connecting panes not skipped |
| M4-07 | merged | in place; tests use in-process server MemStore (Postgres backend untested); reqwest pinned crate-local; TUI lifecycle wiring (start on unlock/stop on lock/local_change, bar status) LEFT TO M4-09; VaultKeySource for rotation needed from M4-08/M5-04; old key versions in memory only; holds per session; http only for loopback; vault_access Revoked only toasts; sverb CLI unit tests not run by agent |
| M7-01 | merged | 10 copies overlap M3-03 copies (app/{mod,effect,event,input}.rs, views/dialogs.rs, services/mod.rs) -> merge after M3-03 finishes; T-09 Docker e2e not done (local install/uninstall substitute passes); T-02 fixture hand-built; prompt learning on first key, not 150ms; ghost text history-only; exec-on-hosts snippet runs still NoHistory; Hosts footer lacks H; include_str! from assets/ outside crate may break cargo package |
| M7-03 | merged | in place; .ppk fixtures from own Python writer (no puttygen) - verify one real puttygen file later; T-06 Windows registry never compiled; fuzz target needs M7-05 fuzz/Cargo.toml; unsupported proxy methods skip the session; proxy not in conflict-diff keys; FINAL CHECK must also run `cargo test -p sverb --no-default-features` (help@local.snap) |
| M3-03 | merged | 9 hunks hand-applied next to M7-01/M2-12 arms; T-08 Docker perf not done; concurrency 8 = reducer queue not Semaphore; management is a dialog (Settings section still placeholder); docs/data-model.md lacks workspace encoding |
| M7-02 | DROPPED (user: "I don't need ai assistant. remove it.") | M7-02 work deleted unmerged. Pre-existing AI pieces REMOVED 2026-10-08: ActionName::AiPrompt + `leader a`, [ai]/AiConfig/AiProvider (model, defaults, validate, tests, schema), palette arm; keymap/which-key snapshots regenerated. SPEC §9.11 marked removed. |
| M4-08 | merged | in place; NO TUI views (wizards are UI-agnostic reducers in sverb-sync account/wizard.rs; M4-09 must render); CLI duplicate choice apply-to-all only; no recovery CLI command; new meta.account / meta.account_keys_enc; T-12 adapted to in-memory backend; M5-03 copies of sverb-sync lib.rs/http.rs and cli mod.rs/tests.rs need 3-way merge |
| M5-03 | merged | copies merged clean; dead_code allows removed; server endpoint GET /v1/users/{id}/public-keys NOT built (M5-01); TUI team_verify view not wired into App/Settings; engine not switched to TrustedKeySource; overlaps M4-08 GrantKeySource (adapter suggested); M4-08 should call Trust::pin_self at login/register; pins device-local |
| M4-09 | merged | cloud session, done directly (no agents/locks). SyncUi facade (app/sync_ui.rs) is the UI's single cfg boundary; Settings section = Sync/Devices/Team pages (Team = M5-03 TeamVerifyView, now wired; pins loaded via SyncEffect::TeamPins); account wizard dialog renders M4-08 flows run in services/sync.rs (login relocks the vault afterwards so the account vault keys load on unlock); engine now uses TrustedKeySource; local changes = new Store::outbox_changes() watch (any committed write that queued an outbox row); last successful sync in meta `sync_last_ok`; ClockSkew SyncEvent (toast "Clock skew detected on device X", once per device per session); new unbound actions sync_status/sync_now/devices/team_keys (palette only when connected; share_pane too); `sverb sync` defaults to --status, `--json`; `devices list [--json]`/`revoke <id|prefix>`; T-07 round trip lives in sverb-sync tests/account.rs (sverb has no sverb-server dev-dep); T-08 uses strace (skips when ptrace unavailable). Not done: Trust::pin_self at login/register; TOTP only on login; registration token tried as invite then setup |
| M7-06 | merged | cloud session, done directly. Benches renamed to the spec table (emulator_parse, render_300x100, index_build_10k, search_query_10k, envelope_seal_open_1k) + new argon2_unlock, key_encode; startup harness crates/sverb/tests/startup.rs (#[ignore], release, test-hooks; test-only FileKeyring `SVERB_KEYRING=file:<dir>`); scripts/bench-gate.py (gate/compare/self-test) + scripts/bench-gates.toml; ci.yml bench-build job (cargo bench --no-run + self-test); bench.yml nightly (gates, >15% regression vs cached main baseline, startup); docs/performance.md. Fixes: kitty probe 2 s -> 50 ms (startup 2.06 s -> 35 ms), zstd reused DCtx for sized frames (open 21.5 -> 4.1 µs, 10k unlock 283 -> 86 ms). On this 4-vCPU VM local targets missed: emulator 70-79 MB/s (<100), index_build 87 ms (>75); CI gates pass. Keys typed during the <=50 ms probe are dropped. Never save a criterion baseline named `new` |
