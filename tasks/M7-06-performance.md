# M7-06 — Performance benchmarks and targets

| | |
|---|---|
| **Milestone** | M7 |
| **Touches** | `crates/*/benches/*.rs` (criterion), `.github/workflows/bench.yml`, `docs/performance.md` |
| **Spec refs** | §1 (startup < 100 ms to interactive host list with keyring unlock; Argon2 0.5–1 s), §5.2 (decrypt 10k items ≈ 50 ms), §19 (emulator ≥ 100 MB/s, render 300×100 < 2 ms), §21 M3 (8-pane workspace < 3 s) |
| **Depends on** | M1-09, M1-10, M1-05, M1-04, M3-03 |
| **Blocks** | — |

---

## 1. Current state in the codebase
Individual tasks added bench stubs (M1-01 envelope, M1-05 search, M1-09 emulator throughput, M1-10 render, M0-09 loop overhead). Nothing gates on them.

## 2. Detailed description
- **Benchmarks** (criterion, consistent input data generated deterministically):
  | Bench | Target | Source |
  |---|---|---|
  | `emulator_parse` (100 MB mixed text and SGR) | ≥ 100 MB/s | §19 |
  | `render_300x100` (dense SGR grid → Buffer) | < 2 ms | §19 |
  | `index_build_10k` (decrypt + index 10k items) | ≈ 50 ms (modern CPU) | §5.2 |
  | `search_query_10k` | < 5 ms | M1-05 |
  | `envelope_seal_open_1k` | informational | M1-01 |
  | `startup_to_hosts_keyring` (process start → first frame with host list, keyring unlock, 1k hosts) | < 100 ms | §1 |
  | `argon2_unlock` (production params) | 0.5–1 s, informational | §5.3 |
  | `key_encode` | informational | M1-11 |
- **Startup measurement:** a PTY harness launches `sverb` with a mock keyring (an env-selected in-memory backend for tests) and measures the time until the PTY output contains the host
  list. 20 runs, report the median. Optimizations to consider: lazy-load non-visible views, parallel decrypt, defer config watcher and sync start until after the first frame, avoid
  blocking on kitty detection (timeout ≤ 50 ms).
- **CI:** `bench.yml` runs on a schedule and on demand (not on every PR, because of noisy runners). It compares against stored baselines (`critcmp` or `github-action-benchmark`) and alerts
  on > 15% regressions. Hard gates (fail) only for the spec targets, with CI-adjusted thresholds documented (CI is slower: allow 2×).
- **Profiling guide:** `docs/performance.md` with how to profile (`cargo flamegraph`, `tokio-console` behind a feature) and the recorded results table per release.

## 3. Codebase changes
- Fill in and complete the benches, the startup harness, the workflow and the docs.

## 4. Test cases to implement

**T-01** Every bench in the table compiles and runs (`cargo bench --no-run` in PR CI).

**T-02** The emulator parse gate is ≥ 50 MB/s on CI (2× allowance) and recorded locally at ≥ 100 MB/s.

**T-03** The render gate is < 4 ms on CI.

**T-04** Startup: median < 200 ms on CI, and < 100 ms on the reference machine (recorded in the docs).

**T-05** A regression alert triggers when a deliberately slowed function (on a throwaway branch) regresses > 15%.

## 5. Passing functional characteristics
- [ ] Benchmarks exist for every quantitative spec target, with documented CI-adjusted gates.
- [ ] Startup to an interactive host list with keyring unlock is under 100 ms on the reference hardware.
- [ ] Emulator parse ≥ 100 MB/s and 300×100 render < 2 ms on the reference hardware.
- [ ] Regressions are detected automatically.
