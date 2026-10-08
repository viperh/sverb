# Performance

The spec's quantitative targets (SPEC §1, §5.2, §5.3, §19), how they are measured,
the gates, and the recorded results (task M7-06).

## Targets and benchmarks

| Bench (criterion `group/function`) | Target | CI gate (2×) | Source | Where |
|---|---|---|---|---|
| `emulator_parse/mixed_1MiB` | ≥ 100 MB/s | ≥ 50 MB/s | §19 | `crates/sverb-term/benches/emulator_throughput.rs` |
| `render_300x100/*` (dense SGR grid → `Buffer`) | < 2 ms | < 4 ms | §19 | `crates/sverb-term/benches/render.rs` |
| `index_build_10k/decrypt_and_index` | ≈ 50 ms (gate 75 ms) | < 150 ms | §5.2 | `crates/sverb-core/benches/search.rs` |
| `search_query_10k/5char` | < 5 ms | < 10 ms | M1-05 | `crates/sverb-core/benches/search.rs` |
| `envelope_seal_open_1k/*` | informational | — | M1-01 | `crates/sverb-crypto/benches/envelope.rs` |
| `argon2_unlock/production` | 0.5–1 s, informational | — | §5.3 | `crates/sverb-core/benches/argon2_unlock.rs` |
| `key_encode/*` | informational | — | M1-11 | `crates/sverb-term/benches/key_encode.rs` |
| `startup_to_hosts_keyring` (process start → host list, keyring unlock, 1k hosts) | < 100 ms | < 200 ms (median of 20) | §1 | `crates/sverb/tests/startup.rs` |

Inputs are generated deterministically inside each bench (no fixture files).
The hard gates live in `scripts/bench-gates.toml`; informational benches have none,
but every bench is covered by the regression check.

## Running

```sh
# All criterion benches, saved as the baseline "ci" (never "new": criterion uses that).
cargo bench --workspace --bench '*' -- --save-baseline ci --noplot

# The spec gates: CI thresholds, or the reference-machine targets.
python3 scripts/bench-gate.py gate
python3 scripts/bench-gate.py gate --local

# Regressions against an older baseline (fails above 15%).
python3 scripts/bench-gate.py compare --old main --new ci --threshold 15

# Startup: median of 20 runs on a release build (the file keyring needs test-hooks).
cargo test --release -p sverb --features test-hooks --test startup -- --ignored --nocapture
```

`--bench '*'` keeps criterion's flags away from the libtest harnesses of the library
targets. `SVERB_STARTUP_GATE_MS` overrides the startup gate; `SVERB_STARTUP_KEEP=1`
keeps the fixture home (its path is printed) for profiling a single start.

### The startup harness

The fixture is a vault with 1,000 hosts and keyring unlock on. The keyring is a
test-only file keyring (`SVERB_KEYRING=file:<dir>`, compiled only with the
`test-hooks` feature, never in release builds). Each run spawns `sverb` on an 80×24
PTY, answers the startup terminal query (`CSI ? u` + DA1) the way a terminal without
the kitty protocol does, and stops the clock when the first host's label is drawn.

## CI

* `ci.yml`, job **Benchmarks compile** (every PR): `cargo bench --no-run` (T-01) and
  the gate script's self-test, which proves a 20% slowdown is flagged and a 5% one
  is not (T-05).
* `bench.yml` (nightly and on demand, not per PR because shared runners are noisy):
  runs every bench, applies the CI gates, compares against the cached `main`
  baseline (> 15% fails the run), runs the startup harness, and on `main` promotes
  the results to the new baseline.

## Profiling

* CPU: `cargo flamegraph -p sverb-term --bench emulator_throughput -- --bench` (needs
  `cargo install flamegraph` and `perf`). For the binary:
  `cargo flamegraph -p sverb --bin sverb` and quit with `ctrl-\ q`.
* Startup: keep the fixture (`SVERB_STARTUP_KEEP=1`), then run
  `SVERB_HOME=<path> SVERB_KEYRING=file:<path>/keyring perf record -g target/release/sverb`
  (built with `--features test-hooks`).
* Async stalls: `tokio-console` needs `RUSTFLAGS="--cfg tokio_unstable"` and a
  `console-subscriber` layer; there is no feature for it yet, so add it locally
  when needed.
* Remember that criterion's numbers vary by 10–20% on shared machines: compare
  medians of several runs before acting on a change.

## Optimizations made (M7-06)

* **Terminal probe:** startup asked the terminal for kitty keyboard support with
  crossterm's probe, which waits up to **2 s** for a terminal that answers neither
  query (many multiplexers, some SSH setups, every test PTY). The probe now waits at
  most 50 ms (`runtime::terminal::kitty_probe`); a late answer is parsed by crossterm
  as an internal event, never as keys. Startup with an unanswering terminal went
  from 2.06 s to ~110 ms; with an answering one it is ~35 ms.
* **Decrypt:** every item open created a streaming zstd decoder, which allocates its
  window each time. Frames that declare their size (all of ours) now decompress in
  one pass with a reused per-thread context; frames without a size keep the bounded
  streaming path (the zip-bomb cap is unchanged: a declared size above the cap is
  rejected up front). `open_item` 1 KiB: 21.5 µs → 4.1 µs; 10k-item unlock:
  283 ms → 86 ms. The seal path keeps a fresh compression context per item on
  purpose: a long-lived one would keep plaintext fragments in its buffers.

## Results

Recorded with `cargo bench` (criterion medians) and the startup harness.

### 2026-10-08, cloud VM (4 vCPU Intel Xeon @ 2.1 GHz, shared)

Not the reference machine: a shared, comparatively slow VM. M1-09 measured the
emulator at ~99 MiB/s on a desktop CPU.

| Bench | Result | Local target | CI gate |
|---|---|---|---|
| `emulator_parse/mixed_1MiB` | 70–79 MB/s (two runs) | ✗ (≥ 100 MB/s) | ✓ |
| `render_300x100/terminal_truecolor` | 0.51 ms | ✓ | ✓ |
| `render_300x100/dracula_truecolor` | 0.51 ms | ✓ | ✓ |
| `render_300x100/dracula_256` | 0.59 ms | ✓ | ✓ |
| `index_build_10k/decrypt_and_index` | 86–87 ms | ✗ (75 ms) | ✓ |
| `search_query_10k/5char` | 2.4–2.6 ms | ✓ | ✓ |
| `envelope_seal_open_1k/seal_1KiB` | 23.6 µs | — | — |
| `envelope_seal_open_1k/open_1KiB` | 4.1 µs | — | — |
| `argon2_unlock/production` | 830 ms | ✓ (0.5–1 s) | — |
| `key_encode/legacy` (40+ keys) | 3.0 µs | — | — |
| `key_encode/kitty` (40+ keys) | 5.5 µs | — | — |
| `startup_to_hosts_keyring` | median 34.5 ms (min 28.5, max 48.8) | ✓ (< 100 ms) | ✓ |

Open items for a reference-machine run: the emulator throughput and the 10k-item
index build, both within the CI allowance here. Next steps if they stay short on
real hardware: parallel decrypt on the blocking pool for large vaults, and
profiling `AlacrittyEmulator::feed` (vte parsing vs. grid updates).
