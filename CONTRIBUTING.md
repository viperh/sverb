# Contributing to sverb

- Read [`SPEC.md`](SPEC.md) for what sverb is meant to do and
  [`docs/architecture.md`](docs/architecture.md) for how the crates fit together.
- Run the checks listed in the README's **Checks** section before sending a change.

## Logging

sverb has a strict logging policy: no hostnames, addresses, usernames, commands, snippet
bodies or item labels at `info` and above, and secrets never, at any level. Read
[`docs/logging.md`](docs/logging.md) before adding a `tracing` call, and use the
review checklist at the end of it.

## Canary secrets (M7-05)

Tests that handle secrets or hostnames plant **canary values**, so a leak anywhere is
found by a plain text search:

| Kind | Form | Rule |
|---|---|---|
| Passwords, passphrases, keys, tokens | `CANARY-PW-…`, `CANARY-PASS-…`, `CANARY-KEY-…`, `CANARY-TOKEN-…` (any `CANARY-…` that is not a host) | never in a log file at any level, a crash report, a SQLite file (`*.db`, `-wal`, `-shm`), a recording, a backup or a server database dump |
| Hostnames | `canary-host-….example` (`CANARY-HOST-…`) | never at `info`, `warn` or `error` in logs, never in crash reports, DB files, recordings, backups or dumps; `debug`/`trace` lines may contain them (SPEC §17) |

Matching is case-insensitive. `scripts/canary-scan.sh [DIR…]` checks those files under
the given directories (default `target/tmp`) and exits 1 on a leak;
`scripts/canary-scan.sh --self-test` checks the scanner itself. The CI job `canary`
runs the whole suite with `SVERB_LOG=trace`, `TMPDIR` and `SVERB_HOME` under one root,
dumps the server database, and scans everything. `crates/sverb/tests/canary.rs` is the
end-to-end fixture: it drives the real binary with planted canaries and keeps its
`SVERB_HOME` in `target/tmp/m7-05-canary/` for the scan.

To keep the scan meaningful, give planted secrets one of these prefixes, and keep test
homes you want scanned under `CARGO_TARGET_TMPDIR` (as `crates/sverb/tests/common` does).

## `unsafe`

The workspace lint is `unsafe_code = "deny"`. Only `crates/sverb-core/src/hardening/`
and `crates/sverb-conn/src/agent/dacl_windows.rs` may lift it, with a `SAFETY` comment
on every block; `python3 scripts/check-unsafe.py` (CI job `unsafe-check`) enforces this.
See `docs/threat-model.md`.

## Fuzzing

`fuzz/` is a cargo-fuzz workspace (nightly). Every target calls a `fuzz_*` function or
public parser that a property test in its crate also runs, so the bodies stay compiled
on stable:

```sh
cargo +nightly fuzz list
fuzz/seed-corpus.sh            # seeds from tests/fixtures and crate fixtures
cargo +nightly fuzz run emulator_feed fuzz/corpus/emulator_feed -- -max_total_time=60
```

PR CI runs each target for 30 s (`ci.yml`, job `fuzz`); `fuzz.yml` runs each for
10 minutes every night and uploads crashes. A new parser of untrusted input gets a
target: add `fuzz_targets/<name>.rs`, a `[[bin]]` in `fuzz/Cargo.toml`, seeds in
`fuzz/seed-corpus.sh`, and the target name to the matrix in `fuzz.yml`.

## Releases and documentation

- Use [conventional commits](https://www.conventionalcommits.org) (`feat:`, `fix:`,
  `sec:`, `perf:`, `refactor:`, `docs:`). They make the changelog easy to write. The
  release flow is in [`docs/release.md`](docs/release.md).
- Some docs are generated, and a test fails when they are stale:
  `docs/keybindings.md` (`SVERB_BLESS=1 cargo test -p sverb-tui --test keybindings_doc`),
  and `docs/config.md` with `docs/config.schema.json`
  (`SVERB_BLESS_SCHEMA=1 cargo test -p sverb-core config::schema`). The man page and
  shell completions come from `sverb generate`. Their snapshot is
  `crates/sverb/src/cli/snapshots/sverb__cli__generate__tests__man_*.snap`.
- A config key, field, endpoint or command that SPEC.md doesn't name is a **spec
  addition**: add it to SPEC.md Appendix B in the same change.
