# M0-02 — CI hardening: OS matrix, cargo-deny, cargo-vet, MSRV, local-only build, layering

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `.github/workflows/ci.yml`, new `deny.toml` content, `supply-chain/` (cargo-vet), `xtask/` or `scripts/check-layering.*` |
| **Spec refs** | §1.1 (local-only build must pass the suite), §17 (supply chain), §19 (CI), §20 (license policy) |
| **Depends on** | M0-01 |
| **Blocks** | — (all later tasks rely on CI being trustworthy) |

---

## 1. Current state in the codebase
`.github/workflows/ci.yml` defines four jobs, **all on `ubuntu-latest`**:
- `test` (lines 11-21): `cargo test --locked --all-features --workspace`
- `rustfmt` (23-35)
- `clippy` (37-49): `--all-targets --all-features -- -D warnings`
- `docs` (51-63): `RUSTDOCFLAGS=-D warnings cargo doc …`

Missing compared to §19 and §17: macOS and Windows test runs, the e2e job, `cargo-deny`, `cargo-vet`,
an MSRV check, the local-only feature build (§1.1), and the crate-layering check from M0-01. The
`actions/checkout@v4` step lacks `fetch-depth: 0`, which `vergen-gix` (`crates/sverb/build.rs`)
needs for a meaningful `VERGEN_GIT_DESCRIBE`. Today `default_on_error()` silently emits
placeholder values.

## 2. Detailed description

### 2.1 Jobs (target `ci.yml`)
Triggers: keep `push` to `main` and `pull_request`, and add `workflow_dispatch`. Add
`concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }`.

| Job | Runs on | Command(s) | Notes |
|---|---|---|---|
| `fmt` | ubuntu | `cargo fmt --all --check` | keep the existing job |
| `clippy` | ubuntu | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` **and** `cargo clippy -p sverb -p sverb-tui --all-targets --no-default-features --locked -- -D warnings` | the second run checks the local-only build |
| `docs` | ubuntu | keep the existing job | |
| `test` | matrix ubuntu/macos/windows | `cargo test --workspace --all-features --locked` | use `cargo nextest` if desired; set `SVERB_HOME=${{ runner.temp }}/sverb-home` |
| `test-local-only` | ubuntu | `cargo test --workspace --no-default-features --locked --exclude sverb-sync --exclude sverb-server --exclude sverb-e2e` | §1.1 rule |
| `e2e` | ubuntu | `cargo test -p sverb-e2e --locked -- --ignored --test-threads=4` | needs Docker. A placeholder until M1-18. Allowed to be a no-op test now. |
| `server-db` | ubuntu, `services: postgres:16` | `cargo test -p sverb-server --locked` with `DATABASE_URL` | placeholder until M4-01 |
| `deny` | ubuntu | `EmbarkStudios/cargo-deny-action@v2` running `check advisories bans licenses sources` | |
| `vet` | ubuntu | `cargo vet --locked` | |
| `msrv` | ubuntu | install the toolchain from `rust-version`, run `cargo check --workspace --all-features --locked` | read the MSRV from `Cargo.toml` with `cargo metadata`/`jq` so it is never duplicated |
| `layering` | ubuntu | run the dependency-direction test from M0-01 T-05 | |

All jobs use `Swatinem/rust-cache@v2` (already used). Use `actions/checkout@v4` with
`fetch-depth: 0` in jobs that build the binary, for vergen.

### 2.2 `deny.toml`
- **licenses:** allow `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`,
  `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`, `CC0-1.0`, `MPL-2.0` (explicit exception, §20).
  Deny everything else, including GPL, LGPL and AGPL. `confidence-threshold = 0.9`.
- **bans:** deny `openssl`, `openssl-sys`, `native-tls` (rustls only). `multiple-versions = "warn"`.
  Add `wrappers` rules that encode the layering (e.g. `ratatui` may only be pulled in by
  `sverb-tui`, `sverb-term` and `sverb`), as a second line of defense next to the layering test.
- **advisories:** `vulnerability = "deny"`, `unmaintained = "workspace"`, `yanked = "deny"`.
- **sources:** `unknown-registry = "deny"`, `unknown-git = "deny"`.
- Check the **template's** dependency set now. `human-panic` pulls `os_info` etc. Record any license
  exceptions needed until M0-05 removes it.

### 2.3 cargo-vet
- `cargo vet init`, then import audits from the Mozilla, Google, Bytecode Alliance and ZcashFoundation
  audit sets.
- Policy: crates in the Appendix A **Crypto** row must be `safe-to-deploy` through an import or our
  own audit. Others may be exempted initially, and the exemptions list is reviewed each milestone.

### 2.4 Determinism and speed
- `CARGO_TERM_COLOR=always`, `RUST_BACKTRACE=1`, `CARGO_INCREMENTAL=0` in CI.
- Windows: set `git config --global core.autocrlf false` before checkout, so fixture files (known_hosts,
  ssh_config) keep LF endings. This matters for M2-11 snapshot tests.

### 2.5 Out of scope
- Release and CD changes (M7-07).

## 3. Codebase changes
- **Rewrite:** `.github/workflows/ci.yml`.
- **Create:** `deny.toml` (if M0-01 only created a stub), `supply-chain/{config.toml,audits.toml,imports.lock}`.
- **Create:** `.github/dependabot.yml` for `cargo` and `github-actions`, weekly.

## 4. Test cases to implement
CI configuration is verified by running it, not by unit tests. These are the required verification runs:

**T-01** Open a PR with the restructure from M0-01. Every job listed in §2.1 runs and passes on it.

**T-02 (negative, license)** On a throwaway branch, add a GPL-3.0 crate dependency (e.g.
`readline`-style crate). The `deny` job fails with a license error. Do not merge.

**T-03 (negative, bans)** On a throwaway branch, add `reqwest` with default features (pulls
`native-tls`/`openssl`). The `deny` job fails on the ban.

**T-04 (negative, layering)** On a throwaway branch, add `ratatui` to `sverb-core`. The `layering` job
(and the `deny` wrapper rule) fails.

**T-05 (negative, local-only)** On a throwaway branch, make `sverb-tui` reference a `sverb_sync`
item without `#[cfg(feature = "sync")]`. The `clippy` no-default-features run and
`test-local-only` fail.

**T-06 (MSRV)** Lower `rust-version` below the real minimum on a throwaway branch. The `msrv` job fails.

**T-07 (Windows)** The `test` job on `windows-latest` runs the template tests, and they pass.

**T-08 (vergen)** In the `test` job, `cargo run -p sverb -- --version` prints a real `git describe`
value, not a placeholder.

## 5. Passing functional characteristics
- [ ] CI runs fmt, clippy (all-features and local-only), docs, tests on Linux/macOS/Windows,
      local-only tests, deny, vet, MSRV and layering on every PR.
- [ ] e2e and server-db jobs exist (placeholders) and are wired for Docker/Postgres.
- [ ] License policy matches §20: MIT-compatible only, MPL-2.0 as an explicit exception, no GPL family.
- [ ] OpenSSL/native-tls cannot enter the dependency graph.
- [ ] Crypto dependencies are vetted.
- [ ] Each negative check (T-02…T-06) was demonstrated to fail once.
- [ ] Dependabot keeps actions and crates updated.

## 6. Notes
- Make `e2e` and `server-db` required checks only after M1-18 and M4-01 make them meaningful.
