# M0-01 — Workspace restructure, lints and crate skeletons

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `Cargo.toml`, `crates/sverb/Cargo.toml`, `crates/sverb-core/*`, new `crates/sverb-{crypto,proto,store,conn,term,sync,tui,server,e2e}`, `README.md`, `.gitignore`, new `deny.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `SPEC.md` |
| **Spec refs** | §2.2, §3, §17 (supply chain, `forbid(unsafe_code)`), §20 (license) |
| **Depends on** | — |
| **Blocks** | every other task |

---

## 1. Current state in the codebase

- `Cargo.toml:1-3`: workspace with `resolver = "3"` and `members = ["crates/*"]`. Only
  `crates/sverb` (binary) and `crates/sverb-core` exist.
- `Cargo.toml:17-66`: `[workspace.dependencies]` pins the template's dependencies, including several
  that the spec does not use or that later tasks replace:
  - `config` and `json5` (replaced by TOML-only config, M0-06)
  - `human-panic` and `better-panic` (replaced by the sverb panic hook, M0-05)
  - `libc` (used only for `EXIT_FAILURE` in `errors.rs:46`)
  - `signal-hook` (used for SIGTSTP suspend in `tui.rs:202`, which stays)
- `Cargo.toml:68-73`: release profile `opt-level = "s"`, `lto = true`. `opt-level = "s"` trades
  speed for size, which conflicts with §19's performance targets (emulator ≥ 100 MB/s, render < 2 ms).
- No `[workspace.lints]`, no `#![forbid(unsafe_code)]` in any crate, and `#![allow(dead_code)]` in
  `crates/sverb/src/config.rs:1` and `crates/sverb/src/tui.rs:1`.
- `crates/sverb-core/Cargo.toml:11-12` already states "no ratatui, no crossterm, no clap". This is a
  comment, not an enforced rule.
- `rust-version = "1.85"`. That's the minimum for edition 2024, but `russh`, `alacritty_terminal`
  and `opaque-ke` may need newer.
- The repo has **no commits**. `README.md` describes the template.
- `SPEC.md` is not in the repo (it lives in `~/Work/sverb/SPEC.md`).

## 2. Detailed description

### 2.1 Goal
Lay out every crate from the target architecture (see `00-README.md` §2.1) as compiling skeletons
with the correct dependency direction. Add workspace-wide lints, drop template dependencies that are
being replaced, and land the first commit, so every following task works on a clean, reviewable base.

### 2.2 Initial commit (do this first)
1. Commit the template exactly as it is (`chore: import ratatui template`), so later diffs show
   what changed.
2. Copy `SPEC.md` into the repo root and commit it (`docs: add SPEC v0.3`).

### 2.3 New crates
Create each crate with `version/edition/authors/license/repository/rust-version.workspace = true`
and `[lints] workspace = true`:

| Crate | Kind | Allowed internal deps | Forbidden deps |
|---|---|---|---|
| `sverb-crypto` | lib | — | tokio, any I/O crate, ratatui, crossterm, rusqlite |
| `sverb-proto` | lib | sverb-crypto | ratatui, crossterm, rusqlite, russh |
| `sverb-core` | lib (exists) | sverb-crypto, sverb-proto | ratatui, crossterm, clap |
| `sverb-store` | lib | sverb-core, sverb-crypto | ratatui, crossterm |
| `sverb-conn` | lib | sverb-core | ratatui, crossterm |
| `sverb-term` | lib | sverb-core | crossterm (it takes ratatui only for `Buffer`/`Rect`/`Style`; use `ratatui-core` if the pinned ratatui version splits it out) |
| `sverb-sync` | lib | sverb-core, sverb-store, sverb-proto, sverb-crypto | ratatui, crossterm |
| `sverb-tui` | lib | everything client-side; `sverb-sync` only behind feature `sync` | — |
| `sverb-server` | lib + bin `sverb-server` | sverb-proto, sverb-crypto | sverb-core, sverb-store, sverb-conn, sverb-term, sverb-tui, sverb-sync, ratatui, crossterm, russh, rusqlite |
| `sverb-e2e` | lib, `publish = false` | any | — |
| `sverb` | bin (exists) | sverb-tui, sverb-core, sverb-store, …; `sverb-sync` behind feature | — |

Each new `lib.rs` contains only a crate-level doc comment describing its responsibility (copy the
wording from §3) and no code.

### 2.4 Feature flags
- `crates/sverb/Cargo.toml`: `[features] default = ["sync"]`,
  `sync = ["dep:sverb-sync", "sverb-tui/sync"]`.
- `crates/sverb-tui/Cargo.toml`: `[features] sync = ["dep:sverb-sync"]`.
- Document in README that `cargo build -p sverb --no-default-features` produces the local-only build
  (§1.1).

### 2.5 Workspace lints (`Cargo.toml`)
- `[workspace.lints.rust]`: `unsafe_code = "forbid"`, `missing_debug_implementations = "warn"`,
  `unreachable_pub = "warn"`.
- `[workspace.lints.clippy]`: `all = { level = "warn", priority = -1 }`, `dbg_macro = "deny"`,
  `todo = "warn"`, `unwrap_used = "warn"`, `expect_used = "warn"`, `await_holding_lock = "deny"`
  (protects the §2.1 rule that the emulator mutex is never held across `.await`),
  `large_futures = "warn"`.
- Tests may `#[allow(clippy::unwrap_used)]` at the module level.
- Remove `#![allow(dead_code)]` from `config.rs:1` and `tui.rs:1`. Remove the dead code it hid,
  or mark individual items until their task lands.

### 2.6 Dependency cleanup
- Keep `color-eyre`, `tracing`, `tracing-subscriber`, `tracing-error`, `clap`, `crossterm`,
  `ratatui`, `tokio`, `tokio-util`, `futures`, `serde`, `thiserror`, `strum`, `directories`,
  `signal-hook`, `vergen-gix`, `anyhow` (build-only), `pretty_assertions`, `strip-ansi-escapes`.
- Mark `config`, `json5`, `human-panic`, `better-panic` and `libc` for removal in the tasks that replace
  their usage (M0-05, M0-06). Don't remove them here if code still uses them. Add a
  `# TODO(M0-06)` comment next to each in `Cargo.toml`.
- Add workspace pins (unused for now, so crates can opt in) for Appendix A crates whose versions
  must be chosen once: `ratatui`, `crossterm`, `russh`, `ssh-key`, `alacritty_terminal`,
  `portable-pty`, `rusqlite` (bundled), `rusqlite_migration`, `chacha20poly1305`, `argon2`,
  `hkdf`, `sha2`, `hpke`, `opaque-ke`, `x25519-dalek`, `ed25519-dalek`, `zeroize`, `secrecy`,
  `uuid` (v7), `uhlc`, `ciborium`, `zstd`, `toml`, `schemars`, `nucleo`, `insta`, `proptest`.
  Choose versions that compile together on the MSRV. Record the result in the table in §6 of this task.

### 2.7 MSRV
Determine the lowest Rust version that builds the pinned set (`cargo msrv find` or bisecting
toolchains). Set `rust-version` and `rust-toolchain.toml` (`channel = "stable"`, components
`rustfmt`, `clippy`). Document the MSRV in the README.

### 2.8 Release profile
Change `opt-level = "s"` → `opt-level = 3`, keep `lto` (`"thin"` is acceptable if build time is a
problem), `codegen-units = 1`, `strip = true`, and add `panic = "unwind"` explicitly, because the panic
hook (M0-05) must run destructors.

### 2.9 Repository files
- `deploy/`, `docs/` (placeholders `keybindings.md`, `threat-model.md`, `self-hosting.md`),
  `migrations/client/`, `migrations/server/`, `tests/fixtures/`, each with a `.gitkeep` or README.
- `.gitignore`: keep `/target` and `/.data`, add `/.state`, `*.snap.new` (insta) and `/.sverb-home`.
- `rustfmt.toml`: `edition = "2024"`, `imports_granularity = "Crate"`,
  `group_imports = "StdExternalCrate"` (the existing files already follow std → external →
  crate grouping, e.g. `app.rs:1-14`).
- `README.md`: rewrite for sverb, covering what it is, the crate map, local-only vs synced, how to run,
  checks (keep the existing "Checks" section, `README.md:70-81`), and `.envrc` usage (updated in M0-03).
- Update `SPEC.md` §3 to show `crates/sverb/` instead of `bin/sverb/` (decision in
  `00-README.md` §2.1).

### 2.10 Out of scope
- Moving code between crates (M0-08 moves `app.rs`, `components/` and `tui.rs` into `sverb-tui`).
- CI changes (M0-02).

## 3. Codebase changes
- **Modify:** `Cargo.toml` (lints, pins, profile, TODO comments), `crates/sverb/Cargo.toml`
  (features, `[lints] workspace = true`), `crates/sverb-core/Cargo.toml` (`[lints]`, deps on
  crypto/proto), `.gitignore`, `README.md`.
- **Create:** 9 crate directories with `Cargo.toml` + `src/lib.rs` (and `src/main.rs` for
  `sverb-server`), `deny.toml`, `rustfmt.toml`, `rust-toolchain.toml`, directory placeholders.
- **Edit:** `crates/sverb/src/config.rs:1`, `crates/sverb/src/tui.rs:1` (remove blanket allows).

## 4. Test cases to implement

**T-01 (build)** `cargo build --workspace --all-features --locked` succeeds with zero warnings.

**T-02 (build, local-only)** `cargo build -p sverb --no-default-features --locked` succeeds, and
`cargo tree -p sverb --no-default-features -e normal` contains no `sverb-sync`.

**T-03 (compile-fail)** Add a `trybuild` test in `crates/sverb-core/tests/compile_fail/` with a
file using `unsafe {}`. It must fail with the `forbid(unsafe_code)` diagnostic. Repeat for one other
crate (`sverb-crypto`), to prove the lint is inherited workspace-wide.

**T-04 (metadata)** An integration test or xtask reads `cargo metadata` and asserts every
workspace package has `license == "MIT"` and `rust-version` set.

**T-05 (metadata)** The same test asserts the "forbidden deps" column of §2.3 for every crate
(transitive closure over normal dependencies). This test is reused by the CI layering job in M0-02.

**T-06 (existing tests)** The template tests in `crates/sverb/src/config.rs:454-603` and
`crates/sverb-core/src/lib.rs:52-71` still pass after the restructure.

**T-07 (binary)** `cargo run -p sverb -- --version` still prints the vergen-stamped version.

**T-08 (clippy)** `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
with the new lint set. Fix or locally allow, with a justification comment, every finding in the
existing template code. Known spots: `config.rs:57` (`unwrap` on embedded JSON), `config.rs:61-62`
(`to_str().unwrap()`), `config.rs:145` (`unwrap` in keybinding deserialize), `config.rs:225`,
`tui.rs:119` (`expect`), `tui.rs:232` (`unwrap` in `Drop`).

## 5. Passing functional characteristics
- [ ] The repository has an initial commit of the template, followed by the restructure commit(s).
- [ ] All crates from `00-README.md` §2.1 exist and compile. `SPEC.md` is in the repo and §3 matches
      the real layout.
- [ ] `unsafe_code` is forbidden in every crate, through workspace lints.
- [ ] Dependency direction (§2.3 table) holds, and a test verifies it.
- [ ] The `sync` feature exists, is on by default, and the binary builds without it.
- [ ] The release profile optimizes for speed (`opt-level = 3`) and keeps unwinding.
- [ ] MSRV is determined, documented and set in `rust-version`.
- [ ] The README describes sverb, not the template.
- [ ] `cargo test --workspace` and `cargo clippy -D warnings` are green.

## 6. Notes and risks
- Record the chosen versions in the table below when done:

| Crate | Version | Note |
|---|---|---|
| russh | | |
| alacritty_terminal | | |
| opaque-ke | | |
| hpke | | |
| rusqlite | | bundled |

- `ratatui 0.30` splits widgets into `ratatui-core`/`ratatui-widgets`. `sverb-term` should depend
  on the smallest crate that provides `Buffer`, `Rect` and `Style`.
