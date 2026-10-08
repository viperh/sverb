# M7-07 — Packaging, release automation, documentation, accessibility pass

| | |
|---|---|
| **Milestone** | M7 (exit criterion: 1.0 release candidate) |
| **Touches** | `.github/workflows/cd.yml` (rewrite), `release-plz.toml`, `packaging/{aur/, homebrew/, nix/flake.nix, scoop/}`, `deploy/` (image publish), `README.md`, `docs/*`, `CHANGELOG.md` |
| **Spec refs** | §20, §10.7 (static musl server binary, distroless image), §8.8 (NO_COLOR, monochrome), §21 M7, §22 |
| **Depends on** | everything |
| **Blocks** | 1.0 |

---

## 1. Current state in the codebase
`.github/workflows/cd.yml` (template) builds tarballs on tag push for `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, `aarch64-unknown-linux-gnu` (cross) and `i686-unknown-linux-gnu` (cross), packages `tar.gz` plus sha256, and uploads with
`softprops/action-gh-release`. It uses `BINARY_NAME: sverb` and builds `--package sverb`. Gaps vs §20: Linux builds are **gnu, not musl**; there's no macOS **universal** binary;
i686 isn't in the spec (keep or drop it; **decision:** drop it); Windows ships a tar.gz (prefer zip); no server binary or Docker image; no changelog or release automation;
no package-manager channels.

## 2. Detailed description

### 2.1 Release automation
- **release-plz** (§20): opens release PRs with version bumps and changelogs from conventional commits. On merge it tags `vX.Y.Z` (workspace version) and publishes crates to crates.io
  (`cargo install sverb` must work: publish the internal crates in dependency order, or keep internal crates `publish = false` and vendor them? **Decision:** publish all library
  crates with the `sverb-` prefix, because `cargo install` needs them on crates.io).
- **SemVer** (§20). The sync protocol is versioned separately (`/v1`, `Sverb-Proto: 1`). The server supports N and N-1 (M4-01).

### 2.2 Binaries (`cd.yml` rewrite)
| Target | Artifact |
|---|---|
| `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | `sverb-<v>-linux-<arch>.tar.gz` (static) |
| macOS universal (`lipo` of x86_64 + aarch64) | `sverb-<v>-macos-universal.tar.gz` (codesigning and notarization if secrets are available; otherwise document the Gatekeeper workaround) |
| `x86_64-pc-windows-msvc` (+ `aarch64` optional) | `sverb-<v>-windows-x86_64.zip` |
| server: `x86_64/aarch64-unknown-linux-musl` | `sverb-server-<v>-linux-<arch>.tar.gz` |
- sha256 sums file plus **reproducible builds** (§17: `--locked`, `SOURCE_DATE_EPOCH`, `-C strip`, remap-path-prefix), and verify by building twice in CI and comparing hashes for
  the Linux musl target.
- Keep vergen stamping (`crates/sverb/build.rs`) with `fetch-depth: 0` (already in the template CD).
- SBOM (`cargo cyclonedx`) attached to releases (nice to have).

### 2.3 Server image (§20, §10.7)
`ghcr.io/<org>/sverb-server:<v>` and `:latest`, multi-arch (amd64, arm64), from `deploy/Dockerfile.server` (M4-01), distroless, non-root. A Helm chart is a stretch goal (§20), out of scope.

### 2.4 Package channels (§20)
- **AUR:** `sverb` (builds from source) and `sverb-bin` (prebuilt) PKGBUILDs in `packaging/aur/`, updated by a workflow on release (via an AUR SSH key secret).
- **Homebrew tap** formula (`packaging/homebrew/sverb.rb`) pushed to a `homebrew-sverb` tap repo.
- **Nix flake** at the repo root (`flake.nix`), with packages `sverb` and `sverb-server`, a devShell, and `nix build` in CI.
- **Scoop** manifest (`packaging/scoop/sverb.json`) with autoupdate.
- **cargo install sverb.**

### 2.5 Documentation (§3 docs/, §21 M7)
- `README.md`: features, screenshots or an asciicast, install per channel, quick start (local-only), enabling sync, a self-hosting pointer, security model summary, and license.
- `docs/`: `keybindings.md` (generated, M0-10), `threat-model.md` (M7-05), `self-hosting.md` (M4-01), `architecture.md` (M0-08), `data-model.md`, `config.md` (generated from the schema
  with descriptions), `cli-json.md`, `themes.md`, `emulator.md`, `performance.md`, `logging.md`, and FAQ/troubleshooting (common `doctor` findings, tmux OSC 52, Windows Terminal notes).
- A man page generated with `clap_mangen` (`sverb.1`) and shell completions with `clap_complete` (bash, zsh, fish, powershell), included in the release archives and packages.

### 2.6 Accessibility pass (§21 M7, §8.8)
- Audit every view in `NO_COLOR` and with `ui.theme = "high-contrast"`: no information is conveyed only by color (status, errors, broadcast, sync state, cert expiry badges all
  have text or glyph equivalents). An ASCII fallback mode for glyphs (`ui.ascii = auto|on|off`, a spec addition; auto when the locale isn't UTF-8 or `TERM=linux`).
- Every action is keyboard-reachable (§1 goal). Run a script over the action registry asserting each action has a default binding **or** is reachable via the palette.
- Screen-reader friendliness is limited in TUIs. Document recommendations (status-bar text, avoiding animations: spinner frames honor a `ui.reduce_motion` flag, a spec addition).
- Snapshot tests of all views in `NO_COLOR` (extending each task's snapshots).

### 2.7 Spec open questions (§22)
Before 1.0, record decisions for each open question in SPEC.md's decisions log: list merge semantics (OR-sets for tags?), `read_ssh_config` live mode, web viewer timing, and emulator
choice. Also record the spec additions made across tasks (collected from the "spec addition" notes in the task files).

## 3. Codebase changes
- Rewrite `cd.yml`, add `release-plz.toml`, the `packaging/` directory, `flake.nix`, docs, man and completions generation (an `xtask` or `build.rs` in the binary crate), and the accessibility config keys.

## 4. Test cases to implement

**T-01 (CI dry run)** `cd.yml` runs on a test tag in a fork or with `workflow_dispatch` in dry-run mode → all artifacts are produced. The musl binaries are static (`file` reports
"statically linked"). The macOS universal binary has both arches (`lipo -info`).

**T-02 (CI)** Reproducibility: two independent builds of the Linux musl binary are byte-identical.

**T-03 (CI)** `nix build .#sverb` succeeds.

**T-04 (CI)** The Docker image runs `sverb-server --version` and passes the compose healthcheck (M4-01 T-13) for amd64 and arm64 (qemu).

**T-05 (unit)** Completions and the man page generate without error. Snapshot the man page.

**T-06 (unit)** Accessibility: every registry action is bound or palette-reachable. Every status indicator renders a text label in `NO_COLOR` (snapshot review list).

**T-07 (manual checklist, recorded in the release PR)** Install via each channel on a clean VM or container and run `sverb doctor`.

## 5. Passing functional characteristics
- [ ] Tagged releases are automated (release-plz) and produce static musl Linux, universal macOS and Windows client binaries, server binaries and a multi-arch distroless image, with checksums.
- [ ] Builds are reproducible. `cargo install sverb`, AUR (`sverb`, `sverb-bin`), Homebrew, Nix and Scoop are available.
- [ ] The documentation set is complete, with a man page and shell completions.
- [ ] The UI passes the accessibility audit: monochrome-usable, glyph fallbacks, keyboard-complete.
- [ ] The §22 open questions and all spec additions are resolved and recorded before 1.0.
