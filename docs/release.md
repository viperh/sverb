# Releasing sverb

How a release is cut (SPEC §20), what the automation checks, and the manual checks that
remain. The files involved: `release-plz.toml`, `.github/workflows/release-plz.yml`,
`.github/workflows/cd.yml`, `scripts/release-package.sh`, `scripts/update-packaging.py`,
`packaging/`, `flake.nix`, `deploy/Dockerfile.server.release`.

## 1. The flow

1. Merge to `main` with [conventional commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `sec:`, `perf:`, `refactor:`, `docs:`; `build:`/`ci:`/`chore:`/`test:`
   are left out of the changelog).
2. `release-plz.yml` opens or updates the **release PR**. It bumps `workspace.package.version`
   and the internal dependency versions together (all published crates share one version)
   and adds a `## [X.Y.Z] - date` section to `CHANGELOG.md`. Edit the changelog in the PR if
   needed; that is the release note.
3. Before merging, do the [manual checks](#3-manual-checks-t-07) on the release PR's head (the
   `cd.yml` dry run gives you the archives).
4. Merging the PR publishes every `sverb-*` crate to crates.io in dependency order, pushes the
   tag `vX.Y.Z` and creates the GitHub release.
5. The tag starts `cd.yml`, which builds, checks and uploads everything below, then updates the
   package channels.

The sync protocol version (`/v1`, `Sverb-Proto: 1`) is separate: bump it only for an
incompatible wire change, and keep the server serving N and N−1.

## 2. What `cd.yml` produces and checks

| Job | Output | Checks |
|---|---|---|
| `assets` | `man/sverb.1`, `completions/{sverb.bash,_sverb,sverb.fish,_sverb.ps1}` | `bash -n`, `groff -ww` clean |
| `linux` (x86_64, aarch64) | `sverb-<v>-linux-<arch>.tar.gz`, `sverb-server-<v>-linux-<arch>.tar.gz` | static (`file`: statically linked), **T-01**; x86_64 built twice from two directories and compared byte for byte, **T-02** |
| `macos` | `sverb-<v>-macos-universal.tar.gz` | `lipo -info` lists x86_64 and arm64, **T-01**; signed and notarized when the Apple secrets exist |
| `windows` | `sverb-<v>-windows-x86_64.zip` | |
| `image` | `ghcr.io/<owner>/sverb-server:<v>` and `:latest`, amd64 + arm64 | each arch (arm64 under qemu) runs `--version` and comes up `healthy` in the compose stack, **T-04** |
| `release` | `SHA256SUMS`, `*.sha256`, CycloneDX SBOM, release notes from `CHANGELOG.md` | `sha256sum -c` |
| `channels` | AUR `sverb` and `sverb-bin`, Homebrew `homebrew-sverb`, Scoop `scoop-sverb` | |

Run it without publishing from the Actions tab: **CD → Run workflow** with `dry-run` checked
(the default). The archives and notes are attached to the run as `release-dry-run`.

`ci.yml` also runs on every push: `nix` (`nix build .#sverb`, **T-03**) and `packaging`
(channel-file self-test and syntax, reproducible archives, `cargo package --workspace`, which
proves the crates build from their published form).

Reproducibility rules (§17): `--locked`; `SOURCE_DATE_EPOCH` is the tagged commit's time (vergen
uses it for the build date); `-C strip=symbols`; `--remap-path-prefix` for the checkout and the
cargo home; archives are sorted, owned by 0:0, dated `SOURCE_DATE_EPOCH`, and gzip stores no
name or time (`scripts/release-package.sh`).

### Secrets

| Secret | Used by | Without it |
|---|---|---|
| `RELEASE_PLZ_TOKEN` | release-plz (a PAT: contents and pull-requests write) | the tag pushed with `GITHUB_TOKEN` doesn't start `cd.yml` |
| `CARGO_REGISTRY_TOKEN` | crates.io publish | no crates.io release |
| `AUR_SSH_PRIVATE_KEY` | AUR push | AUR skipped |
| `HOMEBREW_TAP_TOKEN` | push to `<owner>/homebrew-sverb` | tap skipped |
| `SCOOP_BUCKET_TOKEN` | push to `<owner>/scoop-sverb` | bucket skipped |
| `APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER` | macOS signing and notarization | unsigned binary ([faq.md](faq.md#macos-gatekeeper-says-the-binary-cant-be-opened)) |

The tap and bucket repositories must exist before the first release. The AUR packages must be
registered once by hand (push the first `PKGBUILD` and `.SRCINFO` from `packaging/aur/`).

## 3. Manual checks (T-07)

Record the results in the release PR. On a clean VM or container for each channel:

- [ ] `cargo install sverb --locked` (and `--no-default-features`), then `sverb doctor`
- [ ] the Linux tarball (x86_64 and aarch64) on a distribution without Rust: `sverb doctor`, `man ./man/sverb.1`
- [ ] AUR: `sverb` and `sverb-bin` with `makepkg -si` in a clean Arch container; completions load in bash, zsh and fish
- [ ] Homebrew on macOS (Intel and Apple silicon) and Linux: `brew install`, `brew test sverb`, `sverb doctor`
- [ ] Nix: `nix run github:<owner>/sverb -- doctor`
- [ ] Scoop on Windows 11 (Windows Terminal): `scoop install sverb`, `sverb doctor`, open a session to an OpenSSH server
- [ ] macOS universal tarball: Gatekeeper behavior matches the docs (signed or unsigned)
- [ ] Docker: `docker run ghcr.io/<owner>/sverb-server:<v> --version`, then the compose quick start from [self-hosting.md](self-hosting.md) on amd64 and arm64
- [ ] one sync round trip between two devices against the released server

## 4. Before the first 1.0 tag

Things the 1.0 release candidate could not finish or verify offline; see the M7-07 report and
`tasks/04-PROGRESS.md` for detail.

- Run the release pipeline for real: a `cd.yml` dry run (musl builds, the reproducibility
  comparison, `lipo`, the arm64 image under qemu), the `nix` CI job, and the first crates.io
  publish. None of these could run on the development machine (no network, no musl targets,
  no Nix, no Docker daemon).
- Windows: compile and test on Windows (the DACL and hardening modules have never been
  compiled; M2-07 T-14).
- PostgreSQL: the PostgreSQL-backed server tests (sync, rotation, sharing) only run in CI.
- Docker: the end-to-end suite against OpenSSH containers (`sverb-e2e`), including the M1-15
  host-key cases that are still `unimplemented!` placeholders.
- Supply chain: fix the cargo-vet store and add the pending exemptions; run cargo-deny.
- Fuzzing: a nightly cargo-fuzz run with sanitizers.
- Features still open from earlier tasks: account recovery has no UI or command; the TUI connect
  approval dialog and "needs approval" badges (M2-10); `terminal.bell` modes other than visual;
  live `read_ssh_config` (decided post-1.0); panic messages are not redacted in crash reports.
