# M7-05 — Security hardening, canary tests, fuzzing, threat model

| | |
|---|---|
| **Milestone** | M7 (cross-cutting; individual checks can land earlier) |
| **Touches** | new `crates/sverb-core/src/hardening/{mod.rs, unix.rs, windows.rs}` (the **only** module allowed `unsafe`), `fuzz/` (cargo-fuzz workspace), `.github/workflows/{ci.yml, fuzz.yml}`, `docs/threat-model.md`, a CI log-canary script |
| **Spec refs** | §17 (table, `forbid(unsafe_code)` exceptions), §17.1, §19 (Fuzzing row, canary log test), §5.2 (no plaintext on disk) |
| **Depends on** | all feature tasks (it verifies them) |
| **Blocks** | 1.0 RC |

---

## 1. Current state in the codebase
Each task added local canary tests and fuzz stubs (`fuzz_targets/*.rs` referenced in M1-01, M1-09, M1-11, M1-15, M2-08, M2-11, M6-02, M7-03). `#![forbid(unsafe_code)]` is everywhere (M0-01).
Core dumps aren't disabled (M0-05 left a TODO).

## 2. Detailed description

### 2.1 Process hardening (§17 "Memory scraping")
- **Core dumps disabled** on Linux: `prctl(PR_SET_DUMPABLE, 0)` at startup (it also blocks ptrace by non-root same-UID processes). macOS: `setrlimit(RLIMIT_CORE, 0)`. Windows:
  `SetErrorMode` / WER exclusion is best effort.
- **mlock** (best effort) of the pages holding the LMK and VKs: allocate key material in a dedicated locked arena (`memsec`/`region` crates, or `libc::mlock`) with graceful fallback if
  `RLIMIT_MEMLOCK` is too low (log once at debug).
- These require `unsafe`: the `hardening` module carries `#![allow(unsafe_code)]` with a documented justification. The workspace lint stays `forbid` elsewhere. **Note:**
  `forbid` can't be overridden by `allow`, so change the workspace level to `deny` and add a CI check (grep) that `allow(unsafe_code)` appears **only** in
  `sverb-core/src/hardening/` and the Windows DACL module from M2-07. Document this in `docs/threat-model.md`.

### 2.2 Canary tests (§17 "Secrets in logs", §19)
A CI job runs the **whole test suite** with `SVERB_LOG=trace`, and test fixtures plant canary secrets (`CANARY-PW-…`, `CANARY-KEY-…`, `CANARY-HOST-…`). After the run, grep **all** log
files, crash reports, the SQLite DB files, recordings, backups and server DB dumps (in server tests) for the canary strings:
- secrets (passwords, keys, passphrases, tokens) must **never** appear anywhere except encrypted containers,
- hostnames must not appear in `info`+ logs (per §17; debug may contain hostnames, so filter by level).
Implemented as `scripts/canary-scan.sh` plus fixture conventions, documented in CONTRIBUTING.

### 2.3 Fuzzing (§19)
`cargo-fuzz` targets, each with a seed corpus from the fixtures: `ssh_config_parse`, `ppk_parse`, `known_hosts_parse`, `socks5_request`, `share_frame_decode`, `envelope_open`,
`key_event_encode`, plus `emulator_feed`, `backup_decrypt`, `http_connect_response`, `osc133_scan`. A nightly GitHub workflow runs each for 10 minutes and uploads crashes as artifacts. PR CI runs each for 30 s.

### 2.4 Emulator-level protections (§17 "Malicious remote output")
Verify and consolidate, each with a test: OSC 52 writes are gated (M1-11), OSC 52 reads are always denied (M1-09), no OSC executes or opens anything without confirmation (audit
alacritty's handlers: OSC 7 cwd only stores, OSC 8 needs a keypress, M3-04), titles are capped at 256 (M1-09), query responses are emulator-generated (M1-09 T-05),
and an `ESC[201~` injection in pastes is stripped (M1-11).

### 2.5 Threat model document
`docs/threat-model.md`: assets, actors (malicious server operator, network attacker, malicious remote host, malicious teammate, local attacker with or without an unlocked session),
the §17 table expanded with references to the implementing tasks and tests, residual risks (revoked members keep old data; trust in the server's membership list for grants, M5-03;
debug logs contain hostnames; OSC 52 relies on the outer terminal), and the supply-chain controls (M0-02).

### 2.6 Review checklist
A one-time audit pass: grep for `expose()` calls on secrets (each one justified), `unwrap()` in non-test code, `Debug` derives on types with secret fields, and logging of `?ResolvedHost` at `info`.

## 3. Codebase changes
- The hardening module, the fuzz workspace, the CI workflows, the canary script and the threat-model doc. Switch the workspace `unsafe_code` lint from `forbid` to `deny`, plus the grep check.

## 4. Test cases to implement

**T-01 (integration, Linux)** After startup, `/proc/self/status` shows `CoreDumping`/dumpable 0 (read `prctl(PR_GET_DUMPABLE)` from a test hook).

**T-02 (unit)** mlock fallback with `RLIMIT_MEMLOCK=0` → no crash and a debug log.

**T-03 (CI)** The canary scan passes on main. On a throwaway branch with a deliberate `info!("{}", password.expose())`, the scan fails.

**T-04 (CI)** The `unsafe` grep check fails if `allow(unsafe_code)` appears outside the allowed modules.

**T-05 (fuzz)** Each target builds and runs 30 s in PR CI without crashes.

**T-06 (unit, consolidated)** The emulator-protection tests listed in §2.4 run together in one `security` test module.

## 5. Passing functional characteristics
- [ ] Core dumps are disabled and key material is mlocked where supported. `unsafe` is confined to documented modules and checked by CI.
- [ ] A CI canary scan proves no secrets reach logs, crash reports, the DB or server dumps, and no hostnames reach `info`+ logs.
- [ ] All §19 fuzz targets (plus extras) exist, run briefly on PRs and long nightly.
- [ ] Every §17 mitigation is mapped to code and tests in `docs/threat-model.md`.
