# M7-04 — `sverb doctor [--algos]`

| | |
|---|---|
| **Milestone** | M7 |
| **Touches** | `crates/sverb/src/cli/doctor.rs`, `crates/sverb-tui/src/runtime/capabilities.rs` (shared detection), `crates/sverb-conn/src/ssh/algorithms.rs` (list) |
| **Spec refs** | §16 (`doctor`), §6.1.8 (`sverb doctor --algos` lists the offered algorithms), §1 (degrades without truecolor, mouse or kitty protocol) |
| **Depends on** | M1-13, M1-11, M4-09 |
| **Blocks** | — |

---

## 1. Current state in the codebase
The capability detection code lives in several places (truecolor in M0-11, kitty in M1-11, the keyring probe in M1-04, the agent client in M1-14). `doctor` is a stub (M0-07).

## 2. Detailed description
Headless diagnostic report with sections, each line marked `✓` / `!` / `✗` (ASCII fallback `[ok]`/`[warn]`/`[fail]`), with remediation hints. `--json` is available too.
1. **Environment:** sverb version + features, OS/arch, `SVERB_HOME`, the resolved paths and their permissions (warn if not 0700), config validity (M0-06), DB schema version and
   integrity (`PRAGMA quick_check`), log dir writable.
2. **Terminal:** `TERM`, `COLORTERM` → truecolor yes/no, 256 colors, kitty keyboard protocol support (query with a timeout; only when stdout is a TTY), mouse, bracketed paste,
   OSC 52 likely support (a heuristic by `TERM_PROGRAM`; can't be detected reliably, so say so), unicode width sanity (`unicode-width` vs a cursor-position probe of a wide char), whether
   running over SSH (`SSH_CONNECTION`), and tmux/screen detection (warn about OSC 52 passthrough needing `set -g set-clipboard on` and allow-passthrough).
3. **Agent:** `SSH_AUTH_SOCK` reachable, number of identities, the Windows OpenSSH pipe or Pageant. The sverb built-in agent socket status, if running.
4. **Keyring:** availability (probe), and whether keyring unlock is enabled.
5. **Sync** (if compiled and configured): server URL reachable (`/healthz`, `/readyz`), protocol version compatible, token valid (a refresh dry run without rotating? Rotation is
   mandatory on refresh, so call an authenticated cheap endpoint like `GET /v1/devices` instead), WS connect + auth round-trip, clock offset vs the server `Date` header
   (warn if > 60 s, which matters for HLC skew).
6. **`--algos`:** print the kex, host-key, cipher, MAC and compression lists actually offered (§6.1.8), marking which are default vs legacy opt-in and which of the spec's preferred
   list are **unavailable** in the pinned russh (e.g. `mlkem768x25519-sha256`).
Exit code: 0 if no `✗`, 1 otherwise. Doctor never modifies anything.

## 3. Codebase changes
- Consolidate the capability detection functions into a shared module used by both the TUI startup and doctor.

## 4. Test cases to implement

**T-01 (snapshot)** Doctor text output with injected fake probes (all ok; mixed), so it's deterministic.

**T-02 (snapshot)** `--json` schema.

**T-03 (unit)** Permission warnings for a 0755 data dir.

**T-04 (unit)** The `--algos` list equals the M1-13 preference table filtered by the pinned russh support, with legacy marked.

**T-05 (integration)** Not a TTY → terminal probes are skipped with "not a terminal" and no escape sequences are written.

**T-06 (integration, TestServer)** The sync section reports ok. With the server down → `✗` and exit 1.

**T-07 (unit)** Clock offset warning when the server `Date` is 5 min off.

## 5. Passing functional characteristics
- [ ] `sverb doctor` diagnoses the environment, paths, config, DB, terminal capabilities, agent, keyring and (if configured) sync, with actionable hints and a 0/1 exit code.
- [ ] `sverb doctor --algos` lists the SSH algorithms actually offered and flags spec-preferred ones that are unavailable.
- [ ] Doctor is read-only and safe to run in non-TTY contexts.
