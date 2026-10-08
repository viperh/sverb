# M1-18 — End-to-end test harness (OpenSSH in Docker via `testcontainers`)

| | |
|---|---|
| **Milestone** | M1 (used by every later milestone) |
| **Touches** | `crates/sverb-e2e/` (`src/{lib.rs, sshd.rs, keys.rs, session.rs, pty.rs}`, `tests/*.rs`), `tests/fixtures/sshd/` (Dockerfile, configs, keys, CA), `.github/workflows/ci.yml` (`e2e` job from M0-02) |
| **Spec refs** | §19 (Transports e2e row), §3 (`tests/e2e`, `tests/fixtures`) |
| **Depends on** | M1-13 (to be useful); can start right after M0-02 |
| **Blocks** | e2e tests in M1-13…M3-07 |

---

## 1. Current state in the codebase
The `sverb-e2e` crate exists empty (M0-01), and the CI `e2e` job runs a placeholder (M0-02). No fixtures exist.

## 2. Detailed description

### 2.1 Container images (`tests/fixtures/sshd/`)
One Dockerfile (Alpine or Debian slim + OpenSSH + bash + zsh + fish + htop + vim + tmux + less + netcat + socat +
python3 for an HTTP echo service), plus **runtime-selected configs** for the scenarios §19 lists:

| Profile | sshd_config essentials | Used by |
|---|---|---|
| `password` | `PasswordAuthentication yes`, user `test`/`test` | M1-13/14 |
| `key` | `AuthorizedKeysFile`, `PasswordAuthentication no` | M1-14 |
| `cert` | `TrustedUserCAKeys /etc/ssh/user_ca.pub`, host cert `HostCertificate` signed by the test host CA | M1-14/15 |
| `kbd` | `KbdInteractiveAuthentication yes` + a PAM stack with a scripted OTP module (pam_exec script that checks a fixed code) | M1-14 |
| `maxauth2` | `MaxAuthTries 2` | M1-14 |
| `legacy` | `KexAlgorithms diffie-hellman-group14-sha1`, `HostKeyAlgorithms ssh-rsa`, `Ciphers aes128-cbc` | M1-13 |
| `env` | `AcceptEnv FOO` | M1-13 |
| `forward` | `AllowTcpForwarding yes`, `GatewayPorts clientspecified`, `AllowAgentForwarding yes` | M2-07/08 |
| `jump` | a 3-container network: `bastion` → `inner` (no direct route from the test runner to `inner`) | M2-05 |
| `windows-like` | `ForceCommand` that makes `uname` fail (simulates a non-POSIX shell) | M2-04 |

- Fixture keys (ed25519, ecdsa-p256, rsa-4096, an encrypted ed25519 with the passphrase `fixture`), the host CA and the user CA
  are committed under `tests/fixtures/sshd/keys/`. They're **test-only**. Add a README warning, and exclude them from
  secret scanners via a path allowlist.
- Images are built once per CI run (`docker build` cached with `actions/cache` or a GHCR-published image tagged by the
  Dockerfile hash).

### 2.2 Harness API (`sverb-e2e`)
- `Sshd::start(profile) -> Sshd { host, port, host_keys, stop(), pause(), unpause(), restart(),
  regenerate_host_key(), exec(cmd) -> output }`, via `testcontainers` (async runner).
- `JumpNet::start() -> { bastion: Sshd, inner_addr_from_bastion }`.
- `TestHome`: a temp `SVERB_HOME` with an initialized vault (fast Argon2 params via the test override from M1-04),
  helpers to add hosts, keys and known hosts directly through the store and item services.
- `Headless` session driver: runs the session manager without a TUI and collects the emulator grid
  (`grid_text()`) with `wait_for_text("pattern", timeout)`.
- `PtyApp`: launches the real `sverb` binary inside a `portable-pty` with a given size, sends key strings (chord syntax
  from M0-10) and reads the screen through a local `alacritty_terminal` instance (the same emulator as the product),
  with `wait_for_screen(predicate)`.
- Every test is `#[ignore]` by default, so `cargo test` stays fast. CI runs them with `-- --ignored`. A
  `SVERB_E2E=1` guard returns early with a skip message when Docker isn't available locally.

### 2.3 Reliability rules
- No fixed sleeps. Always poll with a timeout (default 10 s, CI 20 s).
- Each test uses its own container (parallel-safe), or a shared one per profile through a `OnceCell` with unique users.
- On failure, dump the container logs (`docker logs`) and the last screen to the test output.

## 3. Codebase changes
- **Create** `tests/fixtures/sshd/{Dockerfile, profiles/*.conf, pam/, keys/, README.md}`.
- **Create** `crates/sverb-e2e/src/*`. Deps: `testcontainers`, `portable-pty`, `tokio`, internal crates.
- **Update** the CI `e2e` job to build the image and run the tests. Mark it required after this task.

## 4. Test cases to implement (self-tests of the harness)

**T-01** `Sshd::start(password)` → `exec("whoami")` = `test`.

**T-02** `Headless` connects with password auth to the `password` profile and `wait_for_text("$")` succeeds.

**T-03** `pause()` / `unpause()` work (used by keepalive tests).

**T-04** `regenerate_host_key()` changes the host fingerprint.

**T-05** `JumpNet`: `inner` is unreachable directly from the runner (TCP connect fails) and reachable from the bastion (`exec("nc
-z inner 22")`).

**T-06** `PtyApp` launches sverb, sees the shell ("Hosts" visible), sends `ctrl-\ q`, and the process exits 0.

**T-07** Failure diagnostics: a deliberately failing assertion prints the container logs and the screen dump (verify with a
`#[should_panic]` test that captures output).

## 5. Passing functional characteristics
- [ ] All §19 SSH scenarios have container profiles: password, key, cert, keyboard-interactive, jump chain, `MaxAuthTries 2`,
      legacy-only, plus env, forward and windows-like.
- [ ] Tests can drive sessions headlessly and drive the real TUI binary in a PTY.
- [ ] The e2e suite runs in CI on Linux as a required job. Locally it's opt-in and skips cleanly without Docker.
- [ ] There are no sleep-based waits, and failures dump useful diagnostics.
