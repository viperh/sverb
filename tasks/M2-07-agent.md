# M2-07 — Agent forwarding, built-in agent and `sverb agent` local socket

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-conn/src/agent/{mod.rs, builtin.rs, forward.rs, socket.rs, peercred.rs, pipe_windows.rs}`, `crates/sverb-tui/src/views/dialogs/agent_confirm.rs`, `crates/sverb/src/cli/agent.rs` |
| **Spec refs** | §6.1.6, §4.2 (`agent_forwarding`, `agent_source`), §4.5 (`agent_forwardable`, `confirm_on_use`), §5.3 (locked → refuse), §17 (agent-forwarding abuse), §17.1 (`agent_forwarding` + `system` needs approval), §19 (e2e: `ssh-add -l` on remote) |
| **Depends on** | M2-03, M1-14 (agent client) |
| **Blocks** | M2-10 |

---

## 1. Current state in the codebase
`agent_client.rs` (M1-14) talks to the system agent for auth. The host fields `agent_forwarding` and `agent_source` exist in the model and
form, but nothing honors them.

## 2. Detailed description

### 2.1 Requesting forwarding
If the resolved `agent_forwarding == true`, send `auth-agent-req@openssh.com` on the session channel (`agent_forward(true)`),
before the PTY and shell (M1-13 step 5). The server then opens `auth-agent@openssh.com` channels, surfaced via
`client::Handler::server_channel_open_agent_forward`. Each such channel is served according to `agent_source`.

### 2.2 Agent sources (§6.1.6), default `builtin`
- **`system`:** splice the channel byte-for-byte to `SSH_AUTH_SOCK` (Unix) or the OpenSSH agent pipe / Pageant (Windows).
  If there's no system agent, close the channel and log at debug.
- **`builtin`:** serve the agent protocol with `russh::keys::agent::server` (or an in-house implementation over
  `ssh-agent-lib` if more control is needed) from keychain keys with **`agent_forwardable = true`** only.
  Certificates attached to those keys are served too (as additional identities). Supported requests:
  `REQUEST_IDENTITIES` and `SIGN_REQUEST` (with RSA flags for rsa-sha2-256/512). Everything else (add, remove, lock, extensions)
  → `SSH_AGENT_FAILURE`.
- **`both`:** built-in first. `REQUEST_IDENTITIES` returns the union (built-in first, deduplicated by public key). `SIGN_REQUEST` for a key
  the built-in agent doesn't hold → proxy that single request to the system agent.

### 2.3 Signing rules
- **Locked vault** → `SSH_AGENT_FAILURE` for every sign request (§5.3, §6.1.6), and the identities list is empty.
- **`confirm_on_use` key** → a modal "**<host label>** requests a signature with key **<key label>** [a]llow once / [d]eny"
  (§6.1.6). Requests from the local socket show the **peer process** instead (pid and executable name, from peer credentials where
  available). Timeout 60 s → deny. Concurrent requests queue.
- Each signature event is logged at debug (key fingerprint and requesting session id; never the data).

### 2.4 Local socket (`sverb agent [--socket <path>]`)
- Exposes the built-in agent locally, so plain `ssh` and `git` can use vault keys (§6.1.6).
- Default endpoint: `Paths::agent_endpoint()` (M0-03): `$XDG_RUNTIME_DIR/sverb/agent.sock` in a `0700` dir, with the socket
  `0600`. Windows: named pipe `\\.\pipe\sverb-agent` with an **owner-only DACL**.
- **Peer credential check:** `SO_PEERCRED` (Linux), `getpeereid` (macOS/BSD), and pipe client process token SID comparison (Windows).
  Connections from other UIDs are refused and closed immediately (§6.1.6).
- `sverb agent` runs in the foreground (headless), unlocks the vault via `require_unlocked` (M0-07/M1-04), prints
  `SSH_AUTH_SOCK=<path>; export SSH_AUTH_SOCK;` (sh syntax, plus `--fish`/`--csh` variants), and serves until killed. Auto-lock
  applies (idle = no agent requests for `auto_lock_minutes`), after which it refuses signing and prompts on the TTY when the next
  request arrives? **Decision:** headless agent mode refuses after auto-lock and logs it. The user restarts or unlocks via
  `sverb unlock --agent` (signal over the socket). Document this.
- **The TUI** also runs the local agent socket automatically while it's open? **The spec doesn't say.** Proposal: off by default,
  with an opt-in config `agent.socket_in_tui = false` (a new key; record it as a spec addition). The same socket is also used by `sverb lock`
  (M1-04) to signal the running TUI, which needs a control channel: use a sibling socket `control.sock` with the same permission rules.
- Socket file cleanup on exit. A stale socket from a crashed run (connect fails) is removed and recreated. A live socket owned by
  another sverb instance → error "agent already running (pid N)".

### 2.5 Approval (§17.1)
`agent_forwarding = true` combined with `agent_source ∈ {system, both}` coming from another device needs approval (M2-10)
before forwarding is requested.

## 3. Codebase changes
- **Create** the `sverb-conn::agent` modules. Deps: `ssh-agent-lib` (or russh agent server), `nix` (peer creds; it needs the
  documented `unsafe` exception? `nix` itself is safe to call, so no `unsafe` in our code), `windows-sys` for the DACL (behind cfg,
  inside a module with the documented exception, M7-05).
- **Implement** `cli/agent.rs`.

## 4. Test cases to implement

**T-01 (unit) Built-in identities** list only `agent_forwardable` keys plus their certs.

**T-02 (unit) Sign** with an ed25519 key → a valid signature verifying with the public key. RSA flags → correct algorithm.

**T-03 (unit) Locked** → FAILURE for sign, and an empty identity list.

**T-04 (unit) Unsupported requests** (add identity, remove all, lock) → FAILURE.

**T-05 (unit) `both` merge** deduplication, and sign fallback to a mock system agent for unknown keys.

**T-06 (reducer) confirm_on_use dialog**: allow → signature, deny → FAILURE, 60 s timeout → FAILURE.

**T-07 (integration, Unix) Socket permissions:** dir 0700, socket 0600.

**T-08 (integration, Linux) Peer UID check:** a connection from another UID (run a test helper under `sudo -u nobody` in CI, or simulate
via an injectable peer-cred provider) → refused.

**T-09 (integration) `ssh-add -l` against the local socket** lists the forwardable keys. `ssh -o IdentityAgent=<sock>` authenticates against
the e2e container using a vault key.

**T-10 (integration) Stale socket** replaced. Live socket → "already running".

**T-11 (e2e, forward profile)** Connect with `agent_forwarding = true` and `agent_source = builtin` → on the remote, `ssh-add -l` lists exactly
the forwardable keys (§19).

**T-12 (e2e) `agent_source = system`** with a test `ssh-agent` holding a different key → the remote `ssh-add -l` shows that key.

**T-13 (e2e) Forwarding off** → remote `ssh-add -l` says "Could not open a connection to your authentication agent".

**T-14 (integration, Windows)** The named pipe is created, the DACL grants only the current user SID (query the DACL), and `ssh-add -l` works via
`SSH_AUTH_SOCK=\\.\pipe\…`.

## 5. Passing functional characteristics
- [ ] Agent forwarding is requested per host. Forwarded channels are served by built-in, system or both, per `agent_source`.
- [ ] The built-in agent serves only `agent_forwardable` keys (plus certs), refuses everything when locked, and confirms `confirm_on_use` keys via a modal.
- [ ] `sverb agent` exposes a private local socket or pipe with peer-UID checks, usable by `ssh`, `ssh-add` and `git`.
- [ ] Forwarding the system agent for synced hosts from other devices requires approval.
