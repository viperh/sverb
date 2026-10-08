# M1-13 — SSH connection core: resolve, TCP, handshake, session channel, data path, keepalive, algorithms, error mapping

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-conn/src/ssh/{mod.rs, connect.rs, tcp.rs, handler.rs, channel.rs, algorithms.rs, errors.rs, keepalive.rs}`, `crates/sverb-core/src/resolve.rs` (minimal `ResolvedHost` until M2-01) |
| **Spec refs** | §6.1.1 (steps 1–3, 5–8), §6.1.8, §6.1.9, §4.2 (`env`, `keepalive_secs`, `backspace`, `algorithms`, `startup_snippet_id`), §15 `[ssh]` |
| **Depends on** | M1-08, M1-07 |
| **Blocks** | M1-14, M1-15, M1-16, M2-04…M2-08, M3-07 |

---

## 1. Current state in the codebase
The session actor (M1-08) can run any `Transport`. Hosts exist (M1-07). There's no SSH code. `russh`'s version is pinned in the
workspace (M0-01). Per §6.1.1, all russh API usage stays inside `sverb-conn::ssh`, so upstream renames touch one module.

## 2. Detailed description

### 2.1 `ResolvedHost` (minimal now, full in M2-01)
`{ address, port (default 22), username (inline → identity → `$USER`), auth material refs, jump_chain: [],
proxy: None, env, keepalive_secs (host → `ssh.keepalive_secs`), charset, backspace, color_scheme,
algorithms overrides, agent settings, startup_snippet_id, request_pty_for_exec, provenance map (empty) }`.
Built by `resolve(host, store, config)`. M2-01 extends it with group inheritance.

### 2.2 Connection flow (§6.1.1)
1. **Resolve** (state `Resolving`): build `ResolvedHost`, then DNS via `tokio::net::lookup_host((addr, port))`. **Never
   cache** across connections. IP literals skip DNS.
2. **Stream** (`Connecting{1,1}`):
   - **Direct TCP with Happy Eyeballs (RFC 8305):** sort the results to interleave families with IPv6 first. Start the first
     attempt, start the next after 250 ms if not yet connected (or immediately on failure), and the first success wins.
     Cancel the others (drop the futures). The overall timeout is `ssh.connect_timeout_secs` (15). Set `TCP_NODELAY`.
   - Proxy streams (M2-06) and jump channels (M2-05) plug in here behind a `StreamFactory` enum.
3. **Handshake:** `russh::client::connect_stream(config, stream, handler)`. `Handler` implements
   `check_server_key` → delegates to the known-hosts verifier (M1-15). Until M1-15 lands, use a dev-only
   "accept and warn" verifier behind a test flag.
4. **Authentication:** M1-14.
5. **Session channel:** `channel_open_session`, then:
   - `set_env` for each `env` pair, ignoring rejections (logged at `debug`, §6.1.1),
   - agent forwarding request (M2-07 hook),
   - `request_pty(term = terminal.term, cols, rows, px_w, px_h, modes)`, where `modes` includes
     `VERASE` = 0x7f (Del) or 0x08 (CtrlH) from `backspace`, and `IUTF8 = 1` (only when the charset is UTF-8;
     document it),
   - `request_shell`.
6. **Post-connect:** start auto-start forwards (M2-08 hook). Run the startup snippet (M2-09 hook): send it as typed
   input once the first output arrives or after 500 ms, whichever comes first.
7. **Keepalive:** `russh::client::Config { keepalive_interval: Some(keepalive_secs), keepalive_max: 3 }` (sends
   `keepalive@openssh.com`). After 3 missed replies the session becomes `Disconnected{Timeout}`. Measure the keepalive
   **RTT**, emit `SessionEvent::Latency` and show it in the status bar (`23ms`). If russh doesn't expose the RTT, send our
   own `keepalive@openssh.com` global request with `want_reply` on a timer and time the reply.
   `keepalive_secs = 0` disables keepalive (and the latency display shows `–`).
8. **Data path:** `channel.wait()` loop: `Data` → emulator, `ExtendedData{ext:1}` (stderr) → emulator,
   `ExitStatus(code)` → remember it, `ExitSignal` → remember it, `Eof`, `Close` → state `Disconnected{Exited(code)}` (or
   `Closed` when the user closed it). Writes use `channel.data(&bytes[..])`. Resize uses `channel.window_change(cols, rows, px_w,
   px_h)`.
- `SshTransport` adapts the channel to the `Transport` trait (M1-08) so the session actor is unchanged.

### 2.3 Algorithms (§6.1.8)
- Build `russh::Preferred` from a sverb table: kex `mlkem768x25519-sha256` (if the pinned russh has it),
  `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`,
  `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`. Host keys: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`,
  `rsa-sha2-512`, `rsa-sha2-256` + cert variants. Ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
  `aes128-gcm@openssh.com`, `aes256-ctr`, `aes128-ctr`. MACs: `hmac-sha2-512-etm@openssh.com`,
  `hmac-sha2-256-etm@openssh.com`. Compression: `none`.
- **Only offer what the pinned russh implements.** Filter the table at compile time or startup against russh's
  supported lists. `sverb doctor --algos` (M7-04) prints the result.
- **Per-host legacy opt-in** (`Host.algorithms`): `AlgoOverrides { kex_extra, hostkey_extra, cipher_extra, mac_extra,
  compression: bool }`, each a subset of the disabled-by-default list (`diffie-hellman-group14-sha1`,
  `diffie-hellman-group1-sha1`, `ssh-rsa`, `ssh-dss`, `aes*-cbc`, `3des-cbc`, `hmac-sha1`,
  `zlib@openssh.com`). These are **appended** after the secure preferences.
- **Host-key order adjustment** (§9.5): before connecting, move key types already present in known_hosts for this host
  to the front (M1-15 provides the lookup).
- Log the negotiated algorithms at `debug`. The session info panel (`i` on a pane or `leader i`) shows them.
- **No common algorithm:** parse the server's KEXINIT offer (russh error detail or our handler) and produce the message:
  "No common key exchange: server offers diffie-hellman-group14-sha1. Enable it for this host in Host →
  Connection → Algorithms (legacy)." (§6.1.8)

### 2.4 Error mapping (§6.1.9)
`DisconnectReason` → user message, with the raw error chain kept for the detail view (`ErrorReport`):
- DNS failure → `Resolve`: "Could not resolve `host`"
- TCP refused or timeout → `Connect`: "Connection refused / timed out (`addr`)"
- No common algorithms → `Negotiation`: "No common key exchange: server offers …"
- Host key rejected or changed → `HostKey`: "Host key verification failed"
- All auth failed → `Auth`: "Permission denied (methods tried: …)"
- Keepalive timeout → `Timeout`: "Connection lost (no response for N s)", where N = interval × 3
- Remote exit → `Exited(code)`: "Session ended (exit N)", with no reconnect banner.
Hostnames appear in UI messages but **not** in `info`+ logs (§17). Log the `SessionId` instead.

### 2.5 Session lifecycle hooks
`ConnLog` entries (M3-06) are created on attempt start and finalized on end. Leave the hook calls now with a no-op sink.
`device_local.touch_connected` is called on `Connected` (frecency, M1-03).

## 3. Codebase changes
- **Create** the `sverb-conn::ssh` modules. Deps: `russh`, `russh-keys` (or `russh::keys`), `tokio` net/time.
- **Create** `sverb-core::resolve` (minimal).
- **Wire** `Effect::OpenSession(SessionSpec::Ssh(..))` from the Hosts view `Enter` and quick connect (M1-07).
- The session info panel widget (`widgets/session_info.rs`) shows the negotiated algorithms, server version,
  connected-since time and latency.

## 4. Test cases to implement
Unit tests use mocks. Real-server tests use the M1-18 harness (OpenSSH in Docker) and are marked `#[ignore]` until it exists.

**T-01 (unit) Happy Eyeballs ordering.** The address list [v4a, v4b, v6a, v6b] → attempt order v6a, v4a, v6b, v4b.

**T-02 (unit, mock connector) Happy Eyeballs timing.** The v6 attempt hangs and v4 succeeds at 10 ms. The v4 attempt
starts at 250 ms (virtual time) and the winner is v4. When v6 fails immediately, v4 starts immediately.

**T-03 (unit) Connect timeout** after 15 s (virtual) → `Connect` reason with the timed-out wording.

**T-04 (unit) PTY modes.** `backspace = CtrlH` → VERASE 8. UTF-8 → IUTF8 1. A non-UTF-8 charset → no IUTF8.

**T-05 (unit) Algorithm preferences.** The secure list is filtered against the russh-supported set. With overrides
`{kex_extra:[dh-group14-sha1]}` it's appended at the end. Legacy algorithms are never present without an override.

**T-06 (unit) Host-key reordering.** Known types [rsa-sha2-512] → the host-key list starts with rsa-sha2-512.

**T-07 (unit, table) Error mapping.** Each underlying error class → the expected `DisconnectReason` and message.

**T-08 (e2e) Connect + shell.** Password auth against the container (M1-14 dependency for the auth part).
`echo $TERM` → `xterm-256color`. The grid shows output.

**T-09 (e2e) Env.** Server with `AcceptEnv FOO`: `FOO=bar` is visible via `echo $FOO`. A rejected env var (`BAR`) causes no
error toast.

**T-10 (e2e) Resize.** Resize the pane → `stty size` on the remote matches.

**T-11 (e2e) Exit status.** `exit 7` → `Disconnected{Exited(7)}`, with no reconnect banner.

**T-12 (e2e) Keepalive timeout.** Pause the container (`docker pause`) with `keepalive_secs = 1` → `Disconnected{Timeout}`
within about 4 s. The message says "no response for 3 s".

**T-13 (e2e) Latency.** A `Latency` event arrives within 2 × keepalive, and the status bar shows `Nms`.

**T-14 (e2e) Legacy-only server.** The container is configured with only `diffie-hellman-group14-sha1` → `Negotiation`
error naming it. After enabling the override on the host → connects.

**T-15 (e2e) stderr.** `ls /nonexistent` output appears in the pane.

**T-16 (e2e) Startup snippet** (with a stub snippet until M2-09) → sent after the first output.

**T-17 (unit) No hostnames in info logs.** Run a mock connection with the capture subscriber at `info` and grep for
the address → absent.

## 5. Passing functional characteristics
- [ ] Connections follow §6.1.1: per-connection DNS, Happy Eyeballs with a 250 ms stagger, TCP_NODELAY, connect timeout.
- [ ] The session channel sets env (rejections ignored), a PTY with the correct TERM, VERASE and IUTF8, and a shell.
- [ ] Data, stderr, exit status, EOF and close are handled. Writes and window changes work.
- [ ] Keepalive with `keepalive_max = 3` detects dead links, and the RTT is shown as latency.
- [ ] The algorithm preferences match §6.1.8, offer only what russh implements, and allow per-host legacy opt-in with
      actionable errors.
- [ ] Errors map to the §6.1.9 reasons and messages, with detail chains. Hostnames are kept out of `info` logs.
- [ ] All russh API usage is confined to `sverb-conn::ssh`.
