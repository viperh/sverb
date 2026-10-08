# M2-08 — Port forwarding: Local, Remote, Dynamic (SOCKS), standalone tunnels, `sverb forward`

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-conn/src/forward/{mod.rs, local.rs, remote.rs, dynamic.rs, socks_server.rs, manager.rs}`, `crates/sverb-tui/src/views/forwards.rs`, status bar forwards segment, `crates/sverb/src/cli/forward.rs` |
| **Spec refs** | §9.6, §4.8, §4.2 (`port_forwards` auto-start), §8.5 (Forwards view), §17.1 (non-loopback binds / remote dest need approval), §19 (SOCKS5 conformance, half-close, 256 cap) |
| **Depends on** | M1-13, M1-16 |
| **Blocks** | M2-10, M3-07 |

---

## 1. Current state in the codebase
The `PortForward` typed view exists (M1-02). The Forwards sidebar section is a placeholder (M0-11), and `sverb forward` is a stub (M0-07).

## 2. Detailed description

### 2.1 Rule model (§4.8)
`PortForward { label, kind: Local|Remote|Dynamic, host_id, bind_addr (default 127.0.0.1), bind_port, dest_host (None
for Dynamic), dest_port, auto_start }`. Validation: ports 1–65535, except remote `bind_port = 0`, which is allowed (server-allocated); dest
required for Local and Remote; `bind_addr` a valid IP or `localhost` or `*`/`0.0.0.0`/`::`.

### 2.2 Local (`-L`)
`TcpListener::bind(bind_addr:bind_port)`. For each accepted connection → `channel_open_direct_tcpip(dest_host, dest_port,
peer_ip, peer_port)` → `tokio::io::copy_bidirectional` between the TCP stream and the channel stream. **Half-close** propagates both ways:
TCP FIN → channel `eof`, and channel `eof` → `shutdown(Write)` on TCP. Bind failure → state `error: address in use` (or the OS message).

### 2.3 Remote (`-R`)
`tcpip_forward(bind_addr, bind_port)`. If `bind_port == 0`, the server returns the allocated port, which is shown in the UI and status
table. Incoming `forwarded-tcpip` channels arrive via `Handler::server_channel_open_forwarded_tcpip(connected_address,
connected_port, originator…)`, are matched to the rule by `(connected_address, connected_port)`, and are then connected locally to
`dest_host:dest_port` and spliced (half-close as above). An unmatched channel → reject. Stopping the rule → `cancel_tcpip_forward`.

### 2.4 Dynamic (`-D`), the SOCKS server (RFC 1928)
- Methods: offer **no-auth** (0x00) only. If the client doesn't offer 0x00 → reply 0xFF and close.
- Commands: **CONNECT** only. `BIND` and `UDP ASSOCIATE` → reply `0x07` (command not supported) and close.
- Address types: IPv4 (0x01), domain (0x03), IPv6 (0x04). Others → reply `0x08`.
- **Domain names are passed unresolved to `direct-tcpip`** (remote DNS; no local DNS leak).
- **SOCKS4/4a** accepted (§9.6): parse a VN=4 request. 4a with `0.0.0.x` + domain → remote resolution. Reply 0x5A on success, 0x5B
  on failure.
- Success reply: `0x00` with BND.ADDR = 0.0.0.0:0 (as OpenSSH does). Failure mapping: channel open failure "connect failed" →
  0x05 (connection refused), administratively prohibited → 0x02, unreachable → 0x04.
- Request parsing timeout 10 s, and a max domain length of 255.

### 2.5 Lifecycle (§9.6)
- Each rule runs as its own task with a `CancellationToken` that is a **child of the connection's token**. A dropped connection stops all
  its rules (state `stopped (connection lost)`). Reconnect (M1-16) restarts the `auto_start` rules.
- **Max 256 concurrent channels per rule.** Further accepts are refused (accept and immediately close, and for SOCKS send failure
  0x01), and the UI shows a `256/256` saturation indicator.
- **Modes:** with a terminal session (auto-start when the host connects, §4.2 `port_forwards` + rule `auto_start`), or **standalone**
  ("Start without terminal": a tunnel-only connection with no shell channel and no tab, §9.6). Standalone connections show in the Forwards view
  and the status bar only.
- **Non-loopback bind** (§9.6): binding to anything other than 127.0.0.0/8 or ::1 asks for confirmation **the first time** (per rule and
  value, stored in device-local approvals; M2-10 provides the store). For synced rules, the §17.1 approval applies too.
- **Remote dest non-loopback** → approval per §17.1 (M2-10).

### 2.6 Forwards view and status (§8.5, §9.6)
- Saved rules list, plus a **live status table**: rule, kind, `bind → dest`, state (`listening` / `error: address in use` / `stopped`),
  active connections, bytes in and out (atomic counters, refreshed at ≤ 2 Hz to limit redraws). Actions: start, stop, add, edit, start without
  terminal, delete.
- Status bar segment: `⇄ L:5432→db:5432` for one, or `⇄ 3 forwards` for several (§8.1).

### 2.7 `sverb forward <rule> [--detach]` (§16)
- Resolves the rule by label (fuzzy), unlocks (headless), connects standalone, starts the rule, and prints `listening on 127.0.0.1:5432 → db:5432`.
  Ctrl-C stops it.
- `--detach`: daemonize (Unix: double-fork + setsid, writing a pid file to the runtime dir; Windows: spawn a detached child process with
  `CREATE_NO_WINDOW`), with logs to the state dir. **Note:** auth prompts are impossible after detaching, so detach only after the connection
  is established. Approvals required → exit 5 (§17.1).

## 3. Codebase changes
- **Create** the forward modules and the Forwards view. The SOCKS parser is a separate pure module (fuzz target).

## 4. Test cases to implement

### SOCKS conformance (§19), unit tests over an in-memory stream with a mock "direct-tcpip" opener
**T-01** CONNECT IPv4 → the opener is called with `"1.2.3.4", 80` and the reply is `05 00 00 01 00000000 0000`.
**T-02** CONNECT domain `example.com:443` → the opener is called with the **domain string** (not resolved).
**T-03** CONNECT IPv6.
**T-04** BIND → reply 0x07. UDP ASSOCIATE → 0x07.
**T-05** No acceptable auth method (client offers only 0x02) → `05 FF`.
**T-06** Unknown ATYP → 0x08.
**T-07** SOCKS4 CONNECT IPv4 → 0x5A. SOCKS4a with a domain → the opener gets the domain.
**T-08** Truncated and garbage requests → closed without panic, and the timeout fires after 10 s (virtual).
**T-09** Opener failure "connection refused" → reply 0x05.

### Local and remote (integration with a mock SSH channel, plus e2e)
**T-10 (integration) Half-close.** The client sends data then FIN. The channel receives data then eof. The server responds after eof and the client
reads it (a full-duplex half-close scenario like `nc -N`).
**T-11 (integration) 256 cap.** Open 300 concurrent connections → 256 succeed and 44 are closed immediately. After closing some, new ones succeed.
**T-12 (unit) Bind in use** → state `error: address in use`.
**T-13 (e2e) -L** to the container's `python3 -m http.server` → HTTP GET through the forward works. The bytes counters increase.
**T-14 (e2e) -R** with `bind_port = 0` → the allocated port is shown. From inside the container, `curl localhost:<port>` reaches a local test server.
**T-15 (e2e) -D** → `curl --socks5-hostname 127.0.0.1:<p> http://inner-service/` works (remote DNS).
**T-16 (e2e) Connection drop** stops the rules. Reconnect restarts the auto-start ones only.
**T-17 (e2e) Standalone tunnel**: no tab is created, and the forward works.
**T-18 (reducer) Non-loopback bind** confirmation on the first start only.
**T-19 (CLI) `sverb forward db`** prints the listening line, and the forward works until SIGINT. `--detach` returns and the pid file exists (Unix).
**T-20 (fuzz stub)** `fuzz_targets/socks5_request.rs`.

## 5. Passing functional characteristics
- [ ] Local, Remote (including server-allocated ports) and Dynamic forwards work, with half-close in both directions.
- [ ] The SOCKS server is RFC 1928 CONNECT-only (BIND/UDP → 0x07), supports IPv4/IPv6/domain, does remote DNS and accepts SOCKS4a.
- [ ] Rules are tied to the connection's lifetime, auto-start rules restart on reconnect, and each rule has a 256-channel cap.
- [ ] Standalone (no terminal) tunnels and `sverb forward [--detach]` work headlessly.
- [ ] The live status table shows state, connections and bytes. The status bar summarizes active forwards.
- [ ] Non-loopback binds confirm the first time, and synced risky rules need approval.
