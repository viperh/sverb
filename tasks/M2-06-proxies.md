# M2-06 — Proxies: SOCKS5, HTTP CONNECT, ProxyCommand

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-conn/src/proxy/{mod.rs, socks5.rs, http_connect.rs, command.rs}`, host form "Connection → Proxy" |
| **Spec refs** | §6.1.5, §4.2 (`proxy` enum), §17.1 (ProxyCommand from sync needs approval) |
| **Depends on** | M1-13 |
| **Blocks** | M2-10 (approval of `proxy = Command`) |

---

## 1. Current state in the codebase
`StreamFactory` (M1-13) supports direct TCP. The `Host.proxy` field (flattened `proxy.kind/addr/auth.*/command`) exists in the model
(M1-02) without a connector.

## 2. Detailed description
- `Proxy = Socks5{addr: "host:port", auth: Option<{user, password: Secret}>} | Http{addr, auth} | Command(String)`.
- **SOCKS5** (`tokio-socks`): connect to the proxy (TCP with Happy Eyeballs and connect timeout), then CONNECT to the target **by
  domain name** (let the proxy resolve; no local DNS of the target). Username/password auth (RFC 1929) when configured. Map SOCKS
  reply codes to readable errors ("proxy: connection refused by destination", "proxy: authentication failed").
- **HTTP CONNECT** (in-house, about 100 lines, §6.1.5): send `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n`, plus
  `Proxy-Authorization: Basic base64(user:pass)` when configured, then `\r\n`. Read the status line and headers up to `\r\n\r\n`
  (max 16 KiB, with a timeout). Accept any 2xx. On 407, report "proxy authentication required/failed". On other codes, report the code
  and reason phrase (sanitized). **Any bytes received after the header terminator must be preserved** and replayed as the start of the
  SSH stream (use a buffered stream wrapper). IPv6 targets are bracketed in the request line.
- **ProxyCommand:** spawn via `sh -c` (Unix) or `cmd /C` (Windows) with substitutions `%h` → target address, `%p` → port, `%r` →
  remote username, `%%` → `%`. Unknown `%x` → error at validation. Use the child's stdin/stdout as the stream
  (`tokio::process`, `AsyncRead + AsyncWrite` wrapper). **stderr goes to the session log** (debug log plus the ConnLog detail).
  The child is **killed when the session closes** (kill on drop, and also on connect failure). The environment is inherited.
- **Local-action approval** (§17.1): before spawning a ProxyCommand that **didn't originate on this device**, the approval
  check from M2-10 must pass. This task calls `approvals.check(item_id, "proxy.command", value)` and fails with
  `NeedsApproval` if it isn't approved. M2-10 implements the store and UI. Until then the check returns approved when the
  value was typed on this device (the `device` field of the stamp equals the local device id).
- **Jump chains:** the proxy applies only to the first hop (M2-05).
- **Form:** a select (None / SOCKS5 / HTTP / Command) with conditional fields. The command field shows the substitution help.
  Credentials use secret fields.

## 3. Codebase changes
- **Create** the proxy modules. Deps: `tokio-socks`, `base64`.

## 4. Test cases to implement

**T-01 (unit) HTTP CONNECT request** formatting with and without auth, and with an IPv6 target (bracketed).

**T-02 (unit, mock server) HTTP 200 with extra bytes** after the headers → those bytes are delivered first on the stream.

**T-03 (unit) HTTP 407** → auth error. 502 → error with the code. Headers > 16 KiB → error. Slowloris (no `\r\n\r\n` within the timeout)
→ timeout error.

**T-04 (unit, mock SOCKS server)** CONNECT by domain: the request uses ATYP 0x03 with the hostname, not a resolved IP. Auth sub-negotiation
works. Reply 0x05 → "connection refused" message.

**T-05 (unit) ProxyCommand substitution.** `nc %h %p` with host `a`, port 22 → `nc a 22`. `%%` → `%`. `%r` → user. `%x` → validation error.

**T-06 (integration) ProxyCommand stream.** A command `cat` echo-loop test (or `socat - TCP:host:port` in e2e). Data flows both ways.

**T-07 (integration) Child killed on close.** Spawn `sleep 1000`-style long-running ProxyCommand (`sh -c 'exec sleep 1000'`), then
close the session → the child is reaped within 2 s.

**T-08 (integration) stderr captured** in the session log.

**T-09 (e2e) SOCKS5** via a `microsocks` or `dante` container → SSH connects through it.

**T-10 (e2e) HTTP CONNECT** via a `tinyproxy` container with basic auth → connects. Wrong password → 407 message.

**T-11 (e2e) ProxyCommand** `ssh -W %h:%p bastion` isn't available, so use `nc %h %p` from the test image → connects.

**T-12 (unit) Approval gate.** A ProxyCommand stamped by another device id → `NeedsApproval` (stub check).

## 5. Passing functional characteristics
- [ ] SOCKS5 (with optional user/pass, remote DNS) and HTTP CONNECT (with optional basic auth, early-data safe) proxies work.
- [ ] ProxyCommand supports `%h %p %r %%`, uses stdin/stdout as the stream, logs stderr, and is killed with the session.
- [ ] ProxyCommands from other devices never run without approval.
- [ ] Proxy errors are specific and readable. Proxies apply to the first hop only.
