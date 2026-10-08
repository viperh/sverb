# M3-07 — Connection sharing (multiplexing)

| | |
|---|---|
| **Milestone** | M3 |
| **Touches** | `crates/sverb-conn/src/ssh/mux.rs`, `crates/sverb-conn/src/ssh/connect.rs`, forwards and exec call sites |
| **Spec refs** | §6.1.3, §6.1.4 (hop connections shared), §15 `ssh.multiplex` |
| **Depends on** | M1-13, M2-04, M2-05, M2-08 |
| **Blocks** | M3-03 perf target |

---

## 1. Current state in the codebase
Every session, exec run, standalone forward and jump hop opens its own SSH connection (M1-13, M2-04, M2-05, M2-08).

## 2. Detailed description
- **Mux key:** `(address, port, username, jump_chain fingerprint, proxy fingerprint, auth identity fingerprint)`. The spec says "same address, port,
  user and jump chain". Also include the proxy and the key used, because those change the connection's behavior. Document the extension.
- `ConnectionPool` holds `HashMap<MuxKey, Weak<SharedConnection>>`. `SharedConnection` owns the russh client handle, a reference count of users
  (channels: shells, exec, forwards, hop channels), keepalive, and the `CancellationToken` parent of all forwards.
- Opening a session with `ssh.multiplex = true`: look up a live connection → open a new channel on it (no auth, no host-key check), and the state goes
  straight from `Resolving` to `Connected` (or `Connecting{..}` briefly). Otherwise create one and register it.
- **Concurrency:** two sessions opening the same key simultaneously must not create two connections. Use a per-key `OnceCell`/`Mutex` "connecting"
  entry that others await.
- **Lifetime:** the connection closes when the last user releases it, after a **linger of 10 s** (so closing and reopening a tab is instant).
- **Failure propagation:** when the shared connection drops, every user session moves to `Disconnected` with the same reason. Reconnect (M1-16) of
  any of them re-establishes the shared connection, and the others reconnect onto it when they reconnect.
- Exec runs (M2-04), standalone forwards (M2-08) and jump hops (M2-05) all go through the pool.
- **Server limits:** OpenSSH `MaxSessions` (default 10). If a channel open fails with "administratively prohibited / open failed" because of the session
  limit, fall back to a **new** connection for that session and record it, so later opens prefer the newer connection.
- `ssh.multiplex = false` → every session gets its own connection (but jump hops still share within one chain).
- The session info panel shows "shared connection (N channels)".

## 3. Codebase changes
- **Create** `mux.rs`. Refactor `connect.rs` to request channels from the pool instead of owning the connection.

## 4. Test cases to implement

**T-01 (unit)** Mux key equality: same host, port and user → equal. A different jump chain → different. A different key → different.

**T-02 (unit, mock connector)** 5 concurrent opens of the same key → exactly 1 connect call.

**T-03 (unit)** Linger: release the last user, reopen within 10 s → no new connect. After 10 s → closed.

**T-04 (unit)** Drop propagation: the shared connection error → all user sessions get Disconnected with the same reason.

**T-05 (e2e)** Two tabs to the same host → the server sees one TCP connection (count via `ss -tn` in the container) and two shell channels.

**T-06 (e2e)** `MaxSessions 2` on the server, open 3 tabs → the third uses a new connection and all 3 work.

**T-07 (e2e)** A forward and an exec reuse the tab's connection (one TCP connection).

**T-08 (e2e)** Two targets behind the same bastion share the bastion connection.

**T-09 (config)** `multiplex = false` → separate connections.

## 5. Passing functional characteristics
- [ ] Tabs, exec runs, forwards and jump hops to the same resolved endpoint share one SSH connection with separate channels.
- [ ] Concurrent opens never create duplicate connections. Connections linger 10 s after the last user.
- [ ] A shared-connection failure disconnects all its users consistently, and reconnect works.
- [ ] Server `MaxSessions` limits fall back to an extra connection. `ssh.multiplex = false` disables sharing.
