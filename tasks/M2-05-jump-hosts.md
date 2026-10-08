# M2-05 — Jump hosts (ProxyJump-style chains)

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-conn/src/ssh/jump.rs`, `crates/sverb-core/src/resolve.rs` (chain expansion), host form "Connection → Jump chain" |
| **Spec refs** | §6.1.4, §6.1.1 step 2, §4.2 (`jump_chain`, validation), §9.5 (hop key lookup), §2.1.1 (`Connecting{hop, of}`) |
| **Depends on** | M1-14, M1-15, M2-01 |
| **Blocks** | M3-07 (hop connections shared via multiplexer) |

---

## 1. Current state in the codebase
`ResolvedHost.jump_chain` is resolved (M2-01) but ignored by the connector (M1-13 uses direct TCP only). Validation rejects
self-reference and cycles at save time (M1-02).

## 2. Detailed description
- **Expansion:** `expand_chain(target) -> Vec<ResolvedHost>` (the hops in order, then the target). Each hop is itself a host item.
  Its own `jump_chain` is expanded **recursively** (a hop with its own jump chain inserts those hops before it), with a **depth limit of 8**
  total hops and **cycle detection** (seen-set of item ids). The error is "Jump chain too deep (> 8)" or "Jump chain cycle: A → B
  → A".
- **Connection:**
  1. Connect to hop 1 with the normal flow (direct TCP or proxy, its own credentials, host key and auth).
  2. For each next hop i: `channel_open_direct_tcpip(hop_i.address, hop_i.port, "127.0.0.1", 0)` on hop i-1's
     connection, convert it to a stream (`Channel::into_stream()`), then run SSH over it (`connect_stream`).
  3. Finally the target, over the last hop.
- **Each hop resolves its own credentials and host key** (§6.1.4). Host keys are recorded under each hop's **own
  `address:port` as seen from the previous hop**, matching OpenSSH. The verification modal shows "hop 2/3 (bastion-eu)".
- **State:** `Connecting{hop: i, of: n}`. The status shows "Connecting via bastion (1/2)…".
- **Errors:** prefixed with the hop index and label: "hop 2/3 (bastion-eu): auth failed" (§6.1.4). The `DisconnectReason`
  carries `hop: Option<(usize, usize)>`.
- **Sharing:** hop connections are registered in the multiplexer (M3-07) so several targets behind the same bastion reuse it.
  Until M3-07, each session builds its own chain.
- **Lifetime:** if any hop drops, the target session disconnects with reason `Connect` (or `Timeout`) annotated with the hop.
- **Proxy + jump:** a proxy (M2-06) applies only to the first hop's TCP connection (as OpenSSH does).
- **Form:** an ordered list editor of host references (add, remove, move up/down), with inline cycle validation. The resolved chain,
  including recursive expansion, is shown read-only below it ("Effective route: you → bastion → inner-bastion → target").
- **Copy as command** (M1-07) emits `-J hop1,hop2` from the **effective** chain.

## 3. Codebase changes
- **Create** `sverb-conn::ssh::jump` and extend `StreamFactory` with the `ViaHop` variant.
- **Extend** `resolve` with `expand_chain`.

## 4. Test cases to implement

**T-01 (unit) Recursive expansion.** Target T with chain [B], where B has chain [A] → [A, B, T].

**T-02 (unit) Depth limit.** A 9-hop effective chain → error. 8 → OK.

**T-03 (unit) Cycle via recursion.** A chain [B] where B's chain is [A] and A's chain is [B] → cycle error naming the path.

**T-04 (unit) Host-key lookup keys per hop** use each hop's own address:port (non-22 → `[addr]:port`).

**T-05 (e2e, JumpNet) Single hop.** Connect to `inner` via `bastion` → a shell works. Known hosts now contain both the bastion's and the inner's entries
under their own names.

**T-06 (e2e) Hop-labelled errors.** Wrong password on the bastion → "hop 1/2 (bastion): auth failed". Wrong password on inner → "hop
2/2 …" (or the target wording).

**T-07 (e2e) Host-key modal shows the hop info** for the inner host's first connection.

**T-08 (e2e) Bastion dies** (`docker stop bastion`) → the target session disconnects with the hop annotation.

**T-09 (reducer) Form ordering and the effective-route preview.**

## 5. Passing functional characteristics
- [ ] Jump chains connect through each hop with `direct-tcpip` channels, expanding hops' own chains recursively up to 8 hops.
- [ ] Each hop uses its own credentials and host key, recorded under its own address:port.
- [ ] Cycles and excessive depth are rejected with clear messages. Failures name the hop ("hop 2/3 (label): …").
- [ ] The UI shows per-hop progress, and copy-as-command reflects the effective chain.
