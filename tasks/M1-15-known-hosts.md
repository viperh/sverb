# M1-15 — Known hosts and host-key verification

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-core/src/known_hosts/{mod.rs, lookup.rs, hashed.rs, parse.rs, fingerprint.rs, randomart.rs}`, `crates/sverb-conn/src/ssh/verify.rs` (handler integration), `crates/sverb-tui/src/views/{known_hosts.rs, dialogs/host_key.rs}` |
| **Spec refs** | §9.5, §4.7, §6.1.1 step 3 (oneshot + 120 s timeout), §6.1.4 (jump hop keys), §8.5 (Known Hosts view), §15 (`host_key_policy`, `hash_known_hosts`) |
| **Depends on** | M1-13, M1-06 |
| **Blocks** | M2-05, M2-11 (import), M1-16 |

---

## 1. Current state in the codebase
M1-13 uses a dev-only accept-and-warn verifier. The `KnownHost` typed view exists (M1-02). There's no Known Hosts view.

## 2. Detailed description

### 2.1 Data (§4.7)
`KnownHost { host_pattern, key_type, public_key, added_at, comment, marker: None | CertAuthority | Revoked }`.
`host_pattern` uses the OpenSSH form: plain (`example.com`, `[example.com]:2222`), comma lists
(`host,10.0.0.1`), wildcards (`*.example.com`, `?`, negation `!`) for `@cert-authority` lines, and hashed form
`|1|base64(salt)|base64(HMAC-SHA1(salt, host))`.

### 2.2 Lookup (§9.5)
- The lookup key is `host` for port 22 and `[host]:port` otherwise.
- Matching: plain patterns use OpenSSH glob semantics (`*`, `?`, `!negation`, comma-separated). Hashed entries: compute
  `HMAC-SHA1(salt, lookup_key)` per entry and compare in constant time.
- Results: `KnownKeys { matching: Vec<KnownHost>, cas: Vec<KnownHost>, revoked: Vec<KnownHost> }`.
- **Multiple keys per host** (one per key type) are allowed. `key_types_for(host)` feeds the M1-13 host-key algorithm
  reordering.
- **Jump chains** (§6.1.4): each hop is looked up under its own `address:port` as seen from the previous hop.

### 2.3 Verification (`check_server_key`)
Given the presented key (plain or certificate):
1. If the key (or the CA that signed the cert) matches a `@revoked` entry → **reject**, always (§9.5), even if a CA
   would accept.
2. If it's a host **certificate**: find `@cert-authority` entries whose pattern matches the host. Verify the signature by the CA
   key, that the validity window contains now, that the principals include the hostname (the lookup host, without the port),
   that the cert type is host, and that the key type is allowed. All OK → accept. Otherwise treat it like an unknown plain key
   (fall through, with a reason note).
3. A plain key matching an entry with the same type and same key → **accept**.
4. An entry for this host with the **same type and a different key** → **changed**.
5. No entry of this type → **unknown**.
Apply the policy (`ssh.host_key_policy`, overridable per host and group via `HostDefaults` after M2-01):
- `strict`: unknown → reject. Changed → reject.
- `ask` (default): unknown → modal. Changed → red warning.
- `accept-new`: unknown → save automatically and toast "Added host key for X". Changed → reject (red warning, reject only).

### 2.4 Modal flow (§6.1.1 step 3)
The handler sends `SessionEvent::HostKey(Verification { host, port, key_type, fingerprint_sha256,
randomart, kind: Unknown|Changed{old_fingerprints}, hop: Option<(i, n)> })` with a `oneshot::Sender<Decision>`, then
**awaits** it (the handshake is suspended, state `AwaitingHostKey`). **120 s timeout → reject.**
- **Unknown key modal:** host, key type, `SHA256:` fingerprint (base64, no padding, as OpenSSH does), randomart
  (the OpenSSH "drunken bishop" algorithm, 17×9 field, with the header `[ED25519 256]` and footer `[SHA256]`), and the buttons
  `[a]ccept & save`, `[o]nce`, `[r]eject`. "Once" accepts for this connection only (not saved). Hop info is shown when
  verifying a jump hop ("hop 1/2 (bastion)").
- **Changed key:** a **full-screen red warning** (theme `error`, plus a bold "WARNING: REMOTE HOST IDENTIFICATION HAS
  CHANGED" headline for monochrome), with old and new fingerprints. Only `[r]eject` by default. Replacing requires
  pressing `[R]eplace…`, which opens a prompt where the user must **type the hostname exactly**. Only then is the old entry
  (that key type) replaced.
- Saving writes a `KnownHost` item (stamped, encrypted, in the host's vault). New entries are stored unhashed
  unless `ssh.hash_known_hosts = true` (then generate a random 20-byte salt and store the hashed form).

### 2.5 Known Hosts view (§8.5)
List (M1-06) columns: host pattern (hashed shown as `(hashed)` + comment), key type, SHA256 fingerprint
(truncated), marker, added date. Actions: delete, edit (comment, marker, pattern), import from
`~/.ssh/known_hosts` (M2-11 implements the importer; this view triggers it), export (as OpenSSH `known_hosts` text to a
file). The detail pane shows the full fingerprint and randomart.

### 2.6 Parser
`parse_known_hosts(text) -> (Vec<KnownHost>, Vec<ParseWarning{line, reason}>)` supporting comments, blank lines,
markers, hashed hosts and all key types including certs and sk keys. Unknown key types are preserved as opaque
(for export) with a warning. The parser is shared with M2-11.

## 3. Codebase changes
- **Create** the `sverb-core::known_hosts` modules (pure). Deps: `ssh-key` (key and cert parsing, fingerprints),
  `hmac`, `sha1`, `base64`.
- **Create** `sverb-conn::ssh::verify` bridging russh's `check_server_key` to the oneshot flow.
- **Create** the host-key dialogs and the Known Hosts view.

## 4. Test cases to implement

**T-01 (unit, table) Lookup key.** (`h`,22) → `h`. (`h`,2222) → `[h]:2222`. (`::1`, 22) → `::1`. (`::1`, 2222)
→ `[::1]:2222`.

**T-02 (unit) Hashed match.** A known fixture line `|1|…|…` generated by `ssh-keygen -H` for `example.com` matches
`example.com` and not `example.org`.

**T-03 (unit) Pattern globbing.** `*.example.com,!bad.example.com` matches `a.example.com` and not `bad.example.com`.

**T-04 (unit) Decision table.** Revoked > CA cert valid > exact match > changed > unknown, under each policy (3 policies ×
5 cases = 15 rows) → expected decision (Accept / Ask(Unknown) / Ask(Changed) / Reject / AutoSave).

**T-05 (unit) Revoked beats CA.** A cert signed by a trusted CA, with the host key also listed `@revoked` → reject.

**T-06 (unit) CA checks.** Expired cert → not accepted. Principal mismatch → not accepted. A user cert presented as host →
not accepted. Valid → accepted.

**T-07 (unit) Fingerprint.** An ed25519 fixture key → `SHA256:` value equal to `ssh-keygen -lf` output (recorded).

**T-08 (unit) Randomart.** Equal to `ssh-keygen -lv` output for 3 fixture keys (recorded).

**T-09 (unit) Parser.** A fixture file with comments, markers, hashed lines, certs, sk keys and a malformed line →
expected entries + 1 warning.

**T-10 (reducer) Unknown modal.** `[a]` → Decision Accept + SaveItem. `[o]` → Accept with no save. `[r]` → Reject.

**T-11 (reducer) Changed warning.** Only reject is active. `R` → prompt. A wrong hostname → still blocked. The exact hostname → Replace.

**T-12 (unit) Timeout.** No decision within 120 s (virtual) → Reject → `Disconnected{HostKey}`.

**T-13 (unit) hash_known_hosts.** When true, the saved entry is hashed and matches on lookup.

**T-14 (e2e) Unknown → accept → reconnect** with no prompt.

**T-15 (e2e) Changed key.** Regenerate the container host key, reconnect → red warning, reject → `HostKey` reason.

**T-16 (e2e) Multiple key types.** Known ecdsa only, and the server offers ed25519 + ecdsa → no prompt (ecdsa preferred via
reordering).

**T-17 (e2e) CA.** Container with a host cert signed by the test CA, plus a `@cert-authority *.test` entry → no prompt.

**T-18 (fuzz stub)** `fuzz_targets/known_hosts_parse.rs`.

## 5. Passing functional characteristics
- [ ] Host keys are verified against known hosts with plain, wildcard and hashed patterns, multiple keys per host,
      `@cert-authority` (validity, principals, type) and `@revoked` (always wins).
- [ ] Policies `strict`, `ask` and `accept-new` behave per §9.5. The handshake waits for the user, with a 120 s timeout → reject.
- [ ] The unknown-key modal shows the SHA256 fingerprint and randomart with accept & save, once and reject.
- [ ] The changed-key screen is red and full-screen, reject only, and replacing requires typing the hostname.
- [ ] Algorithm ordering favors already-known key types.
- [ ] The Known Hosts view lists, edits, deletes, imports and exports entries.
