# M5-03 — Public-key trust: TOFU pinning, safety numbers, grant-signature verification

| | |
|---|---|
| **Milestone** | M5 |
| **Touches** | `migrations/client/0003_pinned_keys.sql`, `crates/sverb-store/src/pins.rs`, `crates/sverb-sync/src/trust.rs`, `crates/sverb-tui/src/views/settings/team_verify.rs`, `crates/sverb/src/cli/team.rs` (`verify`) |
| **Spec refs** | §13.3, §11.3 (verify before using a VK), §17 (server compromise: key substitution) |
| **Depends on** | M4-03 |
| **Blocks** | M5-02, M5-04 |

---

## 1. Current state in the codebase
The fingerprint and safety-number functions exist in `sverb-crypto` (M4-03 §2.3). There's no pin storage.

## 2. Detailed description
- **TOFU pinning** (§13.3): `pinned_keys(user_id PK, fingerprint BLOB, x25519_pub, ed25519_pub, first_seen_at, verified: bool,
  verified_at)`, device-local. It's device-local because pins are a per-device trust decision. **The spec doesn't say whether pins sync.** Proposal: device-local in
  v1, so a malicious server can't poison pins via sync. Pin every org member's keys **on first sight** (fetching public keys for grants, viewing members, or verifying grants).
- **Key change detection:** a fetched key whose fingerprint ≠ the pin → **loud warning** (a red modal, and the member is marked `⚠ key changed` in the team list). Grants **to** that
  user are blocked, and grants **from** that user are not trusted until the user re-verifies (a safety number comparison, then "Accept new key"). The legitimate cause is the
  member's password reset via the recovery key? No: account keypairs are stable across password changes (only the bundle is re-wrapped). A key change only happens on account
  re-creation, so the warning is justified.
- **Safety numbers** (§13.3): `sverb team verify <user>` and the Team UI show the 60-digit safety number between me and that member (symmetric, M4-03), plus a QR? No QR in a
  TUI: just digits in 12 groups. When both users compare out of band and confirm, mark `verified = true`. Verified members show a **✓** (§13.3). Verification is
  device-local.
- **Granter signature verification** (§13.3, §11.3): before using any wrapped VK, verify (1) the Ed25519 signature over the canonical grant encoding using the **pinned** key
  of `wrapped_by`, (2) that the granter is an org member who has `manage` on the vault, or is an org owner or admin, according to the **membership list from the server**. A malicious
  server could lie about membership, so add a client-side rule: the vault creator's self-grant is trusted on first sight (TOFU), and every later grant chain must lead to a pinned
  granter. Reject self-grants claimed for others. Document the residual risk in `docs/threat-model.md`.
- **Personal vault self-grant:** verified with one's own key.

## 3. Codebase changes
- Migration, store repo, trust module, UI, and the CLI `team verify <user>` (prints the safety number and asks "Mark as verified? [y/N]").

## 4. Test cases to implement

**T-01 (integration)** First fetch pins the key. A second fetch with the same key → no warning.

**T-02 (integration)** The server returns a different key for Bob (test server hook) → warning, the grant to Bob is blocked, and Bob's grants to me are not trusted.

**T-03 (unit)** The safety number shown on Alice's device for Bob equals the one on Bob's device for Alice.

**T-04 (reducer)** Verify flow → ✓ shown, persisted. After a key change, ✓ is cleared and the warning shown.

**T-05 (unit)** Grant verification: valid → ok. Wrong signer (an unpinned or unknown user) → reject. A signer without manage per the membership list → reject. A tampered wrapped key → reject.

**T-06 (CLI)** `team verify bob` prints 12 groups of 5 digits and marks verified on `y`.

**T-07 (integration)** Pins are never pushed to the server (inspect requests).

## 5. Passing functional characteristics
- [ ] Every org member's key is pinned on first sight (device-local), and changes trigger loud warnings and block grant trust.
- [ ] Safety numbers are symmetric and comparable out of band. Verified members show ✓ in the TUI and `sverb team verify`.
- [ ] Every wrapped VK is used only after verifying the granter's signature with a pinned key and the granter's manage rights.
