# M4-03 — Account key hierarchy, recovery key, vault-key grants (HPKE + Ed25519)

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-crypto/src/{account.rs, recovery.rs, grant.rs, hpke.rs, sign.rs}`, `tests/kat/account*.json` |
| **Spec refs** | §11.1, §11.2, §11.2.1 (two derivations), §11.3, §13.3 (signature verification inputs) |
| **Depends on** | M1-01 |
| **Blocks** | M4-02 (bundle formats), M4-07, M4-08, M5-02, M5-03, M5-04 |

---

## 1. Current state in the codebase
`sverb-crypto` has symmetric primitives, envelopes and wrapping (M1-01). There's no public-key crypto.

## 2. Detailed description
All functions are pure, deterministic given an RNG, and covered by KATs. No I/O.

### 2.1 Account keys (§11.2)
- `AKEK = HKDF-SHA256(ikm = export_key (64 B from OPAQUE), info = "sverb/akek/v1")` → 32 bytes.
- Keypairs generated on the device at registration: **X25519** (encryption) and **Ed25519** (signing).
- `private_bundle = AEAD(AKEK, nonce, aad = "sverb/bundle/v1" || user_id || version(u32), cbor({x25519_sk, ed25519_sk}))`,
  serialized as `0x01 || nonce || ct`.
- **Recovery key:** 256 random bits, shown once as a **24-word BIP39** mnemonic (the `bip39` crate, English wordlist; 256-bit entropy maps to 24 words).
  `recovery_bundle = AEAD(HKDF(recovery_key, info="sverb/recovery/v1"), aad = "sverb/recovery-bundle/v1" || user_id, same
  plaintext)`.
- API: `generate_account_keys(rng) -> AccountKeys`, `seal_private_bundle(akek, user_id, version, keys)`,
  `open_private_bundle(...)`, `recovery_key_generate(rng) -> (RecoveryKey, Mnemonic)`, `recovery_key_from_mnemonic(words) ->
  Result<RecoveryKey>` (validating the checksum, case-insensitive, tolerating extra whitespace), and `seal/open_recovery_bundle`.

### 2.2 Vault key grants (§11.3)
- `wrapped_vault_key = HPKE.Seal(member_x25519_pub, info = "sverb/vk/v1" || vault_id(16) || key_version(u32), VK)`, in HPKE base mode,
  single-shot, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (§11.1), via the `hpke` crate. The output is `enc || ct`
  (length-prefixed via the canonical builder).
- **Signature:** the granter signs `"sverb/grant/v1" || vault_id || member_user_id || key_version(u32) || len_prefixed(wrapped_vault_key)`
  with Ed25519 (§11.3). The canonical builder is shared by client and server tests.
- API: `grant_vault_key(vk, vault_id, key_version, member_id, member_x25519_pub, granter_ed25519_sk, rng) -> Grant {
  wrapped, signature }`, `verify_grant(grant, vault_id, member_id, key_version, granter_ed25519_pub) -> Result<()>`,
  `open_grant(grant, vault_id, key_version, my_x25519_sk) -> Result<Key32>` (HPKE open with the same info).
- **Self-grant** (personal vaults, §11.3): the same function with member = self.

### 2.3 Fingerprints and safety numbers (for M5-03)
`key_fingerprint(x25519_pub, ed25519_pub) -> [u8; 32]` = SHA-256 of `"sverb/fpr/v1" || x || ed`. `safety_number(a, b) -> String`: 60 digits
in 12 groups of 5 (Signal-style), computed from the sorted pair of fingerprints so both sides see the same number. Document the formula.

### 2.4 Separation of the two derivations (§11.2.1)
Documented and tested: the local KEK (Argon2id with `local_salt`) and the OPAQUE `export_key` → AKEK are independent. A test asserts that the same password
yields unrelated outputs (sanity only).

## 3. Codebase changes
- Add the modules. Deps: `hpke`, `x25519-dalek`, `ed25519-dalek`, `bip39`, `opaque-ke` (from M4-02's shared suite module).

## 4. Test cases to implement

**T-01 (KAT)** AKEK derivation, bundle seal (deterministic RNG), grant wrap + signature, fingerprint and safety number: fixed vectors.

**T-02 (property)** Bundle round-trip. A wrong AKEK → auth error. A different user_id or version in the AAD → auth error.

**T-03 (unit)** Mnemonic: 24 words, round-trip. A bad checksum (one word swapped) → error. Mixed case and extra spaces → OK.

**T-04 (unit)** Recovery bundle round-trip, and a wrong recovery key → error.

**T-05 (property)** Grant: seal → open with the member's key gives the same VK. Opening with another key → error. A different vault_id or key_version in info → error.

**T-06 (unit)** Signature: verify OK. A tampered wrapped key, member id, key_version or vault id → fails. A wrong granter key → fails.

**T-07 (unit)** Safety number symmetry: `safety_number(a, b) == safety_number(b, a)`, and it changes if either key changes.

**T-08 (unit)** Self-grant opens with one's own key.

**T-09 (fuzz stub)** Grant and bundle decoding with arbitrary bytes.

## 5. Passing functional characteristics
- [ ] AKEK is derived from the OPAQUE export_key via HKDF ("sverb/akek/v1"), and account private keys are sealed under it with context-bound AAD.
- [ ] A 24-word BIP39 recovery key seals a recovery bundle.
- [ ] Vault keys are wrapped per member with HPKE base mode (info binds vault and key_version) and signed by the granter with Ed25519 over a canonical encoding.
- [ ] Personal vaults use self-grants through the same code path.
- [ ] Fingerprints and safety numbers are deterministic and symmetric. KATs freeze all formats.
