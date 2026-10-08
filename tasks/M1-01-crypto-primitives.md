# M1-01 — `sverb-crypto`: primitives, canonical encodings, item envelopes

| | |
|---|---|
| **Milestone** | M1 — Core terminal & SSH |
| **Touches** | `crates/sverb-crypto/` (created empty in M0-01): `src/{lib.rs, aead.rs, kdf.rs, canon.rs, envelope.rs, pad.rs, wrap.rs, random.rs, error.rs}`, `tests/kat/*.json` |
| **Spec refs** | §5.3 (LMK wrapping AAD), §7.5 (recording chunk AAD), §11.1, §11.4, §11.5, §17, §19 (crypto row) |
| **Depends on** | M0-01 |
| **Blocks** | M1-02, M1-03, M1-04, M3-05, M4-03, M6-02 |

---

## 1. Current state in the codebase
`crates/sverb-crypto/src/lib.rs` contains only the crate doc comment (M0-01). No crypto
dependency is used anywhere yet. `Secret` types exist in `sverb-core::secret` (M0-04).
**Layering note:** `sverb-crypto` may not depend on `sverb-core` (core depends on crypto), so it
defines its own minimal zeroizing key types (`Key32`, `Nonce24`). `sverb-core::secret` can
re-export or wrap them.

## 2. Detailed description

### 2.1 Principles
- **No I/O, no async, no tokio** (§3). Pure functions over byte slices. `OsRng` is the only source of
  randomness, injected through a `CryptoRng + RngCore` parameter so tests are deterministic.
- All key material lives in types that `Zeroize` on drop and have redacted `Debug`.
- **Canonical encodings** (§11.1): every AAD, HKDF `info`, HPKE `info` and signature input is
  built through typed builder functions, never by ad-hoc concatenation in callers:
  - UUID → 16 raw bytes
  - integers → big-endian (`u32` for `key_version`, `u64` for `seq`/`chunk_index`)
  - variable-length → `u32` BE length prefix + bytes
  - labels → ASCII constants in one `labels` module (e.g. `ITEM_V1 = "sverb-item-v1"`, `VK_V1 =
    "sverb/vk/v1"`, `ITEM_KEY_V1 = "sverb/item/v1"`, `RECORDING_V1 = "sverb/recording/v1"`,
    `LMK_WRAP_V1 = "sverb-lmk-wrap-v1"`, `AKEK_V1 = "sverb/akek/v1"`, `SHARE_JOIN_V1`,
    `SHARE_CHAN_V1`).
  - **Spec gap:** labels are prefixed to fixed-width fields without a length prefix. Because every label is
    a compile-time constant and the following fields are fixed-width, this is unambiguous. Document it.

### 2.2 Modules
1. **`aead`**: XChaCha20-Poly1305 (`chacha20poly1305::XChaCha20Poly1305`), 24-byte random nonce.
   `seal(key, nonce, aad, pt) -> Vec<u8>` and `open(key, nonce, aad, ct) -> Result<Zeroizing<Vec<u8>>,
   CryptoError::Auth>`. A failed `open` returns a single opaque error. **Never** distinguish
   wrong key from tampering.
2. **`kdf`**:
   - `hkdf_sha256(ikm, salt: Option<&[u8]>, info, out_len)`.
   - `argon2id(password: &[u8], params: Argon2Params { m_kib, t, p, salt: [u8;16] }) -> Key32`.
     Defaults are `m=256 MiB (262144 KiB), t=3, p=1` (§5.3). Params are serializable for storage in `meta`.
     Validate the bounds (`m_kib ≥ 19456`, `t ≥ 1`, `p ≥ 1`). This is CPU-heavy, and callers must run it in
     `spawn_blocking` (documented on the function).
3. **`pad`**: `pad256(data) -> Vec<u8>` appends `0x80` followed by zeros up to the next multiple of 256. If
   the length is already a multiple of 256, a full block of padding is still added (ISO/IEC 7816-4).
   `unpad256(data) -> Result<&[u8]>` strips trailing zeros, requires a `0x80`, and errors on malformed input.
4. **`envelope`** (§11.4): the item envelope format.
   - `item_key = HKDF-SHA256(ikm = VK, salt = item_id(16B), info = "sverb/item/v1")`
   - `aad = "sverb-item-v1" || vault_id(16) || item_id(16) || key_version(u32 BE)`
   - `plaintext = pad256(zstd(cbor_bytes))`. Crypto receives already-CBOR'd bytes from core, so
     this crate does compression and padding but not CBOR.
   - `envelope = 0x01 || key_version(u32 BE) || nonce(24) || ciphertext+tag`.
   - `seal_item(vk, vault_id, item_id, key_version, body_bytes, rng) -> Vec<u8>` and
     `open_item(vk_lookup: impl Fn(u32) -> Option<&Key32>, vault_id, item_id, envelope) ->
     Result<Zeroizing<Vec<u8>>>`, which reads the key_version from the header, picks the VK, verifies the AAD
     (so an envelope moved to another item or vault fails), decrypts, unpads and decompresses.
   - zstd level 3. Decompression is capped at 16 MiB output (zip-bomb guard; items are ≤ 1 MiB, §10.5).
   - Unknown format version byte → `CryptoError::UnsupportedVersion(u8)`.
5. **`wrap`**: generic key wrapping `wrap_key(kek, purpose: WrapPurpose, key) -> Vec<u8>` /
   `unwrap_key`, used for the LMK under the password KEK and keyring KEK, vault keys under the LMK, sync tokens
   under the LMK, and the recording device key. `aad = "sverb-lmk-wrap-v1" || purpose` (§5.3), where `purpose`
   is a length-prefixed string from an enum (`Lmk`, `VaultKey(vault_id)`, `SyncTokens`,
   `RecordingKey`). Output format: `nonce(24) || ct`.
6. **`random`**: `random_key32(rng)`, `random_salt16(rng)`, `uuid_v7` is in core (not crypto).
7. **`recording`** (§7.5) chunk sealing helpers: `recording_key = HKDF(LMK, info = "sverb/recording/v1")`,
   `aad = conn_id(16) || chunk_index(u64 BE) || is_last(u8)`. They live here so M3-05 only does I/O.
8. **`error`**: `CryptoError { Auth, Malformed(&'static str), UnsupportedVersion(u8),
   InvalidParams(&'static str), Decompress }`.

### 2.3 Known-answer tests (KATs)
`tests/kat/*.json` contains fixed inputs (keys, nonces, ids) → expected hex outputs for: HKDF item-key
derivation, the AAD builders, `pad256`, envelope seal (with a fixed nonce through a deterministic RNG), wrap,
recording chunk sealing, and Argon2id with small params (m = 19456, t = 2, p = 1). These vectors are **frozen**:
any change in output is a breaking format change. Generate them once and commit them. Cross-check against the
`argon2` and `hkdf` crate reference vectors.

### 2.4 Cross-version fixtures (§19)
`tests/fixtures/envelopes/v1/*.bin` stores real envelopes produced by this version. Every future version
must still open them.

### 2.5 Out of scope
- OPAQUE, HPKE, Ed25519 and account keys (M4-03), share crypto (M6-02), CBOR of `ItemBody` (M1-02).

## 3. Codebase changes
- **Fill** `crates/sverb-crypto` with the modules above. Dependencies: `chacha20poly1305`, `argon2`,
  `hkdf`, `sha2`, `zstd`, `zeroize`, `subtle`, `rand_core`, `thiserror`. Dev: `proptest`,
  `hex`, `serde_json`, `rand_chacha` (deterministic RNG).
- **Bench** (`benches/envelope.rs`, criterion): seal/open of a 1 KiB item.

## 4. Test cases to implement

**T-01 (KAT)** Every vector in `tests/kat/*.json` reproduces exactly.

**T-02 (property) Envelope round-trip.** For random body bytes (0..64 KiB), ids and key_version,
`open_item(seal_item(x)) == x`.

**T-03 (property) Padding.** For any length 0..2048, `unpad256(pad256(x)) == x`, the padded length is a
multiple of 256 and always strictly greater than the length of x.

**T-04 (unit) Tamper: AAD.** Seal for item A and open as item B (same vault): `Auth` error. Same for a
different vault_id, and for a key_version mutated in the header (with the matching VK supplied).

**T-05 (unit) Tamper: ciphertext.** Flip each byte position of a sealed envelope in turn (1 KiB body):
every flip → error (`Auth`, or `Malformed` for header bytes).

**T-06 (unit) Truncation.** Envelopes truncated to lengths 0…len-1 → error, with no panic.

**T-07 (unit) Unsupported version.** First byte 0x02 → `UnsupportedVersion(2)`.

**T-08 (unit) Nonce freshness.** Sealing the same input twice with the real `OsRng` produces different envelopes.

**T-09 (unit) Wrong key.** `open_item` with another VK → `Auth`, and the error message is identical to the
tamper case.

**T-10 (unit) Wrap purposes are domain-separated.** Wrap with purpose `VaultKey(v1)` and unwrap with
`VaultKey(v2)` or `SyncTokens` → `Auth`.

**T-11 (unit) Argon2 params validation.** `m_kib = 1024` → `InvalidParams`.

**T-12 (unit) Zip bomb.** A crafted envelope whose zstd payload expands beyond 16 MiB → `Decompress` error,
with no OOM.

**T-13 (unit) Canonical builders.** `aad_item(vault, item, 7)` is exactly 13 + 16 + 16 + 4 bytes with the expected layout.
`len_prefixed(b"abc")` = `00 00 00 03 61 62 63`.

**T-14 (fixture)** All `tests/fixtures/envelopes/v1/*.bin` files open with their recorded keys.

**T-15 (unit) Debug redaction.** `format!("{:?}", Key32)` contains no hex of the key.

**T-16 (fuzz target stub)** A `fuzz/fuzz_targets/envelope_open.rs` entry that feeds arbitrary bytes to
`open_item`. It must never panic (run in M7-05, compiled here).

## 5. Passing functional characteristics
- [ ] XChaCha20-Poly1305, HKDF-SHA256, Argon2id and pad256 are implemented exactly as §11.1/§11.4 specify.
- [ ] The envelope format `0x01 || key_version || nonce || ct` round-trips, and its AAD binds vault, item and key version.
- [ ] Every byte-level construction goes through canonical builders, and KATs freeze the outputs.
- [ ] Every tampering, truncation, wrong-key or wrong-context case fails with an indistinguishable auth error,
      and none of them panic.
- [ ] Key types zeroize on drop and never print their contents.
- [ ] The crate has no I/O and no async, and it compiles without tokio.
- [ ] Cross-version fixtures are committed for future compatibility tests.
