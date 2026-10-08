# M6-02 — Share cryptography: join handshake, per-viewer channel keys, sequenced frames

| | |
|---|---|
| **Milestone** | M6 |
| **Touches** | `crates/sverb-crypto/src/share.rs`, `crates/sverb-proto/src/share_frame.rs` (ShareFrame encoding) |
| **Spec refs** | §14.2, §11.1 (canonical encodings), §17 (shared-terminal hijack mitigations) |
| **Depends on** | M1-01 |
| **Blocks** | M6-03 |

---

## 1. Current state in the codebase
Symmetric primitives and canonical builders exist (M1-01), plus X25519 (M4-03).

## 2. Detailed description
Pure, no I/O, KAT-covered.
- **Link key:** `share_key` is 32 random bytes. Link `sverb://join/<server>/<share_id>#<base64url(share_key)>` and the web form
  `https://<server>/s/<share_id>#<key>` (§14.1). Parse and format helpers validate the share_id UUID and key length. The fragment must never be sent to the server (the client
  strips it before any HTTP use).
- **Join handshake** (§14.2.1):
  - The viewer generates an ephemeral X25519 pair and sends `Hello { viewer_eph_pub, name, mac }` with
    `mac = HMAC-SHA256(HKDF(share_key, info="sverb/share/join/v1"), share_id || viewer_eph_pub || len_prefixed(name))`.
  - The host verifies the MAC (constant time), which proves the viewer holds the link. It replies `Welcome { host_eph_pub, mac' }` where `mac'` is the same HMAC key over the **full
    transcript** `share_id || viewer_eph_pub || len_prefixed(name) || host_eph_pub || "welcome"`. The viewer verifies it.
  - The host uses a **fresh ephemeral per viewer**.
- **Channel key** (§14.2.2): `k_viewer = HKDF(ikm = X25519(eph, eph'), salt = share_key, info = "sverb/share/chan/v1" || share_id ||
  viewer_eph_pub || host_eph_pub)`, 64 bytes output, split into `k_h2v` (first 32) and `k_v2h` (last 32). This gives forward secrecy per viewer, and a viewer can't impersonate another.
- **Frames** (§14.2.3): `XChaCha20Poly1305(k_dir, nonce = seq (u64 BE) left-padded with zeros to 24 bytes, aad = share_id || viewer_id (u32 BE) || dir
  (u8: 0 = h2v, 1 = v2h) || seq (u64 BE), plaintext = cbor(ShareFrame))`. The wire payload is `seq (u64 BE) || ct`.
  - **Sequence rule:** the receiver accepts only `seq == last + 1` (starting at 0, or 1? **Decision:** the first frame has `seq = 0`). Anything else → **close the channel** (prevents replay,
    reordering and dropping). Per-direction counters.
  - **`viewer_id` in the AAD:** the viewer learns its id from the relay (M6-01) in the first relayed control message. Both sides bind to it.
- **`ShareFrame`** (§14.2): `Snapshot{cols, rows, vt}`, `Output(Bytes)`, `Resize{cols, rows}`, `Input(Bytes)` (v2h; honored only with control),
  `ControlGranted(bool)`, `Bye{reason}`. Plus the handshake messages `Hello`, `Welcome`, which are sent **unencrypted** inside the relay payload with a type tag, and approval signalling:
  `ApprovalPending`, `Approved`, `Denied` (h2v, encrypted after the handshake). CBOR-encoded and versioned with a leading `u8` version.
- **API:** `ViewerHandshake::start(share_key, share_id, name, rng) -> (Hello, state)`, `state.finish(Welcome) -> Channel`.
  `HostHandshake::respond(share_key, share_id, Hello, rng) -> Result<(Welcome, Channel)>`.
  `Channel::seal(frame) -> Vec<u8>` and `Channel::open(bytes) -> Result<ShareFrame, ChannelError::{Auth, Sequence}>`.

## 3. Codebase changes
- `sverb-crypto::share` and `sverb-proto::share_frame`. Deps: `hmac`, `x25519-dalek`.

## 4. Test cases to implement

**T-01 (KAT)** MAC, channel key split and frame sealing with fixed inputs.

**T-02 (unit)** A full handshake → both sides derive identical `k_h2v`/`k_v2h`. Frames round-trip both directions.

**T-03 (unit)** A wrong share_key on the viewer → the host rejects the Hello MAC. A tampered name → rejected. A tampered Welcome → the viewer rejects.

**T-04 (unit)** Viewer A can't decrypt frames meant for viewer B (different channel keys). A frame replayed to another viewer_id → AAD failure.

**T-05 (unit)** Sequence: replay (seq reused) → Sequence error. Gap (skip one) → error. Reorder → error. After an error the channel is unusable (closed state).

**T-06 (unit)** Direction confusion: an h2v frame fed into the v2h decrypt → auth error.

**T-07 (unit)** Link parse and format round-trip. A missing fragment → error. A key of the wrong length → error. The server part never includes the fragment.

**T-08 (fuzz stub)** `fuzz_targets/share_frame_decode.rs` (§19).

## 5. Passing functional characteristics
- [ ] The link key only authenticates the join via HMAC. Each viewer gets independent X25519-derived channel keys with forward secrecy.
- [ ] Frames are XChaCha20-Poly1305 with counter nonces and AAD binding share, viewer, direction and seq. Any non-consecutive seq closes the channel.
- [ ] ShareFrame covers snapshot, output, resize, input, control and bye. Encodings are frozen with KATs and fuzzed.
