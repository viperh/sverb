//! T-01: known-answer tests. The vectors in `tests/kat/*.json` are FROZEN:
//! any change in output is a breaking format change.
//!
//! They were generated once with
//! `cargo test -p sverb-crypto --test kat -- --ignored generate_kats`
//! and must not be regenerated unless the format version is bumped.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;

use chacha20::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Value, json};
use sverb_crypto::canon::{self, Id16};
use sverb_crypto::envelope::{item_key, open_item, seal_item, seal_item_with_nonce};
use sverb_crypto::kdf::{Argon2Params, argon2id, hkdf_sha256};
use sverb_crypto::pad::pad256;
use sverb_crypto::recording::{open_chunk, recording_key, seal_chunk_with_nonce};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key, wrap_key_with_nonce};
use sverb_crypto::{Key32, Nonce24};

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat")
}

fn load(name: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(kat_dir().join(name)).expect("kat file");
    let v: Value = serde_json::from_str(&text).expect("kat json");
    let vectors = v["vectors"].as_array().expect("vectors").clone();
    assert!(!vectors.is_empty(), "{name} has no vectors");
    vectors
}

fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))).expect("hex")
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))
}
fn id(v: &Value, k: &str) -> Id16 {
    h(v, k).try_into().expect("16 bytes")
}
fn key(v: &Value, k: &str) -> Key32 {
    Key32::from_slice(&h(v, k)).expect("32 bytes")
}
fn nonce(v: &Value, k: &str) -> Nonce24 {
    Nonce24::from_bytes(h(v, k).try_into().expect("24 bytes"))
}
fn n(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or_else(|| panic!("missing {k}"))
}

fn purpose(v: &Value) -> WrapPurpose {
    match s(v, "purpose") {
        "lmk" => WrapPurpose::Lmk,
        "vault-key" => WrapPurpose::VaultKey(id(v, "purpose_vault_id")),
        "sync-tokens" => WrapPurpose::SyncTokens,
        "recording-key" => WrapPurpose::RecordingKey,
        other => panic!("unknown purpose {other}"),
    }
}

#[test]
fn kat_hkdf() {
    for v in load("hkdf.json") {
        let got = match s(&v, "kind") {
            "raw" => {
                let salt = v["salt"].as_str().map(|s| hex::decode(s).unwrap());
                let okm = hkdf_sha256(
                    &h(&v, "ikm"),
                    salt.as_deref(),
                    &h(&v, "info"),
                    n(&v, "len") as usize,
                )
                .unwrap();
                hex::encode(&*okm)
            }
            "item_key" => hex::encode(item_key(&key(&v, "vk"), &id(&v, "item_id")).expose_secret()),
            "recording_key" => hex::encode(recording_key(&key(&v, "lmk")).expose_secret()),
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(got, s(&v, "okm"), "{v}");
    }
}

#[test]
fn kat_canon() {
    for v in load("canon.json") {
        let out = match s(&v, "kind") {
            "aad_item" => canon::aad_item(
                &id(&v, "vault_id"),
                &id(&v, "item_id"),
                n(&v, "key_version") as u32,
            ),
            "info_item_key" => canon::info_item_key(),
            "info_recording_key" => canon::info_recording_key(),
            "info_vk" => canon::info_vk(&id(&v, "vault_id"), n(&v, "key_version") as u32),
            "aad_wrap" => purpose(&v).aad(),
            "aad_recording_chunk" => canon::aad_recording_chunk(
                &id(&v, "conn_id"),
                n(&v, "chunk_index"),
                v["is_last"].as_bool().unwrap(),
            ),
            "len_prefixed" => canon::len_prefixed(&h(&v, "input")),
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(hex::encode(out), s(&v, "output"), "{v}");
    }
}

#[test]
fn kat_pad() {
    for v in load("pad.json") {
        assert_eq!(hex::encode(pad256(&h(&v, "input"))), s(&v, "output"));
    }
}

#[test]
fn kat_envelope() {
    for v in load("envelope.json") {
        let vk = key(&v, "vk");
        let (vault, item) = (id(&v, "vault_id"), id(&v, "item_id"));
        let kv = n(&v, "key_version") as u32;
        let body = h(&v, "body");
        let env = seal_item_with_nonce(&vk, &vault, &item, kv, &body, &nonce(&v, "nonce")).unwrap();
        assert_eq!(hex::encode(&env), s(&v, "envelope"));
        let opened = open_item(|k| (k == kv).then_some(&vk), &vault, &item, &env).unwrap();
        assert_eq!(*opened, body);
        // The same nonce drawn through the deterministic RNG gives the same bytes.
        let mut rng = ChaCha20Rng::from_seed(h(&v, "rng_seed").try_into().unwrap());
        assert_eq!(
            seal_item(&vk, &vault, &item, kv, &body, &mut rng).unwrap(),
            env
        );
    }
}

#[test]
fn kat_wrap() {
    for v in load("wrap.json") {
        let kek = key(&v, "kek");
        let p = purpose(&v);
        let w = wrap_key_with_nonce(&kek, &p, &h(&v, "secret"), &nonce(&v, "nonce")).unwrap();
        assert_eq!(hex::encode(&w), s(&v, "wrapped"));
        assert_eq!(*unwrap_key(&kek, &p, &w).unwrap(), h(&v, "secret"));
    }
}

#[test]
fn kat_recording() {
    for v in load("recording.json") {
        let k = recording_key(&key(&v, "lmk"));
        let (conn, idx) = (id(&v, "conn_id"), n(&v, "chunk_index"));
        let last = v["is_last"].as_bool().unwrap();
        let pt = h(&v, "plaintext");
        let c = seal_chunk_with_nonce(&k, &conn, idx, last, &pt, &nonce(&v, "nonce")).unwrap();
        assert_eq!(hex::encode(&c), s(&v, "chunk"));
        assert_eq!(*open_chunk(&k, &conn, idx, last, &c).unwrap(), pt);
    }
}

#[test]
fn kat_argon2id() {
    for v in load("argon2id.json") {
        let params = Argon2Params {
            m_kib: n(&v, "m_kib") as u32,
            t: n(&v, "t") as u32,
            p: n(&v, "p") as u32,
            salt: id(&v, "salt"),
        };
        assert_eq!(hex::encode(params.to_bytes()), s(&v, "params_encoded"));
        let k = argon2id(&h(&v, "password"), &params).unwrap();
        assert_eq!(hex::encode(k.expose_secret()), s(&v, "key"));
    }
}

// ---------------------------------------------------------------------------
// One-off generator, kept to document how the vectors were produced.

fn bytes(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rng.fill_bytes(&mut b);
    b
}
fn id16(rng: &mut ChaCha20Rng) -> Id16 {
    bytes(rng, 16).try_into().unwrap()
}
fn x<T: AsRef<[u8]>>(t: T) -> String {
    hex::encode(t)
}
fn k32(b: &[u8]) -> Key32 {
    Key32::from_slice(b).unwrap()
}

fn write(name: &str, description: &str, vectors: Vec<Value>) {
    let doc = json!({ "description": description, "vectors": vectors });
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    std::fs::write(kat_dir().join(name), text).unwrap();
}

#[test]
#[ignore = "writes the frozen KAT files; run only when introducing a new format version"]
fn generate_kats() {
    std::fs::create_dir_all(kat_dir()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x5e; 32]);

    // HKDF: RFC 5869 vectors through the wrapper, then sverb derivations.
    let mut hkdf = vec![
        json!({
            "name": "RFC 5869 A.1", "kind": "raw",
            "ikm": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "salt": "000102030405060708090a0b0c", "info": "f0f1f2f3f4f5f6f7f8f9", "len": 42,
            "okm": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        }),
        json!({
            "name": "RFC 5869 A.3 (no salt, empty info)", "kind": "raw",
            "ikm": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "salt": null, "info": "", "len": 42,
            "okm": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        }),
    ];
    for _ in 0..3 {
        let vk = bytes(&mut rng, 32);
        let item = id16(&mut rng);
        let k = item_key(&k32(&vk), &item);
        hkdf.push(json!({"kind": "item_key", "vk": x(&vk), "item_id": x(item), "okm": x(k.expose_secret())}));
    }
    let lmk = bytes(&mut rng, 32);
    let rk = recording_key(&k32(&lmk));
    hkdf.push(json!({"kind": "recording_key", "lmk": x(&lmk), "okm": x(rk.expose_secret())}));
    write(
        "hkdf.json",
        "HKDF-SHA256: RFC 5869 vectors, item-key and recording-key derivation",
        hkdf,
    );

    // Canonical builders.
    let vault = id16(&mut rng);
    let item = id16(&mut rng);
    let big: u64 = 0x0102_0304_0506_0708;
    let canon_v = vec![
        json!({"kind": "aad_item", "vault_id": x(vault), "item_id": x(item), "key_version": 7,
               "output": x(canon::aad_item(&vault, &item, 7))}),
        json!({"kind": "aad_item", "vault_id": x(vault), "item_id": x(item), "key_version": 0xdead_beef_u32,
               "output": x(canon::aad_item(&vault, &item, 0xdead_beef))}),
        json!({"kind": "info_item_key", "output": x(canon::info_item_key())}),
        json!({"kind": "info_recording_key", "output": x(canon::info_recording_key())}),
        json!({"kind": "info_vk", "vault_id": x(vault), "key_version": 3,
               "output": x(canon::info_vk(&vault, 3))}),
        json!({"kind": "aad_wrap", "purpose": "lmk", "output": x(WrapPurpose::Lmk.aad())}),
        json!({"kind": "aad_wrap", "purpose": "vault-key", "purpose_vault_id": x(vault),
               "output": x(WrapPurpose::VaultKey(vault).aad())}),
        json!({"kind": "aad_wrap", "purpose": "sync-tokens", "output": x(WrapPurpose::SyncTokens.aad())}),
        json!({"kind": "aad_wrap", "purpose": "recording-key", "output": x(WrapPurpose::RecordingKey.aad())}),
        json!({"kind": "aad_recording_chunk", "conn_id": x(item), "chunk_index": big, "is_last": true,
               "output": x(canon::aad_recording_chunk(&item, big, true))}),
        json!({"kind": "aad_recording_chunk", "conn_id": x(item), "chunk_index": 0, "is_last": false,
               "output": x(canon::aad_recording_chunk(&item, 0, false))}),
        json!({"kind": "len_prefixed", "input": x(b"abc"), "output": x(canon::len_prefixed(b"abc"))}),
        json!({"kind": "len_prefixed", "input": "", "output": x(canon::len_prefixed(b""))}),
    ];
    write("canon.json", "Canonical AAD / info builders", canon_v);

    // pad256.
    let pad_v = [0usize, 1, 100, 255, 256, 257, 511]
        .iter()
        .map(|&len| {
            let input = bytes(&mut rng, len);
            json!({"input": x(&input), "output": x(pad256(&input))})
        })
        .collect();
    write(
        "pad.json",
        "pad256 (ISO/IEC 7816-4 to a multiple of 256)",
        pad_v,
    );

    // Envelopes: nonce drawn from a seeded ChaCha20Rng (seed recorded).
    let mut env_v = Vec::new();
    for (i, (len, kv)) in [(0usize, 1u32), (17, 1), (1024, 42), (5000, 0xffff_ffff)]
        .into_iter()
        .enumerate()
    {
        let vk = bytes(&mut rng, 32);
        let vault = id16(&mut rng);
        let item = id16(&mut rng);
        let seed = [0xa0 + i as u8; 32];
        let mut nonce_rng = ChaCha20Rng::from_seed(seed);
        let nonce_b: [u8; 24] = bytes(&mut nonce_rng, 24).try_into().unwrap();
        // Compressible but non-trivial bodies.
        let body: Vec<u8> = (0..len)
            .map(|j| b"sverb item body "[j % 16] ^ (j / 97) as u8)
            .collect();
        let env = seal_item_with_nonce(
            &k32(&vk),
            &vault,
            &item,
            kv,
            &body,
            &Nonce24::from_bytes(nonce_b),
        )
        .unwrap();
        env_v.push(json!({"vk": x(&vk), "vault_id": x(vault), "item_id": x(item), "key_version": kv,
                          "rng_seed": x(seed), "nonce": x(nonce_b), "body": x(&body), "envelope": x(&env)}));
    }
    write(
        "envelope.json",
        "Item envelopes v1 (zstd level 3, pad256, XChaCha20-Poly1305)",
        env_v,
    );

    // Wrap.
    let mut wrap_v = Vec::new();
    for p in ["lmk", "vault-key", "sync-tokens", "recording-key"] {
        let kek = bytes(&mut rng, 32);
        let pid = id16(&mut rng);
        let nonce_b: [u8; 24] = bytes(&mut rng, 24).try_into().unwrap();
        let secret = bytes(&mut rng, if p == "sync-tokens" { 70 } else { 32 });
        let mut v =
            json!({"kek": x(&kek), "purpose": p, "nonce": x(nonce_b), "secret": x(&secret)});
        if p == "vault-key" {
            v["purpose_vault_id"] = json!(x(pid));
        }
        let w = wrap_key_with_nonce(
            &k32(&kek),
            &purpose(&v),
            &secret,
            &Nonce24::from_bytes(nonce_b),
        )
        .unwrap();
        v["wrapped"] = json!(x(&w));
        wrap_v.push(v);
    }
    write(
        "wrap.json",
        "Key wrapping (aad = sverb-lmk-wrap-v1 || purpose)",
        wrap_v,
    );

    // Recording chunks.
    let mut rec_v = Vec::new();
    for (idx, last, len) in [(0u64, false, 300usize), (1, true, 0), (u64::MAX, true, 64)] {
        let lmk = bytes(&mut rng, 32);
        let conn = id16(&mut rng);
        let nonce_b: [u8; 24] = bytes(&mut rng, 24).try_into().unwrap();
        let pt = bytes(&mut rng, len);
        let k = recording_key(&k32(&lmk));
        let c = seal_chunk_with_nonce(&k, &conn, idx, last, &pt, &Nonce24::from_bytes(nonce_b))
            .unwrap();
        rec_v.push(
            json!({"lmk": x(&lmk), "conn_id": x(conn), "chunk_index": idx, "is_last": last,
                          "nonce": x(nonce_b), "plaintext": x(&pt), "chunk": x(&c)}),
        );
    }
    write(
        "recording.json",
        "Recording chunk sealing (sverb/recording/v1)",
        rec_v,
    );

    // Argon2id with small params.
    let mut a2 = Vec::new();
    for pw in [&b"correct horse battery staple"[..], b""] {
        let salt: [u8; 16] = bytes(&mut rng, 16).try_into().unwrap();
        let params = Argon2Params {
            m_kib: 19_456,
            t: 2,
            p: 1,
            salt,
        };
        let k = argon2id(pw, &params).unwrap();
        a2.push(
            json!({"password": x(pw), "m_kib": 19_456, "t": 2, "p": 1, "salt": x(salt),
                       "params_encoded": x(params.to_bytes()), "key": x(k.expose_secret())}),
        );
    }
    write(
        "argon2id.json",
        "Argon2id v0x13, 32-byte output, m=19456 t=2 p=1",
        a2,
    );
}
