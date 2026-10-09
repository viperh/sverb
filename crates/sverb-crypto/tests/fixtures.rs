//! Cross-version fixtures (§19). Every `.bin` under
//! `tests/fixtures/envelopes/v1/` was produced by this version and must keep
//! opening with the keys recorded in `manifest.json` in every future version.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;

use serde_json::{Value, json};
use sverb_crypto::Key32;
use sverb_crypto::canon::Id16;
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::random::os_rng;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/envelopes/v1")
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().expect(k)).expect("hex")
}

#[test]
fn v1_fixtures_open() {
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(dir().join("manifest.json")).unwrap())
            .unwrap();
    let entries = manifest["fixtures"].as_array().unwrap();
    assert!(!entries.is_empty());
    let mut seen = 0;
    for e in entries {
        let env = std::fs::read(dir().join(e["file"].as_str().unwrap())).unwrap();
        let vk = Key32::from_slice(&hx(e, "vk")).unwrap();
        let kv = e["key_version"].as_u64().unwrap() as u32;
        let vault: Id16 = hx(e, "vault_id").try_into().unwrap();
        let item: Id16 = hx(e, "item_id").try_into().unwrap();
        let body = open_item(|k| (k == kv).then_some(&vk), &vault, &item, &env).unwrap();
        assert_eq!(*body, hx(e, "body"), "{}", e["file"]);
        seen += 1;
    }
    // Every .bin in the directory is covered by the manifest.
    let bins = std::fs::read_dir(dir())
        .unwrap()
        .filter(|d| {
            d.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "bin")
        })
        .count();
    assert_eq!(bins, seen);
}

/// Poorly compressible deterministic bytes.
fn xorshift_bytes(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
#[ignore = "writes the frozen v1 fixtures; never regenerate, only add new versions"]
fn generate_v1_fixtures() {
    std::fs::create_dir_all(dir()).unwrap();
    let mut rng = os_rng();
    let cases: [(&str, Vec<u8>, u32); 3] = [
        ("empty.bin", Vec::new(), 1),
        (
            "small.bin",
            br#"{"kind":"host","address":"example.org","port":22}"#.to_vec(),
            1,
        ),
        ("large.bin", xorshift_bytes(3000), 0x0001_0002),
    ];
    let mut out = Vec::new();
    for (i, (file, body, kv)) in cases.into_iter().enumerate() {
        let vk = Key32::from_bytes([0x10 + i as u8; 32]);
        let vault: Id16 = [0x20 + i as u8; 16];
        let item: Id16 = [0x30 + i as u8; 16];
        let env = seal_item(&vk, &vault, &item, kv, &body, &mut rng).unwrap();
        std::fs::write(dir().join(file), &env).unwrap();
        out.push(json!({"file": file, "vk": hex::encode(vk.expose_secret()), "vault_id": hex::encode(vault),
                        "item_id": hex::encode(item), "key_version": kv, "body": hex::encode(&body)}));
    }
    let doc = json!({
        "description": "Item envelopes v1 produced by sverb-crypto 0.1.0 (M1-01). Test keys only.",
        "fixtures": out,
    });
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    std::fs::write(dir().join("manifest.json"), text).unwrap();
}
