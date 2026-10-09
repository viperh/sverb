//! Known-answer tests for the account key hierarchy, recovery
//! key, vault-key grants, fingerprints and safety numbers.
//!
//! `tests/kat/account.json` is FROZEN: any change in output is a breaking
//! format change. It was generated once with
//! `cargo test -p sverb-crypto --test account_kat -- --ignored generate_account_kats`.
//!
//! Every randomized operation draws from a `ChaCha20Rng` seeded with the
//! recorded `rng_seed`, in the documented order, so the vectors pin both the
//! formats and the RNG consumption order:
//! - `bundle`: `generate_account_keys` (64 B), then `seal_private_bundle` (24 B nonce).
//! - `recovery`: `recovery_key_generate` (32 B), then `seal_recovery_bundle` (24 B nonce).
//! - `grant`: member keys, granter keys (64 B each), then `grant_vault_key`
//!   (32 B HPKE ephemeral secret).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Map, Value, json};
use sverb_crypto::Key32;
use sverb_crypto::account::{
    AccountKeys, derive_akek, generate_account_keys, open_private_bundle, seal_private_bundle,
};
use sverb_crypto::canon::{self, Id16};
use sverb_crypto::fingerprint::{key_fingerprint, safety_number};
use sverb_crypto::grant::{Grant, grant_vault_key, verify_and_open_grant};
use sverb_crypto::recovery::{
    open_recovery_bundle, recovery_key_from_mnemonic, recovery_key_generate, seal_recovery_bundle,
};

const FILE: &str = "account.json";

fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/kat")
        .join(FILE)
}

fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))).expect("hex")
}
fn a32(v: &Value, k: &str) -> [u8; 32] {
    h(v, k).try_into().expect("32 bytes")
}
fn id(v: &Value, k: &str) -> Id16 {
    h(v, k).try_into().expect("16 bytes")
}
fn u32v(v: &Value, k: &str) -> u32 {
    u32::try_from(v[k].as_u64().unwrap_or_else(|| panic!("missing {k}"))).expect("u32")
}
fn rng(v: &Value) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(a32(v, "rng_seed"))
}
fn x<T: AsRef<[u8]>>(t: T) -> Value {
    Value::String(hex::encode(t))
}

/// Recomputes every output of a vector from its inputs. Used by both the
/// checker and the generator, so they can't drift apart.
fn compute(v: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    match v["kind"].as_str().expect("kind") {
        "akek" => {
            let ek: [u8; 64] = h(v, "export_key").try_into().expect("64 bytes");
            out.insert("akek".into(), x(derive_akek(&ek).expose_secret()));
        }
        "bundle" => {
            let mut r = rng(v);
            let keys = generate_account_keys(&mut r);
            let ek: [u8; 64] = h(v, "export_key").try_into().expect("64 bytes");
            let akek = derive_akek(&ek);
            let (uid, ver) = (id(v, "user_id"), u32v(v, "version"));
            let bundle = seal_private_bundle(&akek, &uid, ver, &keys, &mut r).unwrap();
            let pk = keys.public();
            out.insert("akek".into(), x(akek.expose_secret()));
            out.insert("x25519_sk".into(), x(keys.x25519_secret_bytes()));
            out.insert(
                "ed25519_sk".into(),
                x(keys.ed25519_signing_key().as_bytes()),
            );
            out.insert("x25519_pub".into(), x(pk.x25519));
            out.insert("ed25519_pub".into(), x(pk.ed25519));
            out.insert("aad".into(), x(canon::aad_private_bundle(&uid, ver)));
            out.insert("bundle".into(), x(bundle));
        }
        "recovery" => {
            let mut r = rng(v);
            let (rk, words) = recovery_key_generate(&mut r);
            let keys = AccountKeys::from_secret_bytes(a32(v, "x25519_sk"), a32(v, "ed25519_sk"));
            let uid = id(v, "user_id");
            let bundle = seal_recovery_bundle(&rk, &uid, &keys, &mut r).unwrap();
            out.insert("recovery_key".into(), x(rk.expose_secret()));
            out.insert("mnemonic".into(), Value::String(words.phrase().to_string()));
            out.insert("recovery_kek".into(), x(rk.kek().expose_secret()));
            out.insert("aad".into(), x(canon::aad_recovery_bundle(&uid)));
            out.insert("bundle".into(), x(bundle));
        }
        "grant" => {
            let mut r = rng(v);
            let member = generate_account_keys(&mut r);
            let granter = generate_account_keys(&mut r);
            let vk = Key32::from_bytes(a32(v, "vk"));
            let (vault, kv, mid) = (
                id(v, "vault_id"),
                u32v(v, "key_version"),
                id(v, "member_id"),
            );
            let g = grant_vault_key(
                &vk,
                &vault,
                kv,
                &mid,
                &member.public().x25519,
                granter.ed25519_signing_key(),
                &mut r,
            )
            .unwrap();
            out.insert("member_x25519_sk".into(), x(member.x25519_secret_bytes()));
            out.insert("member_x25519_pub".into(), x(member.public().x25519));
            out.insert("granter_ed25519_pub".into(), x(granter.public().ed25519));
            out.insert("hpke_info".into(), x(canon::info_vk(&vault, kv)));
            out.insert("wrapped".into(), x(&g.wrapped));
            out.insert(
                "sig_message".into(),
                x(canon::sig_grant(&vault, &mid, kv, &g.wrapped)),
            );
            out.insert("signature".into(), x(g.signature));
            out.insert("grant_bytes".into(), x(g.to_bytes()));
        }
        "fingerprint" => {
            let fa = key_fingerprint(&a32(v, "a_x25519_pub"), &a32(v, "a_ed25519_pub"));
            let fb = key_fingerprint(&a32(v, "b_x25519_pub"), &a32(v, "b_ed25519_pub"));
            out.insert("a_fingerprint".into(), x(fa));
            out.insert("b_fingerprint".into(), x(fb));
            out.insert(
                "safety_number".into(),
                Value::String(safety_number(&fa, &fb)),
            );
        }
        other => panic!("unknown kind {other}"),
    }
    out
}

/// Extra checks on the recorded bytes that go beyond recomputation: they
/// must decrypt / verify with the recorded keys.
fn check_opens(v: &Value) {
    match v["kind"].as_str().expect("kind") {
        "bundle" => {
            let akek = Key32::from_bytes(a32(v, "akek"));
            let keys = open_private_bundle(
                &akek,
                &id(v, "user_id"),
                u32v(v, "version"),
                &h(v, "bundle"),
            )
            .unwrap();
            assert_eq!(hex::encode(keys.x25519_secret_bytes()), v["x25519_sk"]);
            assert_eq!(hex::encode(keys.public().ed25519), v["ed25519_pub"]);
        }
        "recovery" => {
            let rk = recovery_key_from_mnemonic(v["mnemonic"].as_str().unwrap()).unwrap();
            assert_eq!(hex::encode(rk.expose_secret()), v["recovery_key"]);
            let keys = open_recovery_bundle(&rk, &id(v, "user_id"), &h(v, "bundle")).unwrap();
            assert_eq!(hex::encode(keys.x25519_secret_bytes()), v["x25519_sk"]);
        }
        "grant" => {
            let g = Grant::from_bytes(&h(v, "grant_bytes")).unwrap();
            // Only the member's X25519 key is needed to open; build a
            // throwaway Ed25519 half.
            let me = AccountKeys::from_secret_bytes(a32(v, "member_x25519_sk"), [0; 32]);
            let vk = verify_and_open_grant(
                &g,
                &id(v, "vault_id"),
                u32v(v, "key_version"),
                &id(v, "member_id"),
                &me,
                &a32(v, "granter_ed25519_pub"),
            )
            .unwrap();
            assert_eq!(hex::encode(vk.expose_secret()), v["vk"]);
        }
        _ => {}
    }
}

#[test]
fn t01_account_kats() {
    let text = std::fs::read_to_string(kat_path()).expect("kat file");
    let doc: Value = serde_json::from_str(&text).expect("kat json");
    let vectors = doc["vectors"].as_array().expect("vectors");
    let mut kinds = std::collections::BTreeSet::new();
    for v in vectors {
        kinds.insert(v["kind"].as_str().unwrap().to_string());
        for (k, expected) in compute(v) {
            assert_eq!(&v[&k], &expected, "field {k} of {v}");
        }
        check_opens(v);
    }
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        ["akek", "bundle", "fingerprint", "grant", "recovery"]
    );
}

#[test]
#[ignore = "writes the frozen KAT file; run only when introducing a new format version"]
fn generate_account_kats() {
    let mut inputs: Vec<Value> = vec![
        json!({ "kind": "akek", "export_key": hex::encode([0u8; 64]) }),
        json!({ "kind": "akek", "export_key": hex::encode((0u8..64).collect::<Vec<_>>()) }),
        json!({ "kind": "akek", "export_key": hex::encode([0xa5u8; 64]) }),
    ];
    for (i, seed) in [0x01u8, 0x02].into_iter().enumerate() {
        inputs.push(json!({
            "kind": "bundle",
            "rng_seed": hex::encode([seed; 32]),
            "export_key": hex::encode([seed.wrapping_mul(0x3d); 64]),
            "user_id": hex::encode([0x10 + seed; 16]),
            "version": i as u64 + 1,
        }));
    }
    // Recovery vectors seal the keys of the bundle vectors.
    let bundle_keys: Vec<Map<String, Value>> = inputs
        .iter()
        .filter(|v| v["kind"] == "bundle")
        .map(compute)
        .collect();
    for (seed, bk) in [0x03u8, 0x04].into_iter().zip(&bundle_keys) {
        inputs.push(json!({
            "kind": "recovery",
            "rng_seed": hex::encode([seed; 32]),
            "user_id": hex::encode([0x10 + seed; 16]),
            "x25519_sk": bk["x25519_sk"],
            "ed25519_sk": bk["ed25519_sk"],
        }));
    }
    for (seed, kv) in [(0x05u8, 1u64), (0x06, 0xdead_beef)] {
        inputs.push(json!({
            "kind": "grant",
            "rng_seed": hex::encode([seed; 32]),
            "vk": hex::encode([seed.wrapping_mul(0x11); 32]),
            "vault_id": hex::encode([0xa0 + seed; 16]),
            "member_id": hex::encode([0xb0 + seed; 16]),
            "key_version": kv,
        }));
    }
    let (b0, b1) = (&bundle_keys[0], &bundle_keys[1]);
    inputs.push(json!({
        "kind": "fingerprint",
        "a_x25519_pub": b0["x25519_pub"], "a_ed25519_pub": b0["ed25519_pub"],
        "b_x25519_pub": b1["x25519_pub"], "b_ed25519_pub": b1["ed25519_pub"],
    }));
    inputs.push(json!({
        "kind": "fingerprint",
        "a_x25519_pub": hex::encode([0u8; 32]), "a_ed25519_pub": hex::encode([0u8; 32]),
        "b_x25519_pub": hex::encode([0xffu8; 32]), "b_ed25519_pub": hex::encode([0xffu8; 32]),
    }));

    let vectors: Vec<Value> = inputs
        .into_iter()
        .map(|v| {
            let mut m = v.as_object().unwrap().clone();
            m.extend(compute(&v));
            Value::Object(m)
        })
        .collect();
    let doc = json!({
        "description": "M4-03 account keys (AKEK, private/recovery bundles, BIP39), HPKE+Ed25519 vault-key grants, fingerprints and safety numbers. RNG: ChaCha20Rng(rng_seed); draw order documented in tests/account_kat.rs.",
        "vectors": vectors,
    });
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    std::fs::write(kat_path(), text).unwrap();
}
