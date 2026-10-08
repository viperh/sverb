//! Item envelope behaviour: round-trip, tampering, truncation, versions,
//! nonce freshness, wrong keys and the zip-bomb guard (T-02, T-04 – T-09, T-12).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::SeedableRng;
use sverb_crypto::canon::{self, Id16};
use sverb_crypto::envelope::{
    FORMAT_V1, HEADER_LEN, MAX_DECOMPRESSED, item_key, open_item, parse_header, seal_item,
};
use sverb_crypto::pad::pad256;
use sverb_crypto::random::{os_rng, random_nonce24};
use sverb_crypto::{CryptoError, Key32, aead};

const VAULT_A: Id16 = [0x0a; 16];
const VAULT_B: Id16 = [0x0b; 16];
const ITEM_A: Id16 = [0x1a; 16];
const ITEM_B: Id16 = [0x1b; 16];

fn vk() -> Key32 {
    Key32::from_bytes([0x77; 32])
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([3; 32])
}

fn body_1k() -> Vec<u8> {
    (0..1024u32).map(|i| (i * 7 % 256) as u8).collect()
}

fn seal_a(body: &[u8], kv: u32) -> Vec<u8> {
    seal_item(&vk(), &VAULT_A, &ITEM_A, kv, body, &mut rng()).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // T-02
    #[test]
    fn envelope_roundtrip(
        body in prop::collection::vec(any::<u8>(), 0..64 * 1024),
        vault in any::<[u8; 16]>(),
        item in any::<[u8; 16]>(),
        kv in any::<u32>(),
        key in any::<[u8; 32]>(),
        seed in any::<[u8; 32]>(),
    ) {
        let vk = Key32::from_bytes(key);
        let env = seal_item(&vk, &vault, &item, kv, &body, &mut ChaCha20Rng::from_seed(seed)).unwrap();
        prop_assert_eq!(env[0], FORMAT_V1);
        prop_assert_eq!(&env[1..5], &kv.to_be_bytes());
        // Padding hides the exact size: ciphertext body is a multiple of 256.
        prop_assert_eq!((env.len() - HEADER_LEN - aead::TAG_LEN) % 256, 0);
        let opened = open_item(|k| (k == kv).then_some(&vk), &vault, &item, &env).unwrap();
        prop_assert_eq!(&*opened, &body);
    }
}

// T-04
#[test]
fn tamper_aad_other_item_vault_or_key_version() {
    let env = seal_a(b"secret host", 5);
    let vk = vk();
    // Hands out the VK for any version, so only the AAD can reject.
    let any_kv = |_: u32| Some(&vk);

    // Moved to another item in the same vault.
    assert_eq!(open_item(any_kv, &VAULT_A, &ITEM_B, &env).unwrap_err(), CryptoError::Auth);
    // Moved to another vault.
    assert_eq!(open_item(any_kv, &VAULT_B, &ITEM_A, &env).unwrap_err(), CryptoError::Auth);
    // key_version rewritten in the header, the matching VK supplied.
    let mut forged = env.clone();
    forged[1..5].copy_from_slice(&6u32.to_be_bytes());
    assert_eq!(open_item(any_kv, &VAULT_A, &ITEM_A, &forged).unwrap_err(), CryptoError::Auth);
    // Sanity: the original opens.
    assert!(open_item(any_kv, &VAULT_A, &ITEM_A, &env).is_ok());
}

// T-05
#[test]
fn tamper_every_byte() {
    let env = seal_a(&body_1k(), 1);
    let vk = vk();
    for pos in 0..env.len() {
        for flip in [0x01u8, 0x80] {
            let mut t = env.clone();
            t[pos] ^= flip;
            let err = open_item(|k| (k == 1).then_some(&vk), &VAULT_A, &ITEM_A, &t).unwrap_err();
            match pos {
                0 => assert!(matches!(err, CryptoError::UnsupportedVersion(_)), "pos {pos}: {err:?}"),
                // key_version bytes: no VK for the mutated version.
                1..=4 => assert!(matches!(err, CryptoError::Malformed(_)), "pos {pos}: {err:?}"),
                _ => assert_eq!(err, CryptoError::Auth, "pos {pos}"),
            }
        }
    }
}

// T-06
#[test]
fn truncation_never_panics() {
    let env = seal_a(&body_1k(), 1);
    let vk = vk();
    for len in 0..env.len() {
        let r = open_item(|_| Some(&vk), &VAULT_A, &ITEM_A, &env[..len]);
        assert!(r.is_err(), "truncated to {len} opened");
    }
}

// T-07
#[test]
fn unsupported_version() {
    let mut env = seal_a(b"x", 1);
    env[0] = 0x02;
    let vk = vk();
    assert_eq!(
        open_item(|_| Some(&vk), &VAULT_A, &ITEM_A, &env).unwrap_err(),
        CryptoError::UnsupportedVersion(2)
    );
    assert_eq!(parse_header(&[0x02]).unwrap_err(), CryptoError::UnsupportedVersion(2));
}

// T-08
#[test]
fn nonce_freshness_with_os_rng() {
    let vk = vk();
    let mut rng = os_rng();
    let a = seal_item(&vk, &VAULT_A, &ITEM_A, 1, b"same", &mut rng).unwrap();
    let b = seal_item(&vk, &VAULT_A, &ITEM_A, 1, b"same", &mut rng).unwrap();
    assert_ne!(a, b);
    assert_ne!(a[5..HEADER_LEN], b[5..HEADER_LEN]);
}

// T-09
#[test]
fn wrong_key_is_indistinguishable_from_tampering() {
    let env = seal_a(b"secret", 1);
    let other = Key32::from_bytes([0x78; 32]);
    let wrong_key = open_item(|_| Some(&other), &VAULT_A, &ITEM_A, &env).unwrap_err();
    let vk = vk();
    let mut t = env.clone();
    *t.last_mut().unwrap() ^= 1;
    let tampered = open_item(|_| Some(&vk), &VAULT_A, &ITEM_A, &t).unwrap_err();
    assert_eq!(wrong_key, CryptoError::Auth);
    assert_eq!(wrong_key, tampered);
    assert_eq!(wrong_key.to_string(), tampered.to_string());
    assert_eq!(format!("{wrong_key:?}"), format!("{tampered:?}"));
}

#[test]
fn unknown_key_version_is_malformed() {
    let env = seal_a(b"x", 9);
    let vk = vk();
    let r = open_item(|k| (k == 1).then_some(&vk), &VAULT_A, &ITEM_A, &env);
    assert!(matches!(r, Err(CryptoError::Malformed(_))));
}

// T-12
#[test]
fn zip_bomb_is_rejected() {
    // A correctly authenticated envelope whose zstd payload expands past 16 MiB,
    // built from the public primitives exactly like seal_item does.
    let bomb = zstd::bulk::compress(&vec![0u8; MAX_DECOMPRESSED + 4096], 19).unwrap();
    assert!(bomb.len() < 64 * 1024, "bomb should be small: {}", bomb.len());
    let vk = vk();
    let kv = 1u32;
    let nonce = random_nonce24(&mut rng());
    let ct = aead::seal(
        &item_key(&vk, &ITEM_A),
        &nonce,
        &canon::aad_item(&VAULT_A, &ITEM_A, kv),
        &pad256(&bomb),
    )
    .unwrap();
    let mut env = vec![FORMAT_V1];
    env.extend_from_slice(&kv.to_be_bytes());
    env.extend_from_slice(nonce.as_bytes());
    env.extend_from_slice(&ct);
    assert_eq!(
        open_item(|_| Some(&vk), &VAULT_A, &ITEM_A, &env).unwrap_err(),
        CryptoError::Decompress
    );

    // Exactly at the cap is still accepted.
    let ok = zstd::bulk::compress(&vec![0u8; MAX_DECOMPRESSED], 19).unwrap();
    let out = sverb_crypto::envelope::decode_plaintext(&pad256(&ok)).unwrap();
    assert_eq!(out.len(), MAX_DECOMPRESSED);
}

#[test]
fn garbage_zstd_is_decompress_error() {
    assert_eq!(
        sverb_crypto::envelope::decode_plaintext(&pad256(b"not zstd at all")).unwrap_err(),
        CryptoError::Decompress
    );
}
