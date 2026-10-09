//! Padding, wrapping, Argon2 params, canonical builders, recording chunks,
//! key-type hygiene and the fuzz entry point (T-03, T-10, T-11, T-13, T-15, T-16).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::SeedableRng;
use sverb_crypto::canon::{aad_item, len_prefixed};
use sverb_crypto::envelope::fuzz_open_item;
use sverb_crypto::kdf::{Argon2Params, argon2id};
use sverb_crypto::pad::{pad256, unpad256};
use sverb_crypto::random::{random_key32, random_salt16};
use sverb_crypto::recording::{open_chunk, recording_key, seal_chunk};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key, unwrap_key32, wrap_key};
use sverb_crypto::{CryptoError, Key32, Nonce24};

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([9; 32])
}

proptest! {
    // T-03
    #[test]
    fn pad_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let p = pad256(&data);
        prop_assert_eq!(p.len() % 256, 0);
        prop_assert!(p.len() > data.len());
        prop_assert!(p.len() <= data.len() + 256);
        prop_assert_eq!(unpad256(&p).unwrap(), &data[..]);
    }

    // T-16: the fuzz target body must never panic on arbitrary input.
    #[test]
    fn fuzz_open_item_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        fuzz_open_item(&data);
        let mut v1 = data.clone();
        if let Some(b) = v1.first_mut() { *b = 0x01; }
        fuzz_open_item(&v1);
    }

    #[test]
    fn unpad_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = unpad256(&data);
    }
}

// T-10
#[test]
fn wrap_purposes_are_domain_separated() {
    let kek = random_key32(&mut rng());
    let vk = random_key32(&mut rng());
    let (v1, v2) = ([1u8; 16], [2u8; 16]);
    let w = wrap_key(
        &kek,
        &WrapPurpose::VaultKey(v1),
        vk.expose_secret(),
        &mut rng(),
    )
    .unwrap();
    assert_eq!(
        unwrap_key32(&kek, &WrapPurpose::VaultKey(v1), &w).unwrap(),
        vk
    );
    for wrong in [
        WrapPurpose::VaultKey(v2),
        WrapPurpose::SyncTokens,
        WrapPurpose::Lmk,
        WrapPurpose::RecordingKey,
    ] {
        assert_eq!(
            unwrap_key(&kek, &wrong, &w).unwrap_err(),
            CryptoError::Auth,
            "{wrong:?}"
        );
    }
    // Wrong KEK.
    let other = Key32::from_bytes([0xee; 32]);
    assert_eq!(
        unwrap_key(&other, &WrapPurpose::VaultKey(v1), &w).unwrap_err(),
        CryptoError::Auth
    );
    // Truncation never panics.
    for len in 0..w.len() {
        assert!(unwrap_key(&kek, &WrapPurpose::VaultKey(v1), &w[..len]).is_err());
    }
}

#[test]
fn wrap_variable_length_secret() {
    let kek = Key32::from_bytes([5; 32]);
    let tokens = b"access=abc;refresh=def".to_vec();
    let w = wrap_key(&kek, &WrapPurpose::SyncTokens, &tokens, &mut rng()).unwrap();
    assert_eq!(
        *unwrap_key(&kek, &WrapPurpose::SyncTokens, &w).unwrap(),
        tokens
    );
    assert!(matches!(
        unwrap_key32(&kek, &WrapPurpose::SyncTokens, &w),
        Err(CryptoError::Malformed(_))
    ));
}

// T-11
#[test]
fn argon2_params_validation() {
    let salt = random_salt16(&mut rng());
    let bad = Argon2Params {
        m_kib: 1024,
        t: 3,
        p: 1,
        salt,
    };
    assert!(matches!(
        argon2id(b"pw", &bad),
        Err(CryptoError::InvalidParams(_))
    ));
    assert!(matches!(
        argon2id(
            b"pw",
            &Argon2Params {
                t: 0,
                ..Argon2Params::with_salt(salt)
            }
        ),
        Err(CryptoError::InvalidParams(_))
    ));
    let d = Argon2Params::with_salt(salt);
    assert_eq!((d.m_kib, d.t, d.p), (262_144, 3, 1));
}

#[test]
fn argon2_wrong_password_differs() {
    let params = Argon2Params {
        m_kib: 19_456,
        t: 1,
        p: 1,
        salt: [4; 16],
    };
    let a = argon2id(b"right", &params).unwrap();
    let b = argon2id(b"wrong", &params).unwrap();
    assert_ne!(a, b);
    assert_eq!(a, argon2id(b"right", &params).unwrap());
}

// T-13
#[test]
fn canonical_builders() {
    let aad = aad_item(&[0xaa; 16], &[0xbb; 16], 7);
    assert_eq!(aad.len(), 13 + 16 + 16 + 4);
    assert_eq!(&aad[..13], b"sverb-item-v1");
    assert_eq!(&aad[13..29], &[0xaa; 16]);
    assert_eq!(&aad[29..45], &[0xbb; 16]);
    assert_eq!(&aad[45..], &[0, 0, 0, 7]);
    assert_eq!(
        len_prefixed(b"abc"),
        [0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63]
    );
}

#[test]
fn recording_chunks_bind_index_and_last_flag() {
    let k = recording_key(&Key32::from_bytes([1; 32]));
    let conn = [3u8; 16];
    let c = seal_chunk(&k, &conn, 4, false, b"line\n", &mut rng()).unwrap();
    assert_eq!(*open_chunk(&k, &conn, 4, false, &c).unwrap(), b"line\n");
    assert_eq!(
        open_chunk(&k, &conn, 5, false, &c).unwrap_err(),
        CryptoError::Auth
    );
    assert_eq!(
        open_chunk(&k, &conn, 4, true, &c).unwrap_err(),
        CryptoError::Auth
    );
    assert_eq!(
        open_chunk(&k, &[4; 16], 4, false, &c).unwrap_err(),
        CryptoError::Auth
    );
    for len in 0..c.len() {
        assert!(open_chunk(&k, &conn, 4, false, &c[..len]).is_err());
    }
}

// T-15
#[test]
fn key_debug_is_redacted() {
    let bytes = [0xab; 32];
    let k = Key32::from_bytes(bytes);
    let dbg = format!("{k:?}");
    assert!(!dbg.contains("ab"), "{dbg}");
    assert!(!dbg.contains("171"), "{dbg}");
    assert!(dbg.contains("REDACTED"));
    let k2 = Key32::from_bytes([0x5c; 32]);
    let dbg2 = format!("{k2:#?}");
    assert!(
        !dbg2.to_lowercase().contains("5c") && !dbg2.contains("92"),
        "{dbg2}"
    );
    // Nonces are public and may print.
    assert!(format!("{:?}", Nonce24::from_bytes([0; 24])).starts_with("Nonce24("));
}

#[test]
fn key_types_zeroize() {
    use zeroize::Zeroize;
    let mut k = Key32::from_bytes([0xff; 32]);
    k.zeroize();
    assert_eq!(k.expose_secret(), &[0u8; 32]);
}
