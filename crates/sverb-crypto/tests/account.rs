//! Account keys, recovery key, vault-key grants, fingerprints.
//! T-02 … T-09 (T-01 KATs live in `tests/account_kat.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use rand_core::SeedableRng;
use sverb_crypto::account::{
    AccountKeys, derive_akek, fuzz_open_bundle, generate_account_keys, open_private_bundle,
    seal_private_bundle,
};
use sverb_crypto::fingerprint::{key_fingerprint, safety_number};
use sverb_crypto::grant::{
    Grant, fuzz_open_grant, grant_vault_key, open_grant, self_grant, verify_and_open_grant,
    verify_grant,
};
use sverb_crypto::kdf::{Argon2Params, argon2id};
use sverb_crypto::recovery::{
    RecoveryKey, open_recovery_bundle, recovery_key_from_mnemonic, recovery_key_generate,
    seal_recovery_bundle,
};
use sverb_crypto::{CryptoError, Key32};

const USER: [u8; 16] = [0x11; 16];
const OTHER_USER: [u8; 16] = [0x22; 16];
const VAULT: [u8; 16] = [0xAA; 16];

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn keys(seed: u8) -> AccountKeys {
    generate_account_keys(&mut rng(seed))
}

// ---------------------------------------------------------------- T-02

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Bundle round-trip; wrong AKEK / user_id / version → Auth.
    #[test]
    fn t02_bundle_roundtrip(
        seed in any::<[u8; 32]>(),
        export in prop::array::uniform32(any::<u8>()),
        uid in any::<[u8; 16]>(),
        version in any::<u32>(),
    ) {
        let mut r = ChaCha20Rng::from_seed(seed);
        let k = generate_account_keys(&mut r);
        let mut ek = [0u8; 64];
        ek[..32].copy_from_slice(&export);
        let akek = derive_akek(&ek);
        let b = seal_private_bundle(&akek, &uid, version, &k, &mut r).unwrap();
        let back = open_private_bundle(&akek, &uid, version, &b).unwrap();
        prop_assert_eq!(back.public(), k.public());
        prop_assert_eq!(back.x25519_secret_bytes(), k.x25519_secret_bytes());

        ek[63] ^= 1;
        let wrong = derive_akek(&ek);
        prop_assert_eq!(open_private_bundle(&wrong, &uid, version, &b).unwrap_err(), CryptoError::Auth);
        let mut uid2 = uid;
        uid2[0] ^= 1;
        prop_assert_eq!(open_private_bundle(&akek, &uid2, version, &b).unwrap_err(), CryptoError::Auth);
        prop_assert_eq!(
            open_private_bundle(&akek, &uid, version.wrapping_add(1), &b).unwrap_err(),
            CryptoError::Auth
        );
    }
}

#[test]
fn t02_bundle_framing() {
    let akek = derive_akek(&[7; 64]);
    let b = seal_private_bundle(&akek, &USER, 1, &keys(1), &mut rng(2)).unwrap();
    assert_eq!(b[0], 0x01);
    let mut v2 = b.clone();
    v2[0] = 2;
    assert_eq!(
        open_private_bundle(&akek, &USER, 1, &v2).unwrap_err(),
        CryptoError::UnsupportedVersion(2)
    );
    assert!(matches!(
        open_private_bundle(&akek, &USER, 1, &b[..b.len() - 1]),
        Err(CryptoError::Malformed(_))
    ));
    let mut flip = b.clone();
    *flip.last_mut().unwrap() ^= 1;
    assert_eq!(
        open_private_bundle(&akek, &USER, 1, &flip).unwrap_err(),
        CryptoError::Auth
    );
}

// ---------------------------------------------------------------- T-03

/// BIP39 reference vectors (trezor/python-mnemonic `vectors.json`, English,
/// 256-bit entropy), which pins us to the standard wordlist and checksum.
#[test]
fn t03_bip39_reference_vectors() {
    let cases: [([u8; 32], &str); 4] = [
        (
            [0x00; 32],
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            [0x7f; 32],
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            [0x80; 32],
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            [0xff; 32],
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
    ];
    for (entropy, phrase) in cases {
        let rk = RecoveryKey::from_bytes(entropy);
        assert_eq!(rk.mnemonic().phrase().as_str(), phrase);
        assert_eq!(recovery_key_from_mnemonic(phrase).unwrap(), rk);
    }
}

#[test]
fn t03_mnemonic_roundtrip_and_errors() {
    let (rk, m) = recovery_key_generate(&mut rng(3));
    assert_eq!(m.words().count(), 24);
    let phrase = m.phrase();
    assert_eq!(recovery_key_from_mnemonic(&phrase).unwrap(), rk);

    // Swap two different words → checksum (or, rarely, still valid: pick a
    // pair whose swap changes the entropy and fails the checksum).
    let words: Vec<&str> = phrase.split(' ').collect();
    let mut found_bad = false;
    for i in 0..23 {
        if words[i] == words[i + 1] {
            continue;
        }
        let mut w = words.clone();
        w.swap(i, i + 1);
        match recovery_key_from_mnemonic(&w.join(" ")) {
            Err(CryptoError::Malformed(_)) => {
                found_bad = true;
                break;
            }
            Ok(other) => assert_ne!(other, rk),
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(found_bad);

    // Replacing the last word with another valid word: checksum error.
    let mut w = words.clone();
    w[23] = if w[23] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    let replaced = w.join(" ");
    // 1/256 chance the replacement is still valid; the seed is fixed so check.
    assert!(recovery_key_from_mnemonic(&replaced).is_err());

    // Unknown word, wrong count.
    let mut w = words.clone();
    w[5] = "notaword";
    assert!(matches!(
        recovery_key_from_mnemonic(&w.join(" ")),
        Err(CryptoError::Malformed(_))
    ));
    assert!(matches!(
        recovery_key_from_mnemonic(&words[..23].join(" ")),
        Err(CryptoError::Malformed(_))
    ));
    // A valid 12-word BIP39 phrase is still rejected (we need 256 bits).
    assert!(matches!(
        recovery_key_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ),
        Err(CryptoError::Malformed(_))
    ));
}

#[test]
fn t03_mixed_case_and_whitespace() {
    let (rk, m) = recovery_key_generate(&mut rng(4));
    let messy: String = m
        .words()
        .enumerate()
        .map(|(i, w)| {
            let w = if i % 2 == 0 {
                w.to_uppercase()
            } else {
                w.to_string()
            };
            let sep = match i % 3 {
                0 => "   ",
                1 => "\t",
                _ => "\n ",
            };
            format!("{sep}{w}")
        })
        .collect::<String>()
        + "  \n";
    assert_eq!(recovery_key_from_mnemonic(&messy).unwrap(), rk);
    let title: String = m
        .words()
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(recovery_key_from_mnemonic(&title).unwrap(), rk);
}

#[test]
fn t03_debug_is_redacted() {
    let (rk, m) = recovery_key_generate(&mut rng(5));
    let first = m.words().next().unwrap().to_string();
    assert!(!format!("{rk:?}{m:?}").contains(&first));
    let k = keys(5);
    let dbg = format!("{k:?}");
    assert!(dbg.contains("REDACTED"));
    assert!(!dbg.contains(&format!("{:?}", k.x25519_secret_bytes())));
}

// ---------------------------------------------------------------- T-04

#[test]
fn t04_recovery_bundle() {
    let k = keys(6);
    let (rk, m) = recovery_key_generate(&mut rng(7));
    let b = seal_recovery_bundle(&rk, &USER, &k, &mut rng(8)).unwrap();
    // Recovery from the typed phrase.
    let rk2 = recovery_key_from_mnemonic(&m.phrase()).unwrap();
    let back = open_recovery_bundle(&rk2, &USER, &b).unwrap();
    assert_eq!(back.public(), k.public());

    let (wrong, _) = recovery_key_generate(&mut rng(9));
    assert_eq!(
        open_recovery_bundle(&wrong, &USER, &b).unwrap_err(),
        CryptoError::Auth
    );
    assert_eq!(
        open_recovery_bundle(&rk, &OTHER_USER, &b).unwrap_err(),
        CryptoError::Auth
    );
    // The recovery bundle is not a private bundle (different key and AAD).
    let akek = derive_akek(&[0; 64]);
    assert!(open_private_bundle(&akek, &USER, 1, &b).is_err());
}

// ---------------------------------------------------------------- T-05

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Seal → open gives the VK; another key, vault_id or key_version → Auth.
    #[test]
    fn t05_grant_open(
        seed in any::<[u8; 32]>(),
        vk in any::<[u8; 32]>(),
        vault in any::<[u8; 16]>(),
        kv in any::<u32>(),
    ) {
        let mut r = ChaCha20Rng::from_seed(seed);
        let member = generate_account_keys(&mut r);
        let granter = generate_account_keys(&mut r);
        let other = generate_account_keys(&mut r);
        let vk = Key32::from_bytes(vk);
        let g = grant_vault_key(
            &vk, &vault, kv, &USER, &member.public().x25519, granter.ed25519_signing_key(), &mut r,
        ).unwrap();
        prop_assert_eq!(open_grant(&g, &vault, kv, member.x25519_secret_bytes()).unwrap(), vk.clone());
        prop_assert_eq!(
            open_grant(&g, &vault, kv, other.x25519_secret_bytes()).unwrap_err(), CryptoError::Auth
        );
        let mut vault2 = vault;
        vault2[15] ^= 0x80;
        prop_assert_eq!(
            open_grant(&g, &vault2, kv, member.x25519_secret_bytes()).unwrap_err(), CryptoError::Auth
        );
        prop_assert_eq!(
            open_grant(&g, &vault, kv ^ 1, member.x25519_secret_bytes()).unwrap_err(),
            CryptoError::Auth
        );
    }
}

#[test]
fn t05_grant_is_randomized_and_encodes() {
    let member = keys(10);
    let granter = keys(11);
    let vk = Key32::from_bytes([3; 32]);
    let mut r = rng(12);
    let g1 = grant_vault_key(
        &vk,
        &VAULT,
        1,
        &USER,
        &member.public().x25519,
        granter.ed25519_signing_key(),
        &mut r,
    )
    .unwrap();
    let g2 = grant_vault_key(
        &vk,
        &VAULT,
        1,
        &USER,
        &member.public().x25519,
        granter.ed25519_signing_key(),
        &mut r,
    )
    .unwrap();
    assert_ne!(g1.wrapped, g2.wrapped, "fresh HPKE ephemeral per grant");
    assert_eq!(g1.wrapped.len(), 4 + 32 + 4 + 48);
    assert_eq!(Grant::from_bytes(&g1.to_bytes()).unwrap(), g1);
    let mut trailing = g1.to_bytes();
    trailing.push(0);
    assert!(Grant::from_bytes(&trailing).is_err());
    // Tampered ciphertext → Auth.
    let mut t = g1.clone();
    *t.wrapped.last_mut().unwrap() ^= 1;
    assert_eq!(
        open_grant(&t, &VAULT, 1, member.x25519_secret_bytes()).unwrap_err(),
        CryptoError::Auth
    );
    // A small-order recipient key is rejected at seal time.
    assert!(
        grant_vault_key(
            &vk,
            &VAULT,
            1,
            &USER,
            &[0; 32],
            granter.ed25519_signing_key(),
            &mut r
        )
        .is_err()
    );
}

// ---------------------------------------------------------------- T-06

#[test]
fn t06_signature() {
    let member = keys(13);
    let granter = keys(14);
    let gp = granter.public().ed25519;
    let vk = Key32::from_bytes([4; 32]);
    let g = grant_vault_key(
        &vk,
        &VAULT,
        5,
        &USER,
        &member.public().x25519,
        granter.ed25519_signing_key(),
        &mut rng(15),
    )
    .unwrap();
    assert_eq!(verify_grant(&g, &VAULT, &USER, 5, &gp), Ok(()));

    let bad = Err(CryptoError::BadSignature);
    let mut t = g.clone();
    t.wrapped[10] ^= 1;
    assert_eq!(verify_grant(&t, &VAULT, &USER, 5, &gp), bad);
    let mut t = g.clone();
    t.wrapped.push(0);
    assert_eq!(verify_grant(&t, &VAULT, &USER, 5, &gp), bad);
    assert_eq!(verify_grant(&g, &VAULT, &OTHER_USER, 5, &gp), bad);
    assert_eq!(verify_grant(&g, &VAULT, &USER, 6, &gp), bad);
    assert_eq!(verify_grant(&g, &[0xAB; 16], &USER, 5, &gp), bad);
    assert_eq!(
        verify_grant(&g, &VAULT, &USER, 5, &member.public().ed25519),
        bad
    );
    let mut t = g.clone();
    t.signature[0] ^= 1;
    assert_eq!(verify_grant(&t, &VAULT, &USER, 5, &gp), bad);
    // Non-canonical S (S + l) is rejected by verify_strict.
    let mut t = g.clone();
    t.signature[63] |= 0xf0;
    assert_eq!(verify_grant(&t, &VAULT, &USER, 5, &gp), bad);

    // verify_and_open checks the signature first.
    assert_eq!(
        verify_and_open_grant(&g, &VAULT, 5, &USER, &member, &gp).unwrap(),
        vk
    );
    assert_eq!(
        verify_and_open_grant(&g, &VAULT, 5, &USER, &member, &member.public().ed25519).unwrap_err(),
        CryptoError::BadSignature
    );
}

// ---------------------------------------------------------------- T-07

#[test]
fn t07_safety_number_symmetry() {
    let a = keys(16).public();
    let b = keys(17).public();
    let fa = a.fingerprint();
    let fb = b.fingerprint();
    assert_eq!(fa, key_fingerprint(&a.x25519, &a.ed25519));
    let n = safety_number(&fa, &fb);
    assert_eq!(n, safety_number(&fb, &fa));
    assert_eq!(n.split(' ').count(), 12);
    assert!(
        n.split(' ')
            .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit()))
    );

    // Changing either half of either key changes the number.
    let c = keys(18).public();
    let mixed_x = key_fingerprint(&c.x25519, &a.ed25519);
    let mixed_ed = key_fingerprint(&a.x25519, &c.ed25519);
    assert_ne!(safety_number(&mixed_x, &fb), n);
    assert_ne!(safety_number(&mixed_ed, &fb), n);
    assert_ne!(safety_number(&fa, &c.fingerprint()), n);
    // Fingerprint is order-sensitive in its two keys.
    assert_ne!(
        key_fingerprint(&a.x25519, &a.ed25519),
        key_fingerprint(&a.ed25519, &a.x25519)
    );
}

// ---------------------------------------------------------------- T-08

#[test]
fn t08_self_grant() {
    let me = keys(19);
    let vk = Key32::from_bytes([5; 32]);
    let g = self_grant(&vk, &VAULT, 1, &USER, &me, &mut rng(20)).unwrap();
    assert_eq!(
        verify_and_open_grant(&g, &VAULT, 1, &USER, &me, &me.public().ed25519).unwrap(),
        vk
    );
    // Same code path: an explicit grant_vault_key to oneself opens the same way.
    let g2 = grant_vault_key(
        &vk,
        &VAULT,
        1,
        &USER,
        &me.public().x25519,
        me.ed25519_signing_key(),
        &mut rng(20),
    )
    .unwrap();
    assert_eq!(g, g2, "self_grant is grant_vault_key with member = self");
    // Someone else can't open it.
    assert_eq!(
        open_grant(&g, &VAULT, 1, keys(21).x25519_secret_bytes()).unwrap_err(),
        CryptoError::Auth
    );
}

// ---------------------------------------------------------------- T-09

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// T-09 (fuzz stub): the grant and bundle decoders never panic on
    /// arbitrary bytes. The same bodies back `fuzz/fuzz_targets/{grant,bundle}_open.rs`.
    #[test]
    fn t09_decoders_never_panic(data in prop::collection::vec(any::<u8>(), 0..300)) {
        fuzz_open_grant(&data);
        fuzz_open_bundle(&data);
    }
}

#[test]
fn t09_structured_edge_cases() {
    // Plausible framings with garbage content.
    let mut g = vec![0, 0, 0, 88];
    g.extend_from_slice(&[0, 0, 0, 32]);
    g.extend_from_slice(&[0; 32]);
    g.extend_from_slice(&[0, 0, 0, 48]);
    g.extend_from_slice(&[0; 48]);
    g.extend_from_slice(&[0; 64]);
    fuzz_open_grant(&g);
    let mut huge = vec![0xff, 0xff, 0xff, 0xff];
    huge.extend_from_slice(&[0; 64]);
    fuzz_open_grant(&huge);
    let mut b = vec![1u8];
    b.extend_from_slice(&[0; 130]);
    fuzz_open_bundle(&b);
    fuzz_open_bundle(&[]);
    fuzz_open_grant(&[]);
}

// ---------------------------------------------------- §11.2.1 (sanity)

/// The local KEK (Argon2id with `local_salt`) and AKEK (HKDF of the OPAQUE
/// export_key) are independent derivations of the same password.
///
/// export_key is stood in for by a 64-byte value derived from the password
/// with an unrelated construction. Sanity check only.
#[test]
fn two_derivations_are_unrelated() {
    let password = b"correct horse battery staple";
    let params = Argon2Params {
        m_kib: Argon2Params::MIN_M_KIB,
        t: 1,
        p: 1,
        salt: [0x5a; 16],
    };
    let local_kek = argon2id(password, &params).unwrap();
    let mut export_key = [0u8; 64];
    let stand_in =
        sverb_crypto::kdf::hkdf_sha256(password, None, b"test/opaque-stand-in", 64).unwrap();
    export_key.copy_from_slice(&stand_in);
    let akek = derive_akek(&export_key);

    assert_ne!(local_kek, akek);
    let l = local_kek.expose_secret();
    let a = akek.expose_secret();
    // No shared prefix/suffix and no byte-wise equality beyond chance.
    let equal = l.iter().zip(a.iter()).filter(|(x, y)| x == y).count();
    assert!(equal < 6, "{equal} equal bytes");
    // AKEK is not the raw export key either.
    assert_ne!(&export_key[..32], a);
    // A KEK from a different local salt is unrelated to both.
    let other = argon2id(
        password,
        &Argon2Params {
            salt: [0x5b; 16],
            ..params
        },
    )
    .unwrap();
    assert_ne!(other, local_kek);
    assert_ne!(other, akek);
}
