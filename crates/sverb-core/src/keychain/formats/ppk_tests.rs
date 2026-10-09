//! `.ppk` parser tests (the T-07 property test).
//!
//! The fixtures (`tests/fixtures/putty/keys/`) are written by
//! `tests/fixtures/putty/gen_ppk.py` from plain OpenSSH keys (`src_*`); the expected
//! fingerprints come from `ssh-keygen -lf` on those keys.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use proptest::prelude::*;
use ssh_key::HashAlg;

use super::{MAX_ARGON2_MEMORY_KIB, MAX_PPK_BYTES, PpkVersion, decode, is_ppk, parse, public_key};
use crate::keychain::{
    KeychainError,
    formats::KeyFormat,
    import::{self, ImportOptions},
};

const PASS: &str = "fixture";
const ALGS: [&str; 3] = ["ed25519", "ecdsa256", "rsa2048"];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/putty")
}

fn ppk(name: &str) -> String {
    std::fs::read_to_string(dir().join("keys").join(format!("{name}.ppk"))).unwrap()
}

fn source(alg: &str) -> ssh_key::PrivateKey {
    let text = std::fs::read_to_string(dir().join("keys").join(format!("src_{alg}"))).unwrap();
    ssh_key::PrivateKey::from_openssh(text.trim()).unwrap()
}

fn expected_fp(alg: &str) -> String {
    std::fs::read_to_string(dir().join("fingerprints.txt"))
        .unwrap()
        .lines()
        .find_map(|l| {
            let (a, fp) = l.split_once(' ')?;
            (a == alg).then(|| fp.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("no fingerprint for {alg}"))
}

/// Every fixture name with its algorithm and whether it is encrypted.
fn fixtures() -> Vec<(String, &'static str, bool)> {
    let mut out = Vec::new();
    for v in ["v2", "v3"] {
        for alg in ALGS {
            for enc in [false, true] {
                let name = format!("{v}_{alg}{}", if enc { "_enc" } else { "" });
                out.push((name, alg, enc));
            }
        }
    }
    out
}

/// Replace the value of the header line `name`.
fn set_header(text: &str, name: &str, value: &str) -> String {
    text.lines()
        .map(|l| match l.split_once(": ") {
            Some((k, _)) if k == name => format!("{k}: {value}"),
            _ => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flip one base64 character of the first private line.
fn tamper_private(text: &str) -> String {
    let mut out = Vec::new();
    let mut in_private = false;
    let mut done = false;
    for l in text.lines() {
        if in_private && !done {
            let mut chars: Vec<char> = l.chars().collect();
            chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
            out.push(chars.into_iter().collect::<String>());
            done = true;
            continue;
        }
        in_private = l.starts_with("Private-Lines:");
        out.push(l.to_owned());
    }
    out.join("\n")
}

// ------------------------------------------------------------------ T-01

/// Each fixture (v2 / v3 × Ed25519 / ECDSA P-256 / RSA 2048, plain and encrypted)
/// decodes to the source key; the fingerprint is the recorded one.
#[test]
fn t01_fixtures_decode_with_expected_fingerprint() {
    for (name, alg, enc) in fixtures() {
        let text = ppk(&name);
        let file = parse(&text).unwrap();
        assert_eq!(file.encrypted, enc, "{name}");
        assert_eq!(
            file.version,
            if name.starts_with("v2") {
                PpkVersion::V2
            } else {
                PpkVersion::V3
            }
        );
        assert_eq!(file.kdf.is_some(), enc && name.starts_with("v3"), "{name}");
        let pass = enc.then_some(PASS);
        let key = decode(&text, pass).unwrap_or_else(|e| panic!("{name}: {e}"));
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        assert_eq!(fp, expected_fp(alg), "{name}");
        assert_eq!(key.key_data(), source(alg).key_data(), "{name}");
        let comment = format!(
            "fixture-{alg}-{}{}",
            &name[..2],
            if enc { "_enc" } else { "" }
        );
        assert_eq!(key.comment().as_bytes(), comment.as_bytes(), "{name}");
        // The public key is readable without the passphrase.
        let public = public_key(&text).unwrap();
        assert_eq!(
            public.fingerprint(HashAlg::Sha256).to_string(),
            expected_fp(alg)
        );
    }
}

/// T-01 through the keychain: the registered importer is the PuTTY parser; the stored
/// key is OpenSSH.
#[test]
fn t01_keychain_import() {
    for (name, alg, enc) in fixtures() {
        let text = ppk(&name);
        assert!(is_ppk(&text));
        assert_eq!(
            import::detect(&text),
            KeyFormat::Plugin(import::PPK_IMPORTER)
        );
        assert_eq!(import::needs_passphrase(&text), enc, "{name}");
        let k = import::import_text(&text, enc.then_some(PASS), ImportOptions::default())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(k.fingerprint, expected_fp(alg), "{name}");
        assert_eq!(k.format, KeyFormat::Plugin(import::PPK_IMPORTER));
        assert!(
            k.private_key
                .unwrap()
                .expose()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(k.comment.starts_with("fixture-"), "{name}: {}", k.comment);
    }
}

// ------------------------------------------------------------------ T-02

/// A wrong passphrase is a MAC mismatch → "wrong passphrase"; a missing one asks.
#[test]
fn t02_wrong_passphrase() {
    for name in ["v2_ed25519_enc", "v3_ed25519_enc", "v2_rsa2048_enc"] {
        let text = ppk(name);
        assert_eq!(
            decode(&text, Some("not-it")).unwrap_err(),
            KeychainError::WrongPassphrase,
            "{name}"
        );
        assert_eq!(
            decode(&text, None).unwrap_err(),
            KeychainError::NeedsPassphrase
        );
    }
}

fn is_mac_error(e: &KeychainError) -> bool {
    matches!(e, KeychainError::Invalid(m) if m.contains("MAC"))
}

/// A tampered private blob, MAC line or comment fails the MAC check.
#[test]
fn t02_tampered_files() {
    for name in ["v2_ed25519", "v3_ed25519", "v2_rsa2048", "v3_ecdsa256"] {
        let text = ppk(name);
        let e = decode(&tamper_private(&text), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?}");

        let mac = parse(&text).unwrap();
        let hex: String = text
            .lines()
            .find_map(|l| l.strip_prefix("Private-MAC: "))
            .unwrap()
            .to_owned();
        let flipped = format!(
            "{}{}",
            if hex.starts_with('0') { '1' } else { '0' },
            &hex[1..]
        );
        let e = decode(&set_header(&text, "Private-MAC", &flipped), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?}");
        // A MAC of the wrong length or not hex: not a key file.
        let e = decode(&set_header(&text, "Private-MAC", &hex[2..]), None).unwrap_err();
        assert_eq!(e, KeychainError::Format);
        let e = decode(
            &set_header(&text, "Private-MAC", &"zz".repeat(hex.len() / 2)),
            None,
        )
        .unwrap_err();
        assert_eq!(e, KeychainError::Format);

        let e = decode(&set_header(&text, "Comment", "someone else"), None).unwrap_err();
        assert!(is_mac_error(&e), "{name}: {e:?} ({:?})", mac.comment);
    }
    // Encrypted and tampered: indistinguishable from a wrong passphrase.
    let e = decode(&tamper_private(&ppk("v2_ed25519_enc")), Some(PASS)).unwrap_err();
    assert_eq!(e, KeychainError::WrongPassphrase);
}

// ------------------------------------------------------------------ T-03

/// DSA and v1 files are refused; truncated files are errors, never panics.
#[test]
fn t03_unsupported_and_truncated() {
    let dss = ppk("v2_ed25519").replace("ssh-ed25519", "ssh-dss");
    assert!(matches!(
        decode(&dss, None).unwrap_err(),
        KeychainError::Unsupported(a) if a.contains("ssh-dss")
    ));
    assert!(matches!(
        import::import_text(&dss, None, ImportOptions::default()).unwrap_err(),
        KeychainError::Unsupported(_)
    ));
    let v1 = ppk("v2_ed25519").replace("File-2", "File-1");
    assert!(matches!(
        decode(&v1, None).unwrap_err(),
        KeychainError::Unsupported(_)
    ));
    let cipher = set_header(&ppk("v2_ed25519_enc"), "Encryption", "3des-cbc");
    assert!(matches!(
        decode(&cipher, Some(PASS)).unwrap_err(),
        KeychainError::Unsupported(_)
    ));

    for name in ["v2_ed25519", "v3_rsa2048", "v2_ecdsa256_enc"] {
        let text = ppk(name);
        let full = text.trim_end();
        // Every line prefix and a sample of byte prefixes.
        let lines: Vec<&str> = full.lines().collect();
        for n in 0..lines.len() {
            let cut = lines[..n].join("\n");
            assert!(decode(&cut, Some(PASS)).is_err(), "{name}: {n} lines");
        }
        for n in (0..full.len()).step_by(7) {
            if let Some(cut) = full.get(..n) {
                assert!(decode(cut, Some(PASS)).is_err(), "{name}: {n} bytes");
            }
        }
    }
    // A missing private line count.
    let e = decode(&set_header(&ppk("v2_ed25519"), "Private-Lines", "x"), None).unwrap_err();
    assert_eq!(e, KeychainError::Format);
    // Oversized inputs are refused before parsing.
    let big = format!("{}{}", ppk("v2_ed25519"), "A".repeat(MAX_PPK_BYTES));
    assert!(matches!(
        decode(&big, None).unwrap_err(),
        KeychainError::Invalid(_)
    ));
    let many = format!("{}{}", ppk("v2_ed25519"), "\n".repeat(2000));
    assert!(matches!(
        decode(&many, None).unwrap_err(),
        KeychainError::Invalid(_)
    ));
    let lines = set_header(&ppk("v2_ed25519"), "Public-Lines", "100000");
    assert!(matches!(
        decode(&lines, None).unwrap_err(),
        KeychainError::Invalid(_)
    ));
}

/// A key whose private part doesn't match its public part (both MAC-covered) is refused.
#[test]
fn t03_mismatched_parts() {
    // The MAC covers both parts, so check the builder directly.
    let ed = parse(&ppk("v2_ed25519")).unwrap();
    let other = super::public_of(&parse(&ppk("v3_ed25519")).unwrap()).unwrap();
    let mine = super::public_of(&ed).unwrap();
    assert_eq!(
        mine.key_data(),
        other.key_data(),
        "same key, two fixture files"
    );
    let rsa = parse(&ppk("v2_rsa2048")).unwrap();
    let rsa_pub = super::public_of(&rsa).unwrap();
    // An Ed25519 private blob against an RSA public key.
    let e = super::build(&rsa_pub, &ed.private_blob, "x").unwrap_err();
    assert!(matches!(e, KeychainError::Invalid(_)), "{e:?}");
}

// ------------------------------------------------------------------ T-04

/// V3 Argon2 parameters out of sane bounds are refused before any derivation.
#[test]
fn t04_argon2_bounds() {
    let text = ppk("v3_ed25519_enc");
    let cases = [
        ("Argon2-Memory", (MAX_ARGON2_MEMORY_KIB + 1).to_string()),
        ("Argon2-Memory", "4294967295".to_owned()),
        ("Argon2-Passes", "0".to_owned()),
        ("Argon2-Passes", "100000".to_owned()),
        ("Argon2-Parallelism", "0".to_owned()),
        ("Argon2-Parallelism", "16777215".to_owned()),
    ];
    for (header, value) in cases {
        let bad = set_header(&text, header, &value);
        let start = std::time::Instant::now();
        let e = parse(&bad).unwrap_err();
        assert!(
            matches!(e, KeychainError::Invalid(_)),
            "{header}={value}: {e:?}"
        );
        assert!(matches!(
            decode(&bad, Some(PASS)).unwrap_err(),
            KeychainError::Invalid(_)
        ));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    // memory × passes over the work budget (each alone in range).
    let bad = set_header(
        &set_header(&text, "Argon2-Memory", &MAX_ARGON2_MEMORY_KIB.to_string()),
        "Argon2-Passes",
        "500",
    );
    assert!(matches!(
        parse(&bad).unwrap_err(),
        KeychainError::Invalid(_)
    ));
    // A salt that is too short or too long.
    assert_eq!(
        parse(&set_header(&text, "Argon2-Salt", "0011")).unwrap_err(),
        KeychainError::Format
    );
    assert_eq!(
        parse(&set_header(&text, "Argon2-Salt", &"00".repeat(65))).unwrap_err(),
        KeychainError::Format
    );
    // An unknown key derivation.
    assert!(matches!(
        parse(&set_header(&text, "Key-Derivation", "scrypt")).unwrap_err(),
        KeychainError::Unsupported(_)
    ));
}

// ------------------------------------------------------------------ T-07

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// T-07 (the body of `fuzz/fuzz_targets/ppk_parse.rs`): arbitrary text after the
    /// header never panics.
    #[test]
    fn t07_arbitrary_text_never_panics(body in "\\PC{0,400}", ver in 0u8..5) {
        let text = format!("PuTTY-User-Key-File-{ver}: ssh-ed25519\n{body}");
        let _ = parse(&text);
        let _ = public_key(&text);
        let _ = decode(&text, Some(PASS));
    }

    /// Single-line mutations of real (cheap: no Argon2) fixtures never panic.
    #[test]
    fn t07_mutated_fixture_never_panics(
        which in 0usize..4,
        line in 0usize..40,
        junk in "[ -~]{0,80}",
    ) {
        let name = ["v2_ed25519", "v3_ecdsa256", "v2_rsa2048_enc", "v3_rsa2048"][which];
        let text = ppk(name);
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let i = line % lines.len();
        lines[i] = junk;
        let mutated = lines.join("\n");
        let _ = decode(&mutated, Some(PASS));
    }
}
