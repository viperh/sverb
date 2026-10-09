#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use super::{
    KeychainError,
    cert::{self, ExpiryBadge},
    decrypt_openssh,
    export::{self, PrivateExport},
    fingerprint,
    formats::KeyFormat,
    generate::{self, GENERATABLE, GenerateRequest},
    import::{self, ImportOptions, KeyImporter},
    same_public_key,
};
use crate::{
    model::{ItemId, KeyAlgorithm},
    secret::SecretString,
};

const PASS: &str = "sverb-test";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/keys")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name)).unwrap()
}

fn expected_fp(name: &str) -> String {
    fixture("fingerprints.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let (f, fp) = l.split_once(' ')?;
            (f == name).then(|| fp.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("no fingerprint for {name}"))
}

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sverb-keychain-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn gen_req(alg: KeyAlgorithm, pass: Option<&str>) -> GenerateRequest {
    GenerateRequest {
        algorithm: alg,
        comment: "test@sverb".to_owned(),
        passphrase: pass.map(SecretString::from),
    }
}

fn check_generated(alg: KeyAlgorithm) {
    let g = generate::generate(&gen_req(alg, None)).unwrap();
    assert_eq!(g.algorithm, alg);
    let parsed = decrypt_openssh(g.private_key.expose(), None).unwrap();
    assert_eq!(
        super::public_key_algorithm(parsed.public_key()),
        Some(alg),
        "{alg:?}"
    );
    assert!(same_public_key(
        &super::public_line(parsed.public_key()).unwrap(),
        &g.public_key
    ));
    assert!(g.public_key.ends_with(" test@sverb"));
    assert_eq!(fingerprint(&g.public_key).unwrap(), g.fingerprint);
    assert!(g.fingerprint.starts_with("SHA256:"));
}

/// Each of the 7 types → a parseable OpenSSH private key, a matching public key,
/// the right algorithm (RSA-4096 takes a few seconds in debug builds).
#[test]
fn t01_generate_each_type() {
    for alg in GENERATABLE {
        check_generated(alg);
    }
    assert!(generate::generate(&gen_req(KeyAlgorithm::SkEd25519, None)).is_err());
}

/// A passphrase-encrypted key decrypts with the passphrase, not without.
#[test]
fn t02_generated_encrypted_key() {
    let g = generate::generate(&gen_req(KeyAlgorithm::Ed25519, Some(PASS))).unwrap();
    assert!(g.encrypted);
    assert!(g.private_key.expose().contains("BEGIN OPENSSH PRIVATE KEY"));
    assert_eq!(
        decrypt_openssh(g.private_key.expose(), None).unwrap_err(),
        KeychainError::NeedsPassphrase
    );
    assert_eq!(
        decrypt_openssh(g.private_key.expose(), Some("nope")).unwrap_err(),
        KeychainError::WrongPassphrase
    );
    let k = decrypt_openssh(g.private_key.expose(), Some(PASS)).unwrap();
    assert!(same_public_key(
        &super::public_line(k.public_key()).unwrap(),
        &g.public_key
    ));
    // Stored as a Key item: the passphrase only when remembered.
    let key = g.into_key("k".into(), Some(SecretString::from(PASS)), true);
    assert_eq!(key.passphrase.as_ref().map(|p| p.expose()), Some(PASS));
    assert!(!key.is_agent_ref());
}

/// T-02 compatibility: `ssh-keygen -y` reads a generated encrypted key (skipped when
/// ssh-keygen is not installed; the e2e container always has it).
#[test]
fn t02_ssh_keygen_reads_generated_key() {
    if std::process::Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .is_err()
    {
        eprintln!("ssh-keygen not installed; skipped");
        return;
    }
    let tmp = Tmp::new("t02");
    for alg in [KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP384] {
        let g = generate::generate(&gen_req(alg, Some(PASS))).unwrap();
        let path = tmp.0.join("id");
        let _ = std::fs::remove_file(&path);
        export::write_private_file(&path, &g.private_key, false).unwrap();
        let out = std::process::Command::new("ssh-keygen")
            .args(["-y", "-P", PASS, "-f"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8(out.stdout).unwrap();
        assert!(same_public_key(&line, &g.public_key));
    }
}

/// Every fixture format imports, and the public key has the expected fingerprint.
#[test]
fn t03_import_formats() {
    let cases: &[(&str, KeyFormat, Option<&str>, KeyAlgorithm)] = &[
        (
            "openssh_ed25519",
            KeyFormat::OpenSsh,
            None,
            KeyAlgorithm::Ed25519,
        ),
        (
            "openssh_ecdsa256",
            KeyFormat::OpenSsh,
            None,
            KeyAlgorithm::EcdsaP256,
        ),
        (
            "openssh_ed25519_enc",
            KeyFormat::OpenSsh,
            Some(PASS),
            KeyAlgorithm::Ed25519,
        ),
        (
            "openssh_rsa_enc",
            KeyFormat::OpenSsh,
            Some(PASS),
            KeyAlgorithm::Rsa2048,
        ),
        (
            "pkcs1_rsa.pem",
            KeyFormat::Pkcs1,
            None,
            KeyAlgorithm::Rsa2048,
        ),
        (
            "pkcs1_rsa_enc.pem",
            KeyFormat::Pkcs1,
            Some(PASS),
            KeyAlgorithm::Rsa2048,
        ),
        (
            "sec1_p256.pem",
            KeyFormat::Sec1,
            None,
            KeyAlgorithm::EcdsaP256,
        ),
        (
            "sec1_p384.pem",
            KeyFormat::Sec1,
            None,
            KeyAlgorithm::EcdsaP384,
        ),
        (
            "sec1_p521.pem",
            KeyFormat::Sec1,
            None,
            KeyAlgorithm::EcdsaP521,
        ),
        (
            "sec1_p384_enc.pem",
            KeyFormat::Sec1,
            Some(PASS),
            KeyAlgorithm::EcdsaP384,
        ),
        (
            "pkcs8_ed25519.pem",
            KeyFormat::Pkcs8,
            None,
            KeyAlgorithm::Ed25519,
        ),
        (
            "pkcs8_rsa.pem",
            KeyFormat::Pkcs8,
            None,
            KeyAlgorithm::Rsa2048,
        ),
        (
            "pkcs8_p256.pem",
            KeyFormat::Pkcs8,
            None,
            KeyAlgorithm::EcdsaP256,
        ),
        (
            "pkcs8_p521_enc.pem",
            KeyFormat::Pkcs8Encrypted,
            Some(PASS),
            KeyAlgorithm::EcdsaP521,
        ),
        (
            "pkcs8_ed25519_enc.pem",
            KeyFormat::Pkcs8Encrypted,
            Some(PASS),
            KeyAlgorithm::Ed25519,
        ),
        (
            "pkcs8_rsa_enc.pem",
            KeyFormat::Pkcs8Encrypted,
            Some(PASS),
            KeyAlgorithm::Rsa2048,
        ),
    ];
    for (name, format, pass, alg) in cases {
        let text = fixture(name);
        assert_eq!(import::detect(&text), *format, "{name}");
        assert_eq!(import::needs_passphrase(&text), pass.is_some(), "{name}");
        let k = import::import_text(&text, *pass, ImportOptions::default())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(k.fingerprint, expected_fp(name), "{name}");
        assert_eq!(k.algorithm, *alg, "{name}");
        let private = k.private_key.as_ref().unwrap();
        // Stored in OpenSSH form; encrypted keys stay encrypted with their passphrase,
        // which is remembered.
        assert!(
            private
                .expose()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(k.encrypted, pass.is_some(), "{name}");
        assert_eq!(k.passphrase.as_ref().map(|p| p.expose()), *pass, "{name}");
        let back = decrypt_openssh(private.expose(), *pass).unwrap();
        assert_eq!(
            back.public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            expected_fp(name)
        );
        // Decrypted storage: plain OpenSSH, no passphrase kept.
        if pass.is_some() {
            let opts = ImportOptions {
                keep_encrypted: false,
                remember_passphrase: true,
            };
            let k = import::import_text(&text, *pass, opts).unwrap();
            assert!(!k.encrypted && k.passphrase.is_none());
            decrypt_openssh(k.private_key.unwrap().expose(), None).unwrap();
        }
    }
    // A legacy 3DES PEM: a clear "convert with ssh-keygen -p" message.
    let err = import::import_text(
        &fixture("pkcs1_rsa_des3.pem"),
        Some(PASS),
        ImportOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, KeychainError::UnsupportedEncryptedPem(_)),
        "{err}"
    );
    assert!(err.to_string().contains("ssh-keygen -p"));
    // Garbage.
    assert_eq!(
        import::import_text("hello", None, ImportOptions::default()).unwrap_err(),
        KeychainError::Format
    );
}

/// T-03 (paste): pasted text with surrounding blank lines imports too.
#[test]
fn t03_import_paste_and_file() {
    let text = format!("\n\n{}\n\n", fixture("sec1_p256.pem"));
    let k = import::import_text(&text, None, ImportOptions::default()).unwrap();
    assert_eq!(k.fingerprint, expected_fp("sec1_p256.pem"));
    let path = fixture_dir().join("openssh_ed25519");
    let k = import::import_file(path.to_str().unwrap(), None, ImportOptions::default()).unwrap();
    assert_eq!(k.comment, "fixture@sverb");
    assert_eq!(k.suggested_label(None), "fixture@sverb");
    assert!(matches!(
        import::import_file("/nonexistent/id", None, ImportOptions::default()),
        Err(KeychainError::Read(_))
    ));
}

/// Three wrong passphrases abort the import; nothing comes out.
#[test]
fn t04_wrong_passphrase_three_times() {
    for name in [
        "openssh_ed25519_enc",
        "pkcs1_rsa_enc.pem",
        "pkcs8_rsa_enc.pem",
        "sec1_p384_enc.pem",
    ] {
        let text = fixture(name);
        let mut asked = Vec::new();
        let r = import::import_with_prompt(&text, ImportOptions::default(), |n, last| {
            asked.push((n, last.cloned()));
            Some(SecretString::from("wrong"))
        });
        assert_eq!(r.unwrap_err(), KeychainError::TooManyTries, "{name}");
        assert_eq!(asked.len(), 3);
        assert_eq!(asked[0].1, None);
        assert_eq!(asked[2].1, Some(KeychainError::WrongPassphrase));
        assert!(
            KeychainError::TooManyTries
                .to_string()
                .contains("nothing was saved")
        );
        // Right on the second try.
        let mut n = 0;
        let k = import::import_with_prompt(&text, ImportOptions::default(), |_, _| {
            n += 1;
            Some(SecretString::from(if n == 1 { "wrong" } else { PASS }))
        })
        .unwrap();
        assert_eq!(k.fingerprint, expected_fp(name));
        // Cancel.
        assert_eq!(
            import::import_with_prompt(&text, ImportOptions::default(), |_, _| None).unwrap_err(),
            KeychainError::Cancelled
        );
    }
}

/// A `.pub` alone → an agent reference key without private material.
#[test]
fn t05_public_key_import() {
    let text = fixture("agent_ref.pub");
    assert_eq!(import::detect(&text), KeyFormat::PublicKey);
    let k = import::import_text(&text, None, ImportOptions::default()).unwrap();
    assert!(k.is_agent_ref());
    assert_eq!(k.fingerprint, expected_fp("agent_ref.pub"));
    let key = k.into_key("hw".into());
    assert!(key.is_agent_ref());
    assert!(key.private_key.expose().is_empty());
    assert_eq!(
        export::private_export(&key, &PrivateExport::Keep, None).unwrap_err(),
        KeychainError::NoPrivateKey
    );
}

/// An existing key with the same public key is found (comments ignored).
#[test]
fn t06_duplicate_detection() {
    let k =
        import::import_text(&fixture("openssh_ed25519"), None, ImportOptions::default()).unwrap();
    let other =
        import::import_text(&fixture("agent_ref.pub"), None, ImportOptions::default()).unwrap();
    let a = ItemId::new();
    let b = ItemId::new();
    let same_other_comment = k.public_key.replace("fixture@sverb", "renamed");
    let existing = [
        (a, other.public_key.as_str()),
        (b, same_other_comment.as_str()),
    ];
    assert_eq!(import::find_duplicate(&k.public_key, existing), Some(b));
    assert_eq!(
        import::find_duplicate(&k.public_key, [(a, other.public_key.as_str())]),
        None
    );
}

/// Certificate fields are derived; a certificate for another key is rejected.
#[test]
fn t07_certificate_parsing() {
    let text = fixture("id_cert-cert.pub");
    let info = cert::validate_for_key(&text, &fixture("id_cert.pub")).unwrap();
    assert_eq!(info.principals, vec!["alice".to_owned(), "bob".to_owned()]);
    assert_eq!(info.key_id, "alice@sverb");
    assert_eq!(info.serial, 42);
    assert_eq!(info.cert_type, "user");
    assert_eq!(info.valid_after, 1_767_225_600);
    assert_eq!(info.valid_before, 2_082_758_400);
    assert_eq!(info.ca_fingerprint, expected_fp("user_ca.pub"));
    assert_eq!(cert::suggested_label(&text), "alice@sverb");
    assert_eq!(
        cert::validate_for_key(&text, &fixture("agent_ref.pub")).unwrap_err(),
        KeychainError::CertMismatch
    );
    assert!(matches!(
        cert::parse_cert(&fixture("agent_ref.pub")),
        Err(KeychainError::Cert(_))
    ));
}

/// Expiry badges with an injected clock.
#[test]
fn t08_expiry_badges() {
    let info = cert::parse_cert(&fixture("id_cert-cert.pub")).unwrap();
    let day = 24 * 60 * 60;
    let end = info.valid_before;
    assert_eq!(
        cert::expiry_badge(&info, end - 3 * day),
        ExpiryBadge::Expiring
    );
    assert_eq!(cert::expiry_badge(&info, end + 1), ExpiryBadge::Expired);
    assert_eq!(cert::expiry_badge(&info, end), ExpiryBadge::Expired);
    assert_eq!(cert::expiry_badge(&info, end - 30 * day), ExpiryBadge::None);
    assert_eq!(
        cert::expiry_badge(&info, info.valid_after - 1),
        ExpiryBadge::NotYetValid
    );
    let forever = cert::CertInfo {
        valid_before: cert::FOREVER,
        ..info
    };
    assert_eq!(
        cert::expiry_badge(&forever, end + 10 * day),
        ExpiryBadge::None
    );
    assert_eq!(
        ExpiryBadge::Expiring.worst(ExpiryBadge::Expired),
        ExpiryBadge::Expired
    );
    assert_eq!(
        ExpiryBadge::Expiring.worst(ExpiryBadge::None),
        ExpiryBadge::Expiring
    );
}

/// Export private → mode 0600, round-trips with re-import; re-encrypt works;
/// no overwrite without confirmation.
#[test]
fn t09_export_private() {
    let tmp = Tmp::new("t09");
    let g = generate::generate(&gen_req(KeyAlgorithm::Ed25519, Some(PASS))).unwrap();
    let key = g.into_key("k".into(), Some(SecretString::from(PASS)), true);
    let path = tmp.0.join("id_export");

    let text = export::private_export(&key, &PrivateExport::Keep, None).unwrap();
    export::write_private_file(&path, &text, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let back =
        import::import_file(path.to_str().unwrap(), Some(PASS), ImportOptions::default()).unwrap();
    assert!(same_public_key(&back.public_key, &key.public_key));

    // Refuses to overwrite unless confirmed.
    assert!(matches!(
        export::write_private_file(&path, &text, false),
        Err(KeychainError::Exists(_))
    ));

    // Re-encrypt with a new passphrase (the stored one decrypts).
    let re = export::private_export(
        &key,
        &PrivateExport::Reencrypt(SecretString::from("new-pass")),
        None,
    )
    .unwrap();
    export::write_private_file(&path, &re, true).unwrap();
    let text = import::read_key_file(path.to_str().unwrap()).unwrap();
    assert_eq!(
        import::check_passphrase(text.expose(), PASS).unwrap_err(),
        KeychainError::WrongPassphrase
    );
    import::check_passphrase(text.expose(), "new-pass").unwrap();

    // Decrypted export.
    let plain = export::private_export(&key, &PrivateExport::Decrypted, None).unwrap();
    decrypt_openssh(plain.expose(), None).unwrap();

    // The public key.
    let pub_path = tmp.0.join("id_export.pub");
    export::write_public_file(&pub_path, &export::public_export(&key), false).unwrap();
    assert!(same_public_key(
        &std::fs::read_to_string(&pub_path).unwrap(),
        &key.public_key
    ));
}

/// Change passphrase → the old one fails, the new one works, the stored
/// passphrase follows.
#[test]
fn t10_change_passphrase() {
    let g = generate::generate(&gen_req(KeyAlgorithm::EcdsaP256, Some(PASS))).unwrap();
    let mut key = g.into_key("k".into(), Some(SecretString::from(PASS)), true);
    // Old passphrase from the vault.
    export::change_passphrase(&mut key, None, Some("second"), true).unwrap();
    assert_eq!(key.passphrase.as_ref().map(|p| p.expose()), Some("second"));
    assert_eq!(
        decrypt_openssh(key.private_key.expose(), Some(PASS)).unwrap_err(),
        KeychainError::WrongPassphrase
    );
    decrypt_openssh(key.private_key.expose(), Some("second")).unwrap();
    // Not remembered: typed old passphrase, stored passphrase cleared.
    key.passphrase = None;
    assert_eq!(
        export::change_passphrase(&mut key, None, Some("third"), false).unwrap_err(),
        KeychainError::NeedsPassphrase
    );
    assert_eq!(
        export::change_passphrase(&mut key, Some("bad"), Some("third"), false).unwrap_err(),
        KeychainError::WrongPassphrase
    );
    export::change_passphrase(&mut key, Some("second"), Some("third"), false).unwrap();
    assert!(key.passphrase.is_none());
    decrypt_openssh(key.private_key.expose(), Some("third")).unwrap();
    // Remove the passphrase.
    export::change_passphrase(&mut key, Some("third"), None, true).unwrap();
    assert!(!export::is_encrypted(&key));
    assert!(key.passphrase.is_none());
}

/// The `.ppk` importer hook: the PuTTY parser is registered by default (a
/// truncated file is a format error); a registered importer takes over its format.
#[test]
fn ppk_importer_hook() {
    let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
    assert_eq!(import::detect(ppk), KeyFormat::Plugin(import::PPK_IMPORTER));
    let err = import::import_text(ppk, None, ImportOptions::default()).unwrap_err();
    // The real parser replaced the placeholder.
    assert_eq!(err, KeychainError::Format);
    assert!(err.to_string().contains("PuTTY"));
    let placeholder = import::PpkPlaceholder.decode(ppk, None).unwrap_err();
    assert!(matches!(placeholder, KeychainError::Importer(_)));

    struct Fake;
    impl KeyImporter for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn detects(&self, text: &str) -> bool {
            text.starts_with("FAKE-KEY")
        }
        fn is_encrypted(&self, _: &str) -> bool {
            false
        }
        fn decode(&self, _: &str, _: Option<&str>) -> Result<ssh_key::PrivateKey, KeychainError> {
            Ok(decrypt_openssh(&fixture("openssh_ed25519"), None).unwrap())
        }
    }
    import::register_importer(std::sync::Arc::new(Fake));
    let k = import::import_text("FAKE-KEY 1", None, ImportOptions::default()).unwrap();
    assert_eq!(k.format, KeyFormat::Plugin("fake"));
    assert_eq!(k.fingerprint, expected_fp("openssh_ed25519"));
}

/// Plain OpenSSH keys are kept byte for byte; an encrypted OpenSSH key without a
/// passphrase is accepted as is (the host form's key-file field).
#[test]
fn openssh_stored_as_given() {
    let text = fixture("openssh_ed25519");
    let k = import::import_text(&text, None, ImportOptions::default()).unwrap();
    assert_eq!(k.private_key.unwrap().expose(), text.trim());
    let enc = fixture("openssh_ed25519_enc");
    let k = import::import_text(&enc, None, ImportOptions::default()).unwrap();
    assert!(k.encrypted && k.passphrase.is_none());
    assert_eq!(k.fingerprint, expected_fp("openssh_ed25519_enc"));
    // Other encrypted formats need the passphrase.
    assert_eq!(
        import::import_text(
            &fixture("pkcs8_rsa_enc.pem"),
            None,
            ImportOptions::default()
        )
        .unwrap_err(),
        KeychainError::NeedsPassphrase
    );
}

#[test]
fn path_completion() {
    let dir = fixture_dir();
    let prefix = format!("{}/pkcs8_r", dir.display());
    let (done, names) = import::complete_path(&prefix);
    assert_eq!(names, vec!["pkcs8_rsa.pem", "pkcs8_rsa_enc.pem"]);
    assert_eq!(done, format!("{}/pkcs8_rsa", dir.display()));
    assert_eq!(
        import::file_stem("~/.ssh/id_ed25519.pub").as_deref(),
        Some("id_ed25519")
    );
}
