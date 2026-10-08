//! M1-18: static checks of the OpenSSH fixture image (no Docker needed).
//!
//! - every `Profile` has a `profiles/<name>.conf` and every file a `Profile`;
//! - the base config plus each profile passes `sshd -t` (when a local `sshd` exists;
//!   `check-configs.sh` rewrites the paths into a temp dir);
//! - the fixture keys parse with sverb's key import, with the expected algorithms;
//! - the Dockerfile copies the build context the harness sends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeSet, path::Path, process::Command};

use sverb_conn::ssh::keyfile::import_openssh;
use sverb_core::model::KeyAlgorithm;
use sverb_e2e::{
    Profile,
    keys::{self, FixtureKey, fixtures_dir},
    sshd::fixture_hash,
};

#[test]
fn every_profile_has_a_config_file() {
    let dir = fixtures_dir().join("profiles");
    let files: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| {
            e.unwrap()
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let profiles: BTreeSet<String> = Profile::ALL.iter().map(|p| p.name().to_owned()).collect();
    assert_eq!(files, profiles);
    for profile in Profile::ALL {
        let text = std::fs::read_to_string(dir.join(format!("{}.conf", profile.name()))).unwrap();
        // A `Match` block would swallow the rest of the base config (see sshd_config).
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("Match")),
            "{}: profiles must not use Match",
            profile.name()
        );
    }
}

fn sshd_binary() -> Option<String> {
    ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map(str::to_owned)
}

/// Every profile is a valid sshd configuration (`sshd -t`). Skipped without a local
/// `sshd` or `ssh-keygen` (the image runs `sshd -t` at every start anyway).
#[cfg(unix)]
#[test]
fn sshd_accepts_every_profile() {
    let Some(sshd) = sshd_binary() else {
        eprintln!("skipped: no local sshd binary");
        return;
    };
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("skipped: no ssh-keygen");
        return;
    }
    let out = Command::new("bash")
        .arg(fixtures_dir().join("check-configs.sh"))
        .arg(&sshd)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for profile in Profile::ALL {
        assert!(
            stdout.contains(&format!("ok      {}", profile.name())),
            "{stdout}"
        );
    }
}

#[test]
fn fixture_keys_import() {
    for (key, algorithm, encrypted) in [
        (FixtureKey::Ed25519, KeyAlgorithm::Ed25519, false),
        (FixtureKey::EcdsaP256, KeyAlgorithm::EcdsaP256, false),
        (FixtureKey::Rsa4096, KeyAlgorithm::Rsa4096, false),
        (FixtureKey::Ed25519Encrypted, KeyAlgorithm::Ed25519, true),
        (FixtureKey::Cert, KeyAlgorithm::Ed25519, false),
        (FixtureKey::UserCa, KeyAlgorithm::Ed25519, false),
        (FixtureKey::HostCa, KeyAlgorithm::Ed25519, false),
    ] {
        let imported = import_openssh(&key.private()).unwrap();
        assert_eq!(imported.algorithm, algorithm, "{key:?}");
        assert_eq!(imported.encrypted, encrypted, "{key:?}");
        let public_line = key.public();
        let public: Vec<&str> = public_line.split_whitespace().take(2).collect();
        let parsed: Vec<&str> = imported.public_key.split_whitespace().take(2).collect();
        assert_eq!(parsed, public, "{key:?}");
        assert!(key.public().contains("TEST-ONLY"), "{key:?}: comment");
    }
    assert_eq!(
        FixtureKey::Ed25519Encrypted.passphrase(),
        Some(keys::PASSPHRASE)
    );
    let cert = FixtureKey::Cert.certificate().unwrap();
    assert!(
        cert.starts_with("ssh-ed25519-cert-v01@openssh.com "),
        "{cert}"
    );
    assert!(keys::known_hosts_ca_line().starts_with("@cert-authority * ssh-ed25519 "));
}

/// `authorized_keys` holds every user key except the certificate-only one.
#[test]
fn authorized_keys_lists_the_user_keys() {
    let text = std::fs::read_to_string(keys::keys_dir().join("authorized_keys")).unwrap();
    let blob = |k: FixtureKey| k.public().split_whitespace().nth(1).unwrap().to_owned();
    for key in [
        FixtureKey::Ed25519,
        FixtureKey::EcdsaP256,
        FixtureKey::Rsa4096,
        FixtureKey::Ed25519Encrypted,
    ] {
        assert!(text.contains(&blob(key)), "{key:?} missing");
    }
    for key in [FixtureKey::Cert, FixtureKey::UserCa, FixtureKey::HostCa] {
        assert!(!text.contains(&blob(key)), "{key:?} must not be authorized");
    }
}

#[test]
fn readme_warns_about_test_only_keys() {
    let readme = std::fs::read_to_string(fixtures_dir().join("README.md")).unwrap();
    assert!(readme.contains("TEST-ONLY"), "{readme}");
}

/// The Dockerfile only copies what the harness puts into the build context.
#[test]
fn dockerfile_copies_the_build_context() {
    let dockerfile = std::fs::read_to_string(fixtures_dir().join("Dockerfile")).unwrap();
    for line in dockerfile.lines().filter(|l| l.starts_with("COPY ")) {
        let src = line.split_whitespace().nth(1).unwrap();
        let top = src.trim_end_matches('/').split('/').next().unwrap();
        assert!(
            [
                "keys",
                "sshd_config",
                "profiles",
                "pam",
                "bin",
                "entrypoint.sh"
            ]
            .contains(&top),
            "{line}: not in the harness build context (sshd.rs CONTEXT)"
        );
        assert!(fixtures_dir().join(src).exists(), "{line}: missing source");
    }
    assert!(
        !dockerfile.lines().any(|l| l.starts_with("EXPOSE")),
        "no EXPOSE: unpublished JumpNet hosts rely on it"
    );
}

#[test]
fn fixture_hash_is_stable() {
    let a = fixture_hash(&fixtures_dir()).unwrap();
    let b = fixture_hash(&fixtures_dir()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 16);
}
