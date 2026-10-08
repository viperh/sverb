//! The committed fixture keys (`tests/fixtures/sshd/keys/`).
//!
//! **TEST-ONLY key material.** These keys and CAs are public (they are in the
//! repository) and protect nothing; never trust them outside the e2e containers.
//!
//! | File | What |
//! |---|---|
//! | `id_ed25519`, `id_ecdsa` (P-256), `id_rsa` (4096) | user keys in `authorized_keys` |
//! | `id_ed25519_encrypted` | user key encrypted with [`PASSPHRASE`], in `authorized_keys` |
//! | `id_cert` + `id_cert-cert.pub` | user key **not** in `authorized_keys`, with a certificate from the user CA (principal `test`) |
//! | `user_ca` | the CA trusted by the `cert` profile (`TrustedUserCAKeys`) |
//! | `host_ca` | signs the `cert` profile's host certificate; `known_hosts_ca` is its `@cert-authority` line |

use std::path::PathBuf;

/// The user of the image (`test`, shell bash). `testzsh` and `testfish` exist too.
pub const USER: &str = "test";
/// The password of every user of the image.
pub const PASSWORD: &str = "test";
/// The passphrase of [`FixtureKey::Ed25519Encrypted`].
pub const PASSPHRASE: &str = "fixture";
/// The OTP accepted by the `kbd` profile's PAM module (prompt `Password: `).
pub const OTP: &str = "424242";

/// `tests/fixtures/sshd/` in the source tree.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sshd")
}

/// `tests/fixtures/sshd/keys/`.
pub fn keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}

/// A committed fixture key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureKey {
    /// `id_ed25519`.
    Ed25519,
    /// `id_ecdsa` (NIST P-256).
    EcdsaP256,
    /// `id_rsa` (4096 bits).
    Rsa4096,
    /// `id_ed25519_encrypted` (passphrase [`PASSPHRASE`]).
    Ed25519Encrypted,
    /// `id_cert`: only accepted with its certificate (`cert` profile).
    Cert,
    /// `user_ca`.
    UserCa,
    /// `host_ca`.
    HostCa,
}

impl FixtureKey {
    /// The private key file name.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::EcdsaP256 => "id_ecdsa",
            Self::Rsa4096 => "id_rsa",
            Self::Ed25519Encrypted => "id_ed25519_encrypted",
            Self::Cert => "id_cert",
            Self::UserCa => "user_ca",
            Self::HostCa => "host_ca",
        }
    }

    /// The private key (OpenSSH format).
    pub fn private(self) -> String {
        read(self.file_name())
    }

    /// The public key line (`ssh-ed25519 AAAA… comment`).
    pub fn public(self) -> String {
        read(&format!("{}.pub", self.file_name())).trim().to_owned()
    }

    /// The passphrase, for the encrypted key.
    pub fn passphrase(self) -> Option<&'static str> {
        (self == Self::Ed25519Encrypted).then_some(PASSPHRASE)
    }

    /// The certificate line (`ssh-ed25519-cert-v01@openssh.com AAAA…`), for
    /// [`FixtureKey::Cert`].
    pub fn certificate(self) -> Option<String> {
        (self == Self::Cert).then(|| read("id_cert-cert.pub").trim().to_owned())
    }
}

/// The `@cert-authority * <host CA>` known_hosts line.
pub fn known_hosts_ca_line() -> String {
    read("known_hosts_ca").trim().to_owned()
}

fn read(name: &str) -> String {
    let path = keys_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture key {}: {e}", path.display()))
}
