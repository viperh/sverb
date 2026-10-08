//! M2-03 §2.4–2.5: export and passphrase changes (SPEC §9.4).
//!
//! - **Public key**: the OpenSSH line ([`public_export`]) to the clipboard or a file
//!   ([`write_public_file`]).
//! - **Private key**: only to a file, mode `0600`, never overwriting without
//!   `overwrite` ([`write_private_file`]); kept as stored, re-encrypted with a new
//!   passphrase, or decrypted ([`PrivateExport`]).
//! - **Change passphrase**: decrypt with the old (or stored) passphrase, re-encrypt with
//!   the new one (or none), and update the stored passphrase when it is remembered
//!   ([`change_passphrase`]).

use std::io::Write as _;
use std::path::Path;

use super::{KeychainError, decrypt_openssh, store_openssh};
use crate::{model::Key, secret::SecretString};

/// How the private key is written out.
#[derive(Debug)]
pub enum PrivateExport {
    /// As stored (encrypted if it is).
    Keep,
    /// Re-encrypted with this passphrase.
    Reencrypt(SecretString),
    /// Decrypted (no passphrase).
    Decrypted,
}

/// The public key line of `key`.
pub fn public_export(key: &Key) -> String {
    key.public_key.trim().to_owned()
}

fn decrypted(key: &Key, passphrase: Option<&str>) -> Result<ssh_key::PrivateKey, KeychainError> {
    if key.is_agent_ref() || key.private_key.expose().trim().is_empty() {
        return Err(KeychainError::NoPrivateKey);
    }
    let pass = passphrase
        .filter(|p| !p.is_empty())
        .or_else(|| key.passphrase.as_ref().map(SecretString::expose));
    decrypt_openssh(key.private_key.expose(), pass)
}

/// The private key text to export. `passphrase` decrypts it when it is encrypted and no
/// passphrase is stored.
///
/// # Errors
/// [`KeychainError::NoPrivateKey`], [`KeychainError::NeedsPassphrase`],
/// [`KeychainError::WrongPassphrase`], [`KeychainError::Invalid`].
pub fn private_export(
    key: &Key,
    how: &PrivateExport,
    passphrase: Option<&str>,
) -> Result<SecretString, KeychainError> {
    match how {
        PrivateExport::Keep => {
            if key.is_agent_ref() || key.private_key.expose().trim().is_empty() {
                return Err(KeychainError::NoPrivateKey);
            }
            Ok(SecretString::from(key.private_key.expose().trim()))
        }
        PrivateExport::Reencrypt(new) => {
            store_openssh(&decrypted(key, passphrase)?, Some(new.expose()))
        }
        PrivateExport::Decrypted => store_openssh(&decrypted(key, passphrase)?, None),
    }
}

/// Write `text` to `path` with mode `0600` (Unix). Refuses an existing file unless
/// `overwrite`.
///
/// # Errors
/// [`KeychainError::Exists`], [`KeychainError::Write`].
pub fn write_private_file(
    path: &Path,
    text: &SecretString,
    overwrite: bool,
) -> Result<(), KeychainError> {
    write_file(path, text.expose(), overwrite, true)
}

/// Write a public key line to `path` (mode `0644` on Unix).
///
/// # Errors
/// As [`write_private_file`].
pub fn write_public_file(path: &Path, line: &str, overwrite: bool) -> Result<(), KeychainError> {
    write_file(path, line, overwrite, false)
}

fn write_file(
    path: &Path,
    text: &str,
    overwrite: bool,
    private: bool,
) -> Result<(), KeychainError> {
    let shown = path.display().to_string();
    let err = |e: std::io::Error| KeychainError::Write(format!("{shown}: {e}"));
    if !overwrite && path.exists() {
        return Err(KeychainError::Exists(shown));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).truncate(true);
    if overwrite {
        opts.create(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KeychainError::Exists(shown.clone())
        } else {
            err(e)
        }
    })?;
    // An overwritten file keeps its old mode: tighten it.
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(err)?;
    }
    #[cfg(not(unix))]
    let _ = private;
    file.write_all(text.as_bytes()).map_err(err)?;
    file.write_all(b"\n").map_err(err)?;
    file.sync_all().map_err(err)
}

/// Change the passphrase of `key`: decrypt with `old` (or the stored passphrase),
/// re-encrypt with `new` (`None` / empty: store decrypted). The stored passphrase
/// follows when `remember` (else it is cleared).
///
/// # Errors
/// [`KeychainError::NoPrivateKey`], [`KeychainError::NeedsPassphrase`],
/// [`KeychainError::WrongPassphrase`], [`KeychainError::Invalid`].
pub fn change_passphrase(
    key: &mut Key,
    old: Option<&str>,
    new: Option<&str>,
    remember: bool,
) -> Result<(), KeychainError> {
    let plain = decrypted(key, old)?;
    let new = new.filter(|p| !p.is_empty());
    key.private_key = store_openssh(&plain, new)?;
    key.passphrase = new.filter(|_| remember).map(SecretString::from);
    Ok(())
}

/// Whether the stored private key is passphrase-encrypted.
pub fn is_encrypted(key: &Key) -> bool {
    super::formats::openssh::is_encrypted(key.private_key.expose())
}
