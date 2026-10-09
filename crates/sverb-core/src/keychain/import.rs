//!
//! - **Sources**: a file ([`read_key_file`], `~` expanded, with [`complete_path`] for
//!   the TUI's tab completion) or pasted text.
//! - **Formats** detected by content ([`detect`]): OpenSSH, PEM PKCS#1 / SEC1, PKCS#8
//!   (plain / encrypted), an OpenSSH public key line (→ an **agent reference** key with
//!   no private part, §9.4), and whatever a registered [`KeyImporter`] claims (PuTTY
//! - **Passphrases**: [`import_with_prompt`] asks up to [`PASSPHRASE_TRIES`] times, then
//!   aborts with [`KeychainError::TooManyTries`] (nothing is created).
//! - **Stored form**: OpenSSH. By default an encrypted key stays encrypted with the same
//!   passphrase (re-encrypted with bcrypt-pbkdf when it came in another format) and the
//!   passphrase is stored in the vault (§4.5); [`ImportOptions`] can store it decrypted
//!   (still protected by the vault encryption) or not remember the passphrase.
//! - **Duplicates**: [`find_duplicate`] finds an existing key with the same public key,
//!   so the UI offers "Use existing" instead.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use ssh_key::PrivateKey;

use super::{
    KeychainError, MAX_KEY_FILE_BYTES, PASSPHRASE_TRIES, expand_home, fingerprint,
    formats::{self, KeyFormat},
    parse_public, public_key_algorithm, public_line, same_public_key, store_openssh,
};
use crate::{
    model::{ItemId, Key, KeyAlgorithm},
    secret::SecretString,
};

// ---------------------------------------------------------------- importer hook

pub trait KeyImporter: Send + Sync {
    /// A short, unique name (`"PuTTY"`); registering the same name replaces it.
    fn name(&self) -> &'static str;
    /// Whether `text` is in this importer's format.
    fn detects(&self, text: &str) -> bool;
    /// Whether the key needs a passphrase.
    fn is_encrypted(&self, text: &str) -> bool;
    /// Decode (and decrypt) the key.
    ///
    /// # Errors
    /// [`KeychainError::NeedsPassphrase`], [`KeychainError::WrongPassphrase`],
    /// [`KeychainError::Importer`], …
    fn decode(&self, text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PpkPlaceholder;

/// The name the PuTTY importer registers under.
pub const PPK_IMPORTER: &str = "PuTTY";

impl KeyImporter for PpkPlaceholder {
    fn name(&self) -> &'static str {
        PPK_IMPORTER
    }

    fn detects(&self, text: &str) -> bool {
        text.trim_start().starts_with("PuTTY-User-Key-File-")
    }

    fn is_encrypted(&self, _text: &str) -> bool {
        false
    }

    fn decode(&self, _text: &str, _pass: Option<&str>) -> Result<PrivateKey, KeychainError> {
        Err(KeychainError::Importer(
            "PuTTY .ppk keys are supported from a later sverb version (M7-03); for now export \
             the key from PuTTYgen with Conversions → Export OpenSSH key"
                .to_owned(),
        ))
    }
}

type Registry = RwLock<Vec<Arc<dyn KeyImporter>>>;

fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    // The real `.ppk` parser replaces the placeholder.
    REG.get_or_init(|| {
        RwLock::new(vec![
            Arc::new(formats::ppk::PpkImporter) as Arc<dyn KeyImporter>
        ])
    })
}

/// Register `importer` (replacing one with the same name).
pub fn register_importer(importer: Arc<dyn KeyImporter>) {
    let mut reg = registry()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.retain(|i| i.name() != importer.name());
    reg.push(importer);
}

fn plugin_for(text: &str) -> Option<Arc<dyn KeyImporter>> {
    registry()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|i| i.detects(text))
        .cloned()
}

fn plugin_named(name: &str) -> Option<Arc<dyn KeyImporter>> {
    registry()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|i| i.name() == name)
        .cloned()
}

// ---------------------------------------------------------------- detection

/// The format of `text`: built-in armor first, then the registered importers.
pub fn detect(text: &str) -> KeyFormat {
    match formats::detect_builtin(text) {
        KeyFormat::Unknown => {
            plugin_for(text).map_or(KeyFormat::Unknown, |p| KeyFormat::Plugin(p.name()))
        }
        f => f,
    }
}

/// Whether importing `text` needs a passphrase.
pub fn needs_passphrase(text: &str) -> bool {
    match detect(text) {
        KeyFormat::OpenSsh => formats::openssh::is_encrypted(text),
        f @ (KeyFormat::Pkcs1 | KeyFormat::Sec1) => formats::pem::is_encrypted(text, f),
        KeyFormat::Pkcs8Encrypted => true,
        KeyFormat::Plugin(name) => plugin_named(name).is_some_and(|p| p.is_encrypted(text)),
        KeyFormat::Pkcs8 | KeyFormat::PublicKey | KeyFormat::Unknown => false,
    }
}

/// Decode a private key in any supported format (decrypted).
///
/// # Errors
/// [`KeychainError::Format`], [`KeychainError::NeedsPassphrase`],
/// [`KeychainError::WrongPassphrase`], [`KeychainError::Unsupported`], …
pub fn decode_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeychainError> {
    let pass = passphrase.filter(|p| !p.is_empty());
    match detect(text) {
        KeyFormat::OpenSsh => formats::openssh::decode(text, pass),
        f @ (KeyFormat::Pkcs1 | KeyFormat::Sec1) => formats::pem::decode(text, f, pass),
        KeyFormat::Pkcs8 => formats::pkcs8::decode(text),
        KeyFormat::Pkcs8Encrypted => formats::pkcs8::decode_encrypted(text, pass),
        KeyFormat::Plugin(name) => plugin_named(name)
            .ok_or(KeychainError::Format)?
            .decode(text, pass),
        KeyFormat::PublicKey => Err(KeychainError::NoPrivateKey),
        KeyFormat::Unknown => Err(KeychainError::Format),
    }
}

// ---------------------------------------------------------------- import

/// How an imported key is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportOptions {
    /// Keep an encrypted key encrypted with its passphrase (default). Off: store it
    /// decrypted (the vault still encrypts it).
    pub keep_encrypted: bool,
    /// Store the passphrase in the vault so auth doesn't prompt (default on).
    pub remember_passphrase: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            keep_encrypted: true,
            remember_passphrase: true,
        }
    }
}

/// A key ready to become a Key item.
#[derive(Debug)]
pub struct ImportedKey {
    /// The detected format.
    pub format: KeyFormat,
    /// The algorithm.
    pub algorithm: KeyAlgorithm,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// The key's comment (a label suggestion; may be empty).
    pub comment: String,
    /// OpenSSH private key (`None`: an agent / hardware reference key).
    pub private_key: Option<SecretString>,
    /// The stored private key is encrypted.
    pub encrypted: bool,
    /// The passphrase to store (remembered and the key encrypted).
    pub passphrase: Option<SecretString>,
}

impl ImportedKey {
    /// An agent / hardware reference (only a public key).
    pub fn is_agent_ref(&self) -> bool {
        self.private_key.is_none()
    }

    /// A label: the comment, else `fallback`, else `"<type> key"`.
    pub fn suggested_label(&self, fallback: Option<&str>) -> String {
        if !self.comment.trim().is_empty() {
            return self.comment.trim().to_owned();
        }
        match fallback.map(str::trim).filter(|s| !s.is_empty()) {
            Some(f) => f.to_owned(),
            None => format!("{} key", super::algorithm_name(self.algorithm)),
        }
    }

    /// The Key item.
    pub fn into_key(self, label: String) -> Key {
        Key {
            label,
            algorithm: self.algorithm,
            private_key: self.private_key.unwrap_or_else(|| SecretString::from("")),
            public_key: self.public_key,
            passphrase: self.passphrase,
            certificate_ids: Vec::new(),
            agent_forwardable: false,
            confirm_on_use: false,
            read_only: false,
        }
    }
}

/// Import `text` with `passphrase` (when encrypted).
///
/// An encrypted **OpenSSH** key without a passphrase is accepted as is (its public key
/// is readable; the auth chain prompts for the passphrase): the host form's key-file
/// field relies on it. Other encrypted formats need the passphrase.
///
/// # Errors
/// As [`decode_private`]; [`KeychainError::Unsupported`] for unsupported algorithms.
pub fn import_text(
    text: &str,
    passphrase: Option<&str>,
    opts: ImportOptions,
) -> Result<ImportedKey, KeychainError> {
    let text = text.trim();
    let pass = passphrase.filter(|p| !p.is_empty());
    let format = detect(text);
    match format {
        KeyFormat::PublicKey => return import_public(text),
        KeyFormat::Unknown => return Err(KeychainError::Format),
        KeyFormat::OpenSsh if pass.is_none() && formats::openssh::is_encrypted(text) => {
            let key = formats::openssh::parse(text)?;
            return described(
                format,
                key.public_key(),
                Some(SecretString::from(text)),
                true,
                None,
            );
        }
        _ => {}
    }
    let encrypted_in = needs_passphrase(text);
    let key = decode_private(text, pass)?;
    let keep = encrypted_in && opts.keep_encrypted;
    let stored = if format == KeyFormat::OpenSsh && (keep || !encrypted_in) {
        // Already in the stored form: keep it byte for byte.
        SecretString::from(text)
    } else {
        store_openssh(&key, if keep { pass } else { None })?
    };
    let remembered = (keep && opts.remember_passphrase)
        .then(|| pass.map(SecretString::from))
        .flatten();
    described(format, key.public_key(), Some(stored), keep, remembered)
}

fn described(
    format: KeyFormat,
    public: &ssh_key::PublicKey,
    private_key: Option<SecretString>,
    encrypted: bool,
    passphrase: Option<SecretString>,
) -> Result<ImportedKey, KeychainError> {
    let algorithm = public_key_algorithm(public)
        .ok_or_else(|| KeychainError::Unsupported(public.algorithm().as_str().to_owned()))?;
    let public_key = public_line(public)?;
    Ok(ImportedKey {
        format,
        algorithm,
        fingerprint: fingerprint(&public_key).unwrap_or_default(),
        comment: public.comment().to_string(),
        public_key,
        private_key,
        encrypted,
        passphrase,
    })
}

fn import_public(text: &str) -> Result<ImportedKey, KeychainError> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let public = parse_public(line)?;
    described(KeyFormat::PublicKey, &public, None, false, None)
}

/// Import `text`, asking `ask(attempt, last_error)` for the passphrase when needed:
/// up to [`PASSPHRASE_TRIES`] tries. `ask` returning `None` cancels.
///
/// # Errors
/// [`KeychainError::TooManyTries`] after the last wrong passphrase,
/// [`KeychainError::Cancelled`], or the import's own errors.
pub fn import_with_prompt(
    text: &str,
    opts: ImportOptions,
    mut ask: impl FnMut(u8, Option<&KeychainError>) -> Option<SecretString>,
) -> Result<ImportedKey, KeychainError> {
    if !needs_passphrase(text) {
        return import_text(text, None, opts);
    }
    let mut last = None;
    for attempt in 1..=PASSPHRASE_TRIES {
        let pass = ask(attempt, last.as_ref()).ok_or(KeychainError::Cancelled)?;
        match import_text(text, Some(pass.expose()), opts) {
            Err(e @ (KeychainError::WrongPassphrase | KeychainError::NeedsPassphrase)) => {
                last = Some(e);
            }
            other => return other,
        }
    }
    Err(KeychainError::TooManyTries)
}

/// Whether `passphrase` decrypts `text` (for a dialog's "try again").
pub fn check_passphrase(text: &str, passphrase: &str) -> Result<(), KeychainError> {
    decode_private(text, Some(passphrase)).map(|_| ())
}

// ---------------------------------------------------------------- files

/// Read a key (or certificate) file: `~` expanded, at most [`MAX_KEY_FILE_BYTES`].
///
/// # Errors
/// [`KeychainError::Read`]; [`KeychainError::Format`] for oversized files.
pub fn read_key_file(path: &str) -> Result<SecretString, KeychainError> {
    let path = expand_home(path.trim());
    let shown = path.display().to_string();
    let meta =
        std::fs::metadata(&path).map_err(|e| KeychainError::Read(format!("{shown}: {e}")))?;
    if !meta.is_file() {
        return Err(KeychainError::Read(format!("{shown}: not a file")));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(KeychainError::Format);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| KeychainError::Read(format!("{shown}: {e}")))?;
    Ok(SecretString::from(text))
}

/// Read and import a key file (see [`import_text`]).
///
/// # Errors
/// As [`read_key_file`] and [`import_text`].
pub fn import_file(
    path: &str,
    passphrase: Option<&str>,
    opts: ImportOptions,
) -> Result<ImportedKey, KeychainError> {
    let text = read_key_file(path)?;
    import_text(text.expose(), passphrase, opts)
}

/// The file name of `path` (a label fallback).
pub fn file_stem(path: &str) -> Option<String> {
    Path::new(path.trim())
        .file_name()
        .map(|n| n.to_string_lossy().trim_end_matches(".pub").to_owned())
        .filter(|s| !s.is_empty())
}

/// Tab completion for a path prompt: the longest common completion of `prefix`
/// (`~` kept as typed), and the candidates (directories end with `/`).
pub fn complete_path(prefix: &str) -> (String, Vec<String>) {
    let (dir_part, name_part) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => ("", prefix),
    };
    let dir: PathBuf = if dir_part.is_empty() {
        PathBuf::from(".")
    } else {
        expand_home(dir_part)
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (prefix.to_owned(), Vec::new());
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(name_part)
                || (name.starts_with('.') && !name_part.starts_with('.'))
            {
                return None;
            }
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            Some(if is_dir { format!("{name}/") } else { name })
        })
        .collect();
    names.sort();
    let Some(first) = names.first() else {
        return (prefix.to_owned(), names);
    };
    let common = names.iter().skip(1).fold(first.clone(), |acc, n| {
        acc.chars()
            .zip(n.chars())
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| a)
            .collect()
    });
    (format!("{dir_part}{common}"), names)
}

// ---------------------------------------------------------------- duplicates

/// The existing key with the same public key as `public_line` (comments ignored).
pub fn find_duplicate<'a>(
    public_line: &str,
    existing: impl IntoIterator<Item = (ItemId, &'a str)>,
) -> Option<ItemId> {
    existing
        .into_iter()
        .find(|(_, p)| same_public_key(public_line, p))
        .map(|(id, _)| id)
}
