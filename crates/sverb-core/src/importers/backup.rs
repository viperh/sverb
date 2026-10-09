//! The `.sverb-backup` format (§9.13) and its import.
//!
//! ```json
//! { "format": "sverb-backup", "version": 1,
//!   "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt_b64": "…" },
//!   "nonce_b64": "…", "ciphertext_b64": "…",
//!   "created_at": "2026-10-08T12:00:00Z", "app_version": "0.1.0" }
//! ```
//!
//! The ciphertext is XChaCha20-Poly1305 under `Argon2id(export password)`, AAD
//! `"sverb-backup-v1"`, over `zstd(cbor(BackupPayload))`. The payload holds every item
//! body **with its stamps** (secrets included) and its id, so a restore keeps ids and
//! HLC history. Device-local data (frecency, approvals, recordings) is not included.
//!
//! Spec addition: each item is stored as `{ id, vault, body }` (the id is not part of
//! `ItemBody`), and each vault as `{ id, name, kind, defaults }` where `defaults` is
//! the id of its vault-defaults item, if any.

use std::io::Read as _;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sverb_crypto::{Nonce24, aead, kdf::Argon2Params};

use super::{
    Draft, ImportPlan, ImportSource, PlannedItem,
    preview::{body_label, fill_fields},
};
use crate::model::{ItemBody, ItemId, VaultId};

/// `format` of a backup file.
pub const FORMAT: &str = "sverb-backup";
/// The format version this build writes and reads.
pub const VERSION: u32 = 1;
/// The AEAD associated data.
pub const AAD: &[u8] = b"sverb-backup-v1";
/// The file extension.
pub const EXTENSION: &str = "sverb-backup";
/// Upper bound of the decompressed payload (zstd-bomb guard).
pub const MAX_PAYLOAD: u64 = 1 << 30;

/// Why a backup cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    /// Not a sverb backup (bad JSON or another `format`).
    #[error("not a sverb backup: {0}")]
    NotABackup(String),
    /// A newer format version.
    #[error(
        "this backup has format version {0}; this sverb reads version {VERSION}. Update sverb to import it"
    )]
    UnsupportedVersion(u32),
    /// Wrong export password, or the ciphertext was modified (indistinguishable).
    #[error("cannot decrypt the backup: wrong export password, or the file was modified")]
    Decrypt,
    /// The decrypted payload is invalid.
    #[error("the backup is corrupted: {0}")]
    Corrupt(String),
    /// Invalid key-derivation parameters.
    #[error("invalid key-derivation parameters: {0}")]
    Kdf(String),
    /// The export password is too weak.
    #[error("{0}")]
    WeakPassword(String),
    /// Encoding failed.
    #[error("cannot write the backup: {0}")]
    Encode(String),
}

/// `kdf` of the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfHeader {
    /// Always `argon2id`.
    pub alg: String,
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// The 16-byte salt.
    pub salt_b64: String,
}

/// The JSON file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// [`FORMAT`]
    pub format: String,
    /// [`VERSION`]
    pub version: u32,
    /// Argon2id parameters.
    pub kdf: KdfHeader,
    /// 24-byte nonce.
    pub nonce_b64: String,
    /// `ciphertext || tag`.
    pub ciphertext_b64: String,
    /// RFC 3339 UTC.
    pub created_at: String,
    /// The sverb version that wrote it.
    pub app_version: String,
}

/// A vault in a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupVault {
    /// The vault id.
    pub id: VaultId,
    /// Display name.
    pub name: String,
    /// `personal` or `shared`.
    pub kind: String,
    /// Its vault-defaults item, if any.
    pub defaults: Option<ItemId>,
}

/// An item in a backup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupItem {
    /// The item id.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The full stamped body.
    pub body: ItemBody,
}

/// The encrypted payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Vaults.
    pub vaults: Vec<BackupVault>,
    /// Items (tombstoned ones included, so deletes survive a restore).
    pub items: Vec<BackupItem>,
}

/// Reads the header without decrypting (format and version checks).
///
/// # Errors
/// [`BackupError::NotABackup`], [`BackupError::UnsupportedVersion`].
pub fn read_header(text: &str) -> Result<BackupFile, BackupError> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| BackupError::NotABackup(e.to_string()))?;
    if v.get("format").and_then(|f| f.as_str()) != Some(FORMAT) {
        return Err(BackupError::NotABackup(
            "missing \"format\": \"sverb-backup\"".to_owned(),
        ));
    }
    match v.get("version").and_then(serde_json::Value::as_u64) {
        Some(n) if n == u64::from(VERSION) => {}
        Some(n) => {
            return Err(BackupError::UnsupportedVersion(
                u32::try_from(n).unwrap_or(u32::MAX),
            ));
        }
        None => return Err(BackupError::NotABackup("missing \"version\"".to_owned())),
    }
    serde_json::from_value(v).map_err(|e| BackupError::NotABackup(e.to_string()))
}

/// The Argon2id parameters of a header.
///
/// # Errors
/// [`BackupError::Kdf`] for another algorithm or out-of-range values.
pub fn kdf_params(kdf: &KdfHeader) -> Result<Argon2Params, BackupError> {
    if kdf.alg != "argon2id" {
        return Err(BackupError::Kdf(format!(
            "unsupported algorithm {:?}",
            kdf.alg
        )));
    }
    let salt = STANDARD
        .decode(&kdf.salt_b64)
        .map_err(|e| BackupError::Kdf(format!("salt: {e}")))?;
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| BackupError::Kdf("the salt is not 16 bytes".to_owned()))?;
    let params = Argon2Params {
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
        salt,
    };
    params
        .validate()
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    Ok(params)
}

/// Decrypts a backup file. CPU- and memory-heavy (Argon2id): run it off the async
/// runtime.
///
/// # Errors
/// See [`BackupError`]; a wrong password is [`BackupError::Decrypt`].
pub fn decrypt(text: &str, password: &str) -> Result<BackupPayload, BackupError> {
    let file = read_header(text)?;
    let params = kdf_params(&file.kdf)?;
    let nonce = STANDARD
        .decode(&file.nonce_b64)
        .map_err(|e| BackupError::NotABackup(format!("nonce: {e}")))?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| BackupError::NotABackup("the nonce is not 24 bytes".to_owned()))?;
    let ct = STANDARD
        .decode(&file.ciphertext_b64)
        .map_err(|e| BackupError::NotABackup(format!("ciphertext: {e}")))?;
    let key = sverb_crypto::kdf::argon2id(password.as_bytes(), &params)
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    let compressed = aead::open(&key, &Nonce24::from_bytes(nonce), AAD, &ct)
        .map_err(|_| BackupError::Decrypt)?;
    decode_payload(&compressed)
}

/// The authenticated plaintext → payload: capped zstd, then CBOR.
fn decode_payload(compressed: &[u8]) -> Result<BackupPayload, BackupError> {
    let mut cbor = zeroize::Zeroizing::new(Vec::new());
    zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| BackupError::Corrupt(e.to_string()))?
        .take(MAX_PAYLOAD + 1)
        .read_to_end(&mut cbor)
        .map_err(|e| BackupError::Corrupt(format!("decompression: {e}")))?;
    if cbor.len() as u64 > MAX_PAYLOAD {
        return Err(BackupError::Corrupt("the payload is too large".to_owned()));
    }
    ciborium::from_reader(cbor.as_slice()).map_err(|e| BackupError::Corrupt(e.to_string()))
}

/// M7-05: the `backup_decrypt` fuzz target (`fuzz/fuzz_targets/backup_decrypt.rs`). The
/// input is tried as a backup file (header, KDF parameter checks, base64 fields) and,
/// separately, as the authenticated plaintext (capped zstd + CBOR), then planned. Argon2
/// itself is skipped (a fixed key stands in), so the fuzzer spends its time in parsers.
/// Must never panic.
#[doc(hidden)]
pub fn fuzz_backup_decrypt(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Ok(file) = read_header(&text) {
        let _ = kdf_params(&file.kdf);
        let _ = STANDARD.decode(&file.nonce_b64);
        if let Ok(ct) = STANDARD.decode(&file.ciphertext_b64) {
            let key = sverb_crypto::Key32::from_bytes([7; 32]);
            let _ = aead::open(&key, &Nonce24::from_bytes([0; 24]), AAD, &ct);
        }
    }
    if let Ok(payload) = decode_payload(data) {
        let _ = plan(&payload);
    }
}

/// The import plan of a decrypted backup: one item per body, keeping its id.
pub fn plan(payload: &BackupPayload) -> ImportPlan {
    let mut plan = ImportPlan::new(ImportSource::Backup);
    for item in &payload.items {
        let mut label = body_label(&item.body);
        if label.is_empty() {
            label = item.id.short();
        }
        plan.push(PlannedItem::new(
            item.body.kind,
            label,
            Draft::Backup {
                id: item.id,
                body: Box::new(item.body.clone()),
            },
        ));
    }
    fill_fields(&mut plan);
    plan
}
