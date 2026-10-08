//! Writes the encrypted `.sverb-backup` (format: [`crate::importers::backup`]).

use std::io::Write as _;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sverb_crypto::{aead, kdf::Argon2Params, random};

use crate::importers::backup::{
    AAD, BackupError, BackupFile, BackupPayload, FORMAT, KdfHeader, VERSION,
};
use crate::model::UnixMillis;
use crate::vault::password::check_strength;

/// zstd level of the payload.
const ZSTD_LEVEL: i32 = 9;

/// Accepts an export password (zxcvbn score ≥ 3, like the master password).
///
/// # Errors
/// [`BackupError::WeakPassword`] with zxcvbn's feedback.
pub fn check_password(password: &str) -> Result<(), BackupError> {
    check_strength(password, &["sverb", "backup"])
        .map(|_| ())
        .map_err(|e| BackupError::WeakPassword(e.to_string()))
}

/// RFC 3339 UTC (`2026-10-08T12:00:00Z`) of `t`.
pub fn rfc3339(t: UnixMillis) -> String {
    let secs = t.0.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Encrypts `payload` under `password` with Argon2id(`m_kib`, `t`, `p`) and a fresh
/// salt and nonce. Returns the JSON file. CPU- and memory-heavy: run it off the async
/// runtime. The password strength is not checked here ([`check_password`]).
///
/// # Errors
/// [`BackupError::Kdf`] for bad parameters, [`BackupError::Encode`].
pub fn encrypt(
    payload: &BackupPayload,
    password: &str,
    m_kib: u32,
    t: u32,
    p: u32,
    created_at: UnixMillis,
) -> Result<String, BackupError> {
    let mut rng = random::os_rng();
    let params = Argon2Params {
        m_kib,
        t,
        p,
        salt: random::random_salt16(&mut rng),
    };
    let key = sverb_crypto::kdf::argon2id(password.as_bytes(), &params)
        .map_err(|e| BackupError::Kdf(e.to_string()))?;
    let mut cbor = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(payload, &mut *cbor).map_err(|e| BackupError::Encode(e.to_string()))?;
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)
        .map_err(|e| BackupError::Encode(e.to_string()))?;
    enc.write_all(&cbor)
        .map_err(|e| BackupError::Encode(e.to_string()))?;
    let compressed = zeroize::Zeroizing::new(
        enc.finish()
            .map_err(|e| BackupError::Encode(e.to_string()))?,
    );
    let nonce = random::random_nonce24(&mut rng);
    let ct = aead::seal(&key, &nonce, AAD, &compressed)
        .map_err(|e| BackupError::Encode(e.to_string()))?;
    let file = BackupFile {
        format: FORMAT.to_owned(),
        version: VERSION,
        kdf: KdfHeader {
            alg: "argon2id".to_owned(),
            m_kib,
            t,
            p,
            salt_b64: STANDARD.encode(params.salt),
        },
        nonce_b64: STANDARD.encode(nonce.as_bytes()),
        ciphertext_b64: STANDARD.encode(ct),
        created_at: rfc3339(created_at),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let mut out =
        serde_json::to_string_pretty(&file).map_err(|e| BackupError::Encode(e.to_string()))?;
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats() {
        assert_eq!(rfc3339(UnixMillis(0)), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UnixMillis(1_791_460_800_000)),
            "2026-10-08T12:00:00Z"
        );
        assert_eq!(rfc3339(UnixMillis(951_782_400_000)), "2000-02-29T00:00:00Z");
    }
}
