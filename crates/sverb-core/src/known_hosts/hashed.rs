//! Hashed host names: `|1|base64(salt)|base64(HMAC-SHA1(salt, lookup_key))`, as written
//! by `ssh-keygen -H` and `HashKnownHosts yes` (20-byte salt and digest).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// The marker of a hashed host field.
pub const HASH_MAGIC: &str = "|1|";

/// Salt and digest length (SHA-1).
pub const HASH_LEN: usize = 20;

/// Whether `pattern` is a hashed host field.
pub fn is_hashed(pattern: &str) -> bool {
    pattern.starts_with(HASH_MAGIC)
}

/// The salt and digest of a hashed host field (`None`: not hashed or malformed).
pub fn decode(pattern: &str) -> Option<([u8; HASH_LEN], [u8; HASH_LEN])> {
    let rest = pattern.strip_prefix(HASH_MAGIC)?;
    let (salt, hash) = rest.split_once('|')?;
    let salt: [u8; HASH_LEN] = STANDARD.decode(salt).ok()?.try_into().ok()?;
    let hash: [u8; HASH_LEN] = STANDARD.decode(hash).ok()?.try_into().ok()?;
    Some((salt, hash))
}

fn hmac(salt: &[u8; HASH_LEN], host: &str) -> [u8; HASH_LEN] {
    // HMAC accepts keys of any length: this cannot fail.
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(salt)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(host.as_bytes());
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The hashed form of `lookup_key` with `salt`.
pub fn hash_with_salt(salt: &[u8; HASH_LEN], lookup_key: &str) -> String {
    format!(
        "{HASH_MAGIC}{}|{}",
        STANDARD.encode(salt),
        STANDARD.encode(hmac(salt, lookup_key))
    )
}

/// The hashed form of `lookup_key` with a fresh random salt.
///
/// # Errors
/// The OS random source failed.
pub fn hash_host(lookup_key: &str) -> Result<String, getrandom::Error> {
    let mut salt = [0_u8; HASH_LEN];
    getrandom::fill(&mut salt)?;
    Ok(hash_with_salt(&salt, lookup_key))
}

/// Whether the hashed field `pattern` is the hash of `lookup_key` (constant-time
/// comparison). `false` for malformed or unhashed fields.
pub fn matches(pattern: &str, lookup_key: &str) -> bool {
    let Some((salt, want)) = decode(pattern) else {
        return false;
    };
    hmac(&salt, lookup_key).ct_eq(&want).into()
}
