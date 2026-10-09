//! Access, refresh and reauth tokens (SPEC §10.4).
//!
//! * Every token is 256 random bits, sent as base64url without padding
//!   (43 characters) and stored **only** as `SHA-256(raw 32 bytes)`.
//! * Access tokens live 15 minutes; refresh tokens 30 days. Both are bound
//!   to a device and share a rotation `family`. A refresh rotates the pair:
//!   the old refresh token gets `used_at`, the new pair keeps the family.
//! * Presenting a refresh token that was already used revokes the whole
//!   family (reuse detection). There is deliberately **no grace window**
//!   (strict spec reading): clients must persist the new pair atomically
//!   before using it.
//! * Reauth tokens (5 minutes, single use) prove a fresh password login
//!   for password change and account deletion.

use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use sverb_crypto::random;
use sverb_proto::auth::TokenPair;
use zeroize::Zeroizing;

/// Access-token lifetime.
pub const ACCESS_TTL: TimeDelta = TimeDelta::minutes(15);
/// Refresh-token lifetime.
pub const REFRESH_TTL: TimeDelta = TimeDelta::days(30);
/// Reauth-token lifetime ("a login performed within the last 5 minutes").
pub const REAUTH_TTL: TimeDelta = TimeDelta::minutes(5);
/// `devices.last_seen_at` is written at most this often per device.
pub const LAST_SEEN_THROTTLE: TimeDelta = TimeDelta::minutes(5);
/// Lifetime of a server-side OPAQUE login state.
pub const LOGIN_STATE_TTL: TimeDelta = TimeDelta::seconds(60);

/// Lifetime of a recovery code (long enough for an operator hand-over).
pub const RECOVERY_CODE_TTL: TimeDelta = TimeDelta::hours(24);

/// Raw token length in bytes.
pub const TOKEN_LEN: usize = 32;

/// `SHA-256` of a raw token: the only form that is stored.
pub type TokenHash = [u8; 32];

/// `auth_tokens.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// 15-minute bearer token.
    Access,
    /// 30-day rotating refresh token.
    Refresh,
}

impl TokenKind {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }
}

/// A freshly generated token: the wire form (shown to the client once) and
/// its hash.
pub struct NewToken {
    /// base64url (no padding) of the 32 random bytes.
    pub wire: Zeroizing<String>,
    /// What is stored.
    pub hash: TokenHash,
}

impl std::fmt::Debug for NewToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewToken")
            .field("hash", &hex::encode(self.hash))
            .finish_non_exhaustive()
    }
}

impl NewToken {
    /// Generates a token from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let key = random::random_key32(&mut random::os_rng());
        Self {
            wire: Zeroizing::new(sverb_proto::b64::encode(key.expose_secret())),
            hash: hash_raw(key.expose_secret()),
        }
    }
}

/// `SHA-256` of raw token bytes.
#[must_use]
pub fn hash_raw(raw: &[u8]) -> TokenHash {
    Sha256::digest(raw).into()
}

/// Hashes a token as presented by a client; `None` unless it is base64url
/// (no padding) of exactly 32 bytes.
#[must_use]
pub fn hash_presented(wire: &str) -> Option<TokenHash> {
    let raw = Zeroizing::new(sverb_proto::b64::decode(wire.trim()).ok()?);
    (raw.len() == TOKEN_LEN).then(|| hash_raw(&raw))
}

/// A fresh one-time recovery code: 120 random bits in base32, grouped as
/// `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
#[must_use]
pub fn generate_recovery_code() -> Zeroizing<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let key = random::random_key32(&mut random::os_rng());
    let bytes = &key.expose_secret()[..15];
    let mut out = Zeroizing::new(String::with_capacity(29));
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
            n += 1;
        }
    }
    out
}

/// Hash of a recovery code as typed: case, spaces and dashes are ignored.
#[must_use]
pub fn hash_recovery_code(code: &str) -> TokenHash {
    let norm: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let mut h = Sha256::new();
    h.update(b"sverb/recovery-code/v1:");
    h.update(norm.as_bytes());
    h.finalize().into()
}

/// One stored token row (without device and family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRecord {
    /// Hash.
    pub hash: TokenHash,
    /// Kind.
    pub kind: TokenKind,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
}

/// A new access + refresh pair.
#[derive(Debug)]
pub struct IssuedTokens {
    /// Access token.
    pub access: NewToken,
    /// Refresh token.
    pub refresh: NewToken,
    /// Access expiry.
    pub access_expires_at: DateTime<Utc>,
    /// Refresh expiry.
    pub refresh_expires_at: DateTime<Utc>,
}

impl IssuedTokens {
    /// Generates a pair valid from `now`.
    #[must_use]
    pub fn issue(now: DateTime<Utc>) -> Self {
        Self {
            access: NewToken::generate(),
            refresh: NewToken::generate(),
            access_expires_at: now + ACCESS_TTL,
            refresh_expires_at: now + REFRESH_TTL,
        }
    }

    /// The two rows to store.
    #[must_use]
    pub fn records(&self) -> [TokenRecord; 2] {
        [
            TokenRecord {
                hash: self.access.hash,
                kind: TokenKind::Access,
                expires_at: self.access_expires_at,
            },
            TokenRecord {
                hash: self.refresh.hash,
                kind: TokenKind::Refresh,
                expires_at: self.refresh_expires_at,
            },
        ]
    }

    /// The wire DTO.
    #[must_use]
    pub fn to_pair(&self) -> TokenPair {
        TokenPair {
            access_token: self.access.wire.to_string(),
            refresh_token: self.refresh.wire.to_string(),
            access_expires_in_s: secs(ACCESS_TTL),
            refresh_expires_in_s: secs(REFRESH_TTL),
        }
    }
}

/// Whole seconds of a non-negative duration.
#[must_use]
pub fn secs(d: TimeDelta) -> u64 {
    u64::try_from(d.num_seconds()).unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_base64url_and_hashed() {
        let t = NewToken::generate();
        assert_eq!(t.wire.len(), 43);
        assert_eq!(hash_presented(&t.wire), Some(t.hash));
        assert_ne!(
            t.hash.as_slice(),
            sverb_proto::b64::decode(&t.wire).unwrap()
        );
        assert_ne!(NewToken::generate().hash, t.hash);
    }

    #[test]
    fn malformed_tokens_have_no_hash() {
        assert_eq!(hash_presented(""), None);
        assert_eq!(hash_presented("not base64 !"), None);
        assert_eq!(hash_presented(&sverb_proto::b64::encode(&[0; 31])), None);
        assert_eq!(hash_presented(&sverb_proto::b64::encode(&[0; 33])), None);
    }

    #[test]
    fn recovery_codes() {
        let c = generate_recovery_code();
        assert_eq!(c.len(), 29);
        assert_eq!(c.matches('-').count(), 5);
        let typed = c.to_lowercase().replace('-', " ");
        assert_eq!(hash_recovery_code(&typed), hash_recovery_code(&c));
        assert_ne!(
            hash_recovery_code(&generate_recovery_code()),
            hash_recovery_code(&c)
        );
    }

    #[test]
    fn pair_lifetimes() {
        let now = Utc::now();
        let t = IssuedTokens::issue(now);
        let p = t.to_pair();
        assert_eq!(p.access_expires_in_s, 900);
        assert_eq!(p.refresh_expires_in_s, 30 * 86_400);
        let [a, r] = t.records();
        assert_eq!((a.kind, r.kind), (TokenKind::Access, TokenKind::Refresh));
        assert_eq!(a.expires_at - now, ACCESS_TTL);
    }
}
