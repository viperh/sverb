//! Vault-key grants (§11.3).
//!
//! ```text
//! wrapped_vault_key = HPKE.Seal(member_x25519_pub,
//!                               info = "sverb/vk/v1" || vault_id(16) || key_version(u32 BE),
//!                               aad = "", pt = VK)              // base mode, single-shot
//!                   = u32 len || enc(32) || u32 len || ct(48)    // see crate::hpke
//! signature         = Ed25519(granter_sk,
//!                       "sverb/grant/v1" || vault_id(16) || member_user_id(16)
//!                       || key_version(u32 BE) || u32 len || wrapped_vault_key)
//! ```
//!
//! Personal vaults use the same code path: a **self-grant** is
//! [`grant_vault_key`] with the member set to oneself (see [`self_grant`]).
//!
//! Clients must call [`verify_grant`] against a granter key they trust
//! (§13.3) before using a VK; [`verify_and_open_grant`] does both.

use ed25519_dalek::SigningKey;
use rand_core::CryptoRng;

use crate::account::AccountKeys;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::hpke::{self, X25519_LEN, take_len_prefixed};
use crate::keys::Key32;
use crate::sign::{self, ED25519_PUBLIC_LEN, SIGNATURE_LEN};

/// A signed, HPKE-wrapped vault key for one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// `wrapped_vault_key` in the [`crate::hpke`] wire format.
    pub wrapped: Vec<u8>,
    /// The granter's Ed25519 signature over [`canon::sig_grant`].
    pub signature: [u8; SIGNATURE_LEN],
}

impl Grant {
    /// Transport encoding: `u32 BE len || wrapped || signature(64)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = canon::len_prefixed(&self.wrapped);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Strict decoder of [`Grant::to_bytes`]. Also checks the framing of
    /// `wrapped` (no crypto).
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] on any framing error or trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (wrapped, rest) = take_len_prefixed(bytes)?;
        let signature: [u8; SIGNATURE_LEN] = rest
            .try_into()
            .map_err(|_| CryptoError::Malformed("grant signature length"))?;
        hpke::decode_sealed(wrapped)?;
        Ok(Self {
            wrapped: wrapped.to_vec(),
            signature,
        })
    }
}

/// Wraps `vk` to `member_x25519_pub` and signs the result with
/// `granter_ed25519_sk`.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the member's public key is rejected by
/// the KEM.
#[allow(clippy::too_many_arguments)]
pub fn grant_vault_key<R: CryptoRng + ?Sized>(
    vk: &Key32,
    vault_id: &Id16,
    key_version: u32,
    member_id: &Id16,
    member_x25519_pub: &[u8; X25519_LEN],
    granter_ed25519_sk: &SigningKey,
    rng: &mut R,
) -> Result<Grant> {
    let info = canon::info_vk(vault_id, key_version);
    let wrapped = hpke::seal_base(member_x25519_pub, &info, vk.expose_secret(), rng)?;
    let msg = canon::sig_grant(vault_id, member_id, key_version, &wrapped);
    let signature = sign::sign(granter_ed25519_sk, &msg);
    Ok(Grant { wrapped, signature })
}

/// The personal-vault self-grant (§11.3): [`grant_vault_key`] with the
/// member, recipient key and granter all being `me`.
///
/// # Errors
/// As [`grant_vault_key`].
pub fn self_grant<R: CryptoRng + ?Sized>(
    vk: &Key32,
    vault_id: &Id16,
    key_version: u32,
    my_user_id: &Id16,
    me: &AccountKeys,
    rng: &mut R,
) -> Result<Grant> {
    grant_vault_key(
        vk,
        vault_id,
        key_version,
        my_user_id,
        &me.public().x25519,
        me.ed25519_signing_key(),
        rng,
    )
}

/// Verifies the granter's signature over `(vault_id, member_id,
/// key_version, wrapped)`.
///
/// # Errors
/// [`CryptoError::BadSignature`] if any of those differs or the key is wrong.
pub fn verify_grant(
    grant: &Grant,
    vault_id: &Id16,
    member_id: &Id16,
    key_version: u32,
    granter_ed25519_pub: &[u8; ED25519_PUBLIC_LEN],
) -> Result<()> {
    let msg = canon::sig_grant(vault_id, member_id, key_version, &grant.wrapped);
    sign::verify(granter_ed25519_pub, &msg, &grant.signature)
}

/// HPKE-opens the wrapped VK with the member's X25519 secret key. Does
/// **not** check the signature; see [`verify_and_open_grant`].
///
/// # Errors
/// [`CryptoError::Auth`] for a wrong key, `vault_id` or `key_version`, or
/// tampered bytes; [`CryptoError::Malformed`] for bad framing.
pub fn open_grant(
    grant: &Grant,
    vault_id: &Id16,
    key_version: u32,
    my_x25519_sk: &[u8; X25519_LEN],
) -> Result<Key32> {
    let info = canon::info_vk(vault_id, key_version);
    let pt = hpke::open_base(my_x25519_sk, &info, &grant.wrapped)?;
    Key32::from_slice(&pt).map_err(|_| CryptoError::Malformed("wrapped vault key length"))
}

/// [`verify_grant`] then [`open_grant`], with `me` as the member.
///
/// # Errors
/// [`CryptoError::BadSignature`] first, then as [`open_grant`].
pub fn verify_and_open_grant(
    grant: &Grant,
    vault_id: &Id16,
    key_version: u32,
    my_user_id: &Id16,
    me: &AccountKeys,
    granter_ed25519_pub: &[u8; ED25519_PUBLIC_LEN],
) -> Result<Key32> {
    verify_grant(
        grant,
        vault_id,
        my_user_id,
        key_version,
        granter_ed25519_pub,
    )?;
    open_grant(grant, vault_id, key_version, me.x25519_secret_bytes())
}

/// Fuzz entry point (T-09): feeds arbitrary bytes to the grant decoders and
/// to open/verify with fixed keys. Must never panic.
#[doc(hidden)]
pub fn fuzz_open_grant(data: &[u8]) {
    let me = AccountKeys::from_secret_bytes([0x42; 32], [0x43; 32]);
    let pk = me.public();
    if let Ok(g) = Grant::from_bytes(data) {
        let _ = verify_grant(&g, &[1; 16], &[2; 16], 1, &pk.ed25519);
        let _ = open_grant(&g, &[1; 16], 1, me.x25519_secret_bytes());
    }
    let raw = Grant {
        wrapped: data.to_vec(),
        signature: [0; SIGNATURE_LEN],
    };
    let _ = open_grant(&raw, &[1; 16], 1, me.x25519_secret_bytes());
    let _ = verify_grant(&raw, &[1; 16], &[2; 16], 1, &pk.ed25519);
    if let Ok(pk) = <[u8; 32]>::try_from(data.get(..32).unwrap_or_default()) {
        let _ = sign::verify(&pk, data, &[0; SIGNATURE_LEN]);
    }
}
