//! Randomness helpers.
//!
//! Every function takes the RNG as a parameter so tests can inject a
//! deterministic generator. Production code passes [`os_rng()`], which is the
//! operating system CSPRNG (the spec's `OsRng`, §11.1). UUIDv7 generation lives
//! in `sverb-core`, not here.

use rand_core::{CryptoRng, UnwrapErr};

use crate::keys::{KEY_LEN, Key32, NONCE_LEN, Nonce24};

/// The operating-system CSPRNG. `getrandom` failures are unrecoverable and
/// panic, which is the conventional behaviour of `OsRng`.
pub type OsRng = UnwrapErr<getrandom::SysRng>;

/// Returns the operating-system CSPRNG.
#[must_use]
pub const fn os_rng() -> OsRng {
    UnwrapErr(getrandom::SysRng)
}

/// Generates a fresh random 256-bit key.
pub fn random_key32<R: CryptoRng + ?Sized>(rng: &mut R) -> Key32 {
    let mut bytes = [0u8; KEY_LEN];
    rng.fill_bytes(&mut bytes);
    let key = Key32::from_bytes(bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    key
}

/// Generates a fresh random 16-byte salt (Argon2id salt, §5.3).
pub fn random_salt16<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 16] {
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    salt
}

/// Generates a fresh random 24-byte XChaCha20-Poly1305 nonce.
pub fn random_nonce24<R: CryptoRng + ?Sized>(rng: &mut R) -> Nonce24 {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    Nonce24::from_bytes(nonce)
}
