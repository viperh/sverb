//! Canonical byte encodings (§11.1).
//!
//! Every AAD, HKDF `info`, HPKE `info` and signature input in sverb is built
//! here, never by ad-hoc concatenation in callers:
//!
//! - UUIDs are 16 raw bytes ([`Id16`]).
//! - Integers are big-endian (`u32` for `key_version`, `u64` for `seq` /
//!   `chunk_index`).
//! - Variable-length fields are prefixed with their length as `u32` BE.
//! - Domain-separation labels are ASCII constants from [`labels`].
//!
//! **Labels are not length-prefixed** (spec gap, resolved here). A label is
//! always the first field, every label is a compile-time constant, and the
//! fields that follow a given label have a fixed layout (fixed-width or
//! length-prefixed). A decoder that knows which construction it is looking at
//! therefore knows the label's length, so the encoding is unambiguous. Each
//! construction is also used under its own key or context, so a collision
//! between "label A || fields" and "label B || fields" cannot be exploited.

/// A UUID (or any other 16-byte identifier) in its raw byte form, e.g.
/// `uuid::Uuid::as_bytes()`.
pub type Id16 = [u8; 16];

/// Domain-separation labels. Changing any of these is a breaking format change.
pub mod labels {
    /// Item envelope AAD prefix (§11.4).
    pub const ITEM_V1: &str = "sverb-item-v1";
    /// HKDF `info` for per-item subkeys (§11.4).
    pub const ITEM_KEY_V1: &str = "sverb/item/v1";
    /// HPKE `info` prefix for vault-key grants (§11.3, used in M4-03).
    pub const VK_V1: &str = "sverb/vk/v1";
    /// HKDF `info` for the recording key (§7.5).
    pub const RECORDING_V1: &str = "sverb/recording/v1";
    /// AAD prefix for key wrapping under the LMK / KEKs (§5.3).
    pub const LMK_WRAP_V1: &str = "sverb-lmk-wrap-v1";
    /// HKDF `info` for the account key-encryption key (§11.2, used in M4-03).
    pub const AKEK_V1: &str = "sverb/akek/v1";
    // M6-02: confirmed against §14.2 (join HMAC key `info`, channel HKDF `info` prefix).
    /// HKDF `info` deriving the share join HMAC key from `share_key` (§14.2.1).
    pub const SHARE_JOIN_V1: &str = "sverb/share/join/v1";
    /// HKDF `info` prefix of the per-viewer share channel key (§14.2.2).
    pub const SHARE_CHAN_V1: &str = "sverb/share/chan/v1";
    /// Fixed trailer of the share `Welcome` MAC transcript (§14.2.1, M6-02).
    pub const SHARE_WELCOME: &str = "welcome";
    // M4-03: account bundles, recovery key, grants, fingerprints.
    /// AAD prefix of the account `private_bundle` (§11.2).
    pub const BUNDLE_V1: &str = "sverb/bundle/v1";
    /// HKDF `info` deriving the recovery KEK from the recovery key (§11.2).
    pub const RECOVERY_V1: &str = "sverb/recovery/v1";
    /// AAD prefix of the account `recovery_bundle` (§11.2).
    pub const RECOVERY_BUNDLE_V1: &str = "sverb/recovery-bundle/v1";
    /// Ed25519 signature input prefix for vault-key grants (§11.3).
    pub const GRANT_V1: &str = "sverb/grant/v1";
    /// SHA-256 input prefix for account key fingerprints (§13.3, M5-03).
    pub const FPR_V1: &str = "sverb/fpr/v1";
}

/// A typed builder for canonical byte strings. Prefer the named construction
/// functions below; new constructions should get their own function here.
#[derive(Debug, Default, Clone)]
pub struct Canon {
    buf: Vec<u8>,
}

impl Canon {
    /// Starts a new encoding with a domain-separation label (no length prefix,
    /// see the module docs).
    #[must_use]
    pub fn with_label(label: &'static str) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(label.as_bytes());
        Self { buf }
    }

    /// Appends a 16-byte identifier.
    #[must_use]
    pub fn id(mut self, id: &Id16) -> Self {
        self.buf.extend_from_slice(id);
        self
    }

    /// Appends a fixed-width field (e.g. a 32-byte public key) with no
    /// length prefix. Only for fields whose width is fixed by the construction.
    #[must_use]
    pub fn fixed<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Appends a `u8`.
    #[must_use]
    pub fn u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }

    /// Appends a `u32` big-endian.
    #[must_use]
    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a `u64` big-endian.
    #[must_use]
    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a variable-length field as `u32 BE length || bytes`.
    ///
    /// # Panics
    /// If `bytes` is longer than `u32::MAX`. Canonical inputs are small
    /// identifiers and labels, so this is a programming error.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn bytes(mut self, bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len()).expect("canonical field longer than u32::MAX");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// `u32 BE length || bytes`.
#[must_use]
pub fn len_prefixed(bytes: &[u8]) -> Vec<u8> {
    Canon::default().bytes(bytes).finish()
}

/// Item envelope AAD (§11.4):
/// `"sverb-item-v1" || vault_id(16) || item_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn aad_item(vault_id: &Id16, item_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::ITEM_V1)
        .id(vault_id)
        .id(item_id)
        .u32(key_version)
        .finish()
}

/// HKDF `info` for the per-item subkey (§11.4): `"sverb/item/v1"`.
#[must_use]
pub fn info_item_key() -> Vec<u8> {
    Canon::with_label(labels::ITEM_KEY_V1).finish()
}

/// HKDF `info` for the recording key (§7.5): `"sverb/recording/v1"`.
#[must_use]
pub fn info_recording_key() -> Vec<u8> {
    Canon::with_label(labels::RECORDING_V1).finish()
}

/// HPKE `info` for a vault-key grant (§11.3):
/// `"sverb/vk/v1" || vault_id(16) || key_version(u32 BE)`.
#[must_use]
pub fn info_vk(vault_id: &Id16, key_version: u32) -> Vec<u8> {
    Canon::with_label(labels::VK_V1)
        .id(vault_id)
        .u32(key_version)
        .finish()
}

/// Key-wrap AAD (§5.3): `"sverb-lmk-wrap-v1" || purpose`, where `purpose` is
/// `u32 BE len || purpose name`, followed by the purpose's fixed-width
/// parameter (the 16-byte vault id for `vault-key`, nothing otherwise).
#[must_use]
pub fn aad_wrap(purpose_name: &'static str, purpose_id: Option<&Id16>) -> Vec<u8> {
    let c = Canon::with_label(labels::LMK_WRAP_V1).bytes(purpose_name.as_bytes());
    match purpose_id {
        Some(id) => c.id(id),
        None => c,
    }
    .finish()
}

/// Recording chunk AAD (§7.5): `conn_id(16) || chunk_index(u64 BE) || is_last(u8)`.
///
/// As the spec states, this AAD carries no label: domain separation comes from
/// the recording key, which is derived under its own HKDF label.
#[must_use]
pub fn aad_recording_chunk(conn_id: &Id16, chunk_index: u64, is_last: bool) -> Vec<u8> {
    Canon::default()
        .id(conn_id)
        .u64(chunk_index)
        .u8(u8::from(is_last))
        .finish()
}

// M4-03: account key hierarchy (§11.2), grants (§11.3), fingerprints (§13.3).

/// HKDF `info` for the account key-encryption key (§11.2): `"sverb/akek/v1"`.
#[must_use]
pub fn info_akek() -> Vec<u8> {
    Canon::with_label(labels::AKEK_V1).finish()
}

/// AAD of the account `private_bundle` (§11.2):
/// `"sverb/bundle/v1" || user_id(16) || version(u32 BE)`.
#[must_use]
pub fn aad_private_bundle(user_id: &Id16, version: u32) -> Vec<u8> {
    Canon::with_label(labels::BUNDLE_V1)
        .id(user_id)
        .u32(version)
        .finish()
}

/// HKDF `info` for the recovery KEK (§11.2): `"sverb/recovery/v1"`.
#[must_use]
pub fn info_recovery_key() -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_V1).finish()
}

/// AAD of the account `recovery_bundle` (§11.2):
/// `"sverb/recovery-bundle/v1" || user_id(16)`.
#[must_use]
pub fn aad_recovery_bundle(user_id: &Id16) -> Vec<u8> {
    Canon::with_label(labels::RECOVERY_BUNDLE_V1)
        .id(user_id)
        .finish()
}

/// Ed25519 signature input of a vault-key grant (§11.3), shared by client and
/// server: `"sverb/grant/v1" || vault_id(16) || member_user_id(16) ||
/// key_version(u32 BE) || u32 BE len || wrapped_vault_key`.
#[must_use]
pub fn sig_grant(vault_id: &Id16, member_id: &Id16, key_version: u32, wrapped: &[u8]) -> Vec<u8> {
    Canon::with_label(labels::GRANT_V1)
        .id(vault_id)
        .id(member_id)
        .u32(key_version)
        .bytes(wrapped)
        .finish()
}

/// SHA-256 input of an account key fingerprint (§13.3):
/// `"sverb/fpr/v1" || x25519_pub(32) || ed25519_pub(32)`.
#[must_use]
pub fn fpr_input(x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> Vec<u8> {
    Canon::with_label(labels::FPR_V1)
        .fixed(x25519_pub)
        .fixed(ed25519_pub)
        .finish()
}

// M6-02: terminal sharing (§14.2).

/// HKDF `info` of the share join HMAC key (§14.2.1): `"sverb/share/join/v1"`.
#[must_use]
pub fn info_share_join() -> Vec<u8> {
    Canon::with_label(labels::SHARE_JOIN_V1).finish()
}

/// HMAC input of a share `Hello` (§14.2.1):
/// `share_id(16) || viewer_eph_pub(32) || u32 BE len || name`.
///
/// No label: the HMAC key is already derived under [`labels::SHARE_JOIN_V1`].
#[must_use]
pub fn mac_share_hello(share_id: &Id16, viewer_eph_pub: &[u8; 32], name: &[u8]) -> Vec<u8> {
    Canon::default()
        .id(share_id)
        .fixed(viewer_eph_pub)
        .bytes(name)
        .finish()
}

/// HMAC input of a share `Welcome`, the full transcript (§14.2.1):
/// `share_id(16) || viewer_eph_pub(32) || u32 BE len || name ||
/// host_eph_pub(32) || "welcome"`.
///
/// It can never equal a [`mac_share_hello`] input: the name's length prefix
/// fixes where a `Hello` input ends, and a `Welcome` input is always 39 bytes
/// longer than that.
#[must_use]
pub fn mac_share_welcome(
    share_id: &Id16,
    viewer_eph_pub: &[u8; 32],
    name: &[u8],
    host_eph_pub: &[u8; 32],
) -> Vec<u8> {
    let mut out = mac_share_hello(share_id, viewer_eph_pub, name);
    out.extend_from_slice(host_eph_pub);
    out.extend_from_slice(labels::SHARE_WELCOME.as_bytes());
    out
}

/// HKDF `info` of a share channel key (§14.2.2):
/// `"sverb/share/chan/v1" || share_id(16) || viewer_eph_pub(32) || host_eph_pub(32)`.
#[must_use]
pub fn info_share_chan(
    share_id: &Id16,
    viewer_eph_pub: &[u8; 32],
    host_eph_pub: &[u8; 32],
) -> Vec<u8> {
    Canon::with_label(labels::SHARE_CHAN_V1)
        .id(share_id)
        .fixed(viewer_eph_pub)
        .fixed(host_eph_pub)
        .finish()
}

/// AAD of a share frame (§14.2.3):
/// `share_id(16) || viewer_id(u32 BE) || dir(u8: 0 = h2v, 1 = v2h) || seq(u64 BE)`.
///
/// As the spec states, no label: domain separation comes from the channel
/// key, which is derived under [`labels::SHARE_CHAN_V1`].
#[must_use]
pub fn aad_share_frame(share_id: &Id16, viewer_id: u32, dir: u8, seq: u64) -> Vec<u8> {
    Canon::default()
        .id(share_id)
        .u32(viewer_id)
        .u8(dir)
        .u64(seq)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-13
    #[test]
    fn len_prefixed_abc() {
        assert_eq!(len_prefixed(b"abc"), [0, 0, 0, 3, 0x61, 0x62, 0x63]);
        assert_eq!(len_prefixed(b""), [0, 0, 0, 0]);
    }

    // T-13
    #[test]
    fn aad_item_layout() {
        let vault = [0xAA; 16];
        let item = [0xBB; 16];
        let aad = aad_item(&vault, &item, 7);
        assert_eq!(aad.len(), 13 + 16 + 16 + 4);
        assert_eq!(&aad[..13], b"sverb-item-v1");
        assert_eq!(&aad[13..29], &vault);
        assert_eq!(&aad[29..45], &item);
        assert_eq!(&aad[45..], &[0, 0, 0, 7]);
    }

    #[test]
    fn recording_aad_layout() {
        let aad = aad_recording_chunk(&[1; 16], 0x0102_0304_0506_0708, true);
        assert_eq!(aad.len(), 25);
        assert_eq!(&aad[16..24], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(aad[24], 1);
    }

    // M4-03
    #[test]
    fn grant_sig_layout() {
        let m = sig_grant(&[1; 16], &[2; 16], 3, b"wk");
        assert_eq!(&m[..14], b"sverb/grant/v1");
        assert_eq!(&m[14..30], &[1; 16]);
        assert_eq!(&m[30..46], &[2; 16]);
        assert_eq!(&m[46..50], &[0, 0, 0, 3]);
        assert_eq!(&m[50..], &[0, 0, 0, 2, b'w', b'k']);
        let b = aad_private_bundle(&[9; 16], 0x0102_0304);
        assert_eq!(&b[..15], b"sverb/bundle/v1");
        assert_eq!(&b[31..], &[1, 2, 3, 4]);
        assert_eq!(fpr_input(&[1; 32], &[2; 32]).len(), 12 + 64);
    }

    // M6-02
    #[test]
    fn share_layouts() {
        assert_eq!(info_share_join(), b"sverb/share/join/v1");
        let h = mac_share_hello(&[1; 16], &[2; 32], b"ab");
        assert_eq!(h.len(), 16 + 32 + 4 + 2);
        assert_eq!(&h[48..], &[0, 0, 0, 2, b'a', b'b']);
        let w = mac_share_welcome(&[1; 16], &[2; 32], b"ab", &[3; 32]);
        assert_eq!(&w[..h.len()], &h[..]);
        assert_eq!(&w[h.len()..h.len() + 32], &[3; 32]);
        assert_eq!(&w[h.len() + 32..], b"welcome");
        let c = info_share_chan(&[1; 16], &[2; 32], &[3; 32]);
        assert_eq!(&c[..19], b"sverb/share/chan/v1");
        assert_eq!(c.len(), 19 + 16 + 64);
        let a = aad_share_frame(&[1; 16], 0x0102_0304, 1, 5);
        assert_eq!(&a[16..], &[1, 2, 3, 4, 1, 0, 0, 0, 0, 0, 0, 0, 5]);
    }

    #[test]
    fn wrap_aad_layout() {
        let aad = aad_wrap("vault-key", Some(&[7; 16]));
        assert_eq!(&aad[..17], b"sverb-lmk-wrap-v1");
        assert_eq!(&aad[17..21], &[0, 0, 0, 9]);
        assert_eq!(&aad[21..30], b"vault-key");
        assert_eq!(&aad[30..], &[7; 16]);
    }
}
