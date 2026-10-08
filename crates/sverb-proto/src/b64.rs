//! Binary fields on the wire: base64url **without padding** (SPEC §10.4).
//!
//! Use as `#[serde(with = "sverb_proto::b64")]` on `Vec<u8>` fields and
//! `#[serde(with = "sverb_proto::b64::option")]` on `Option<Vec<u8>>`.
//! Decoding is strict: padding and the standard alphabet are rejected.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serializer};

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
///
/// # Errors
/// Invalid characters, padding or length.
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Serde `serialize_with`.
///
/// # Errors
/// Serializer errors.
pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(bytes))
}

/// Serde `deserialize_with`.
///
/// # Errors
/// Not a string, or not base64url without padding.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
    decode(&s).map_err(serde::de::Error::custom)
}

/// The same for `Option<Vec<u8>>` (`null` or absent ↔ `None`; combine with
/// `#[serde(default)]`).
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serde `serialize_with`.
    ///
    /// # Errors
    /// Serializer errors.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&super::encode(b)),
            None => s.serialize_none(),
        }
    }

    /// Serde `deserialize_with`.
    ///
    /// # Errors
    /// Not a string or null, or not base64url without padding.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<std::borrow::Cow<'de, str>>::deserialize(d)?
            .map(|s| super::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn no_padding_url_alphabet() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(decode("-_8=").is_err());
        assert!(decode("+/8").is_err());
    }
}
