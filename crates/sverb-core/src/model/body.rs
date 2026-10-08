//! The item envelope plaintext (SPEC §4.1): [`ItemBody`] with HLC-[`Stamped`] fields.
//!
//! The body is CBOR-encoded with [`ItemBody::to_cbor`] and the bytes are what
//! `sverb_crypto::envelope::seal_item` encrypts (§11.4). Encoding is deterministic: the
//! fields map is a `BTreeMap` (sorted keys), structs are written in declaration order,
//! and `ciborium::Value` maps keep their insertion order, which decoding preserves.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use ciborium::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hlc::{Hlc, HlcClock};
use super::ids::DeviceId;
use super::kinds::ItemKind;

/// Field names (last dotted segment) whose values are secrets (§11.5). They are plain
/// CBOR text inside the encrypted body, exposed only as `SecretString` by typed views,
/// and redacted by `ItemBody`'s `Debug`.
pub const SECRET_FIELDS: [&str; 3] = ["password", "private_key", "passphrase"];

/// Whether `field` (a possibly dotted key) holds a secret.
pub fn is_secret_field(field: &str) -> bool {
    let last = field.rsplit('.').next().unwrap_or(field);
    SECRET_FIELDS.contains(&last)
}

/// A value with the HLC stamp and device of its last write.
///
/// Merge order is `(hlc, device)` ([`Stamped::cmp_stamp`]). Encoded in CBOR as the
/// array `[value, hlc, device]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Stamped<T> {
    /// The value.
    pub value: T,
    /// When it was written.
    pub hlc: Hlc,
    /// Which device wrote it; breaks ties between equal stamps.
    pub device: DeviceId,
}

impl<T> Stamped<T> {
    /// Bundles a value with its stamp.
    pub fn new(value: T, hlc: Hlc, device: DeviceId) -> Self {
        Self { value, hlc, device }
    }

    /// The merge key `(hlc, device)`.
    pub fn stamp(&self) -> (Hlc, DeviceId) {
        (self.hlc, self.device)
    }

    /// Compares by `(hlc, device)`, ignoring the value (§12.4).
    pub fn cmp_stamp<U>(&self, other: &Stamped<U>) -> Ordering {
        self.stamp().cmp(&other.stamp())
    }

    /// Whether this write wins over `other` under LWW.
    pub fn is_newer_than<U>(&self, other: &Stamped<U>) -> bool {
        self.cmp_stamp(other) == Ordering::Greater
    }
}

impl<T: Serialize> Serialize for Stamped<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.value, &self.hlc, &self.device).serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Stamped<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (value, hlc, device) = <(T, Hlc, DeviceId)>::deserialize(d)?;
        Ok(Self { value, hlc, device })
    }
}

/// Errors encoding or decoding an [`ItemBody`].
#[derive(Debug, thiserror::Error)]
pub enum BodyCodecError {
    /// The bytes are not a valid CBOR item body.
    #[error("invalid item body: {0}")]
    Decode(String),
    /// The body could not be encoded (should not happen).
    #[error("could not encode item body: {0}")]
    Encode(String),
}

/// The plaintext of an item (§4.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemBody {
    /// What the item is.
    pub kind: ItemKind,
    /// Bumped only for breaking changes (§4.1, `model::migrate`).
    pub schema_version: u16,
    /// Field-level LWW registers. Nested structs use dotted keys (`proxy.addr`).
    /// Unknown keys are kept as they are.
    #[serde(default)]
    pub fields: BTreeMap<String, Stamped<Value>>,
    /// The tombstone; see [`ItemBody::is_deleted`].
    #[serde(default)]
    pub deleted: Option<Stamped<bool>>,
}

impl fmt::Debug for ItemBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Fields<'a>(&'a BTreeMap<String, Stamped<Value>>);
        impl fmt::Debug for Fields<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut m = f.debug_map();
                for (k, v) in self.0 {
                    if is_secret_field(k) && !v.value.is_null() {
                        m.entry(k, &format_args!("[REDACTED] @ {:?}/{:?}", v.hlc, v.device));
                    } else {
                        m.entry(k, v);
                    }
                }
                m.finish()
            }
        }
        f.debug_struct("ItemBody")
            .field("kind", &self.kind)
            .field("schema_version", &self.schema_version)
            .field("fields", &Fields(&self.fields))
            .field("deleted", &self.deleted)
            .finish()
    }
}

impl ItemBody {
    /// An empty body.
    pub fn new(kind: ItemKind, schema_version: u16) -> Self {
        Self {
            kind,
            schema_version,
            fields: BTreeMap::new(),
            deleted: None,
        }
    }

    /// A stamp for a write that replaces `current`: the clock's next stamp, raised past
    /// `current` if needed. (After a clamped skewed observation the clock can lag behind
    /// a stored stamp; a local overwrite must still win over what it replaced.)
    fn next_stamp_after(clock: &mut HlcClock, current: Option<Hlc>) -> Hlc {
        let now = clock.now();
        match current {
            Some(cur) if cur >= now => Hlc::from_u64(cur.as_u64().saturating_add(1)),
            _ => now,
        }
    }

    /// Writes `value` to `field` with a fresh stamp. Returns whether anything changed.
    ///
    /// Writing the value a field already holds is a no-op (no new stamp), so the outbox
    /// sees no spurious changes. A missing field and an explicit `Null` are different.
    pub fn set(
        &mut self,
        field: &str,
        value: impl Into<Value>,
        clock: &mut HlcClock,
        device: DeviceId,
    ) -> bool {
        let value = value.into();
        let current = self.fields.get(field);
        if current.is_some_and(|c| c.value == value) {
            return false;
        }
        let hlc = Self::next_stamp_after(clock, current.map(|c| c.hlc));
        self.fields
            .insert(field.to_owned(), Stamped::new(value, hlc, device));
        true
    }

    /// Writes an explicit `Null` ("None"), which wins merges against older values.
    /// The key stays in the map. Returns whether anything changed.
    pub fn unset(&mut self, field: &str, clock: &mut HlcClock, device: DeviceId) -> bool {
        self.set(field, Value::Null, clock, device)
    }

    /// The current value of `field`; `Null` and missing are both `None`.
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields
            .get(field)
            .map(|s| &s.value)
            .filter(|v| !v.is_null())
    }

    /// The stamped register for `field`, including explicit `Null`s.
    pub fn get_stamped(&self, field: &str) -> Option<&Stamped<Value>> {
        self.fields.get(field)
    }

    /// Whether the key is present (even as `Null`).
    pub fn contains(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Sets the tombstone, stamped after every field so the item is deleted.
    pub fn delete(&mut self, clock: &mut HlcClock, device: DeviceId) {
        let hlc = Self::next_stamp_after(clock, self.max_hlc());
        self.deleted = Some(Stamped::new(true, hlc, device));
    }

    /// Clears the tombstone (undo of a delete). No-op if the item isn't deleted.
    pub fn restore(&mut self, clock: &mut HlcClock, device: DeviceId) {
        if self.deleted.as_ref().is_some_and(|d| d.value) {
            let hlc = Self::next_stamp_after(clock, self.max_hlc());
            self.deleted = Some(Stamped::new(false, hlc, device));
        }
    }

    /// The highest field stamp (`None` for a body without fields).
    pub fn max_field_hlc(&self) -> Option<Hlc> {
        self.fields.values().map(|s| s.hlc).max()
    }

    /// The highest stamp in the body, tombstone included.
    pub fn max_hlc(&self) -> Option<Hlc> {
        let d = self.deleted.as_ref().map(|d| d.hlc);
        self.max_field_hlc().max(d)
    }

    /// §12.4: deleted iff the tombstone is `true` and newer than every field. An edit
    /// newer than the delete resurrects the item.
    pub fn is_deleted(&self) -> bool {
        match &self.deleted {
            Some(d) if d.value => self.max_field_hlc().is_none_or(|max| d.hlc > max),
            _ => false,
        }
    }

    /// Deterministic CBOR encoding (the input of `sverb_crypto::envelope::seal_item`).
    pub fn to_cbor(&self) -> Result<Vec<u8>, BodyCodecError> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| BodyCodecError::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Decodes [`ItemBody::to_cbor`] output.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, BodyCodecError> {
        ciborium::from_reader(bytes).map_err(|e| BodyCodecError::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::hlc::ManualClock;

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn tombstone_only_body_is_deleted() {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let mut b = ItemBody::new(ItemKind::Host, 1);
        assert!(!b.is_deleted());
        b.delete(&mut clock, dev(1));
        assert!(b.is_deleted());
        b.restore(&mut clock, dev(1));
        assert!(!b.is_deleted());
    }

    #[test]
    fn debug_redacts_secret_fields() {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let mut b = ItemBody::new(ItemKind::Host, 1);
        b.set("password", "CANARY-pw", &mut clock, dev(1));
        b.set("proxy.auth.password", "CANARY-proxy", &mut clock, dev(1));
        b.set("address", "example.com", &mut clock, dev(1));
        let s = format!("{b:?}");
        assert!(!s.contains("CANARY"), "{s}");
        assert!(s.contains("example.com"));
    }

    #[test]
    fn local_write_beats_skewed_stamp() {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let mut b = ItemBody::new(ItemKind::Host, 1);
        let future = Hlc::from_duration(Duration::from_secs(1_900_000_000));
        b.fields
            .insert("port".into(), Stamped::new(Value::from(22), future, dev(2)));
        assert!(b.set("port", 2222, &mut clock, dev(1)));
        let s = b.get_stamped("port").map(|s| s.hlc);
        assert!(s > Some(future));
    }
}
