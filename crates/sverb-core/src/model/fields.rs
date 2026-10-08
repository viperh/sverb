//! Typed reads and change-only writes of [`ItemBody`] fields, shared by the typed views.

use ciborium::Value;

use super::body::ItemBody;
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use super::migrate::is_read_only;
use crate::secret::SecretString;

/// Errors converting an [`ItemBody`] into a typed view.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// The body is a different kind of item.
    #[error("expected a {expected} item, found {found}")]
    WrongKind {
        /// The kind the view needs.
        expected: ItemKind,
        /// The kind of the body.
        found: ItemKind,
    },
    /// A field holds a CBOR value of the wrong type (or out of range).
    #[error("field `{field}` has the wrong type")]
    FieldTypeError {
        /// The (dotted) field name.
        field: String,
    },
    /// A required field is missing.
    #[error("required field `{field}` is missing")]
    MissingField {
        /// The (dotted) field name.
        field: String,
    },
}

/// A closed enum encoded as a stable lowercase string (see `docs/data-model.md`).
pub trait WireEnum: Sized + Copy {
    /// The wire string.
    fn as_wire(&self) -> &'static str;
    /// Parses the wire string.
    fn from_wire(s: &str) -> Option<Self>;
}

/// Defines a fieldless enum with stable wire strings.
macro_rules! wire_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $crate::model::fields::WireEnum for $name {
            fn as_wire(&self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            fn from_wire(s: &str) -> Option<Self> {
                match s { $($wire => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}
pub(crate) use wire_enum;

fn type_err(field: &str) -> ViewError {
    ViewError::FieldTypeError {
        field: field.to_owned(),
    }
}

/// Checks the kind and returns the view's `read_only` flag.
pub(crate) fn check_kind(body: &ItemBody, expected: ItemKind) -> Result<bool, ViewError> {
    if body.kind != expected {
        return Err(ViewError::WrongKind {
            expected,
            found: body.kind,
        });
    }
    Ok(is_read_only(body))
}

/// Typed reads. Missing and `Null` mean `None`; a wrong CBOR type is a `FieldTypeError`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    body: &'a ItemBody,
    prefix: &'a str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(body: &'a ItemBody) -> Self {
        Self { body, prefix: "" }
    }

    /// A reader whose keys are prefixed with `prefix` (e.g. `"defaults."`).
    pub(crate) fn with_prefix(body: &'a ItemBody, prefix: &'a str) -> Self {
        Self { body, prefix }
    }

    pub(crate) fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    pub(crate) fn value(&self, key: &str) -> Option<&'a Value> {
        self.body.get(&self.key(key))
    }

    fn map<T>(
        &self,
        key: &str,
        f: impl FnOnce(&Value) -> Option<T>,
    ) -> Result<Option<T>, ViewError> {
        match self.value(key) {
            None => Ok(None),
            Some(v) => f(v).map(Some).ok_or_else(|| type_err(&self.key(key))),
        }
    }

    pub(crate) fn opt_str(&self, key: &str) -> Result<Option<String>, ViewError> {
        self.map(key, |v| v.as_text().map(str::to_owned))
    }

    pub(crate) fn str(&self, key: &str) -> Result<String, ViewError> {
        Ok(self.opt_str(key)?.unwrap_or_default())
    }

    pub(crate) fn opt_secret(&self, key: &str) -> Result<Option<SecretString>, ViewError> {
        self.map(key, |v| v.as_text().map(SecretString::from))
    }

    pub(crate) fn int<T: TryFrom<ciborium::value::Integer>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ViewError> {
        self.map(key, |v| v.as_integer().and_then(|i| T::try_from(i).ok()))
    }

    pub(crate) fn req_int<T: TryFrom<ciborium::value::Integer>>(
        &self,
        key: &str,
    ) -> Result<T, ViewError> {
        self.int(key)?.ok_or_else(|| self.missing(key))
    }

    pub(crate) fn opt_bool(&self, key: &str) -> Result<Option<bool>, ViewError> {
        self.map(key, Value::as_bool)
    }

    pub(crate) fn bool(&self, key: &str) -> Result<bool, ViewError> {
        Ok(self.opt_bool(key)?.unwrap_or(false))
    }

    pub(crate) fn opt_id(&self, key: &str) -> Result<Option<ItemId>, ViewError> {
        self.map(key, ItemId::from_value)
    }

    pub(crate) fn req_id(&self, key: &str) -> Result<ItemId, ViewError> {
        self.opt_id(key)?.ok_or_else(|| self.missing(key))
    }

    pub(crate) fn opt_ids(&self, key: &str) -> Result<Option<Vec<ItemId>>, ViewError> {
        self.map(key, |v| {
            v.as_array()?
                .iter()
                .map(ItemId::from_value)
                .collect::<Option<Vec<_>>>()
        })
    }

    pub(crate) fn ids(&self, key: &str) -> Result<Vec<ItemId>, ViewError> {
        Ok(self.opt_ids(key)?.unwrap_or_default())
    }

    pub(crate) fn opt_strs(&self, key: &str) -> Result<Option<Vec<String>>, ViewError> {
        self.map(key, |v| {
            v.as_array()?
                .iter()
                .map(|s| s.as_text().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
    }

    /// `[[name, value], …]`
    pub(crate) fn opt_pairs(&self, key: &str) -> Result<Option<Vec<(String, String)>>, ViewError> {
        self.map(key, |v| {
            v.as_array()?
                .iter()
                .map(|pair| match pair.as_array()?.as_slice() {
                    [k, v] => Some((k.as_text()?.to_owned(), v.as_text()?.to_owned())),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
        })
    }

    pub(crate) fn opt_enum<E: WireEnum>(&self, key: &str) -> Result<Option<E>, ViewError> {
        self.map(key, |v| v.as_text().and_then(E::from_wire))
    }

    pub(crate) fn req_enum<E: WireEnum>(&self, key: &str) -> Result<E, ViewError> {
        self.opt_enum(key)?.ok_or_else(|| self.missing(key))
    }

    pub(crate) fn missing(&self, key: &str) -> ViewError {
        ViewError::MissingField {
            field: self.key(key),
        }
    }

    pub(crate) fn type_err(&self, key: &str) -> ViewError {
        type_err(&self.key(key))
    }
}

/// Change-only writes: every write goes through [`ItemBody::set`], which skips values
/// equal to the current one. A `Null` (or a type's default) is not written to a key
/// that doesn't exist yet, so applying an unchanged view creates no stamps.
#[derive(Debug)]
pub(crate) struct Writer<'a> {
    body: &'a mut ItemBody,
    clock: &'a mut HlcClock,
    device: DeviceId,
    prefix: &'a str,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(body: &'a mut ItemBody, clock: &'a mut HlcClock, device: DeviceId) -> Self {
        Self {
            body,
            clock,
            device,
            prefix: "",
        }
    }

    /// Runs `f` with keys prefixed by `prefix`.
    pub(crate) fn with_prefix<R>(
        &mut self,
        prefix: &str,
        f: impl FnOnce(&mut Writer<'_>) -> R,
    ) -> R {
        let full = format!("{}{prefix}", self.prefix);
        let mut w = Writer {
            body: self.body,
            clock: self.clock,
            device: self.device,
            prefix: &full,
        };
        f(&mut w)
    }

    /// Writes `value`, unless it is a default (`is_default`) and the key is absent.
    pub(crate) fn put_or_skip(&mut self, key: &str, value: Value, is_default: bool) {
        let key = format!("{}{key}", self.prefix);
        if is_default && !self.body.contains(&key) {
            return;
        }
        self.body.set(&key, value, self.clock, self.device);
    }

    /// An optional value: `None` is `Null`.
    pub(crate) fn opt<T: Into<Value>>(&mut self, key: &str, value: Option<T>) {
        match value {
            Some(v) => self.put_or_skip(key, v.into(), false),
            None => self.put_or_skip(key, Value::Null, true),
        }
    }

    /// A required string: `""` is the default.
    pub(crate) fn text(&mut self, key: &str, value: &str) {
        self.put_or_skip(key, Value::Text(value.to_owned()), value.is_empty());
    }

    /// A required value with no meaningful default (always written).
    pub(crate) fn always(&mut self, key: &str, value: impl Into<Value>) {
        self.put_or_skip(key, value.into(), false);
    }

    /// A plain bool: `false` is the default.
    pub(crate) fn flag(&mut self, key: &str, value: bool) {
        self.put_or_skip(key, Value::Bool(value), !value);
    }

    pub(crate) fn opt_secret(&mut self, key: &str, value: Option<&SecretString>) {
        self.opt(key, value.map(|s| s.expose_for_envelope().to_owned()));
    }

    pub(crate) fn ids(&mut self, key: &str, ids: &[ItemId]) {
        self.put_or_skip(key, ids_value(ids), ids.is_empty());
    }

    pub(crate) fn opt_ids(&mut self, key: &str, ids: Option<&[ItemId]>) {
        self.opt(key, ids.map(ids_value));
    }

    pub(crate) fn opt_strs(&mut self, key: &str, v: Option<&[String]>) {
        self.opt(
            key,
            v.map(|v| Value::Array(v.iter().cloned().map(Value::Text).collect())),
        );
    }

    pub(crate) fn opt_pairs(&mut self, key: &str, pairs: Option<&[(String, String)]>) {
        self.opt(key, pairs.map(pairs_value));
    }

    pub(crate) fn opt_enum<E: WireEnum>(&mut self, key: &str, value: Option<E>) {
        self.opt(key, value.map(|e| e.as_wire()));
    }

    /// Writes `Null` to `key` if it currently holds a value (clears stale sub-fields).
    pub(crate) fn clear(&mut self, key: &str) {
        self.put_or_skip(key, Value::Null, true);
    }
}

pub(crate) fn ids_value(ids: &[ItemId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(*id)).collect())
}

fn pairs_value(pairs: &[(String, String)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(k, v)| Value::Array(vec![Value::Text(k.clone()), Value::Text(v.clone())]))
            .collect(),
    )
}
