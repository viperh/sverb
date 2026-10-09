//! Per-user credential overrides for shared hosts (SPEC §13.4).
//!
//! A host in a shared vault must not reference personal items (other members
//! could not resolve them). Teams still want each member to log in with their
//! own key or user: a [`CredentialOverride`] stored in the member's **personal**
//! vault, keyed by the shared host's id, supplies credentials **for that user
//! only**. It is the one allowed cross-vault reference (`shared_host_id`);
//! its own references (`identity_id`, `key_id`) point into the personal vault.
//!
//! Resolution (`resolve::overrides`) puts it above the shared host's own
//! credential fields; provenance shows "(your override)".
//!
//! Fields: `shared_host_id` (id, required), `username` (text), `password`
//! (secret), `key_id` (id), `identity_id` (id). An override with none of the
//! credential fields set does nothing (the UI deletes it instead).

use super::body::ItemBody;
use super::fields::{Reader, ViewError, Writer, check_kind};
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use crate::secret::SecretString;

/// A user's own credentials for one shared host (§13.4).
#[derive(Debug)]
pub struct CredentialOverride {
    /// The shared host these credentials are for.
    pub shared_host_id: ItemId,
    /// `username` (`None`: the host's).
    pub username: Option<String>,
    /// `password` (`None`: the host's).
    pub password: Option<SecretString>,
    /// `key_id` (a personal key).
    pub key_id: Option<ItemId>,
    /// `identity_id` (a personal identity; its user, password and key count as
    /// override values, below the inline fields above).
    pub identity_id: Option<ItemId>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl CredentialOverride {
    /// An empty override for `shared_host_id`.
    pub fn new(shared_host_id: ItemId) -> Self {
        Self {
            shared_host_id,
            username: None,
            password: None,
            key_id: None,
            identity_id: None,
            read_only: false,
        }
    }

    /// Whether it sets nothing.
    pub fn is_empty(&self) -> bool {
        self.username.as_deref().is_none_or(str::is_empty)
            && self.password.is_none()
            && self.key_id.is_none()
            && self.identity_id.is_none()
    }

    /// A short description for the host detail: `user bob · key · identity`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(u) = self.username.as_deref().filter(|u| !u.is_empty()) {
            parts.push(format!("user {u}"));
        }
        if self.password.is_some() {
            parts.push("password".to_owned());
        }
        if self.key_id.is_some() {
            parts.push("key".to_owned());
        }
        if self.identity_id.is_some() {
            parts.push("identity".to_owned());
        }
        if parts.is_empty() {
            "nothing".to_owned()
        } else {
            parts.join(" · ")
        }
    }

    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.always("shared_host_id", self.shared_host_id);
        w.opt("username", self.username.clone().filter(|u| !u.is_empty()));
        w.opt_secret("password", self.password.as_ref());
        w.opt("key_id", self.key_id);
        w.opt("identity_id", self.identity_id);
    }

    /// A new body of kind [`ItemKind::CredentialOverride`] holding `self`.
    pub fn to_body(&self, clock: &mut HlcClock, device: DeviceId) -> ItemBody {
        let mut body = ItemBody::new(
            ItemKind::CredentialOverride,
            super::migrate::current_schema(ItemKind::CredentialOverride),
        );
        self.apply_to(&mut body, clock, device);
        body
    }
}

impl TryFrom<&ItemBody> for CredentialOverride {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::CredentialOverride)?;
        let r = Reader::new(body);
        Ok(Self {
            shared_host_id: r.req_id("shared_host_id")?,
            username: r.opt_str("username")?.filter(|u| !u.is_empty()),
            password: r.opt_secret("password")?,
            key_id: r.opt_id("key_id")?,
            identity_id: r.opt_id("identity_id")?,
            read_only,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let host = ItemId::new();
        let key = ItemId::new();
        let mut o = CredentialOverride::new(host);
        assert!(o.is_empty());
        o.username = Some("bob".into());
        o.password = Some(SecretString::from("hunter2"));
        o.key_id = Some(key);
        let body = o.to_body(&mut clock, dev);
        let back = CredentialOverride::try_from(&body).unwrap();
        assert_eq!(back.shared_host_id, host);
        assert_eq!(back.username.as_deref(), Some("bob"));
        assert_eq!(back.password.as_ref().unwrap().expose(), "hunter2");
        assert_eq!(back.key_id, Some(key));
        assert_eq!(back.identity_id, None);
        assert!(!back.is_empty());
        assert_eq!(back.describe(), "user bob · password · key");
        // Through CBOR.
        let cbor = body.to_cbor().unwrap();
        let again = CredentialOverride::try_from(&ItemBody::from_cbor(&cbor).unwrap()).unwrap();
        assert_eq!(again.username.as_deref(), Some("bob"));
        // Another kind is rejected.
        let host_body = ItemBody::new(ItemKind::Host, 1);
        assert!(CredentialOverride::try_from(&host_body).is_err());
    }
}
