//! The credential override layer (SPEC §13.4).
//!
//! A [`CredentialOverride`] in the user's personal vault sits **above the
//! shared host's own credential fields** (`identity_id`, `username`, `password`,
//! `key_id`) for that user only: resolution first runs as usual
//! ([`resolve_settings`](super::resolve_settings)), then [`apply_override`]
//! replaces each credential the override sets, with provenance
//! [`Source::Override`] ("your override"). Like every other level, an identity
//! set on the override is expanded there: its user, password and key count as
//! override values, below the override's inline fields. Credentials the override
//! does not set keep resolving from the host, its groups and the vault defaults.
//!
//! Only the user's own device has the override (it is in their personal vault),
//! so other members keep seeing the shared values.

use tracing::debug;

use super::{ItemLookup, ResolveWarning, ResolvedHost, SecretOrigin, SettingKey, Source};
use crate::model::{CredentialOverride, ItemId};

/// An override as resolution sees it (no secret values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideLayer {
    /// The override item.
    pub item: ItemId,
    /// The shared host it applies to.
    pub host: ItemId,
    /// `username`.
    pub username: Option<String>,
    /// A password is stored on the override.
    pub password: bool,
    /// `key_id`.
    pub key_id: Option<ItemId>,
    /// `identity_id`.
    pub identity_id: Option<ItemId>,
}

impl OverrideLayer {
    /// The layer of override item `item`.
    pub fn new(item: ItemId, o: &CredentialOverride) -> Self {
        Self {
            item,
            host: o.shared_host_id,
            username: o.username.clone().filter(|u| !u.is_empty()),
            password: o.password.is_some(),
            key_id: o.key_id,
            identity_id: o.identity_id,
        }
    }
}

/// The override for `host` among `overrides` (if a sync race left several, the
/// smallest item id wins, so every device picks the same one).
pub fn pick_override<'a>(
    host: ItemId,
    overrides: impl IntoIterator<Item = &'a OverrideLayer>,
) -> Option<&'a OverrideLayer> {
    overrides
        .into_iter()
        .filter(|o| o.host == host)
        .min_by_key(|o| o.item)
}

fn push_warning(r: &mut ResolvedHost, w: ResolveWarning) {
    if !r.warnings.contains(&w) {
        r.warnings.push(w);
        r.warnings.sort();
    }
}

/// Puts `layer` above the host's own credentials in `r` (see the module docs).
pub fn apply_override<L: ItemLookup + ?Sized>(
    r: &mut ResolvedHost,
    layer: &OverrideLayer,
    lookup: &L,
) {
    let src = Source::Override { item: layer.item };
    let identity = match layer.identity_id {
        Some(id) => match lookup.identity(id) {
            Some(node) => Some((id, node)),
            None => {
                debug!(identity = %id.short(), "override: missing identity reference");
                push_warning(r, ResolveWarning::MissingIdentity(id));
                None
            }
        },
        None => None,
    };
    let key_ok = |id: ItemId, r: &mut ResolvedHost| {
        let ok = lookup.exists(id);
        if !ok {
            push_warning(r, ResolveWarning::MissingItem(id));
        }
        ok
    };

    if let Some((id, _)) = identity {
        r.identity_id = Some(id);
        r.provenance.set(SettingKey::IdentityId, src.clone());
    }
    let username = layer.username.clone().or_else(|| {
        identity
            .map(|(_, i)| i.username.clone())
            .filter(|u| !u.is_empty())
    });
    if let Some(u) = username {
        r.username = Some(u);
        r.provenance.set(SettingKey::Username, src.clone());
    }
    let password = if layer.password {
        Some(None)
    } else {
        identity
            .filter(|(_, i)| i.has_password)
            .map(|(id, _)| Some(id))
    };
    if let Some(identity) = password {
        r.password = Some(SecretOrigin {
            source: src.clone(),
            identity,
        });
        r.provenance.set(SettingKey::Password, src.clone());
    }
    let key = match layer.key_id {
        Some(k) if key_ok(k, r) => Some(k),
        _ => identity
            .and_then(|(_, i)| i.key_id)
            .filter(|k| key_ok(*k, r)),
    };
    if let Some(k) = key {
        r.key_id = Some(k);
        r.provenance.set(SettingKey::KeyId, src);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{DeviceId, HlcClock, Host, ItemBody, ItemKind};
    use crate::resolve::{
        GlobalDefaults, IdentityNode, LookupTable, Settings, Target, resolve_settings,
    };
    use crate::secret::SecretString;

    fn shared_host() -> (Host, ItemBody) {
        let mut clock = HlcClock::default();
        let mut body = ItemBody::new(ItemKind::Host, 1);
        let host = Host {
            label: "db".into(),
            address: "db.example".into(),
            username: Some("deploy".into()),
            ..Host::default()
        };
        host.apply_to(&mut body, &mut clock, DeviceId::new());
        (Host::try_from(&body).unwrap(), body)
    }

    fn resolve(host: &Host, table: &LookupTable) -> ResolvedHost {
        resolve_settings(
            &Target::of(host),
            &Settings::from_host(host),
            table,
            None,
            &GlobalDefaults::default(),
        )
    }

    // T-07 (unit): the override's username wins for its owner only; provenance
    // says "your override"; without the override the shared value stays.
    #[test]
    fn t07_override_username() {
        let (host, _) = shared_host();
        let host_id = ItemId::new();
        let table = LookupTable::default();

        // Alice: no override.
        let alice = resolve(&host, &table);
        assert_eq!(alice.username.as_deref(), Some("deploy"));
        assert_eq!(alice.source(SettingKey::Username), &Source::Host);

        // Bob: his override.
        let item = ItemId::new();
        let mut o = CredentialOverride::new(host_id);
        o.username = Some("bob".into());
        let layer = OverrideLayer::new(item, &o);
        let mut bob = resolve(&host, &table);
        apply_override(&mut bob, &layer, &table);
        assert_eq!(bob.username.as_deref(), Some("bob"));
        assert_eq!(bob.source(SettingKey::Username), &Source::Override { item });
        assert_eq!(
            bob.source(SettingKey::Username).to_string(),
            "your override"
        );
        // Untouched credentials keep their source.
        assert_eq!(bob.password, None);
        assert_eq!(bob.port, 22);
    }

    #[test]
    fn identity_and_password_on_the_override() {
        let (host, _) = shared_host();
        let mut table = LookupTable::default();
        let ident = ItemId::new();
        let key = ItemId::new();
        table.identities.insert(
            ident,
            IdentityNode {
                label: "mine".into(),
                username: "bob-id".into(),
                has_password: true,
                key_id: Some(key),
            },
        );
        let item = ItemId::new();
        let mut o = CredentialOverride::new(ItemId::new());
        o.identity_id = Some(ident);
        let mut r = resolve(&host, &table);
        apply_override(&mut r, &OverrideLayer::new(item, &o), &table);
        assert_eq!(r.identity_id, Some(ident));
        assert_eq!(r.username.as_deref(), Some("bob-id"));
        assert_eq!(r.key_id, Some(key));
        assert_eq!(
            r.password,
            Some(SecretOrigin {
                source: Source::Override { item },
                identity: Some(ident)
            })
        );
        // An inline password and user beat the override's identity.
        o.username = Some("bob".into());
        o.password = Some(SecretString::from("pw"));
        let mut r = resolve(&host, &table);
        apply_override(&mut r, &OverrideLayer::new(item, &o), &table);
        assert_eq!(r.username.as_deref(), Some("bob"));
        assert_eq!(r.password.as_ref().unwrap().identity, None);
        // A missing identity is a warning, not a credential.
        o.identity_id = Some(ItemId::new());
        o.username = None;
        o.password = None;
        let mut r = resolve(&host, &table);
        apply_override(&mut r, &OverrideLayer::new(item, &o), &table);
        assert_eq!(r.username.as_deref(), Some("deploy"));
        assert!(
            r.warnings
                .iter()
                .any(|w| matches!(w, ResolveWarning::MissingIdentity(_)))
        );
    }

    #[test]
    fn pick_is_deterministic() {
        let host = ItemId::new();
        let o = CredentialOverride::new(host);
        let a = OverrideLayer::new(ItemId::from_bytes([1; 16]), &o);
        let b = OverrideLayer::new(ItemId::from_bytes([2; 16]), &o);
        let other = OverrideLayer::new(
            ItemId::from_bytes([0; 16]),
            &CredentialOverride::new(ItemId::new()),
        );
        let all = [b.clone(), other, a.clone()];
        assert_eq!(pick_override(host, &all), Some(&a));
        assert_eq!(pick_override(ItemId::new(), &all), None);
    }
}
