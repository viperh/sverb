//! M2-02: identities (SPEC §4.4, §9.3, §13.4).
//!
//! An [`Identity`] is reusable credentials: many hosts (directly, or through a
//! group's or the vault's defaults) reference one identity, and editing it changes
//! every referencing host **through resolution**, never by copying (`resolve.rs`).
//!
//! - [`hosts_referencing`]: the "used by N hosts" count of the Keychain view and
//!   the delete dialog. A host counts when its **resolved** identity is this one, so
//!   hosts that inherit it from a group count too ([`IdentityUsage::inherited`]).
//! - [`check_identity_vault`]: an identity may only be referenced from its own vault
//!   (§4.12, §13.4); a cross-vault reference is rejected on save.
//! - [`InlineConversion`]: "Convert to inline credentials on those hosts" when an
//!   identity is deleted. It copies exactly the credentials a host took from the
//!   identity (by comparing its resolution with and without the identity), so the
//!   host connects the same way afterwards.
//! - [`auth_summary`]: `password` / `key: <label>` / `password + key` for lists.

use super::{Host, Identity, ItemId, ValidationError, VaultId};
use crate::resolve::{ResolvedHost, SettingKey, Source};
use crate::secret::SecretString;

/// The message of a cross-vault identity reference (§13.4).
pub const CROSS_VAULT_MESSAGE: &str =
    "this identity belongs to another vault; pick one from the host's vault";

/// Which hosts use an identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityUsage {
    /// Hosts that reference it themselves (`host.identity_id`).
    pub direct: Vec<ItemId>,
    /// Hosts that inherit it (a group's or the vault's `defaults.identity_id`).
    pub inherited: Vec<ItemId>,
}

impl IdentityUsage {
    /// Every host using the identity.
    pub fn total(&self) -> usize {
        self.direct.len() + self.inherited.len()
    }

    /// No host uses it.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// All hosts, direct ones first.
    pub fn hosts(&self) -> impl Iterator<Item = ItemId> + '_ {
        self.direct.iter().chain(&self.inherited).copied()
    }

    /// `used by 3 hosts (2 direct, 1 via group)` / `used by 1 host` / `not used`.
    pub fn describe(&self) -> String {
        let n = self.total();
        if n == 0 {
            return "not used by any host".to_owned();
        }
        let hosts = if n == 1 { "host" } else { "hosts" };
        if self.inherited.is_empty() {
            return format!("used by {n} {hosts}");
        }
        if self.direct.is_empty() {
            return format!("used by {n} {hosts} (via group)");
        }
        format!(
            "used by {n} {hosts} ({} direct, {} via group)",
            self.direct.len(),
            self.inherited.len()
        )
    }
}

/// The hosts whose **resolved** identity is `identity`, split by whether the host
/// sets it itself or inherits it from a group / the vault defaults. `resolved`
/// pairs each host id with its resolution (`resolve::resolve_settings`).
pub fn hosts_referencing<'a>(
    identity: ItemId,
    resolved: impl IntoIterator<Item = (ItemId, &'a ResolvedHost)>,
) -> IdentityUsage {
    let mut usage = IdentityUsage::default();
    for (host, r) in resolved {
        if r.identity_id != Some(identity) {
            continue;
        }
        if matches!(r.source(SettingKey::IdentityId), Source::Host) {
            usage.direct.push(host);
        } else {
            usage.inherited.push(host);
        }
    }
    usage.direct.sort();
    usage.inherited.sort();
    usage
}

/// `password`, `key: <label>`, `password + key` or `none` (the Identities list).
pub fn auth_summary(has_password: bool, key: Option<&str>) -> String {
    match (has_password, key) {
        (true, Some(_)) => "password + key".to_owned(),
        (true, None) => "password".to_owned(),
        (false, Some(k)) => format!("key: {k}"),
        (false, None) => "none".to_owned(),
    }
}

/// An identity referenced from an item of `vault` must live in the same vault
/// (§13.4). `identity_vault` looks up the vault of a live identity; a reference to a
/// missing identity passes (it resolves as `None`, §12.4).
///
/// # Errors
/// A [`ValidationError`] on `field` (`identity_id`) with [`CROSS_VAULT_MESSAGE`].
pub fn check_identity_vault(
    field: &str,
    vault: VaultId,
    identity: Option<ItemId>,
    identity_vault: impl Fn(ItemId) -> Option<VaultId>,
) -> Result<(), ValidationError> {
    match identity.and_then(identity_vault) {
        Some(v) if v != vault => Err(ValidationError::new(field, CROSS_VAULT_MESSAGE)),
        _ => Ok(()),
    }
}

/// An identity's own rules: it needs a label.
///
/// # Errors
/// The failing fields.
pub fn validate_identity(identity: &Identity) -> Result<(), Vec<ValidationError>> {
    if identity.label.trim().is_empty() {
        return Err(vec![ValidationError::new(
            "label",
            "an identity needs a label",
        )]);
    }
    Ok(())
}

/// What "convert to inline credentials" writes on one host before the identity
/// is deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InlineConversion {
    /// Set the inline `username` to this.
    pub username: Option<String>,
    /// Copy the identity's password into the inline `password`.
    pub copy_password: bool,
    /// Set the inline `key_id` to this.
    pub key_id: Option<ItemId>,
    /// Clear `host.identity_id` (it points at the deleted identity).
    pub clear_identity: bool,
}

impl InlineConversion {
    /// Nothing to write.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Apply to the typed host (`identity` supplies the password).
    pub fn apply(&self, host: &mut Host, identity: &Identity) {
        if let Some(u) = &self.username {
            host.username = Some(u.clone());
        }
        if self.copy_password {
            host.password = identity
                .password
                .as_ref()
                .map(|p| SecretString::from(p.expose()));
        }
        if let Some(k) = self.key_id {
            host.key_id = Some(k);
        }
        if self.clear_identity {
            host.identity_id = None;
        }
    }
}

/// The inline credentials that keep a host's resolved credentials unchanged once
/// `identity` is gone: `before` is its resolution with the identity, `after`
/// without it. Only what changes is copied (a host's own username override stays).
pub fn inline_conversion(
    identity: ItemId,
    host_identity: Option<ItemId>,
    before: &ResolvedHost,
    after: &ResolvedHost,
) -> InlineConversion {
    InlineConversion {
        username: before
            .username
            .clone()
            .filter(|_| before.username != after.username),
        copy_password: before
            .password
            .as_ref()
            .is_some_and(|p| p.identity == Some(identity)),
        key_id: before.key_id.filter(|_| before.key_id != after.key_id),
        clear_identity: host_identity == Some(identity),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::{DeviceId, Group, HlcClock, ItemBody, ItemKind};
    use crate::resolve::{GlobalDefaults, LookupTable, Settings, Target, resolve_settings};
    use crate::search::{ItemIndex, Query, Scope};

    fn id(n: u8) -> ItemId {
        let mut b = [0; 16];
        b[15] = n;
        ItemId::from_bytes(b)
    }

    fn vault(n: u8) -> VaultId {
        VaultId::from_bytes([n; 16])
    }

    fn identity(user: &str, password: Option<&str>, key: Option<ItemId>) -> Identity {
        Identity {
            label: "ops".into(),
            username: user.into(),
            password: password.map(SecretString::from),
            key_id: key,
            read_only: false,
        }
    }

    fn resolve(
        own: &Settings,
        group: Option<ItemId>,
        lookup: &LookupTable,
    ) -> crate::resolve::ResolvedHost {
        let target = Target {
            label: "h".into(),
            address: "h.example".into(),
            group_id: group,
        };
        resolve_settings(&target, own, lookup, None, &GlobalDefaults::default())
    }

    fn table(ident: ItemId, i: &Identity, group: ItemId) -> LookupTable {
        let mut t = LookupTable::default();
        t.insert_identity(ident, i);
        let g = Group {
            name: "prod".into(),
            defaults: crate::model::HostDefaults {
                identity_id: Some(ident),
                ..Default::default()
            },
            ..Group::default()
        };
        t.insert_group(group, vault(1), &g);
        t
    }

    // M2-02 T-03 (the count): 2 direct, 1 via group.
    #[test]
    fn usage_counts_direct_and_group_inherited_hosts() {
        let ident = id(1);
        let group = id(2);
        let t = table(ident, &identity("ops", None, None), group);
        let direct = Settings {
            identity_id: Some(ident),
            ..Settings::default()
        };
        let r1 = resolve(&direct, None, &t);
        let r2 = resolve(&direct, Some(group), &t);
        let r3 = resolve(&Settings::default(), Some(group), &t);
        let r4 = resolve(&Settings::default(), None, &t);
        let usage = hosts_referencing(
            ident,
            [(id(11), &r1), (id(12), &r2), (id(13), &r3), (id(14), &r4)],
        );
        assert_eq!(usage.direct, [id(11), id(12)]);
        assert_eq!(usage.inherited, [id(13)]);
        assert_eq!(usage.total(), 3);
        assert_eq!(usage.describe(), "used by 3 hosts (2 direct, 1 via group)");
        assert_eq!(IdentityUsage::default().describe(), "not used by any host");
    }

    #[test]
    fn a_host_identity_shadows_the_group_one() {
        let ident = id(1);
        let other = id(3);
        let group = id(2);
        let mut t = table(ident, &identity("ops", None, None), group);
        t.insert_identity(other, &identity("dev", None, None));
        let own = Settings {
            identity_id: Some(other),
            ..Settings::default()
        };
        let r = resolve(&own, Some(group), &t);
        assert!(hosts_referencing(ident, [(id(11), &r)]).is_empty());
        assert_eq!(hosts_referencing(other, [(id(11), &r)]).direct, [id(11)]);
    }

    #[test]
    fn auth_summaries() {
        assert_eq!(auth_summary(true, None), "password");
        assert_eq!(auth_summary(false, Some("laptop")), "key: laptop");
        assert_eq!(auth_summary(true, Some("laptop")), "password + key");
        assert_eq!(auth_summary(false, None), "none");
    }

    // M2-02 T-07
    #[test]
    fn cross_vault_identity_reference_is_rejected() {
        let ident = id(1);
        let lookup = |i: ItemId| (i == ident).then_some(vault(2));
        let err = check_identity_vault("identity_id", vault(1), Some(ident), lookup).unwrap_err();
        assert_eq!(err.field, "identity_id");
        assert_eq!(err.message, CROSS_VAULT_MESSAGE);
        assert!(check_identity_vault("identity_id", vault(2), Some(ident), lookup).is_ok());
        assert!(check_identity_vault("identity_id", vault(1), None, lookup).is_ok());
        // A dangling reference resolves as `None` (§12.4) and is not a vault error.
        assert!(check_identity_vault("identity_id", vault(1), Some(id(9)), lookup).is_ok());
    }

    #[test]
    fn an_identity_needs_a_label() {
        let mut i = identity("ops", None, None);
        assert!(validate_identity(&i).is_ok());
        i.label = "  ".into();
        assert_eq!(validate_identity(&i).unwrap_err()[0].field, "label");
    }

    // M2-02 T-04 (the conversion rule)
    #[test]
    fn conversion_copies_what_the_identity_supplied() {
        let ident = id(1);
        let key = id(5);
        let group = id(2);
        let i = identity("ops", Some("pw"), Some(key));
        let with = table(ident, &i, group);
        let mut without = with.clone();
        without.identities.remove(&ident);

        // Direct reference, no inline fields: everything is copied.
        let own = Settings {
            identity_id: Some(ident),
            ..Settings::default()
        };
        let conv = inline_conversion(
            ident,
            Some(ident),
            &resolve(&own, None, &with),
            &resolve(&own, None, &without),
        );
        assert_eq!(
            conv,
            InlineConversion {
                username: Some("ops".into()),
                copy_password: true,
                key_id: Some(key),
                clear_identity: true,
            }
        );
        let mut host = Host {
            identity_id: Some(ident),
            ..Host::default()
        };
        conv.apply(&mut host, &i);
        assert_eq!(host.username.as_deref(), Some("ops"));
        assert_eq!(host.password.as_ref().map(|p| p.expose()), Some("pw"));
        assert_eq!(host.key_id, Some(key));
        assert_eq!(host.identity_id, None);

        // Inherited, with the host's own username override: that stays.
        let own = Settings {
            username: Some("root".into()),
            ..Settings::default()
        };
        let conv = inline_conversion(
            ident,
            None,
            &resolve(&own, Some(group), &with),
            &resolve(&own, Some(group), &without),
        );
        assert_eq!(conv.username, None);
        assert!(conv.copy_password);
        assert_eq!(conv.key_id, Some(key));
        assert!(!conv.clear_identity);
    }

    // M2-02 T-08: the identity's password never reaches the search index.
    #[test]
    fn identity_password_is_not_indexed() {
        const CANARY: &str = "CANARY-7f3a9c-pass";
        let mut clock = HlcClock::default();
        let device = DeviceId::from_bytes([1; 16]);
        let mut body = ItemBody::new(ItemKind::Identity, 1);
        Identity {
            label: "deploy".into(),
            username: "deployer".into(),
            password: Some(SecretString::from(CANARY)),
            key_id: None,
            read_only: false,
        }
        .apply_to(&mut body, &mut clock, device);
        let mut index = ItemIndex::build([(id(1), vault(1), &body)]);
        let snap = index.snapshot();
        // Label and username are searchable …
        assert_eq!(snap.query(&Query::parse("deploy"), Scope::All).len(), 1);
        assert_eq!(snap.query(&Query::parse("deployer"), Scope::All).len(), 1);
        // … the password is not, in any field of any entry.
        assert!(snap.query(&Query::parse(CANARY), Scope::All).is_empty());
        assert!(snap.query(&Query::parse("CANARY"), Scope::All).is_empty());
        for e in snap.entries() {
            for text in [&e.label, &e.address, &e.user, &e.search_text, &e.body_text] {
                assert!(!text.contains(CANARY));
            }
        }
    }
}
