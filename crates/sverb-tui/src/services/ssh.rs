//! M1-13: SSH connections from the TUI.
//!
//! [`VaultHostResolver`] is the SSH connector's
//! [`HostResolver`]: on every connect and reconnect it
//! reads the saved host from the vault, resolves it through its group chain and vault
//! defaults (`sverb_core::resolve`, M2-01), reads the secrets that resolution only
//! points at (the password's [`SecretOrigin`]), and builds the connector's
//! [`SshTarget`]. Unsaved targets (quick connect) resolve from the spec and the config.
//!
//! M1-14: the resolver also reads the configured key's material (private key, stored
//! passphrase, attached certificates) for the authentication chain, and
//! [`ssh_connector`] authenticates with [`ChainAuthenticator`] and the system agent.
//! [`save_key_changes`] stores a passphrase typed into an auth prompt (only after the
//! login succeeded). [`import_key_file`] is the host form's key-file import, routed
//! through the keychain since M2-03.
//!
//! [`ssh_connector`] builds the connector. M1-15: host keys are verified against the
//! known hosts in the vault (`services::known_hosts`) with `ssh.host_key_policy`.
//! `SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1` replaces that with an accept-anything verifier
//! for **tests and development only** (an error is logged for every connection).

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use sverb_conn::{
    SshSpec,
    ssh::{
        AuthMaterial, HostResolver, InsecureAcceptAnyHostKey, SshConnector, SshError, SshTarget,
        local_user, resolve_spec,
    },
};
// M2-06
use sverb_conn::proxy::{COMMAND_FIELD, ProxyConfig, ValueOrigin};
// M1-14
use sverb_conn::{
    agent_client::SystemAgent,
    ssh::{ChainAuthenticator, KeyMaterial, allows_ssh_rsa},
};
use sverb_core::{
    config::Config,
    model::{Certificate, Group, Host, Identity, ItemId, ItemKind, Key, Snippet},
    resolve::{LookupTable, ResolvedHost, SecretOrigin, Source},
    secret::SecretString,
};
use tracing::{debug, warn};

use super::vault::{VaultService, items::Loaded};

/// The env var that enables the insecure accept-any host-key verifier.
pub const INSECURE_HOST_KEYS_ENV: &str = "SVERB_INSECURE_ACCEPT_ANY_HOST_KEY";

/// Resolves saved hosts from the vault (see the module docs).
#[derive(Debug, Clone)]
pub struct VaultHostResolver {
    vault: Option<VaultService>,
    config: Arc<Config>,
}

impl VaultHostResolver {
    /// A resolver over `vault` (`None`: only unsaved targets resolve) and `config`.
    pub fn new(vault: Option<VaultService>, config: Arc<Config>) -> Self {
        Self { vault, config }
    }
}

fn settings_err(msg: &str) -> SshError {
    SshError::Settings(msg.to_owned())
}

fn copy(secret: &SecretString) -> SecretString {
    SecretString::from(secret.expose())
}

/// The secret a [`SecretOrigin`] points at.
fn password_at(
    origin: &SecretOrigin,
    host: &Host,
    host_vault: sverb_core::model::VaultId,
    items: &[Loaded],
) -> Option<SecretString> {
    let body = |id: ItemId| items.iter().find(|i| i.id == id).map(|i| &i.body);
    if let Some(identity) = origin.identity {
        return Identity::try_from(body(identity)?)
            .ok()?
            .password
            .as_ref()
            .map(copy);
    }
    match &origin.source {
        Source::Host => host.password.as_ref().map(copy),
        Source::Group { id, .. } => Group::try_from(body(*id)?)
            .ok()?
            .defaults
            .password
            .as_ref()
            .map(copy),
        Source::VaultDefaults => items
            .iter()
            .filter(|i| i.vault == host_vault && i.body.kind == ItemKind::Group)
            .filter_map(|i| Group::try_from(&i.body).ok())
            .find(|g| g.is_vault_defaults)
            .and_then(|g| g.defaults.password.as_ref().map(copy)),
        // M5-02: the inline password of the user's credential override.
        Source::Override { item } => sverb_core::model::CredentialOverride::try_from(body(*item)?)
            .ok()?
            .password
            .as_ref()
            .map(copy),
        _ => None,
    }
}

// M2-09
/// The built-in snippet variables of a resolved target (`{{date}}`: today, local).
pub fn startup_builtins(t: &SshTarget) -> sverb_core::snippet::Builtins {
    sverb_core::snippet::Builtins {
        label: t.label.clone(),
        address: t.address.clone(),
        user: t.username.clone(),
        date: sverb_conn::ssh::exec::snippets::today(),
    }
}

/// The connector's target from the domain resolution, the secrets and the config.
pub fn target_from(
    host_id: ItemId,
    r: &ResolvedHost,
    password: Option<SecretString>,
    startup_input: Option<String>,
    config: &Config,
) -> SshTarget {
    SshTarget {
        host_id: Some(host_id),
        label: if r.label.is_empty() {
            r.address.clone()
        } else {
            r.label.clone()
        },
        address: r.address.clone(),
        port: r.port,
        username: r.username.clone().or_else(local_user).unwrap_or_default(),
        auth: AuthMaterial {
            password,
            key_id: r.key_id,
            identity_id: r.identity_id,
            // M1-14: the key's material is read by the resolver (`key_material`).
            key: None,
            max_attempts: config.ssh.max_auth_attempts,
            use_system_agent: config.ssh.use_system_agent,
            allow_ssh_rsa: r.algorithms.as_ref().is_some_and(allows_ssh_rsa),
        },
        jump_chain: r.jump_chain.clone(),
        proxy_configured: r.proxy.is_some(),
        // M2-06: filled in by the resolver (`proxy_config`), which reads the password.
        proxy: None,
        env: r.env.clone(),
        keepalive_secs: r.keepalive_secs,
        charset: Some(r.charset.clone()),
        backspace: r.backspace,
        color_scheme: Some(r.color_scheme.clone()),
        algorithms: r.algorithms.clone().unwrap_or_default(),
        agent_forwarding: r.agent_forwarding,
        agent_source: r.agent_source,
        // M2-07: filled in by the resolver (`agent_origin`), which reads the stamps.
        agent_origin: sverb_conn::proxy::ValueOrigin::default(),
        startup_snippet_id: r.startup_snippet_id,
        startup_input,
        request_pty_for_exec: r.request_pty_for_exec,
        term: config.terminal.term.clone(),
        connect_timeout: Duration::from_secs(u64::from(config.ssh.connect_timeout_secs.max(1))),
    }
}

#[async_trait]
impl HostResolver for VaultHostResolver {
    async fn resolve(&self, spec: &SshSpec) -> Result<SshTarget, SshError> {
        let Some(host_id) = spec.host_id else {
            return Ok(resolve_spec(spec, &self.config, local_user));
        };
        let ops = self
            .vault
            .as_ref()
            .and_then(VaultService::item_ops)
            .ok_or_else(|| settings_err("the vault is locked"))?;
        let items = ops
            .list(&[
                ItemKind::Host,
                ItemKind::Group,
                ItemKind::Identity,
                ItemKind::Snippet,
                // M1-14
                ItemKind::Key,
                ItemKind::Certificate,
                // M5-02
                ItemKind::CredentialOverride,
            ])
            .await
            .map_err(|e| SshError::Settings(e.to_string()))?;
        let host_item = items
            .iter()
            .find(|i| i.id == host_id)
            .ok_or_else(|| settings_err("the host no longer exists"))?;
        let host =
            Host::try_from(&host_item.body).map_err(|e| SshError::Settings(e.to_string()))?;
        let mut lookup = LookupTable::default();
        for item in &items {
            match item.body.kind {
                ItemKind::Group => {
                    if let Ok(g) = Group::try_from(&item.body) {
                        lookup.insert_group(item.id, item.vault, &g);
                    }
                }
                ItemKind::Identity => {
                    if let Ok(i) = Identity::try_from(&item.body) {
                        lookup.insert_identity(item.id, &i);
                    }
                }
                _ => {}
            }
        }
        let mut resolved = sverb_core::resolve::resolve(
            &host,
            &lookup,
            lookup.defaults_of(host_item.vault),
            &self.config,
        );
        // M5-02: this user's own credentials for a shared host (§13.4).
        if let Some(layer) = crate::services::vault::shared::override_for(
            host_id,
            &items,
            ops.vault().personal_vault(),
        ) {
            sverb_core::resolve::overrides::apply_override(&mut resolved, &layer, &lookup);
        }
        let password = resolved
            .password
            .as_ref()
            .and_then(|origin| password_at(origin, &host, host_item.vault, &items));
        let mut target = target_from(host_id, &resolved, password, None, &self.config);
        // M2-09: the startup snippet, Paste & execute, with its defaults and this host's
        // built-ins; typed once the shell prints (or after 500 ms). One with variables
        // without defaults is asked for by the UI when the pane connects.
        target.startup_input = resolved.startup_snippet_id.and_then(|id| {
            let item = items.iter().find(|i| i.id == id)?;
            let snippet = Snippet::try_from(&item.body).ok()?;
            debug!(snippet = %id.short(), "startup snippet");
            sverb_core::snippet::startup(&snippet, &startup_builtins(&target)).ready()
        });
        // M1-14
        target.auth.key = resolved.key_id.and_then(|id| key_material(id, &items));
        // M2-06
        target.proxy = proxy_config(&resolved, host_item, &items, ops.vault().device_id());
        // M2-07
        target.agent_origin = agent_origin(&resolved, host_item, &items, ops.vault().device_id());
        Ok(target)
    }
}

// M2-06
/// The resolved proxy with its password, read from the item that defines it (the
/// host, a group or the vault defaults: provenance). For a ProxyCommand the origin
/// names that item and the device of the `proxy.command` stamp (§17.1 approval).
pub fn proxy_config(
    r: &ResolvedHost,
    host_item: &Loaded,
    items: &[Loaded],
    this_device: sverb_core::model::DeviceId,
) -> Option<ProxyConfig> {
    use sverb_core::{model::GROUP_DEFAULTS_PREFIX, resolve::SettingKey};
    r.proxy.as_ref()?;
    let groups = || {
        items
            .iter()
            .filter(|i| i.vault == host_item.vault && i.body.kind == ItemKind::Group)
    };
    let (item, prefix) = match r.source(SettingKey::Proxy) {
        Source::Host => (host_item, ""),
        Source::Group { id, .. } => (items.iter().find(|i| i.id == *id)?, GROUP_DEFAULTS_PREFIX),
        Source::VaultDefaults => (
            groups().find(|i| Group::try_from(&i.body).is_ok_and(|g| g.is_vault_defaults))?,
            GROUP_DEFAULTS_PREFIX,
        ),
        _ => return None,
    };
    let proxy = if prefix.is_empty() {
        Host::try_from(&item.body).ok()?.proxy?
    } else {
        Group::try_from(&item.body).ok()?.defaults.proxy?
    };
    let origin = ValueOrigin {
        item_id: Some(item.id),
        written_by: item
            .body
            .get_stamped(&format!("{prefix}{COMMAND_FIELD}"))
            .map(|s| s.device),
        this_device: Some(this_device),
    };
    Some(ProxyConfig::from_model(&proxy, origin))
}

// M2-07
/// Where the resolved agent settings come from (§17.1): the item defining
/// `agent_source` (or, when that one was typed here, `agent_forwarding`) and the
/// device of that field's stamp.
pub fn agent_origin(
    r: &ResolvedHost,
    host_item: &Loaded,
    items: &[Loaded],
    this_device: sverb_core::model::DeviceId,
) -> ValueOrigin {
    use sverb_core::{model::GROUP_DEFAULTS_PREFIX, resolve::SettingKey};
    let origin_of = |key: SettingKey, field: &str| {
        let (item, prefix) = match r.source(key) {
            Source::Host => (host_item, ""),
            Source::Group { id, .. } => {
                (items.iter().find(|i| i.id == *id)?, GROUP_DEFAULTS_PREFIX)
            }
            Source::VaultDefaults => (
                items
                    .iter()
                    .filter(|i| i.vault == host_item.vault && i.body.kind == ItemKind::Group)
                    .find(|i| Group::try_from(&i.body).is_ok_and(|g| g.is_vault_defaults))?,
                GROUP_DEFAULTS_PREFIX,
            ),
            _ => return None,
        };
        Some(ValueOrigin {
            item_id: Some(item.id),
            written_by: item
                .body
                .get_stamped(&format!("{prefix}{field}"))
                .map(|s| s.device),
            this_device: Some(this_device),
        })
    };
    let source = origin_of(SettingKey::AgentSource, "agent_source");
    let forwarding = origin_of(SettingKey::AgentForwarding, "agent_forwarding");
    match (source, forwarding) {
        (Some(s), _) if !s.typed_here() => s,
        (_, Some(f)) if !f.typed_here() => f,
        (Some(s), _) => s,
        (None, Some(f)) => f,
        (None, None) => ValueOrigin {
            item_id: Some(host_item.id),
            written_by: Some(this_device),
            this_device: Some(this_device),
        },
    }
}

// M1-14
/// The configured key's material: the private key, its stored passphrase and the
/// certificates attached to it (`certificate_ids`, and Certificate items naming the
/// key). `None` when the key item is missing or unreadable.
pub fn key_material(key_id: ItemId, items: &[Loaded]) -> Option<KeyMaterial> {
    let item = items.iter().find(|i| i.id == key_id)?;
    let key = match Key::try_from(&item.body) {
        Ok(key) => key,
        Err(err) => {
            debug!(key = %key_id.short(), %err, "configured key unreadable");
            return None;
        }
    };
    let certificates = items
        .iter()
        .filter(|i| i.body.kind == ItemKind::Certificate)
        .filter_map(|i| Certificate::try_from(&i.body).ok().map(|c| (i.id, c)))
        .filter(|(id, c)| key.certificate_ids.contains(id) || c.key_id == Some(key_id))
        .map(|(_, c)| c.cert)
        .collect();
    Some(KeyMaterial {
        key_id: Some(key_id),
        label: key.label.clone(),
        // M2-03: an agent / hardware reference key hands its public line instead; the
        // chain then asks the system agent to sign with that key only
        // (`sverb_conn::ssh::auth::agent_reference`).
        private_key: if key.is_agent_ref() {
            SecretString::from(key.public_key.trim())
        } else {
            copy(&key.private_key)
        },
        passphrase: key.passphrase.as_ref().map(copy),
        certificates,
    })
}

// M1-14
/// Store a passphrase typed into an auth prompt on its Key item: only `passphrase`
/// changes (stamped by the item writer). Called for `ItemEffect::Save` of a Key, which
/// the auth flow emits only after the login succeeded.
///
/// # Errors
/// As [`ItemOps::save`](super::vault::items::ItemOps::save); a change other than
/// `passphrase` is invalid.
pub async fn save_key_changes(
    ops: &super::vault::items::ItemOps,
    id: Option<ItemId>,
    changes: crate::widgets::form::FieldChanges,
) -> Result<super::vault::items::Written, super::vault::items::ItemError> {
    use crate::widgets::form::FieldValue;
    use sverb_core::model::ValidationError;
    let Some(id) = id else {
        return Err(super::vault::items::ItemError::Invalid(vec![
            ValidationError::new("item", "keys are created in the keychain"),
        ]));
    };
    ops.save(ItemKind::Key, Some(id), None, move |body, clock, device| {
        let mut key =
            Key::try_from(&*body).map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
        for (field, value) in &changes.0 {
            match (field.as_str(), value) {
                ("passphrase", FieldValue::Secret(s)) => {
                    key.passphrase = (!s.is_empty()).then(|| SecretString::from(s.expose()));
                }
                _ => {
                    return Err(vec![ValidationError::new(
                        field.as_str(),
                        "only the passphrase can be changed here",
                    )]);
                }
            }
        }
        key.apply_to(body, clock, device);
        Ok(())
    })
    .await
}

// M1-14, M2-03
/// The host form's key-file import (M1-14 §2.6), now through the keychain
/// (`sverb_core::keychain::import`): every keychain format, with the comment (else the
/// file name) as the label. Encrypted keys other than OpenSSH need the Keychain view
/// (it asks for the passphrase).
///
/// # Errors
/// The file can't be read or isn't a key the keychain reads.
pub fn import_key_file(path: &str) -> Result<Key, sverb_core::keychain::KeychainError> {
    use sverb_core::keychain::import::{ImportOptions, file_stem, import_file};
    let k = import_file(path, None, ImportOptions::default())?;
    let label = k.suggested_label(file_stem(path).as_deref());
    Ok(k.into_key(label))
}

/// The SSH connector for the TUI.
pub fn ssh_connector(vault: Option<VaultService>, config: Arc<Config>) -> SshConnector {
    ssh_connector_with_events(vault, config, None)
}

// M1-15
/// [`ssh_connector`] whose known-hosts store reports saves (the "Added host key"
/// toasts) on `events`.
pub fn ssh_connector_with_events(
    vault: Option<VaultService>,
    config: Arc<Config>,
    events: Option<super::EventSender>,
) -> SshConnector {
    // M1-15: the known-hosts verifier.
    let verifier = super::known_hosts::verifier(vault.clone(), &config, events);
    // M3-07: connection sharing follows `ssh.multiplex` (default on).
    let multiplex = config.ssh.multiplex;
    // M2-10: ProxyCommand / system-agent checks against this device's
    // `local_approvals` (replaces the M2-06 `StampApprovals` default).
    let approvals = vault.as_ref().map(|v| v.store().device_approvals());
    let connector = SshConnector::new(Arc::new(VaultHostResolver::new(vault, config)))
        .with_multiplex(multiplex)
        // M1-14: cert → key → system agent (IdentitiesOnly) → password → kbd-interactive.
        .with_authenticator(Arc::new(
            ChainAuthenticator::new().with_agent(Arc::new(SystemAgent)),
        ));
    // M2-10
    let connector = match approvals {
        Some(a) => connector.with_local_approvals(a),
        None => connector,
    };
    if std::env::var(INSECURE_HOST_KEYS_ENV).is_ok_and(|v| v == "1") {
        // M1-15: tests and development only; the verifier also warns per connection.
        warn!(
            "{INSECURE_HOST_KEYS_ENV}=1: host keys are NOT verified; this disables \
             protection against man-in-the-middle attacks (tests and development only)"
        );
        connector.with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
    } else {
        connector.with_verifier(Arc::new(verifier))
    }
}

// M1-14
/// The host form's key-file field (task §2.6): a path to a private key (any keychain format),
/// imported into a new Key item when the host is saved.
pub const KEY_FILE_FIELD: &str = "key_file";

// M1-14
/// When `changes` carry a [`KEY_FILE_FIELD`] path: import that key file as a new Key
/// item and replace the change with `key_id` pointing at it. Returns the written Key
/// (for the search index), `None` without a path.
///
/// # Errors
/// [`ItemError::Invalid`](super::vault::items::ItemError::Invalid) on the `key_file`
/// field when the file can't be read or isn't a key; storage errors.
pub async fn import_key_file_change(
    ops: &super::vault::items::ItemOps,
    changes: &mut crate::widgets::form::FieldChanges,
) -> Result<Option<super::vault::items::Written>, super::vault::items::ItemError> {
    use crate::widgets::form::FieldValue;
    let Some(pos) = changes.0.iter().position(|(k, _)| k == KEY_FILE_FIELD) else {
        return Ok(None);
    };
    let (_, value) = changes.0.remove(pos);
    let FieldValue::Text(path) = value else {
        return Ok(None);
    };
    if path.trim().is_empty() {
        return Ok(None);
    }
    let key = import_key_file(&path).map_err(|e| {
        super::vault::items::ItemError::Invalid(vec![sverb_core::model::ValidationError::new(
            KEY_FILE_FIELD,
            e.to_string(),
        )])
    })?;
    let written = ops
        .save(ItemKind::Key, None, None, move |body, clock, device| {
            key.apply_to(body, clock, device);
            Ok(())
        })
        .await?;
    changes.0.retain(|(k, _)| k != "key_id");
    changes
        .0
        .push(("key_id".to_owned(), FieldValue::Reference(Some(written.id))));
    Ok(Some(written))
}

// M1-14
/// Send the user's answer to an auth prompt to the session
/// (`SessionCmd::AuthAnswer`).
pub fn send_auth_answer(
    sessions: &mut super::sessions::SessionService,
    id: crate::app::SessionId,
    reply: crate::widgets::auth_prompt::AuthReply,
) {
    let outcome = sessions.command(id, sverb_conn::SessionCmd::AuthAnswer(reply.into_answer()));
    debug!(session = id.0, ?outcome, "auth answer sent");
}

// M1-14
/// Store a credential the user asked to save, after its login succeeded: the host's
/// inline `password` or the Key item's `passphrase` (only that field changes). A failure
/// is reported as an error toast of the session (`notify`).
pub fn save_credential(
    vault: Option<&VaultService>,
    req: crate::widgets::auth_prompt::SaveCredential,
    notify: impl Fn(crate::app::SessionId, sverb_conn::SessionEvent) + Send + 'static,
) {
    let fail = move |req: &crate::widgets::auth_prompt::SaveCredential, why: String| {
        notify(
            req.session,
            sverb_conn::SessionEvent::Error(sverb_core::error_report::ErrorReport::msg(format!(
                "Could not save the {} to the vault: {why}",
                req.noun()
            ))),
        );
    };
    let Some(ops) = vault.and_then(VaultService::item_ops) else {
        fail(&req, "the vault is locked".to_owned());
        return;
    };
    tokio::spawn(async move {
        let result = match req.kind {
            ItemKind::Key => save_key_changes(&ops, Some(req.item), req.changes()).await,
            _ => ops.save_host(Some(req.item), req.changes()).await,
        };
        match result {
            Ok(_) => debug!(item = %req.item.short(), field = req.field, "credential saved"),
            Err(err) => fail(&req, err.to_string()),
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sverb_core::resolve::{GlobalDefaults, Settings, Target, resolve_settings};

    use super::*;

    #[test]
    fn targets_carry_the_resolved_settings() {
        let host = Host {
            label: "db".into(),
            address: "10.0.0.5".into(),
            port: Some(2222),
            username: Some("deploy".into()),
            keepalive_secs: Some(0),
            env: vec![("FOO".into(), "bar".into())],
            ..Host::default()
        };
        let r = resolve_settings(
            &Target::of(&host),
            &Settings::from_host(&host),
            &LookupTable::default(),
            None,
            &GlobalDefaults::default(),
        );
        let id = ItemId::from_bytes([9; 16]);
        let t = target_from(
            id,
            &r,
            Some(SecretString::from("pw")),
            None,
            &Config::default(),
        );
        assert_eq!(t.host_id, Some(id));
        assert_eq!(
            (t.address.as_str(), t.port, t.username.as_str()),
            ("10.0.0.5", 2222, "deploy")
        );
        assert_eq!(t.keepalive_secs, 0);
        assert_eq!(t.env, host.env);
        assert!(t.is_utf8());
        assert_eq!(t.term, "xterm-256color");
        assert_eq!(t.auth.password.unwrap().expose(), "pw");
    }

    // M1-14
    #[test]
    fn saving_without_a_vault_reports_an_error() {
        use crate::widgets::{auth_prompt::SaveCredential, form::SecretValue};
        let seen = std::sync::Arc::new(seen_events::Seen::default());
        let s2 = std::sync::Arc::clone(&seen);
        save_credential(
            None,
            SaveCredential {
                session: crate::app::SessionId(9),
                item: ItemId::from_bytes([1; 16]),
                kind: ItemKind::Host,
                field: "password",
                secret: SecretValue::from("pw"),
            },
            move |id, ev| s2.push(id, ev),
        );
        let got = seen.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, crate::app::SessionId(9));
        assert!(matches!(
            &got[0].1,
            sverb_conn::SessionEvent::Error(r)
                if r.short == "Could not save the password to the vault: the vault is locked"
        ));
    }

    mod seen_events {
        #[derive(Default)]
        pub(super) struct Seen(
            std::sync::Mutex<Vec<(crate::app::SessionId, sverb_conn::SessionEvent)>>,
        );

        impl Seen {
            pub(super) fn push(&self, id: crate::app::SessionId, ev: sverb_conn::SessionEvent) {
                self.0.lock().unwrap().push((id, ev));
            }

            pub(super) fn take(&self) -> Vec<(crate::app::SessionId, sverb_conn::SessionEvent)> {
                std::mem::take(&mut *self.0.lock().unwrap())
            }
        }
    }

    // M2-06
    /// The proxy comes with its password from the item that defines it; a
    /// ProxyCommand's origin names that item and the device of its stamp.
    #[test]
    fn proxy_config_carries_password_and_origin() {
        use sverb_conn::proxy::ProxyConfig;
        use sverb_core::model::{
            DeviceId, HlcClock, ItemBody, Proxy, ProxyAuth, VaultId, current_schema,
        };
        let here = DeviceId::from_bytes([1; 16]);
        let other = DeviceId::from_bytes([2; 16]);
        let vault = VaultId::from_bytes([5; 16]);
        let mut clock = HlcClock::default();
        let loaded = |id: ItemId, kind: ItemKind, write: &dyn Fn(&mut ItemBody, &mut HlcClock)| {
            let mut body = ItemBody::new(kind, current_schema(kind));
            let mut c = HlcClock::default();
            write(&mut body, &mut c);
            Loaded { id, vault, body }
        };
        let resolve_with = |host: &Host, items: &[Loaded]| {
            let mut lookup = LookupTable::default();
            for i in items.iter().filter(|i| i.body.kind == ItemKind::Group) {
                lookup.insert_group(i.id, i.vault, &Group::try_from(&i.body).unwrap());
            }
            sverb_core::resolve::resolve(
                host,
                &lookup,
                lookup.defaults_of(vault),
                &Config::default(),
            )
        };

        // On the host, SOCKS5 with a password.
        let host = Host {
            address: "db".into(),
            proxy: Some(Proxy::Socks5 {
                addr: "proxy:1080".into(),
                auth: Some(ProxyAuth {
                    user: "alice".into(),
                    password: Some(SecretString::from("pw")),
                }),
            }),
            ..Host::default()
        };
        let host_id = ItemId::from_bytes([7; 16]);
        let item = loaded(host_id, ItemKind::Host, &|b, c| host.apply_to(b, c, here));
        let r = resolve_with(&host, std::slice::from_ref(&item));
        let Some(ProxyConfig::Socks5 {
            addr,
            auth: Some(a),
        }) = proxy_config(&r, &item, std::slice::from_ref(&item), here)
        else {
            panic!("socks5 expected");
        };
        assert_eq!(
            (addr.as_str(), a.user.as_str(), a.password_text()),
            ("proxy:1080", "alice", "pw")
        );

        // A ProxyCommand from a group, written by another device: the approval key is
        // the group (provenance) and the stamp names the other device.
        let group_id = ItemId::from_bytes([8; 16]);
        let group = Group {
            name: "prod".into(),
            defaults: sverb_core::model::HostDefaults {
                proxy: Some(Proxy::Command("nc %h %p".into())),
                ..Default::default()
            },
            ..Group::default()
        };
        let group_item = loaded(group_id, ItemKind::Group, &|b, c| {
            group.apply_to(b, c, other)
        });
        let member = Host {
            address: "db".into(),
            group_id: Some(group_id),
            ..Host::default()
        };
        let member_item = loaded(host_id, ItemKind::Host, &|b, c| member.apply_to(b, c, here));
        let items = [member_item, group_item];
        let r = resolve_with(&member, &items);
        let Some(ProxyConfig::Command { command, origin }) =
            proxy_config(&r, &items[0], &items, here)
        else {
            panic!("command expected");
        };
        assert_eq!(command, "nc %h %p");
        assert_eq!(origin.item_id, Some(group_id));
        assert_eq!(origin.written_by, Some(other));
        assert!(!origin.typed_here());
        let _ = &mut clock;
    }

    #[tokio::test]
    async fn unsaved_targets_resolve_without_a_vault() {
        let resolver = VaultHostResolver::new(None, Arc::new(Config::default()));
        let spec = SshSpec {
            host: "example.org".into(),
            port: 22,
            user: Some("me".into()),
            ..SshSpec::default()
        };
        let t = resolver.resolve(&spec).await.unwrap();
        assert_eq!(
            (t.address.as_str(), t.username.as_str()),
            ("example.org", "me")
        );
        // A saved host needs the vault.
        let saved = SshSpec {
            host_id: Some(ItemId::from_bytes([1; 16])),
            ..spec
        };
        let err = resolver.resolve(&saved).await.unwrap_err();
        assert_eq!(
            err.message(),
            "Could not load the host settings: the vault is locked"
        );
    }
}
