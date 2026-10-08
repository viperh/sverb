//! M1-07: the host form (SPEC §4.2, §8.6) on the shared form framework (M1-06).
//!
//! Sections: General, Credentials, Connection, Terminal, Forwards, Notes. Field keys
//! are the model's field names, so [`FieldChanges`] map one-to-one onto the [`Host`]
//! view ([`apply_changes`]); only changed fields are written, so an edit of the port
//! stamps only `port` (§4.1).
//!
//! Fields of features that have not landed are hidden by the [`HOST_FORM_FEATURES`]
//! registry (not by cfg flags): the tasks that implement them flip their entry.

use std::sync::Arc;

use sverb_core::model::{
    AgentSource, Backspace, Group, Host, ItemId, ItemKind, ValidationError, VaultId, WireEnum,
    validate::{validate_address, validate_host},
};
// M2-01
use sverb_core::resolve::{GlobalDefaults, ResolvedHost, SettingKey, Settings, Source};
use sverb_core::search::IndexSnapshot;

use super::catalog::{HostCatalog, HostRecord, HostSummary};
// M2-06
use super::catalog::ProxySummary;
use crate::widgets::form::{
    Field, FieldChanges, FieldValue, FieldValues, FieldWidget, Form, FormValidator, Inherited,
    KeyCheck, ReadOnly, RefValue, SecretValue, SelectOption, Validator,
};

/// Which optional parts of the host form exist yet. Each later task turns its entry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HostFormFeatures {
    /// Jump chain (M2-05).
    pub jump_chain: bool,
    /// Proxy (M2-06).
    pub proxy: bool,
    /// Agent forwarding and agent source (M2-07).
    pub agent: bool,
    /// Port forwards (M2-08).
    pub forwards: bool,
    /// Startup snippet (M2-09).
    pub snippets: bool,
    /// Per-host algorithm overrides (M1-13 §2.6).
    pub algorithms: bool,
}

impl HostFormFeatures {
    /// Everything on (snapshots of the full form).
    pub const ALL: Self = Self {
        jump_chain: true,
        proxy: true,
        agent: true,
        forwards: true,
        snippets: true,
        algorithms: true,
    };
}

/// The feature registry for this build.
pub const HOST_FORM_FEATURES: HostFormFeatures = HostFormFeatures {
    // M2-05
    jump_chain: true,
    // M2-06
    proxy: true,
    agent: false,
    forwards: false,
    snippets: false,
    algorithms: false,
};

/// Charsets offered (WHATWG labels `encoding_rs` knows; UTF-8 is the default).
pub const CHARSETS: &[&str] = &[
    "ISO-8859-1",
    "ISO-8859-2",
    "ISO-8859-5",
    "ISO-8859-7",
    "ISO-8859-15",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "KOI8-R",
    "KOI8-U",
    "Shift_JIS",
    "EUC-JP",
    "EUC-KR",
    "GBK",
    "gb18030",
    "Big5",
    "IBM866",
    "macintosh",
];

/// Value of the "inherit" option of tri-state selects.
pub(crate) const INHERIT: &str = "";

/// What the form edits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostFormInit {
    /// The host being edited (`None`: a new host).
    pub item: Option<ItemId>,
    /// Prefill.
    pub summary: HostSummary,
    /// The stored password.
    pub password: Option<SecretValue>,
}

impl HostFormInit {
    /// A new host prefilled with `address`, `user` and `port` (quick connect "Save as host").
    pub fn new_host(address: &str, user: Option<&str>, port: Option<u16>) -> Self {
        Self {
            item: None,
            summary: HostSummary {
                address: address.to_owned(),
                username: user.map(str::to_owned),
                port,
                ..HostSummary::default()
            },
            password: None,
        }
    }

    /// Editing a loaded host.
    pub fn edit(record: HostRecord) -> Self {
        Self {
            item: Some(record.summary.id),
            password: record.password,
            summary: record.summary,
        }
    }
}

fn address_check(v: &FieldValue) -> Result<(), String> {
    validate_address(v.as_text().unwrap_or_default().trim())
        .map(|_| ())
        .map_err(|e| e.message)
}

pub(crate) fn charset_check(v: &FieldValue) -> Result<(), String> {
    match v {
        FieldValue::Choice(Some(c)) if !c.is_empty() => {
            sverb_term::charset::CharsetCodec::for_label(c)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        _ => Ok(()),
    }
}

/// Cross-field rules: the typed host must pass `validate_host`.
fn host_rules(values: &FieldValues) -> Vec<ValidationError> {
    let mut host = Host::default();
    let changes = FieldChanges(values.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    // Field-level errors (unparseable ids, …) are reported by `apply_changes` too.
    let mut errors = apply_changes(&mut host, &changes).err().unwrap_or_default();
    if let Err(more) = validate_host(&host) {
        for e in more {
            if !errors.iter().any(|x| x.field == e.field) {
                errors.push(e);
            }
        }
    }
    errors
}

pub(crate) fn tri(value: Option<bool>) -> &'static str {
    match value {
        None => INHERIT,
        Some(true) => "yes",
        Some(false) => "no",
    }
}

pub(crate) fn tri_options(default: &str) -> Vec<SelectOption> {
    vec![
        SelectOption::new(INHERIT, format!("{default} (default)")),
        SelectOption::new("yes", "yes"),
        SelectOption::new("no", "no"),
    ]
}

pub(crate) fn reference(
    key: &str,
    label: &str,
    kind: ItemKind,
    id: Option<ItemId>,
    name: impl Fn(ItemId) -> Option<String>,
) -> Field {
    let value = id.map(|id| RefValue {
        id,
        label: name(id).unwrap_or_else(|| id.short()),
    });
    Field::reference(key, label, kind, value)
}

/// Build the host form.
pub fn host_form(
    init: &HostFormInit,
    catalog: Option<&HostCatalog>,
    index: Option<Arc<IndexSnapshot>>,
    schemes: &[String],
    keepalive_default: u32,
    features: HostFormFeatures,
) -> Form {
    let h = &init.summary;
    let empty = HostCatalog::default();
    let cat = catalog.unwrap_or(&empty);
    let host_name = |id: ItemId| cat.hosts.get(&id).map(|h| h.display_label().to_owned());

    let tag_options: Vec<SelectOption> = cat
        .tags
        .iter()
        .map(|(id, t)| SelectOption::new(id.to_string(), t.name.clone()))
        .collect();
    let tag_values: Vec<String> = h.tags.iter().map(ToString::to_string).collect();
    let has_identity = h.identity_id.is_some();
    // M2-02: identities are picked within the host's vault (§13.4).
    let host_vault = init.item.map(|_| h.vault).or(cat.personal_vault);

    let general = vec![
        Field::text("label", "Label", &h.label).help("Shown in lists; defaults to the address"),
        Field::text("address", "Address", &h.address)
            .required()
            .validate(Validator::new("address", address_check))
            .help("Hostname, IPv4 or IPv6 (no user@, no :port)"),
        Field::number("port", "Port", h.port.map(u64::from), 1, 65_535)
            .inherited(Inherited::default_value("22")),
        reference("group_id", "Group", ItemKind::Group, h.group_id, |id| {
            cat.groups.get(&id).cloned()
        }),
        Field::multiselect("tags", "Tags", tag_options, &tag_values),
        Field::toggle("pinned", "Pinned", h.pinned),
    ];
    // M2-02: "Use identity" vs "Inline" (§9.3); `sync_identity` shows the fields of
    // the chosen mode.
    let mut identity = reference(
        "identity_id",
        "Identity",
        ItemKind::Identity,
        h.identity_id,
        |id| cat.identities.get(&id).map(|i| i.label.clone()),
    )
    .help("Reusable credentials from this vault; edit them in Keychain → Identities");
    if let FieldWidget::Reference(r) = &mut identity.widget {
        r.set_vault(host_vault);
        r.set_create(crate::views::keychain::identity_form::NEW_IDENTITY);
    }
    let mode = if has_identity {
        CREDENTIALS_IDENTITY
    } else {
        CREDENTIALS_INLINE
    };
    let credentials = vec![
        Field::select(
            CREDENTIALS_MODE,
            "Credentials",
            vec![
                SelectOption::new(CREDENTIALS_IDENTITY, "Use identity"),
                SelectOption::new(CREDENTIALS_INLINE, "Inline"),
            ],
            Some(mode),
        )
        .help("←/→ switch between an identity and inline credentials"),
        identity,
        Field::text(
            "username",
            "Username",
            h.username.as_deref().unwrap_or_default(),
        )
        .help("Overrides the identity's user"),
        Field::secret("password", "Password", init.password.clone()),
        reference("key_id", "Key", ItemKind::Key, h.key_id, |id| {
            cat.keys.get(&id).cloned()
        }),
        // M1-14: the minimal key import until the keychain (M2-03).
        Field::text(crate::services::ssh::KEY_FILE_FIELD, "Key file", "")
            .help("Path to an OpenSSH private key, imported as a Key on save"),
    ];
    let mut proxy_options = vec![SelectOption::new(INHERIT, "none")];
    proxy_options.extend([
        SelectOption::new("socks5", "SOCKS5"),
        SelectOption::new("http", "HTTP CONNECT"),
        SelectOption::new("command", "ProxyCommand"),
    ]);
    // M2-06: the proxy section's prefill (the password is never shown).
    let (proxy_kind, proxy_addr, proxy_user, proxy_command) = match &h.proxy {
        None => (INHERIT, "", "", ""),
        Some(ProxySummary::Socks5 { addr, user }) => (
            "socks5",
            addr.as_str(),
            user.as_deref().unwrap_or_default(),
            "",
        ),
        Some(ProxySummary::Http { addr, user }) => (
            "http",
            addr.as_str(),
            user.as_deref().unwrap_or_default(),
            "",
        ),
        Some(ProxySummary::Command(c)) => ("command", "", "", c.as_str()),
    };
    // M2-05: the ordered chain; `sync_jump_chain` adds the effective route.
    let jump_rows = h
        .jump_chain
        .iter()
        .map(|id| RefValue {
            id: *id,
            label: host_name(*id).unwrap_or_else(|| id.short()),
        })
        .collect();
    let connection = vec![
        Field::reference_list(JUMP_CHAIN, "Jump hosts", ItemKind::Host, jump_rows)
            .hidden(!features.jump_chain)
            .help("Hosts to hop through, in order (each with its own credentials)"),
        Field::select("proxy.kind", "Proxy", proxy_options, Some(proxy_kind))
            .hidden(!features.proxy)
            .help("←/→ direct, SOCKS5, HTTP CONNECT or a local ProxyCommand (first hop only)"),
        // M2-06: the fields of the chosen kind (`sync_proxy` shows them).
        Field::text(PROXY_ADDR, "Proxy address", proxy_addr)
            .validate(Validator::new("proxy-addr", proxy_addr_check))
            .hidden(true)
            .help("host:port of the proxy ([v6]:port for IPv6)"),
        Field::text(PROXY_USER, "Proxy user", proxy_user)
            .hidden(true)
            .help("Optional; SOCKS5 user/password or HTTP basic auth"),
        Field::secret(PROXY_PASSWORD, "Proxy password", None)
            .hidden(true)
            .help("Leave empty to keep the stored password"),
        Field::text(PROXY_COMMAND, "ProxyCommand", proxy_command)
            .validate(Validator::new("proxy-command", proxy_command_check))
            .hidden(true)
            .help(
                "Runs locally, stdin/stdout are the connection: %h host, %p port, %r user, %% = %",
            ),
        Field::number(
            "keepalive_secs",
            "Keepalive (s)",
            h.keepalive_secs.map(u64::from),
            0,
            86_400,
        )
        .inherited(Inherited::default_value(keepalive_default.to_string())),
        Field::select(
            "agent_forwarding",
            "Agent forwarding",
            tri_options("no"),
            Some(tri(h.agent_forwarding)),
        )
        .hidden(!features.agent),
        Field::select(
            "agent_source",
            "Agent source",
            vec![
                SelectOption::new(INHERIT, "built-in (default)"),
                SelectOption::new(AgentSource::Builtin.as_wire(), "built-in"),
                SelectOption::new(AgentSource::System.as_wire(), "system"),
                SelectOption::new(AgentSource::Both.as_wire(), "both"),
            ],
            Some(h.agent_source.as_deref().unwrap_or(INHERIT)),
        )
        .hidden(!features.agent),
        Field::text("algorithms", "Algorithms", "").hidden(!features.algorithms),
        Field::select(
            "request_pty_for_exec",
            "PTY for exec",
            tri_options("no"),
            Some(tri(h.request_pty_for_exec)),
        )
        .help("Needed for sudo prompts in snippets"),
        // M1-16
        Field::select(
            "auto_reconnect",
            "Reconnect",
            tri_options("no"),
            Some(tri(h.auto_reconnect)),
        )
        .help("Reconnect automatically after a drop (1 s → 30 s backoff, 10 tries)"),
    ];
    let mut charset_options = vec![SelectOption::new(INHERIT, "UTF-8 (default)")];
    charset_options.extend(CHARSETS.iter().map(|c| SelectOption::new(*c, *c)));
    let mut scheme_options = vec![SelectOption::new(INHERIT, "default")];
    scheme_options.extend(
        schemes
            .iter()
            .map(|s| SelectOption::new(s.clone(), s.clone())),
    );
    let terminal = vec![
        Field::select(
            "charset",
            "Charset",
            charset_options,
            Some(h.charset.as_deref().unwrap_or(INHERIT)),
        )
        .validate(Validator::new("charset", charset_check)),
        Field::select(
            "backspace",
            "Backspace",
            vec![
                SelectOption::new(INHERIT, "DEL (default)"),
                SelectOption::new(Backspace::Del.as_wire(), "DEL (0x7f)"),
                SelectOption::new(Backspace::CtrlH.as_wire(), "Ctrl-H (0x08)"),
            ],
            Some(h.backspace.as_deref().unwrap_or(INHERIT)),
        ),
        Field::select(
            "color_scheme",
            "Color scheme",
            scheme_options,
            Some(h.color_scheme.as_deref().unwrap_or(INHERIT)),
        ),
        reference(
            "startup_snippet_id",
            "Startup snippet",
            ItemKind::Snippet,
            h.startup_snippet_id,
            |id| cat.snippets.get(&id).cloned(),
        )
        .hidden(!features.snippets),
        Field::key_values("env", "Environment", h.env.clone(), KeyCheck::EnvName),
    ];
    let forwards = vec![
        Field::text(
            "port_forwards",
            "Port forwards",
            &format!("{} rule(s)", h.port_forwards.len()),
        )
        .hidden(!features.forwards),
    ];
    let notes = vec![Field::multiline(
        "notes",
        "Notes",
        h.notes.as_deref().unwrap_or_default(),
    )];

    let title = if init.item.is_some() {
        format!("Edit host · {}", h.display_label())
    } else {
        "New host".to_owned()
    };
    let mut form = Form::new(title)
        .section("General", general)
        .section("Credentials", credentials)
        .section("Connection", connection)
        .section("Terminal", terminal)
        .section("Forwards", forwards)
        .section("Notes", notes)
        .validator(FormValidator::new("host", host_rules));
    if h.read_only {
        form = form.read_only(ReadOnly::NewerSchema);
    }
    if let Some(index) = index {
        form.set_index(index);
    }
    // M2-02
    sync_identity(&mut form);
    form
}

// M2-02
/// The host form's credentials mode field (not stored).
pub const CREDENTIALS_MODE: &str = "credentials";
/// "Use identity".
pub const CREDENTIALS_IDENTITY: &str = "identity";
/// "Inline".
pub const CREDENTIALS_INLINE: &str = "inline";

// M2-02
/// The credentials mode of a host form (`None`: a form without the choice).
pub fn credentials_mode(form: &Form) -> Option<String> {
    match form.field(CREDENTIALS_MODE).map(Field::value) {
        Some(FieldValue::Choice(c)) => c,
        _ => None,
    }
}

// M2-06
/// `proxy.addr`
pub const PROXY_ADDR: &str = "proxy.addr";
/// `proxy.auth.user`
pub const PROXY_USER: &str = "proxy.auth.user";
/// `proxy.auth.password`
pub const PROXY_PASSWORD: &str = "proxy.auth.password";
/// `proxy.command`
pub const PROXY_COMMAND: &str = "proxy.command";

// M2-06
fn proxy_addr_check(v: &FieldValue) -> Result<(), String> {
    sverb_conn::proxy::validate_proxy_addr(v.as_text().unwrap_or_default())
}

// M2-06
fn proxy_command_check(v: &FieldValue) -> Result<(), String> {
    sverb_conn::proxy::validate_command(v.as_text().unwrap_or_default()).map_err(|e| e.to_string())
}

// M2-06
/// Show the proxy fields of the chosen kind: address, user and password for SOCKS5
/// and HTTP, the command for ProxyCommand. Values of hidden fields are kept while
/// editing. Called by [`sync_identity`] (after every key).
pub fn sync_proxy(form: &mut Form) {
    let Some(kind) = form.field("proxy.kind") else {
        return;
    };
    let kind = (!kind.hidden).then(|| choice(&kind.value())).flatten();
    let via_addr = matches!(kind.as_deref(), Some("socks5" | "http"));
    let via_command = kind.as_deref() == Some("command");
    for key in [PROXY_ADDR, PROXY_USER, PROXY_PASSWORD] {
        if let Some(f) = form.field_mut(key) {
            f.hidden = !via_addr;
        }
    }
    if let Some(f) = form.field_mut(PROXY_COMMAND) {
        f.hidden = !via_command;
    }
}

/// M2-02: show the fields of the credentials mode (§9.3). "Use identity": the
/// identity picker and an optional username override (§4.2: inline overrides the
/// identity); "Inline": username, password and key. Values of hidden fields are kept
/// while editing, so switching back loses nothing. Call after every key.
pub fn sync_identity(form: &mut Form) {
    // M2-06
    sync_proxy(form);
    let use_identity = match credentials_mode(form) {
        Some(mode) => mode == CREDENTIALS_IDENTITY,
        // Without the choice (older callers): dim the inline credentials while an
        // identity is picked.
        None => {
            let has_identity = matches!(
                form.field("identity_id").map(Field::value),
                Some(FieldValue::Reference(Some(_)))
            );
            for key in ["password", "key_id", crate::services::ssh::KEY_FILE_FIELD] {
                if let Some(f) = form.field_mut(key) {
                    f.disabled = has_identity;
                }
            }
            return;
        }
    };
    if let Some(f) = form.field_mut("identity_id") {
        f.hidden = !use_identity;
    }
    for key in ["password", "key_id", crate::services::ssh::KEY_FILE_FIELD] {
        if let Some(f) = form.field_mut(key) {
            f.hidden = use_identity;
            f.disabled = false;
        }
    }
    if let Some(f) = form.field_mut("username") {
        if use_identity {
            "Username override".clone_into(&mut f.label);
            f.help = Some("Optional; overrides the identity's user".to_owned());
        } else {
            "Username".clone_into(&mut f.label);
            f.help = Some("The remote login user".to_owned());
        }
    }
}

// M2-02
/// What a save writes for the credentials: when the user switched modes, the other
/// mode's stored values are cleared ("Inline" drops the identity; "Use identity"
/// drops the inline password and key; the username is kept as the override).
pub fn credential_changes(form: &Form, mut changes: FieldChanges) -> FieldChanges {
    let switched = form.field(CREDENTIALS_MODE).is_some_and(Field::changed);
    let Some(mode) = credentials_mode(form).filter(|_| switched) else {
        return changes;
    };
    let mut set = |key: &str, value: FieldValue| match changes.0.iter_mut().find(|(k, _)| k == key)
    {
        Some(entry) => entry.1 = value,
        None => changes.0.push((key.to_owned(), value)),
    };
    if mode == CREDENTIALS_INLINE {
        set("identity_id", FieldValue::Reference(None));
    } else {
        set("password", FieldValue::Secret(SecretValue::empty()));
        set("key_id", FieldValue::Reference(None));
    }
    changes
}

pub(crate) fn err(field: &str, msg: impl Into<String>) -> ValidationError {
    ValidationError::new(field, msg)
}

pub(crate) fn tri_value(v: &FieldValue) -> Option<bool> {
    match v {
        FieldValue::Choice(Some(c)) if c == "yes" => Some(true),
        FieldValue::Choice(Some(c)) if c == "no" => Some(false),
        _ => None,
    }
}

pub(crate) fn choice(v: &FieldValue) -> Option<String> {
    match v {
        FieldValue::Choice(Some(c)) if !c.is_empty() => Some(c.clone()),
        _ => None,
    }
}

pub(crate) fn text(v: &FieldValue) -> Option<String> {
    v.as_text()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Apply form changes to a typed host. Unknown keys are ignored (hidden fields of
/// later tasks); every problem is returned as a field error.
///
/// # Errors
/// Field-level [`ValidationError`]s (bad address, port out of range, unknown option).
pub fn apply_changes(host: &mut Host, changes: &FieldChanges) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    for (key, value) in &changes.0 {
        match (key.as_str(), value) {
            ("label", v) => host.label = text(v).unwrap_or_default(),
            ("address", v) => {
                let raw = text(v).unwrap_or_default();
                match validate_address(&raw) {
                    Ok(norm) => host.address = norm,
                    Err(e) => {
                        host.address = raw;
                        errors.push(e);
                    }
                }
            }
            ("port", FieldValue::Number(n)) => match n.map(u16::try_from) {
                None => host.port = None,
                Some(Ok(p)) if p > 0 => host.port = Some(p),
                Some(_) => errors.push(err("port", "port must be between 1 and 65535")),
            },
            ("keepalive_secs", FieldValue::Number(n)) => match n.map(u32::try_from) {
                None => host.keepalive_secs = None,
                Some(Ok(s)) => host.keepalive_secs = Some(s),
                Some(Err(_)) => errors.push(err("keepalive_secs", "too large")),
            },
            ("group_id", FieldValue::Reference(r)) => host.group_id = *r,
            ("identity_id", FieldValue::Reference(r)) => host.identity_id = *r,
            ("key_id", FieldValue::Reference(r)) => host.key_id = *r,
            ("startup_snippet_id", FieldValue::Reference(r)) => host.startup_snippet_id = *r,
            // M2-05: the ordered list (empty: inherit).
            ("jump_chain", FieldValue::References(ids)) => {
                host.jump_chain.clone_from(ids);
                host.explicit_empty.jump_chain = false;
            }
            ("tags", FieldValue::Choices(ids)) => {
                let mut tags = Vec::new();
                for id in ids {
                    match id.parse::<ItemId>() {
                        Ok(id) => tags.push(id),
                        Err(_) => errors.push(err("tags", "unknown tag")),
                    }
                }
                host.tags = tags;
            }
            ("pinned", FieldValue::Bool(b)) => host.pinned = *b,
            ("username", v) => host.username = text(v),
            ("password", FieldValue::Secret(s)) => {
                host.password = (!s.is_empty()).then(|| s.expose().into());
            }
            ("agent_forwarding", v) => host.agent_forwarding = tri_value(v),
            ("request_pty_for_exec", v) => host.request_pty_for_exec = tri_value(v),
            // M1-16
            ("auto_reconnect", v) => host.auto_reconnect = tri_value(v),
            ("agent_source", v) => match choice(v) {
                None => host.agent_source = None,
                Some(s) => match AgentSource::from_wire(&s) {
                    Some(a) => host.agent_source = Some(a),
                    None => errors.push(err("agent_source", "unknown agent source")),
                },
            },
            ("backspace", v) => match choice(v) {
                None => host.backspace = None,
                Some(s) => match Backspace::from_wire(&s) {
                    Some(b) => host.backspace = Some(b),
                    None => errors.push(err("backspace", "unknown backspace mode")),
                },
            },
            ("charset", v) => host.charset = choice(v),
            ("color_scheme", v) => host.color_scheme = choice(v),
            ("env", FieldValue::Pairs(pairs)) => {
                host.env = pairs.clone();
                // M2-01: an empty list in the form means "inherit".
                host.explicit_empty.env = false;
            }
            ("notes", v) => {
                host.notes = v
                    .as_text()
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_owned);
            }
            // Hidden fields of later tasks and display-only fields.
            _ => {}
        }
    }
    // M2-06
    apply_proxy(host, changes, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// M2-06
/// Apply the `proxy.*` changes: the stored proxy with the changed parts replaced
/// (a kind switch keeps the address and credentials it can use; an unchanged
/// password field keeps the stored password).
fn apply_proxy(host: &mut Host, changes: &FieldChanges, errors: &mut Vec<ValidationError>) {
    use sverb_core::model::{Proxy, ProxyAuth};
    if !changes.0.iter().any(|(k, _)| k.starts_with("proxy.")) {
        return;
    }
    let mut kind = host.proxy.as_ref().map(|p| match p {
        Proxy::Socks5 { .. } => "socks5".to_owned(),
        Proxy::Http { .. } => "http".to_owned(),
        Proxy::Command(_) => "command".to_owned(),
    });
    let (mut addr, mut user, mut password, mut command) = match host.proxy.take() {
        Some(Proxy::Socks5 { addr, auth } | Proxy::Http { addr, auth }) => {
            let (user, password) = auth.map_or((None, None), |a| (Some(a.user), a.password));
            (Some(addr), user, password, None)
        }
        Some(Proxy::Command(c)) => (None, None, None, Some(c)),
        None => (None, None, None, None),
    };
    for (key, value) in &changes.0 {
        match (key.as_str(), value) {
            ("proxy.kind", v) => kind = choice(v),
            (PROXY_ADDR, v) => addr = text(v),
            (PROXY_USER, v) => user = text(v),
            (PROXY_PASSWORD, FieldValue::Secret(s)) if !s.is_empty() => {
                password = Some(s.expose().into());
            }
            (PROXY_COMMAND, v) => command = text(v),
            _ => {}
        }
    }
    let auth = user.map(|user| ProxyAuth { user, password });
    let addr_of = |errors: &mut Vec<ValidationError>| match addr.clone() {
        Some(a) => match sverb_conn::proxy::validate_proxy_addr(&a) {
            Ok(()) => Some(a),
            Err(msg) => {
                errors.push(err(PROXY_ADDR, msg));
                None
            }
        },
        None => {
            errors.push(err(PROXY_ADDR, "a proxy needs host:port"));
            None
        }
    };
    host.proxy = match kind.as_deref() {
        None => None,
        Some("socks5") => addr_of(errors).map(|addr| Proxy::Socks5 { addr, auth }),
        Some("http") => addr_of(errors).map(|addr| Proxy::Http { addr, auth }),
        Some("command") => match command {
            Some(c) => match sverb_conn::proxy::validate_command(&c) {
                Ok(()) => Some(Proxy::Command(c)),
                Err(e) => {
                    errors.push(err(PROXY_COMMAND, e.to_string()));
                    None
                }
            },
            None => {
                errors.push(err(PROXY_COMMAND, "enter the command to run"));
                None
            }
        },
        Some(_) => {
            errors.push(err("proxy.kind", "unknown proxy kind"));
            None
        }
    };
}

/// The host form on the dialog stack (`DialogKind::HostForm`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFormDialog {
    /// The host being edited (`None`: a new host).
    pub item: Option<ItemId>,
    /// The form.
    pub form: Form,
    // M2-01
    /// What the placeholders resolve against (`None`: global defaults only).
    pub inherit: Option<Box<InheritCx>>,
}

impl HostFormDialog {
    /// What a save writes: the changed fields of an edit, every field of a new host
    /// (prefilled values count: they are not "changes" to the form).
    pub fn save_changes(&self, changes: FieldChanges) -> FieldChanges {
        if self.item.is_some() {
            changes
        } else {
            FieldChanges(self.form.values().into_iter().collect())
        }
    }
}

#[cfg(test)]
impl HostFormDialog {
    /// An empty "New host" form (tests).
    pub(crate) fn blank() -> Self {
        let init = HostFormInit::default();
        Self {
            item: None,
            form: host_form(&init, None, None, &[], 30, HOST_FORM_FEATURES),
            inherit: None,
        }
    }
}

// ---------------------------------------------------------------------- M2-01

/// What inherited placeholders resolve against: the catalog (groups, identities,
/// vault defaults) and the global defaults (M2-01, SPEC §4.3, §8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritCx {
    /// The catalog the form was opened with.
    pub catalog: Arc<HostCatalog>,
    /// `config.toml` defaults.
    pub globals: GlobalDefaults,
    /// The vault of the edited item (`None`: the Personal vault).
    pub vault: Option<VaultId>,
}

impl InheritCx {
    /// The display name of a referenced item.
    fn name_of(&self, key: SettingKey, id: ItemId) -> String {
        let c = &self.catalog;
        let name = match key {
            SettingKey::IdentityId => c
                .identities
                .get(&id)
                .map(|i| i.label.clone())
                .or_else(|| c.lookup.identities.get(&id).map(|i| i.label.clone())),
            SettingKey::KeyId => c.keys.get(&id).cloned(),
            SettingKey::StartupSnippetId => c.snippets.get(&id).cloned(),
            _ => None,
        };
        name.unwrap_or_else(|| id.short())
    }

    /// The placeholder for `key` from `r` (`None`: nothing to inherit).
    fn placeholder(&self, r: &ResolvedHost, key: SettingKey) -> Option<Inherited> {
        let value = match key {
            SettingKey::IdentityId => r.identity_id.map(|id| self.name_of(key, id)),
            SettingKey::KeyId => r.key_id.map(|id| self.name_of(key, id)),
            SettingKey::StartupSnippetId => r.startup_snippet_id.map(|id| self.name_of(key, id)),
            _ => r.display(key),
        }?;
        Some(match r.source(key) {
            Source::BuiltinDefault | Source::GlobalConfig => Inherited::default_value(value),
            src => Inherited::from_source(value, src.to_string()),
        })
    }
}

/// The fields whose placeholders follow resolution (form key, setting).
const INHERITABLE_FIELDS: [(&str, SettingKey); 16] = [
    ("port", SettingKey::Port),
    ("identity_id", SettingKey::IdentityId),
    ("username", SettingKey::Username),
    ("key_id", SettingKey::KeyId),
    ("keepalive_secs", SettingKey::KeepaliveSecs),
    ("agent_forwarding", SettingKey::AgentForwarding),
    ("agent_source", SettingKey::AgentSource),
    ("request_pty_for_exec", SettingKey::RequestPtyForExec),
    ("charset", SettingKey::Charset),
    ("backspace", SettingKey::Backspace),
    ("color_scheme", SettingKey::ColorScheme),
    ("startup_snippet_id", SettingKey::StartupSnippetId),
    ("jump_chain", SettingKey::JumpChain),
    ("record_sessions", SettingKey::RecordSessions),
    // M1-16
    ("auto_reconnect", SettingKey::AutoReconnect),
    // M2-06
    ("proxy.kind", SettingKey::Proxy),
];

fn reference_value(form: &Form, key: &str) -> Option<ItemId> {
    match form.field(key).map(Field::value) {
        Some(FieldValue::Reference(r)) => r,
        _ => None,
    }
}

/// Refresh the inherited placeholders of a host or group form from the draft's
/// group (`group_key`: `group_id` for a host, `parent_id` for a group). Live: call
/// after every key, so picking another group updates them.
pub fn sync_inherited(form: &mut Form, cx: &InheritCx, group_key: &str) {
    let group = reference_value(form, group_key);
    let r = cx.catalog.inherited(group, cx.vault, &cx.globals);
    // An identity picked on this level supplies the user (§4.2).
    let identity = reference_value(form, "identity_id")
        .and_then(|id| cx.catalog.lookup.identities.get(&id))
        .filter(|i| !i.username.is_empty())
        .map(|i| Inherited::from_source(i.username.clone(), "identity"));
    for (key, setting) in INHERITABLE_FIELDS {
        let mut inherited = cx.placeholder(&r, setting);
        if setting == SettingKey::Username && identity.is_some() {
            inherited.clone_from(&identity);
        }
        let Some(field) = form.field_mut(key) else {
            continue;
        };
        if let FieldWidget::Select(sel) = &mut field.widget {
            // The "inherit" option names what it inherits (only when it is not the
            // built-in default the label already shows).
            let label = match &inherited {
                Some(i) if i.source.is_some() => Some(i.to_string()),
                _ => None,
            };
            if let (Some(label), Some(opt)) =
                (label, sel.options.iter_mut().find(|o| o.value == INHERIT))
            {
                opt.label = label;
            }
        }
        field.inherited = inherited;
    }
}

impl HostFormDialog {
    /// Refresh the placeholders (after every key).
    pub fn sync_inherited(&mut self) {
        if let Some(cx) = &self.inherit {
            sync_inherited(&mut self.form, cx, "group_id");
            // M2-05
            sync_jump_chain(&mut self.form, cx, self.item);
        }
    }
}

// ---------------------------------------------------------------------- M2-05

/// The host form's jump chain field.
pub const JUMP_CHAIN: &str = "jump_chain";

/// The draft's jump chain: its own entries, else what its group would give it.
fn draft_chain(form: &Form, cx: &InheritCx) -> Vec<ItemId> {
    match form.field(JUMP_CHAIN).map(Field::value) {
        Some(FieldValue::References(ids)) if !ids.is_empty() => ids,
        _ => {
            let group = reference_value(form, "group_id");
            cx.catalog
                .inherited(group, cx.vault, &cx.globals)
                .jump_chain
        }
    }
}

/// Refresh the jump chain's inline check and its effective-route preview
/// ("Effective route: you → bastion → inner-bastion → target"): the chain is expanded
/// recursively through the hops' own chains (§6.1.4). A cycle (including one back to
/// the edited host) or more than 8 hops is an error on the field.
pub fn sync_jump_chain(form: &mut Form, cx: &InheritCx, item: Option<ItemId>) {
    let chain = draft_chain(form, cx);
    let text = |key: &str| match form.field(key).map(Field::value) {
        Some(FieldValue::Text(t)) => t.trim().to_owned(),
        _ => String::new(),
    };
    let name = Some(text("label"))
        .filter(|l| !l.is_empty())
        .or_else(|| Some(text("address")).filter(|a| !a.is_empty()))
        .unwrap_or_else(|| "this host".to_owned());
    let expanded = sverb_core::resolve::expand_by(item, &name, &chain, |id| {
        let hop = cx.catalog.hosts.get(&id)?;
        let resolved = cx.catalog.resolve(hop, &cx.globals);
        Some(sverb_core::resolve::HopInfo {
            value: hop.display_label().to_owned(),
            name: hop.display_label().to_owned(),
            chain: resolved.jump_chain,
        })
    });
    let Some(FieldWidget::RefList(list)) = form.field_mut(JUMP_CHAIN).map(|f| &mut f.widget) else {
        return;
    };
    match expanded {
        Ok(hops) if hops.is_empty() => {
            list.note = None;
            list.error = None;
        }
        Ok(hops) => {
            let mut parts = vec!["you".to_owned()];
            parts.extend(hops.into_iter().map(|(_, label)| label));
            parts.push(name);
            list.note = Some(format!("Effective route: {}", parts.join(" → ")));
            list.error = None;
        }
        Err(err) => {
            list.note = None;
            list.error = Some(err.to_string());
        }
    }
}

/// What the group editor edits (`item: None`: a new group).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupFormInit {
    /// The group (`None`: new).
    pub item: Option<ItemId>,
    /// This is the vault-defaults item (§4.13): no name or parent.
    pub vault_defaults: bool,
    /// `name`
    pub name: String,
    /// `parent_id`
    pub parent_id: Option<ItemId>,
    /// `icon`
    pub icon: Option<String>,
    /// `defaults.*`
    pub defaults: Settings,
}

impl GroupFormInit {
    /// Editing an existing group of the catalog.
    pub fn edit(catalog: &HostCatalog, id: ItemId) -> Option<Self> {
        let g = catalog.lookup.groups.get(&id)?;
        Some(Self {
            item: Some(id),
            vault_defaults: false,
            name: g.name.clone(),
            parent_id: g.parent_id,
            icon: g.icon.clone(),
            defaults: g.defaults.clone(),
        })
    }

    /// The vault defaults of `vault` (a new item if none exists yet).
    pub fn vault_defaults(catalog: &HostCatalog, vault: VaultId) -> Self {
        Self {
            item: catalog.lookup.vault_defaults_items.get(&vault).copied(),
            vault_defaults: true,
            name: VAULT_DEFAULTS_NAME.to_owned(),
            parent_id: None,
            icon: None,
            defaults: catalog
                .lookup
                .defaults_of(vault)
                .cloned()
                .unwrap_or_default(),
        }
    }
}

/// The `name` stored on the vault-defaults item.
pub const VAULT_DEFAULTS_NAME: &str = "Vault defaults";

fn icon_check(v: &FieldValue) -> Result<(), String> {
    let t = v.as_text().unwrap_or_default().trim();
    if t.chars().count() > 16 {
        Err("a single symbol or a short name (16 characters at most)".to_owned())
    } else {
        Ok(())
    }
}

fn name_check(v: &FieldValue) -> Result<(), String> {
    if v.as_text().unwrap_or_default().trim().is_empty() {
        Err("a group needs a name".to_owned())
    } else {
        Ok(())
    }
}

/// The group editor: name, parent, icon and the defaults (the host form's
/// inheritable fields; the defaults password is not editable here yet). The vault
/// defaults editor (§4.13) is the same form without name, parent and icon.
pub fn group_form(
    init: &GroupFormInit,
    catalog: Option<&HostCatalog>,
    index: Option<Arc<IndexSnapshot>>,
    schemes: &[String],
    features: HostFormFeatures,
) -> Form {
    let empty = HostCatalog::default();
    let cat = catalog.unwrap_or(&empty);
    let d = &init.defaults;
    let general = vec![
        Field::text("name", "Name", &init.name)
            .required()
            .validate(Validator::new("group-name", name_check)),
        reference(
            "parent_id",
            "Parent",
            ItemKind::Group,
            init.parent_id,
            |id| cat.group_name(id).map(str::to_owned),
        )
        .help("Nest inside another group"),
        Field::text("icon", "Icon", init.icon.as_deref().unwrap_or_default())
            .validate(Validator::new("group-icon", icon_check))
            .help("A single symbol or a short name"),
    ];
    let credentials = vec![
        reference(
            "identity_id",
            "Identity",
            ItemKind::Identity,
            d.identity_id,
            |id| cat.lookup.identities.get(&id).map(|i| i.label.clone()),
        ),
        Field::text(
            "username",
            "Username",
            d.username.as_deref().unwrap_or_default(),
        ),
        reference("key_id", "Key", ItemKind::Key, d.key_id, |id| {
            cat.keys.get(&id).cloned()
        }),
    ];
    let wire = |v: Option<&str>| v.unwrap_or(INHERIT).to_owned();
    let connection = vec![
        Field::number("port", "Port", d.port.map(u64::from), 1, 65_535),
        Field::number(
            "keepalive_secs",
            "Keepalive (s)",
            d.keepalive_secs.map(u64::from),
            0,
            86_400,
        ),
        Field::select(
            "agent_forwarding",
            "Agent forwarding",
            tri_options("no"),
            Some(tri(d.agent_forwarding)),
        )
        .hidden(!features.agent),
        Field::select(
            "request_pty_for_exec",
            "PTY for exec",
            tri_options("no"),
            Some(tri(d.request_pty_for_exec)),
        ),
        Field::select(
            "record_sessions",
            "Record sessions",
            tri_options("no"),
            Some(tri(d.record_sessions)),
        ),
        // M1-16
        Field::select(
            "auto_reconnect",
            "Reconnect",
            tri_options("no"),
            Some(tri(d.auto_reconnect)),
        ),
    ];
    let mut charset_options = vec![SelectOption::new(INHERIT, "UTF-8 (default)")];
    charset_options.extend(CHARSETS.iter().map(|c| SelectOption::new(*c, *c)));
    let mut scheme_options = vec![SelectOption::new(INHERIT, "default")];
    scheme_options.extend(
        schemes
            .iter()
            .map(|s| SelectOption::new(s.clone(), s.clone())),
    );
    let terminal = vec![
        Field::select(
            "charset",
            "Charset",
            charset_options,
            Some(&wire(d.charset.as_deref())),
        )
        .validate(Validator::new("charset", charset_check)),
        Field::select(
            "backspace",
            "Backspace",
            vec![
                SelectOption::new(INHERIT, "DEL (default)"),
                SelectOption::new(Backspace::Del.as_wire(), "DEL (0x7f)"),
                SelectOption::new(Backspace::CtrlH.as_wire(), "Ctrl-H (0x08)"),
            ],
            Some(&wire(d.backspace.map(|b| b.as_wire()))),
        ),
        Field::select(
            "color_scheme",
            "Color scheme",
            scheme_options,
            Some(&wire(d.color_scheme.as_deref())),
        ),
        Field::key_values(
            "env",
            "Environment",
            d.env.clone().unwrap_or_default(),
            KeyCheck::EnvName,
        ),
    ];
    let title = match (init.vault_defaults, init.item) {
        (true, _) => "Vault defaults".to_owned(),
        (false, Some(_)) => format!("Edit group · {}", init.name),
        (false, None) => "New group".to_owned(),
    };
    let mut form = Form::new(title);
    if !init.vault_defaults {
        form = form.section("Group", general);
    }
    form = form
        .section("Credentials", credentials)
        .section("Connection", connection)
        .section("Terminal", terminal);
    if let Some(index) = index {
        form.set_index(index);
    }
    form
}

/// Apply group-form changes to a typed group: `name`, `parent_id`, `icon` and the
/// defaults (same keys as the host form).
///
/// # Errors
/// Field-level [`ValidationError`]s.
pub fn apply_group_changes(
    group: &mut Group,
    changes: &FieldChanges,
) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    let d = &mut group.defaults;
    for (key, value) in &changes.0 {
        match (key.as_str(), value) {
            ("name", v) => group.name = text(v).unwrap_or_default(),
            ("parent_id", FieldValue::Reference(r)) => group.parent_id = *r,
            ("icon", v) => group.icon = text(v),
            ("is_vault_defaults", FieldValue::Bool(b)) => group.is_vault_defaults = *b,
            ("port", FieldValue::Number(n)) => match n.map(u16::try_from) {
                None => d.port = None,
                Some(Ok(p)) if p > 0 => d.port = Some(p),
                Some(_) => errors.push(err("port", "port must be between 1 and 65535")),
            },
            ("keepalive_secs", FieldValue::Number(n)) => match n.map(u32::try_from) {
                None => d.keepalive_secs = None,
                Some(Ok(s)) => d.keepalive_secs = Some(s),
                Some(Err(_)) => errors.push(err("keepalive_secs", "too large")),
            },
            ("identity_id", FieldValue::Reference(r)) => d.identity_id = *r,
            ("key_id", FieldValue::Reference(r)) => d.key_id = *r,
            ("username", v) => d.username = text(v),
            ("agent_forwarding", v) => d.agent_forwarding = tri_value(v),
            ("request_pty_for_exec", v) => d.request_pty_for_exec = tri_value(v),
            ("record_sessions", v) => d.record_sessions = tri_value(v),
            // M1-16
            ("auto_reconnect", v) => d.auto_reconnect = tri_value(v),
            ("backspace", v) => match choice(v) {
                None => d.backspace = None,
                Some(s) => match Backspace::from_wire(&s) {
                    Some(b) => d.backspace = Some(b),
                    None => errors.push(err("backspace", "unknown backspace mode")),
                },
            },
            ("charset", v) => d.charset = choice(v),
            ("color_scheme", v) => d.color_scheme = choice(v),
            ("env", FieldValue::Pairs(pairs)) => {
                d.env = (!pairs.is_empty()).then(|| pairs.clone());
            }
            _ => {}
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// M2-05
#[cfg(test)]
#[path = "jump_tests.rs"]
mod jump_tests;
