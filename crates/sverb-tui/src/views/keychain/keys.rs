//! M2-03: the Keychain view's Keys sub-tab (SPEC §4.5, §8.5, §9.4).
//!
//! - **Rows**: every key (alphabetical) with its type, `SHA256` fingerprint, flags
//!   (`agent` reference, `enc`rypted, `fwd` agent-forwardable, `confirm`) and the worst
//!   badge of its certificates: yellow "expiring" within 7 days, red "expired" (§9.4).
//!   Badges are computed against the catalog's build time (deterministic in tests).
//! - **Detail**: type, fingerprint, public key, passphrase state, flags, the attached
//!   certificates with their validity, and "used by N" (hosts whose resolved key is this
//!   one, plus identities naming it).
//! - **Actions** (Normal mode; `g`/`i` stay the list's top / detail keys): `a`
//!   generate, `I` import a file, `p` import pasted text, `c` copy the public key, `x`
//!   export the public key to a file, `X` export the private key, `P` change the
//!   passphrase, `t` attach a certificate, `f` toggle `agent_forwardable`, `o` toggle
//!   `confirm_on_use`, `H` install on hosts (M2-04), `d` delete
//!   (warns "used by N"). The view records the request; the
//!   reducer (`app/keychain/keys.rs`) carries it out.
//!
//! No private material ever reaches this view: the catalog holds public data only.

use std::collections::BTreeMap;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
};
use sverb_core::{
    keychain::{
        algorithm_name,
        cert::{CertInfo, ExpiryBadge, expiry_badge},
        fingerprint,
    },
    model::{ItemId, Key, KeyAlgorithm, VaultId},
    resolve::GlobalDefaults,
};

use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent, hosts::catalog::HostCatalog},
    widgets::{
        form::{highlighted, match_style},
        list::{EmptyState, FilterSource, ListRow, ListView, RowCx, RowRenderer},
        truncate, width,
    },
};

/// The public data of a key, for the catalog (no private material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Its vault.
    pub vault: VaultId,
    /// `label`
    pub label: String,
    /// `algorithm`
    pub algorithm: KeyAlgorithm,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:…` (empty if the public key doesn't parse).
    pub fingerprint: String,
    /// An agent / hardware reference (no private part).
    pub agent_ref: bool,
    /// The stored private key is passphrase-encrypted.
    pub encrypted: bool,
    /// The passphrase is stored in the vault.
    pub has_passphrase: bool,
    /// `agent_forwardable`
    pub agent_forwardable: bool,
    /// `confirm_on_use`
    pub confirm_on_use: bool,
    /// `certificate_ids`
    pub certificate_ids: Vec<ItemId>,
}

impl KeyInfo {
    /// From the typed view (only `is_encrypted` looks at the private key's header).
    pub fn from_key(vault: VaultId, k: &Key) -> Self {
        Self {
            vault,
            label: k.label.clone(),
            algorithm: k.algorithm,
            fingerprint: fingerprint(&k.public_key).unwrap_or_default(),
            public_key: k.public_key.trim().to_owned(),
            agent_ref: k.is_agent_ref(),
            encrypted: !k.is_agent_ref() && sverb_core::keychain::export::is_encrypted(k),
            has_passphrase: k.passphrase.is_some(),
            agent_forwardable: k.agent_forwardable,
            confirm_on_use: k.confirm_on_use,
            certificate_ids: k.certificate_ids.clone(),
        }
    }
}

/// A certificate for the catalog: the line (public) and its derived fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSummary {
    /// Its vault.
    pub vault: VaultId,
    /// `label`
    pub label: String,
    /// `key_id` (the key it certifies).
    pub key_id: Option<ItemId>,
    /// The OpenSSH certificate line.
    pub cert: String,
    /// Derived fields (`None`: unparseable).
    pub info: Option<CertInfo>,
}

/// The certificates of `key` (`certificate_ids`, and certificates naming the key).
pub fn certs_of<'a>(
    catalog: &'a HostCatalog,
    key: ItemId,
    info: &'a KeyInfo,
) -> impl Iterator<Item = (ItemId, &'a CertSummary)> + 'a {
    catalog
        .certs
        .iter()
        .filter(move |(id, c)| info.certificate_ids.contains(id) || c.key_id == Some(key))
        .map(|(id, c)| (*id, c))
}

/// The worst expiry badge of a key's certificates at `now` (UNIX seconds).
pub fn key_badge(catalog: &HostCatalog, key: ItemId, info: &KeyInfo, now: u64) -> ExpiryBadge {
    certs_of(catalog, key, info)
        .filter_map(|(_, c)| c.info.as_ref())
        .map(|i| expiry_badge(i, now))
        .fold(ExpiryBadge::None, ExpiryBadge::worst)
}

/// The badge style: yellow for expiring, red for expired.
pub fn badge_style(badge: ExpiryBadge, theme: &Theme) -> Style {
    match badge {
        ExpiryBadge::Expired => theme.error,
        ExpiryBadge::Expiring | ExpiryBadge::NotYetValid => theme.warn,
        ExpiryBadge::None => theme.dim,
    }
}

/// What uses a key: hosts (resolved key) and identities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyUsage {
    /// Hosts whose resolved key is this one.
    pub hosts: Vec<ItemId>,
    /// Identities with this `key_id`.
    pub identities: Vec<ItemId>,
}

impl KeyUsage {
    /// Hosts + identities.
    pub fn total(&self) -> usize {
        self.hosts.len() + self.identities.len()
    }
}

/// Usage of every key of `catalog`.
pub fn key_usage(catalog: &HostCatalog) -> BTreeMap<ItemId, KeyUsage> {
    let mut map: BTreeMap<ItemId, KeyUsage> = BTreeMap::new();
    let globals = GlobalDefaults::default();
    for h in catalog.hosts.values() {
        if let Some(k) = catalog.resolve(h, &globals).key_id {
            map.entry(k).or_default().hosts.push(h.id);
        }
    }
    for (id, i) in &catalog.identities {
        if let Some(k) = i.key_id {
            map.entry(k).or_default().identities.push(*id);
        }
    }
    map
}

/// One row of the Keys list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// The key.
    pub id: ItemId,
    /// `label`
    pub label: String,
    /// `"Ed25519"`, `"RSA 4096"`, …
    pub kind: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// `agent`, `enc`, `fwd`, `confirm`.
    pub flags: Vec<&'static str>,
    /// The worst certificate badge.
    pub badge: ExpiryBadge,
    /// Attached certificates.
    pub certs: usize,
    /// Hosts + identities using it.
    pub used: usize,
}

impl ListRow for KeyRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.id
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn filter_text(&self) -> String {
        format!("{} {} {}", self.label, self.kind, self.fingerprint)
    }

    fn item_id(&self) -> Option<ItemId> {
        Some(self.id)
    }

    fn secondary(&self) -> String {
        self.kind.clone()
    }
}

/// What the user asked the Keys sub-tab for (handled by the reducer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRequest {
    /// `a`: the generate form.
    Generate,
    /// `I`: import a key file (path prompt).
    ImportFile,
    /// `p`: import pasted text.
    ImportPaste,
    /// `c`: copy the public key.
    CopyPublic(ItemId),
    /// `x`: export the public key to a file.
    ExportPublic(ItemId),
    /// `X`: export the private key to a file.
    ExportPrivate(ItemId),
    /// `P`: change the passphrase.
    ChangePassphrase(ItemId),
    /// `t`: attach a certificate.
    AttachCert(ItemId),
    /// `f`: toggle `agent_forwardable`.
    ToggleForwardable(ItemId),
    /// `o`: toggle `confirm_on_use`.
    ToggleConfirm(ItemId),
    /// `H`: install on hosts (M2-04).
    Install(ItemId),
    /// `d`: delete (asks).
    Delete(ItemId),
}

/// The Keys sub-tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysView {
    /// The list.
    pub list: ListView<KeyRow>,
    catalog: Option<Arc<HostCatalog>>,
    usage: BTreeMap<ItemId, KeyUsage>,
    request: Option<KeyRequest>,
    /// Offset east of UTC for dates (`None`: local time; tests pin it).
    pub utc_offset_secs: Option<i32>,
}

impl Default for KeysView {
    fn default() -> Self {
        Self {
            list: ListView::new("Keys").with_empty(EmptyState::new(
                "No keys yet",
                &[
                    ("a", "generate a key"),
                    ("I", "import a key file"),
                    ("p", "paste a key"),
                ],
            )),
            catalog: None,
            usage: BTreeMap::new(),
            request: None,
            utc_offset_secs: None,
        }
    }
}

impl KeysView {
    /// The latest catalog.
    pub fn catalog(&self) -> Option<&Arc<HostCatalog>> {
        self.catalog.as_ref()
    }

    /// A new catalog: rows, badges and usage follow.
    pub fn set_catalog(&mut self, catalog: Arc<HostCatalog>) {
        self.usage = key_usage(&catalog);
        self.catalog = Some(catalog);
        self.rebuild();
    }

    /// Drop all decrypted data (the vault locked).
    pub fn clear(&mut self) {
        if self.catalog.is_some() || !self.list.rows().is_empty() {
            self.catalog = None;
            self.usage.clear();
            self.list.set_source(FilterSource::Local);
            self.list.set_rows(Vec::new());
        }
    }

    /// The pending request, if any.
    pub fn take_request(&mut self) -> Option<KeyRequest> {
        self.request.take()
    }

    /// Whether the list edits text (filter line).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    /// Put the cursor on a key.
    pub fn select(&mut self, id: ItemId) -> bool {
        self.list.select_key(&id)
    }

    /// A key's public data.
    pub fn info(&self, id: ItemId) -> Option<&KeyInfo> {
        self.catalog.as_ref()?.key_details.get(&id)
    }

    /// What uses a key.
    pub fn usage(&self, id: ItemId) -> KeyUsage {
        self.usage.get(&id).cloned().unwrap_or_default()
    }

    /// The catalog's build time in UNIX seconds (badges are relative to it).
    pub fn now_secs(&self) -> u64 {
        self.catalog
            .as_ref()
            .map_or(0, |c| u64::try_from(c.loaded_at / 1000).unwrap_or(0))
    }

    /// The rows for a catalog.
    pub fn rows(
        catalog: &HostCatalog,
        usage: &BTreeMap<ItemId, KeyUsage>,
        now: u64,
    ) -> Vec<KeyRow> {
        let mut rows: Vec<KeyRow> = catalog
            .key_details
            .iter()
            .map(|(id, k)| {
                let mut flags = Vec::new();
                if k.agent_ref {
                    flags.push("agent");
                }
                if k.encrypted {
                    flags.push("enc");
                }
                if k.agent_forwardable {
                    flags.push("fwd");
                }
                if k.confirm_on_use {
                    flags.push("confirm");
                }
                KeyRow {
                    id: *id,
                    label: k.label.clone(),
                    kind: algorithm_name(k.algorithm).to_owned(),
                    fingerprint: k.fingerprint.clone(),
                    flags,
                    badge: key_badge(catalog, *id, k, now),
                    certs: certs_of(catalog, *id, k).count(),
                    used: usage.get(id).map_or(0, KeyUsage::total),
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            a.label
                .to_lowercase()
                .cmp(&b.label.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        rows
    }

    fn rebuild(&mut self) {
        let rows = match &self.catalog {
            Some(c) => Self::rows(c, &self.usage, self.now_secs()),
            None => Vec::new(),
        };
        self.list.set_rows(rows);
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<KeyRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        let selected = self.list.selected_key();
        Some(match code {
            KeyCode::Char('a') => KeyRequest::Generate,
            KeyCode::Char('I') => KeyRequest::ImportFile,
            KeyCode::Char('p') => KeyRequest::ImportPaste,
            KeyCode::Char('c') => KeyRequest::CopyPublic(selected?),
            KeyCode::Char('x') => KeyRequest::ExportPublic(selected?),
            KeyCode::Char('X') => KeyRequest::ExportPrivate(selected?),
            KeyCode::Char('P') => KeyRequest::ChangePassphrase(selected?),
            KeyCode::Char('t') => KeyRequest::AttachCert(selected?),
            KeyCode::Char('f') => KeyRequest::ToggleForwardable(selected?),
            KeyCode::Char('o') => KeyRequest::ToggleConfirm(selected?),
            KeyCode::Char('H') => KeyRequest::Install(selected?),
            KeyCode::Char('d') => KeyRequest::Delete(selected?),
            _ => return None,
        })
    }

    fn detail(&self) -> KeyDetail<'_> {
        KeyDetail {
            catalog: self.catalog.as_deref(),
            usage: &self.usage,
            now: self.now_secs(),
            offset: self.utc_offset_secs,
        }
    }

    /// Draw the selected key's details (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let lines = match self.list.selected() {
            Some(row) => self.detail().lines_with(row, cx, usize::from(area.width)),
            None => vec![Line::styled("Nothing selected.", cx.theme.dim)],
        };
        let title = self
            .list
            .selected()
            .map_or_else(|| " Details ".to_owned(), |r| format!(" {} ", r.label));
        super::render_pane(frame, area, cx, &title, lines);
    }

    /// Draw the list.
    pub fn render_list(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        self.list
            .render_with(frame, area, cx, &KeyRowRenderer, None);
    }
}

/// Draws a key row: label, type, fingerprint, flags, badge, usage.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyRowRenderer;

impl RowRenderer<KeyRow> for KeyRowRenderer {
    fn spans(&self, row: &KeyRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let dim = if cx.selected { cx.base } else { cx.theme.dim };
        let label = truncate(&row.label, cx.width.min(32));
        let mut used = width(&label);
        let mut spans = highlighted(
            &label,
            cx.highlights,
            cx.base,
            match_style(cx.base, cx.theme),
        );
        if row.badge != ExpiryBadge::None && used + 4 < cx.width {
            let text = format!(" [{}]", row.badge.label());
            used += width(&text);
            let style = if cx.selected {
                cx.base
            } else {
                badge_style(row.badge, cx.theme)
            };
            spans.push(Span::styled(text, style));
        }
        let flags = row.flags.join(" ");
        let usage = match row.used {
            0 => String::new(),
            1 => "used by 1".to_owned(),
            n => format!("used by {n}"),
        };
        for part in [
            row.kind.as_str(),
            row.fingerprint.as_str(),
            flags.as_str(),
            usage.as_str(),
        ] {
            if part.is_empty() {
                continue;
            }
            if used + 4 >= cx.width {
                break;
            }
            let t = truncate(part, cx.width - used - 2);
            used += 2 + width(&t);
            spans.push(Span::styled(format!("  {t}"), dim));
        }
        spans
    }
}

/// The detail lines of a key.
#[derive(Debug, Clone, Copy)]
pub struct KeyDetail<'a> {
    /// The catalog (`None` until loaded).
    pub catalog: Option<&'a HostCatalog>,
    /// Usage per key.
    pub usage: &'a BTreeMap<ItemId, KeyUsage>,
    /// Badges are relative to this (UNIX seconds).
    pub now: u64,
    /// UTC offset for dates (`None`: local).
    pub offset: Option<i32>,
}

fn row(label: &str, value: String, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), theme.dim),
        Span::styled(value, theme.base),
    ])
}

/// A UNIX time in `ui.date_format` (`forever` for the no-expiry sentinel).
pub fn format_secs(secs: u64, fmt: &str, offset: Option<i32>) -> String {
    if secs == sverb_core::keychain::cert::FOREVER {
        return "forever".to_owned();
    }
    let ms = i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    crate::views::logs::list::format_time(sverb_core::model::UnixMillis(ms), fmt, offset)
}

impl KeyDetail<'_> {
    fn lines_with(&self, r: &KeyRow, cx: &RenderCx<'_>, width: usize) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let fmt = &cx.config.ui.date_format;
        let mut lines = vec![row("Label", r.label.clone(), theme)];
        let Some(c) = self.catalog else {
            lines.push(Line::styled("Loading…", theme.dim));
            return lines;
        };
        let Some(k) = c.key_details.get(&r.id) else {
            return lines;
        };
        lines.push(row("Type", r.kind.clone(), theme));
        lines.push(Line::styled(k.fingerprint.clone(), theme.base));
        let private = if k.agent_ref {
            "none (agent / hardware key)"
        } else if k.encrypted && k.has_passphrase {
            "encrypted, passphrase stored"
        } else if k.encrypted {
            "encrypted, asks passphrase"
        } else {
            "plain (vault-protected)"
        };
        lines.push(row("Private key", private.to_owned(), theme));
        let yes_no = |b: bool| if b { "yes" } else { "no" }.to_owned();
        lines.push(row("Forwardable", yes_no(k.agent_forwardable), theme));
        lines.push(row("Confirm use", yes_no(k.confirm_on_use), theme));
        if let Some(v) = c.vault_names.get(&k.vault) {
            lines.push(row("Vault", v.clone(), theme));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("Public key", theme.accent));
        let max = width.saturating_sub(2).max(8);
        let chars: Vec<char> = k.public_key.chars().collect();
        for chunk in chars.chunks(max).take(6) {
            lines.push(Line::styled(chunk.iter().collect::<String>(), theme.base));
        }
        lines.push(Line::raw(""));
        let certs: Vec<_> = certs_of(c, r.id, k).collect();
        lines.push(Line::styled(
            match certs.len() {
                0 => "No certificates".to_owned(),
                1 => "1 certificate".to_owned(),
                n => format!("{n} certificates"),
            },
            theme.accent,
        ));
        for (_, cert) in certs {
            let mut spans = vec![Span::styled(format!("  {}", cert.label), theme.base)];
            match &cert.info {
                Some(info) => {
                    let badge = expiry_badge(info, self.now);
                    if badge != ExpiryBadge::None {
                        spans.push(Span::styled(
                            format!(" [{}]", badge.label()),
                            badge_style(badge, theme),
                        ));
                    }
                    lines.push(Line::from(spans));
                    lines.push(Line::styled(
                        format!(
                            "    until {}",
                            format_secs(info.valid_before, fmt, self.offset)
                        ),
                        theme.dim,
                    ));
                }
                None => {
                    spans.push(Span::styled(" (unreadable)", theme.error));
                    lines.push(Line::from(spans));
                }
            }
        }
        lines.push(Line::raw(""));
        let usage = self.usage.get(&r.id).cloned().unwrap_or_default();
        lines.push(Line::styled(
            match (usage.hosts.len(), usage.identities.len()) {
                (0, 0) => "Not used by any host or identity".to_owned(),
                (h, i) => format!("Used by {h} host(s), {i} identity(ies)"),
            },
            theme.accent,
        ));
        lines.push(Line::raw(""));
        for hint in [
            "a generate · I import · p paste",
            "c copy · x / X export · P passphrase",
            "t attach cert · f forwardable",
            "o confirm · H install · d delete",
        ] {
            lines.push(Line::styled(hint, theme.dim));
        }
        lines
    }
}

impl View for KeysView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        if self.list.handle(ev, cx) == Outcome::Consumed {
            return Outcome::Consumed;
        }
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        match self.on_action_key(key.code, key.modifiers) {
            Some(req) => {
                self.request = Some(req);
                cx.request_redraw();
                Outcome::Consumed
            }
            None => Outcome::Ignored,
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        self.render_list(frame, area, cx);
    }

    fn insert_mode(&self) -> bool {
        KeysView::insert_mode(self)
    }
}
