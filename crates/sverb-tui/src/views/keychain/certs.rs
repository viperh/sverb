//! The Keychain view's Certificates sub-tab (SPEC §4.6, §9.4).
//!
//! - **Rows**: every certificate with the key it certifies, its principals and expiry,
//!   badged yellow when it expires within 7 days and red when expired.
//! - **Detail**: the derived fields (type, key id, serial, principals, validity window
//!   in `ui.date_format`, CA fingerprint), never stored (§4.6).
//! - **Actions** (Normal mode): `a` import a certificate (file; it is attached to the key
//!   with the same public key), `c` copy the certificate line, `d` delete.

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
};
use sverb_core::{
    keychain::cert::{ExpiryBadge, expiry_badge},
    model::ItemId,
};

use super::keys::{badge_style, format_secs};
use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent, hosts::catalog::HostCatalog},
    widgets::{
        form::{highlighted, match_style},
        list::{EmptyState, FilterSource, ListRow, ListView, RowCx, RowRenderer},
        truncate, width,
    },
};

/// One row of the Certificates list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRow {
    /// The certificate.
    pub id: ItemId,
    /// `label`
    pub label: String,
    /// The certified key's label.
    pub key: String,
    /// Comma-separated principals (`(any)` when empty).
    pub principals: String,
    /// `valid_before` (UNIX seconds; 0 when unreadable).
    pub valid_before: u64,
    /// The badge.
    pub badge: ExpiryBadge,
}

impl ListRow for CertRow {
    type Key = ItemId;

    fn key(&self) -> ItemId {
        self.id
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn filter_text(&self) -> String {
        format!("{} {} {}", self.label, self.key, self.principals)
    }

    fn item_id(&self) -> Option<ItemId> {
        Some(self.id)
    }

    fn secondary(&self) -> String {
        self.key.clone()
    }
}

/// What the user asked the Certificates sub-tab for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertRequest {
    /// `a`: import a certificate (attached to the matching key).
    Import,
    /// `c`: copy the certificate line.
    Copy(ItemId),
    /// `d`: delete (asks).
    Delete(ItemId),
}

/// The Certificates sub-tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertsView {
    /// The list.
    pub list: ListView<CertRow>,
    catalog: Option<Arc<HostCatalog>>,
    request: Option<CertRequest>,
    /// Offset east of UTC for dates (`None`: local time; tests pin it).
    pub utc_offset_secs: Option<i32>,
}

impl Default for CertsView {
    fn default() -> Self {
        Self {
            list: ListView::new("Certificates").with_empty(EmptyState::new(
                "No certificates yet",
                &[
                    ("a", "import a certificate"),
                    ("t", "attach one from the Keys tab"),
                ],
            )),
            catalog: None,
            request: None,
            utc_offset_secs: None,
        }
    }
}

impl CertsView {
    /// A new catalog.
    pub fn set_catalog(&mut self, catalog: Arc<HostCatalog>) {
        self.catalog = Some(catalog);
        let rows = self.catalog.as_deref().map(Self::rows).unwrap_or_default();
        self.list.set_rows(rows);
    }

    /// Drop all decrypted data (the vault locked).
    pub fn clear(&mut self) {
        if self.catalog.is_some() || !self.list.rows().is_empty() {
            self.catalog = None;
            self.list.set_source(FilterSource::Local);
            self.list.set_rows(Vec::new());
        }
    }

    /// The pending request, if any.
    pub fn take_request(&mut self) -> Option<CertRequest> {
        self.request.take()
    }

    /// Whether the list edits text (filter line).
    pub fn insert_mode(&self) -> bool {
        self.list.insert_mode()
    }

    /// Put the cursor on a certificate.
    pub fn select(&mut self, id: ItemId) -> bool {
        self.list.select_key(&id)
    }

    fn now(&self) -> u64 {
        self.catalog
            .as_ref()
            .map_or(0, |c| u64::try_from(c.loaded_at / 1000).unwrap_or(0))
    }

    /// The rows of a catalog.
    pub fn rows(catalog: &HostCatalog) -> Vec<CertRow> {
        let now = u64::try_from(catalog.loaded_at / 1000).unwrap_or(0);
        let mut rows: Vec<CertRow> = catalog
            .certs
            .iter()
            .map(|(id, c)| {
                let key = c
                    .key_id
                    .or_else(|| {
                        catalog
                            .key_details
                            .iter()
                            .find(|(_, k)| k.certificate_ids.contains(id))
                            .map(|(k, _)| *k)
                    })
                    .map_or_else(
                        || "(no key)".to_owned(),
                        |k| {
                            catalog.key_details.get(&k).map_or_else(
                                || format!("(missing {})", k.short()),
                                |i| i.label.clone(),
                            )
                        },
                    );
                let (principals, valid_before, badge) = match &c.info {
                    Some(i) => (
                        if i.principals.is_empty() {
                            "(any)".to_owned()
                        } else {
                            i.principals.join(",")
                        },
                        i.valid_before,
                        expiry_badge(i, now),
                    ),
                    None => ("(unreadable)".to_owned(), 0, ExpiryBadge::None),
                };
                CertRow {
                    id: *id,
                    label: c.label.clone(),
                    key,
                    principals,
                    valid_before,
                    badge,
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

    /// The certificate line of `id`.
    pub fn cert_text(&self, id: ItemId) -> Option<String> {
        self.catalog
            .as_ref()?
            .certs
            .get(&id)
            .map(|c| c.cert.clone())
    }

    /// The label of `id`.
    pub fn label_of(&self, id: ItemId) -> Option<String> {
        self.catalog
            .as_ref()?
            .certs
            .get(&id)
            .map(|c| c.label.clone())
    }

    fn on_action_key(&self, code: KeyCode, mods: KeyModifiers) -> Option<CertRequest> {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            return None;
        }
        let selected = self.list.selected_key();
        Some(match code {
            KeyCode::Char('a') => CertRequest::Import,
            KeyCode::Char('c') => CertRequest::Copy(selected?),
            KeyCode::Char('d') => CertRequest::Delete(selected?),
            _ => return None,
        })
    }

    /// Draw the selected certificate's details.
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let row = |l: &str, v: String| {
            Line::from(vec![
                Span::styled(format!("{l:<12}"), theme.dim),
                Span::styled(v, theme.base),
            ])
        };
        let Some(r) = self.list.selected() else {
            super::render_pane(
                frame,
                area,
                cx,
                " Details ",
                vec![Line::styled("Nothing selected.", theme.dim)],
            );
            return;
        };
        let mut lines = vec![row("Label", r.label.clone()), row("Key", r.key.clone())];
        let info = self
            .catalog
            .as_ref()
            .and_then(|c| c.certs.get(&r.id))
            .and_then(|c| c.info.clone());
        match info {
            Some(i) => {
                let fmt = &cx.config.ui.date_format;
                lines.push(row("Type", format!("{} ({})", i.cert_type, i.algorithm)));
                lines.push(row("Key ID", i.key_id.clone()));
                lines.push(row("Serial", i.serial.to_string()));
                lines.push(row("Principals", r.principals.clone()));
                lines.push(row(
                    "Valid from",
                    format_secs(i.valid_after, fmt, self.utc_offset_secs),
                ));
                let mut until = vec![
                    Span::styled(format!("{:<12}", "Valid until"), theme.dim),
                    Span::styled(
                        format_secs(i.valid_before, fmt, self.utc_offset_secs),
                        theme.base,
                    ),
                ];
                let badge = expiry_badge(&i, self.now());
                if badge != ExpiryBadge::None {
                    until.push(Span::styled(
                        format!(" [{}]", badge.label()),
                        badge_style(badge, theme),
                    ));
                }
                lines.push(Line::from(until));
                lines.push(Line::styled("CA", theme.dim));
                lines.push(Line::styled(format!("  {}", i.ca_fingerprint), theme.base));
                lines.push(Line::styled("Certifies", theme.dim));
                lines.push(Line::styled(format!("  {}", i.key_fingerprint), theme.base));
            }
            None => lines.push(Line::styled(
                "The certificate could not be parsed.",
                theme.error,
            )),
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("a import · c copy · d delete", theme.dim));
        super::render_pane(frame, area, cx, &format!(" {} ", r.label), lines);
    }
}

/// Draws a certificate row: label, badge, key, principals.
#[derive(Debug, Clone, Copy, Default)]
pub struct CertRowRenderer;

impl RowRenderer<CertRow> for CertRowRenderer {
    fn spans(&self, row: &CertRow, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let theme: &Theme = cx.theme;
        let dim = if cx.selected { cx.base } else { theme.dim };
        let label = truncate(&row.label, cx.width.min(32));
        let mut used = width(&label);
        let mut spans = highlighted(&label, cx.highlights, cx.base, match_style(cx.base, theme));
        if row.badge != ExpiryBadge::None && used + 4 < cx.width {
            let text = format!(" [{}]", row.badge.label());
            used += width(&text);
            let style = if cx.selected {
                cx.base
            } else {
                badge_style(row.badge, theme)
            };
            spans.push(Span::styled(text, style));
        }
        for part in [format!("key: {}", row.key), row.principals.clone()] {
            if used + 4 >= cx.width {
                break;
            }
            let t = truncate(&part, cx.width - used - 2);
            used += 2 + width(&t);
            spans.push(Span::styled(format!("  {t}"), dim));
        }
        spans
    }
}

impl View for CertsView {
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
        self.list
            .render_with(frame, area, cx, &CertRowRenderer, None);
    }

    fn insert_mode(&self) -> bool {
        CertsView::insert_mode(self)
    }
}
