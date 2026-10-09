//! The Keychain section (SPEC §8.5): sub-tabs **Keys | Certificates | Identities**.
//!
//! - The section view with its sub-tab bar and the [`identities`] sub-tab
//!   (list, detail, CRUD dialogs in [`identity_form`]).
//! - The [`keys`] and [`certs`] sub-tabs (generate, import, export, passphrase,
//!   certificates; the dialogs are in [`generate_form`] and [`import_dialog`]). Keys is
//!   the default sub-tab.
//!
//! `[` / `]` switch sub-tabs (Normal mode); every other key goes to the active
//! sub-tab. Requests are taken by the reducer (`app/keychain.rs`).

pub mod certs;
pub mod generate_form;
pub mod identities;
pub mod identity_form;
pub mod import_dialog;
pub mod keys;
// Install key on host (picker, results).
pub mod install;

#[cfg(test)]
pub(crate) mod tests;

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use sverb_core::search::IndexSnapshot;

use self::identities::{IdentitiesView, IdentityRequest};
use self::{
    certs::{CertRequest, CertsView},
    keys::{KeyRequest, KeysView},
};
use super::{Outcome, RenderCx, View, ViewCx, ViewEvent, hosts::catalog::HostCatalog};
use sverb_core::model::ItemId;

/// The Keychain sub-tabs, in tab-bar order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeychainTab {
    /// SSH keys.
    Keys,
    /// Certificates.
    Certificates,
    /// Identities.
    Identities,
}

impl KeychainTab {
    /// Every sub-tab, in order.
    pub const ALL: [Self; 3] = [Self::Keys, Self::Certificates, Self::Identities];

    /// The tab label.
    pub fn title(self) -> &'static str {
        match self {
            Self::Keys => "Keys",
            Self::Certificates => "Certificates",
            Self::Identities => "Identities",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// The next (`forward`) or previous sub-tab, wrapping.
    pub fn cycle(self, forward: bool) -> Self {
        let n = Self::ALL.len();
        let i = self.index();
        Self::ALL[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }]
    }

    /// Whether the sub-tab exists in this build (all of them).
    pub fn available(self) -> bool {
        true
    }
}

/// What the Keychain view asks the reducer for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeychainRequest {
    /// An Identities sub-tab request.
    Identity(IdentityRequest),
    /// A Keys sub-tab request.
    Key(KeyRequest),
    /// A Certificates sub-tab request.
    Cert(CertRequest),
}

/// The Keychain section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainView {
    /// The active sub-tab.
    pub tab: KeychainTab,
    /// The Identities sub-tab.
    pub identities: IdentitiesView,
    /// The Keys sub-tab.
    pub keys: KeysView,
    /// The Certificates sub-tab.
    pub certs: CertsView,
    /// The keychain operation in flight (`app/keychain/keys.rs`).
    pub keys_op: Option<crate::app::keychain::keys::KeyOp>,
    /// The last keychain token issued.
    pub next_token: u64,
    /// A new key to select once the catalog has it.
    pub pending_select: Option<ItemId>,
    /// Session ids of install-run connections still running (their prompt answers go
    /// to the run, not to a session).
    pub install_sessions: std::collections::BTreeSet<crate::app::SessionId>,
}

impl Default for KeychainView {
    fn default() -> Self {
        Self {
            // Keys is the first sub-tab.
            tab: KeychainTab::Keys,
            identities: IdentitiesView::default(),
            keys: KeysView::default(),
            certs: CertsView::default(),
            keys_op: None,
            next_token: 0,
            pending_select: None,
            install_sessions: std::collections::BTreeSet::new(),
        }
    }
}

impl KeychainView {
    /// A new index snapshot.
    pub fn set_index(&mut self, index: Arc<IndexSnapshot>) {
        self.identities.set_index(index);
    }

    /// A new catalog (identities, hosts, key names).
    pub fn set_catalog(&mut self, catalog: Arc<HostCatalog>) {
        self.keys.set_catalog(Arc::clone(&catalog));
        self.certs.set_catalog(Arc::clone(&catalog));
        if let Some(id) = self.pending_select
            && self.keys.select(id)
        {
            self.pending_select = None;
        }
        self.identities.set_catalog(catalog);
    }

    /// Drop all decrypted data (the vault locked).
    pub fn clear(&mut self) {
        self.identities.clear();
        self.keys.clear();
        self.certs.clear();
        self.keys_op = None;
        self.pending_select = None;
    }

    /// Whether the active sub-tab edits text (filter line: Insert mode).
    pub fn insert_mode(&self) -> bool {
        match self.tab {
            KeychainTab::Identities => self.identities.insert_mode(),
            KeychainTab::Keys => self.keys.insert_mode(),
            KeychainTab::Certificates => self.certs.insert_mode(),
        }
    }

    /// The pending request, if any.
    pub fn take_request(&mut self) -> Option<KeychainRequest> {
        self.identities
            .take_request()
            .map(KeychainRequest::Identity)
            .or_else(|| self.keys.take_request().map(KeychainRequest::Key))
            .or_else(|| self.certs.take_request().map(KeychainRequest::Cert))
    }

    /// Draw the active sub-tab's detail (the shell's detail pane).
    pub fn render_detail(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match self.tab {
            KeychainTab::Identities => self.identities.render_detail(frame, area, cx),
            KeychainTab::Keys => self.keys.render_detail(frame, area, cx),
            KeychainTab::Certificates => self.certs.render_detail(frame, area, cx),
        }
    }

    fn tab_line(&self, cx: &RenderCx<'_>) -> Line<'static> {
        let mut spans = Vec::new();
        for (i, tab) in KeychainTab::ALL.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" │ ", cx.theme.dim));
            }
            let text = if *tab == self.tab {
                format!("[{}]", tab.title())
            } else {
                format!(" {} ", tab.title())
            };
            let style = if *tab == self.tab {
                cx.theme.title_for(cx.focused)
            } else {
                cx.theme.dim
            };
            spans.push(Span::styled(text, style));
        }
        spans.push(Span::styled("   [ ] switch", cx.theme.dim));
        Line::from(spans)
    }
}

/// A bordered pane with `title` and wrapped `lines` (detail panes, placeholders).
pub(crate) fn render_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    cx: &RenderCx<'_>,
    title: &str,
    lines: Vec<Line<'static>>,
) {
    let theme = cx.theme;
    let block = Block::bordered()
        .title(Span::styled(title.to_owned(), theme.title_for(cx.focused)))
        .border_style(theme.border_for(cx.focused));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block)
            .style(theme.base),
        area,
    );
}

impl View for KeychainView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        if let ViewEvent::Key(key) = ev
            && !self.insert_mode()
            && !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Char('[' | ']'))
        {
            self.tab = self.tab.cycle(key.code == KeyCode::Char(']'));
            cx.request_redraw();
            return Outcome::Consumed;
        }
        match self.tab {
            KeychainTab::Identities => self.identities.handle(ev, cx),
            KeychainTab::Keys => self.keys.handle(ev, cx),
            KeychainTab::Certificates => self.certs.handle(ev, cx),
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        if area.width < 3 || area.height < 2 {
            return;
        }
        frame.render_widget(
            Paragraph::new(self.tab_line(cx)).style(cx.theme.base),
            Rect { height: 1, ..area },
        );
        let body = Rect {
            y: area.y + 1,
            height: area.height - 1,
            ..area
        };
        match self.tab {
            KeychainTab::Identities => self.identities.render(frame, body, cx),
            KeychainTab::Keys => self.keys.render(frame, body, cx),
            KeychainTab::Certificates => self.certs.render(frame, body, cx),
        }
    }

    fn insert_mode(&self) -> bool {
        KeychainView::insert_mode(self)
    }
}
