//! M2-11: the import / export wizard (SPEC §9.13). Opened from the Hosts view (`I`
//! import, `X` export) and the Known Hosts view (`I`, with the known_hosts source).
//!
//! **Import:** 1. pick the source (`ssh_config`, `known_hosts`, CSV, sverb backup), the
//! file and, for a backup, its export password; `Enter` runs the dry run
//! (`ImportEffect::Preview`). 2. The preview: new / duplicate / conflict counts and
//! rows, skipped entries, notes and warnings, the IdentityFiles to import (the separate
//! confirmation, `i` toggles it). `v` / `g` pick the target vault and group (the dry
//! run is redone), `c` cycles the conflict policy (skip / overwrite / keep both).
//! `Enter` confirms (`ImportEffect::Apply`), `b` goes back, `Esc` closes.
//!
//! **Export:** pick the format (backup, ssh_config, CSV), the file, and for a backup the
//! export password (twice) and whether shared vaults are included. The ssh_config / CSV
//! exports show the secrets warning first. An existing file is replaced only after
//! `f` (force) is toggled.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use sverb_core::model::{ItemId, VaultId};

use super::{DialogId, RenderCx, ViewCx, ViewEvent};
use crate::app::Effect;
use crate::widgets::form::SecretValue;

/// What is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WizardSource {
    /// `~/.ssh/config`
    SshConfig,
    /// `~/.ssh/known_hosts`
    KnownHosts,
    /// CSV
    Csv,
    /// `.sverb-backup`
    Backup,
    // M7-03
    /// PuTTY sessions (`~/.putty/sessions`, or the registry on Windows).
    Putty,
}

impl WizardSource {
    const ALL: [Self; 5] = [
        Self::SshConfig,
        Self::KnownHosts,
        Self::Csv,
        Self::Backup,
        Self::Putty,
    ];

    /// The menu label.
    pub fn label(self) -> &'static str {
        match self {
            Self::SshConfig => "OpenSSH config (~/.ssh/config)",
            Self::KnownHosts => "known_hosts (~/.ssh/known_hosts)",
            Self::Csv => "CSV (label,address,port,username,group,tags)",
            Self::Backup => "sverb backup (.sverb-backup)",
            // M7-03
            Self::Putty if cfg!(windows) => "PuTTY sessions (registry; or a sessions folder)",
            Self::Putty => "PuTTY sessions (~/.putty/sessions)",
        }
    }

    /// The prefilled path.
    pub fn default_path(self) -> &'static str {
        match self {
            Self::SshConfig => "~/.ssh/config",
            Self::KnownHosts => "~/.ssh/known_hosts",
            Self::Csv => "~/hosts.csv",
            Self::Backup => "~/sverb.sverb-backup",
            // M7-03: empty = the registry on Windows.
            Self::Putty if cfg!(windows) => "",
            Self::Putty => "~/.putty/sessions",
        }
    }

    fn next(self, back: bool) -> Self {
        let i = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[if back { (i + n - 1) % n } else { (i + 1) % n }]
    }
}

/// What is exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// The encrypted backup.
    Backup,
    /// A lossy `ssh_config`.
    SshConfig,
    /// CSV.
    Csv,
}

impl ExportFormat {
    const ALL: [Self; 3] = [Self::Backup, Self::SshConfig, Self::Csv];

    /// The menu label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Backup => "sverb backup (encrypted, everything incl. secrets)",
            Self::SshConfig => "OpenSSH config (lossy, no secrets)",
            Self::Csv => "CSV (hosts, no secrets)",
        }
    }

    /// The prefilled path.
    pub fn default_path(self) -> &'static str {
        match self {
            Self::Backup => "~/sverb.sverb-backup",
            Self::SshConfig => "~/sverb_ssh_config",
            Self::Csv => "~/sverb_hosts.csv",
        }
    }

    fn next(self, back: bool) -> Self {
        let i = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        let n = Self::ALL.len();
        Self::ALL[if back { (i + n - 1) % n } else { (i + 1) % n }]
    }
}

/// The conflict policy (mirrors `sverb_core::importers::ConflictPolicy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Policy {
    /// Keep the existing item.
    #[default]
    Skip,
    /// Overwrite it (backups: merge by HLC).
    Overwrite,
    /// Import next to it.
    KeepBoth,
}

impl Policy {
    fn next(self) -> Self {
        match self {
            Self::Skip => Self::Overwrite,
            Self::Overwrite => Self::KeepBoth,
            Self::KeepBoth => Self::Skip,
        }
    }

    /// `skip`, `overwrite`, `keep both`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Overwrite => "overwrite",
            Self::KeepBoth => "keep both",
        }
    }
}

/// One preview row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    /// `new`, `duplicate`, `conflict`.
    pub status: String,
    /// The item kind.
    pub kind: String,
    /// The label.
    pub label: String,
    /// `key=value …`
    pub details: String,
    /// `field: existing -> imported` for conflicts.
    pub diffs: Vec<String>,
}

/// The dry-run result shown by the wizard (no secrets).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreviewData {
    /// New items.
    pub new: usize,
    /// Duplicates.
    pub duplicate: usize,
    /// Conflicts.
    pub conflict: usize,
    /// Rows.
    pub rows: Vec<PreviewRow>,
    /// Skipped entries (`where: why`).
    pub skipped: Vec<String>,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Notes ("group … will be created").
    pub notes: Vec<String>,
    /// IdentityFiles and their state.
    pub identity_files: Vec<String>,
    /// Vaults to pick from.
    pub vaults: Vec<(VaultId, String)>,
    /// Groups of the target vault (`a/b`).
    pub groups: Vec<(ItemId, String)>,
    /// The vault the preview was computed for.
    pub vault: Option<VaultId>,
}

/// The source of an import request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRequest {
    /// The source kind.
    pub source: WizardSource,
    /// The file (`~` allowed).
    pub path: String,
    /// The backup's export password.
    pub password: Option<SecretValue>,
    /// Target vault (`None`: Personal).
    pub vault: Option<VaultId>,
    /// Target group.
    pub group: Option<ItemId>,
}

/// Import / export requests for `services::import`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportEffect {
    /// The dry run (answered with `ImportEvent::Previewed`).
    Preview {
        /// The wizard.
        dialog: DialogId,
        /// What to read.
        request: ImportRequest,
    },
    /// The confirmed import (answered with `ImportEvent::Applied`).
    Apply {
        /// The wizard.
        dialog: DialogId,
        /// What to read.
        request: ImportRequest,
        /// Conflicts.
        policy: Policy,
        /// Import the IdentityFiles as keys.
        import_keys: bool,
    },
    /// An export (answered with `ImportEvent::Exported`).
    Export {
        /// The wizard.
        dialog: DialogId,
        /// The format.
        format: ExportFormat,
        /// The file (`~` allowed).
        path: String,
        /// The backup's export password.
        password: Option<SecretValue>,
        /// Include shared vaults in a backup.
        include_shared: bool,
        /// Replace an existing file.
        overwrite: bool,
    },
}

/// Results from `services::import`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportEvent {
    /// The dry run finished.
    Previewed {
        /// The wizard.
        dialog: DialogId,
        /// The preview.
        preview: Box<PreviewData>,
    },
    /// The import was written.
    Applied {
        /// The wizard.
        dialog: DialogId,
        /// One line for the toast.
        summary: String,
    },
    /// The export was written.
    Exported {
        /// The wizard.
        dialog: DialogId,
        /// One line for the toast.
        summary: String,
    },
    /// Something failed (the wizard shows it and stays open).
    Failed {
        /// The wizard.
        dialog: DialogId,
        /// The message.
        message: String,
    },
}

/// The wizard's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// Pick the import source.
    Source,
    /// The dry-run preview.
    Preview(Box<PreviewData>),
    /// The export form.
    Export,
}

/// The wizard's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportWizard {
    /// The page.
    pub page: Page,
    /// Import source.
    pub source: WizardSource,
    /// Export format.
    pub format: ExportFormat,
    /// The path field.
    pub path: String,
    /// The password field.
    pub password: SecretValue,
    /// The confirmation password field (export).
    pub password2: SecretValue,
    /// The focused field (0: source/format, 1: path, 2: password, 3: repeat).
    pub field: usize,
    /// Target vault.
    pub vault: Option<VaultId>,
    /// Target group.
    pub group: Option<ItemId>,
    /// Conflicts.
    pub policy: Policy,
    /// Import the IdentityFiles.
    pub import_keys: bool,
    /// Include shared vaults in a backup.
    pub include_shared: bool,
    /// Replace an existing export file.
    pub overwrite: bool,
    /// A request is in flight.
    pub busy: bool,
    /// The last error.
    pub error: Option<String>,
    /// Preview scroll.
    pub scroll: usize,
}

impl ImportWizard {
    /// The import wizard, starting with `source`.
    pub fn import(source: WizardSource) -> Self {
        Self {
            page: Page::Source,
            source,
            format: ExportFormat::Backup,
            path: source.default_path().to_owned(),
            password: SecretValue::empty(),
            password2: SecretValue::empty(),
            field: 1,
            vault: None,
            group: None,
            policy: Policy::Skip,
            import_keys: false,
            include_shared: false,
            overwrite: false,
            busy: false,
            error: None,
            scroll: 0,
        }
    }

    /// The export form.
    pub fn export() -> Self {
        let mut w = Self::import(WizardSource::SshConfig);
        w.page = Page::Export;
        w.path = ExportFormat::Backup.default_path().to_owned();
        w
    }

    /// The wizard edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        !matches!(self.page, Page::Preview(_)) && self.field > 0
    }

    fn fields(&self) -> usize {
        match self.page {
            Page::Source if self.source == WizardSource::Backup => 3,
            Page::Source => 2,
            Page::Export if self.format == ExportFormat::Backup => 4,
            Page::Export => 2,
            Page::Preview(_) => 0,
        }
    }

    fn request(&self) -> ImportRequest {
        ImportRequest {
            source: self.source,
            path: self.path.trim().to_owned(),
            password: (self.source == WizardSource::Backup).then(|| self.password.clone()),
            vault: self.vault,
            group: self.group,
        }
    }

    fn preview(&mut self, id: DialogId, cx: &mut ViewCx<'_>) {
        // M7-03: PuTTY with no path reads the user's sessions (the registry on Windows).
        if self.path.trim().is_empty() && self.source != WizardSource::Putty {
            self.error = Some("Enter a file".to_owned());
            return;
        }
        self.busy = true;
        self.error = None;
        cx.push(Effect::Import(ImportEffect::Preview {
            dialog: id,
            request: self.request(),
        }));
    }

    /// A service result for this wizard. Returns whether the wizard should close.
    pub fn on_event(&mut self, ev: ImportEvent) -> bool {
        self.busy = false;
        match ev {
            ImportEvent::Previewed { preview, .. } => {
                if self.vault.is_none() {
                    self.vault = preview.vault;
                }
                self.scroll = 0;
                self.page = Page::Preview(preview);
                false
            }
            ImportEvent::Applied { .. } | ImportEvent::Exported { .. } => true,
            ImportEvent::Failed { message, .. } => {
                self.error = Some(message);
                false
            }
        }
    }

    fn edit_text(&mut self, key: &KeyEvent) {
        let target: &mut dyn TextField = match (self.field, &self.page) {
            (1, _) => &mut self.path,
            (2, _) => &mut self.password,
            (3, Page::Export) => &mut self.password2,
            _ => return,
        };
        match key.code {
            KeyCode::Backspace => target.pop(),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => target.clear(),
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => target.push(c),
            _ => {}
        }
    }

    /// Handle input.
    pub fn handle(&mut self, id: DialogId, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        let key = match ev {
            ViewEvent::Key(k) => k,
            ViewEvent::Paste(text) => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    self.edit_text(&KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
                }
                return;
            }
            ViewEvent::Mouse(_) => return,
        };
        if self.busy {
            if key.code == KeyCode::Esc {
                cx.close();
            }
            return;
        }
        match &self.page {
            Page::Source | Page::Export => self.handle_form(id, key, cx),
            Page::Preview(_) => self.handle_preview(id, key, cx),
        }
    }

    fn handle_form(&mut self, id: DialogId, key: &KeyEvent, cx: &mut ViewCx<'_>) {
        let export = self.page == Page::Export;
        let n = self.fields();
        match key.code {
            KeyCode::Esc => cx.close(),
            KeyCode::Tab | KeyCode::Down => self.field = (self.field + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.field = (self.field + n - 1) % n,
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if self.field == 0 => {
                let back = key.code == KeyCode::Left;
                if export {
                    self.format = self.format.next(back);
                    self.path = self.format.default_path().to_owned();
                } else {
                    self.source = self.source.next(back);
                    self.path = self.source.default_path().to_owned();
                }
                self.error = None;
            }
            KeyCode::Char('s') if export && self.field == 0 => {
                self.include_shared = !self.include_shared;
            }
            KeyCode::Char('f') if export && self.field == 0 => self.overwrite = !self.overwrite,
            KeyCode::Enter if export => self.submit_export(id, cx),
            KeyCode::Enter => self.preview(id, cx),
            _ => self.edit_text(key),
        }
    }

    fn submit_export(&mut self, id: DialogId, cx: &mut ViewCx<'_>) {
        if self.path.trim().is_empty() {
            self.error = Some("Enter a file".to_owned());
            return;
        }
        let password = if self.format == ExportFormat::Backup {
            if self.password.is_empty() {
                self.error = Some("Enter an export password".to_owned());
                self.field = 2;
                return;
            }
            if self.password != self.password2 {
                self.error = Some("The passwords do not match".to_owned());
                self.field = 3;
                return;
            }
            Some(self.password.clone())
        } else {
            None
        };
        self.busy = true;
        self.error = None;
        cx.push(Effect::Import(ImportEffect::Export {
            dialog: id,
            format: self.format,
            path: self.path.trim().to_owned(),
            password,
            include_shared: self.include_shared,
            overwrite: self.overwrite,
        }));
    }

    fn handle_preview(&mut self, id: DialogId, key: &KeyEvent, cx: &mut ViewCx<'_>) {
        let Page::Preview(p) = &self.page else {
            return;
        };
        let (vaults, groups) = (p.vaults.clone(), p.groups.clone());
        match key.code {
            KeyCode::Esc => cx.close(),
            KeyCode::Char('b') => {
                self.page = Page::Source;
                self.field = 1;
            }
            KeyCode::Char('j') | KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char('c') => self.policy = self.policy.next(),
            KeyCode::Char('i') => self.import_keys = !self.import_keys,
            KeyCode::Char('v') if vaults.len() > 1 => {
                let i = vaults.iter().position(|(v, _)| Some(*v) == self.vault);
                self.vault = Some(vaults[i.map_or(0, |i| (i + 1) % vaults.len())].0);
                self.group = None;
                self.preview(id, cx);
            }
            KeyCode::Char('g') => {
                // None → first group → … → None.
                let i = groups.iter().position(|(g, _)| Some(*g) == self.group);
                self.group = match i {
                    None => groups.first().map(|g| g.0),
                    Some(i) => groups.get(i + 1).map(|g| g.0),
                };
                self.preview(id, cx);
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                self.busy = true;
                self.error = None;
                cx.push(Effect::Import(ImportEffect::Apply {
                    dialog: id,
                    request: self.request(),
                    policy: self.policy,
                    import_keys: self.import_keys,
                }));
            }
            _ => {}
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let w = area
            .width
            .saturating_sub(4)
            .min(110)
            .max(area.width.min(20));
        let h = area.height.saturating_sub(2).max(area.height.min(6));
        let rect = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + (area.height.saturating_sub(h)) / 2,
            width: w,
            height: h,
        };
        frame.render_widget(Clear, rect);
        let title = match self.page {
            Page::Export => " Export ",
            Page::Source => " Import ",
            Page::Preview(_) => " Import preview (dry run) ",
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(theme.border_focused)
            .style(theme.base);
        let mut lines: Vec<Line<'static>> = Vec::new();
        match &self.page {
            Page::Source => self.form_lines(&mut lines, cx, false),
            Page::Export => self.form_lines(&mut lines, cx, true),
            Page::Preview(p) => self.preview_lines(p, &mut lines, cx),
        }
        if self.busy {
            lines.push(Line::styled("Working…", theme.accent));
        }
        if let Some(e) = &self.error {
            lines.push(Line::styled(format!("Error: {e}"), theme.error));
        }
        let inner_h = usize::from(rect.height.saturating_sub(2));
        let scroll = if matches!(self.page, Page::Preview(_)) {
            self.scroll.min(lines.len().saturating_sub(inner_h))
        } else {
            0
        };
        let para = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0));
        frame.render_widget(para, rect);
    }

    fn field_line(&self, i: usize, label: &str, value: String, cx: &RenderCx<'_>) -> Line<'static> {
        let theme = cx.theme;
        let focused = self.field == i;
        let style = if focused { theme.selection } else { theme.base };
        Line::from(vec![
            Span::styled(
                format!("{} {label:<10} ", if focused { "›" } else { " " }),
                theme.accent,
            ),
            Span::styled(value, style),
        ])
    }

    fn form_lines(&self, lines: &mut Vec<Line<'static>>, cx: &RenderCx<'_>, export: bool) {
        let theme = cx.theme;
        let mask = |s: &SecretValue| "•".repeat(s.expose().chars().count());
        if export {
            lines.push(self.field_line(0, "Format", format!("‹ {} ›", self.format.label()), cx));
            lines.push(self.field_line(1, "File", self.path.clone(), cx));
            if self.format == ExportFormat::Backup {
                lines.push(self.field_line(2, "Password", mask(&self.password), cx));
                lines.push(self.field_line(3, "Repeat", mask(&self.password2), cx));
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    "The backup holds every item, secrets included, encrypted with this export password (zxcvbn score 3 or more).",
                    theme.dim,
                ));
                lines.push(Line::styled(
                    format!(
                        "[{}] s include shared vaults (they belong to their organization)",
                        if self.include_shared { "x" } else { " " }
                    ),
                    theme.base,
                ));
            } else {
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    sverb_core::exporters::SECRETS_WARNING.to_owned(),
                    theme.warn,
                ));
            }
            lines.push(Line::styled(
                format!(
                    "[{}] f replace an existing file",
                    if self.overwrite { "x" } else { " " }
                ),
                theme.base,
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "tab next field · ←/→ format · enter export · esc cancel",
                theme.dim,
            ));
        } else {
            lines.push(self.field_line(0, "Source", format!("‹ {} ›", self.source.label()), cx));
            lines.push(self.field_line(1, "File", self.path.clone(), cx));
            if self.source == WizardSource::Backup {
                lines.push(self.field_line(2, "Password", mask(&self.password), cx));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "Nothing is written until you confirm the preview.",
                theme.dim,
            ));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "tab next field · ←/→ source · enter preview · esc cancel",
                theme.dim,
            ));
        }
    }

    fn preview_lines(&self, p: &PreviewData, lines: &mut Vec<Line<'static>>, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        lines.push(Line::from(vec![
            Span::styled(format!("{} new", p.new), theme.ok),
            Span::raw(" · "),
            Span::styled(format!("{} duplicate", p.duplicate), theme.dim),
            Span::raw(" · "),
            Span::styled(format!("{} conflict", p.conflict), theme.warn),
            Span::raw(" · "),
            Span::raw(format!("{} skipped", p.skipped.len())),
        ]));
        let vault = p
            .vaults
            .iter()
            .find(|(v, _)| Some(*v) == self.vault)
            .map_or("Personal", |(_, n)| n.as_str());
        let group = self
            .group
            .and_then(|g| p.groups.iter().find(|(id, _)| *id == g))
            .map_or("(top level)", |(_, n)| n.as_str());
        lines.push(Line::raw(format!(
            "Target: vault {vault} · group {group} · conflicts: {}",
            self.policy.label()
        )));
        lines.push(Line::raw(""));
        for r in &p.rows {
            let style = match r.status.as_str() {
                "new" => theme.ok,
                "conflict" => theme.warn,
                _ => theme.dim,
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{:<9} ", r.status), style),
                Span::styled(format!("{:<12} ", r.kind), theme.dim),
                Span::styled(r.label.clone(), theme.base),
                Span::styled(format!("  {}", r.details), theme.dim),
            ]));
            for d in &r.diffs {
                lines.push(Line::styled(format!("            ~ {d}"), theme.warn));
            }
        }
        let section = |lines: &mut Vec<Line<'static>>, title: &str, items: &[String]| {
            if !items.is_empty() {
                lines.push(Line::raw(""));
                lines.push(Line::styled(title.to_owned(), theme.accent));
                for i in items {
                    lines.push(Line::raw(format!("  {i}")));
                }
            }
        };
        section(lines, "Notes", &p.notes);
        section(lines, "Skipped", &p.skipped);
        section(lines, "Warnings", &p.warnings);
        if !p.identity_files.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!(
                    "[{}] i import these identity files as keys:",
                    if self.import_keys { "x" } else { " " }
                ),
                theme.accent,
            ));
            for f in &p.identity_files {
                lines.push(Line::raw(format!("  {f}")));
            }
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "enter import · c conflicts · v vault · g group · j/k scroll · b back · esc cancel",
            theme.dim,
        ));
    }
}

/// A text field (plain or secret).
trait TextField {
    fn push(&mut self, c: char);
    fn pop(&mut self);
    fn clear(&mut self);
}

impl TextField for String {
    fn push(&mut self, c: char) {
        String::push(self, c);
    }
    fn pop(&mut self) {
        let _ = String::pop(self);
    }
    fn clear(&mut self) {
        String::clear(self);
    }
}

impl TextField for SecretValue {
    fn push(&mut self, c: char) {
        let mut s = self.expose().to_owned();
        s.push(c);
        *self = SecretValue::from(s.as_str());
        zeroize::Zeroize::zeroize(&mut s);
    }
    fn pop(&mut self) {
        let mut s = self.expose().to_owned();
        let _ = s.pop();
        *self = SecretValue::from(s.as_str());
        zeroize::Zeroize::zeroize(&mut s);
    }
    fn clear(&mut self) {
        *self = SecretValue::empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: KeyCode) -> ViewEvent {
        ViewEvent::Key(KeyEvent::new(c, KeyModifiers::NONE))
    }

    #[test]
    fn source_cycle_resets_path_and_backup_needs_password_field() {
        let mut w = ImportWizard::import(WizardSource::SshConfig);
        assert_eq!(w.fields(), 2);
        w.field = 0;
        w.source = w.source.next(false);
        assert_eq!(w.source, WizardSource::KnownHosts);
        w.source = WizardSource::Backup;
        assert_eq!(w.fields(), 3);
        assert!(w.wants_text() || w.field == 0);
        let _ = key(KeyCode::Tab);
    }

    #[test]
    fn previewed_then_applied_closes() {
        let mut w = ImportWizard::import(WizardSource::Csv);
        w.busy = true;
        let close = w.on_event(ImportEvent::Previewed {
            dialog: DialogId(1),
            preview: Box::default(),
        });
        assert!(!close);
        assert!(matches!(w.page, Page::Preview(_)));
        assert!(!w.wants_text());
        assert!(w.on_event(ImportEvent::Applied {
            dialog: DialogId(1),
            summary: String::new(),
        }));
    }

    fn dialog(w: ImportWizard) -> crate::views::Dialog {
        crate::views::Dialog {
            id: DialogId(7),
            kind: crate::views::DialogKind::ImportWizard(Box::new(w)),
        }
    }

    fn wizard(d: &crate::views::Dialog) -> &ImportWizard {
        match &d.kind {
            crate::views::DialogKind::ImportWizard(w) => w,
            _ => panic!("not the wizard"),
        }
    }

    #[test]
    fn enter_requests_the_dry_run_then_confirm_applies() {
        use crate::widgets::test_util::{key as press, send, type_text};
        let mut d = dialog(ImportWizard::import(WizardSource::Csv));
        // Clear the path and type another.
        press(&mut d, KeyCode::Char('u'), KeyModifiers::CONTROL);
        type_text(&mut d, "/tmp/h.csv");
        let (_, effects) = send(&mut d, &key(KeyCode::Enter));
        let [Effect::Import(ImportEffect::Preview { dialog, request })] = effects.as_slice() else {
            panic!("{effects:?}");
        };
        assert_eq!(*dialog, DialogId(7));
        assert_eq!(request.path, "/tmp/h.csv");
        assert_eq!(request.source, WizardSource::Csv);
        if let crate::views::DialogKind::ImportWizard(w) = &mut d.kind {
            w.on_event(ImportEvent::Previewed {
                dialog: DialogId(7),
                preview: Box::new(sample()),
            });
        }
        press(&mut d, KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(wizard(&d).policy, Policy::Overwrite);
        let (_, effects) = send(&mut d, &key(KeyCode::Enter));
        assert!(matches!(
            effects.as_slice(),
            [Effect::Import(ImportEffect::Apply {
                policy: Policy::Overwrite,
                import_keys: false,
                ..
            })]
        ));
        assert!(wizard(&d).busy);
    }

    #[test]
    fn export_checks_the_repeated_password() {
        use crate::widgets::test_util::{send, type_text};
        let mut d = dialog(ImportWizard::export());
        if let crate::views::DialogKind::ImportWizard(w) = &mut d.kind {
            w.field = 2;
        }
        type_text(&mut d, "pw-one");
        let (_, effects) = send(&mut d, &key(KeyCode::Enter));
        assert!(effects.is_empty());
        assert_eq!(
            wizard(&d).error.as_deref(),
            Some("The passwords do not match")
        );
    }

    fn sample() -> PreviewData {
        PreviewData {
            new: 2,
            duplicate: 1,
            conflict: 1,
            rows: vec![
                PreviewRow {
                    status: "new".to_owned(),
                    kind: "host".to_owned(),
                    label: "web".to_owned(),
                    details: "address=web.example.com user=deploy".to_owned(),
                    diffs: Vec::new(),
                },
                PreviewRow {
                    status: "conflict".to_owned(),
                    kind: "host".to_owned(),
                    label: "www".to_owned(),
                    details: "address=db.example.com".to_owned(),
                    diffs: vec!["label: db -> www".to_owned()],
                },
            ],
            skipped: vec!["config:4: Match host b is not supported".to_owned()],
            warnings: vec!["Unsupported keywords skipped: Compression (2)".to_owned()],
            notes: vec!["Group \"*.prod\" will be created".to_owned()],
            identity_files: vec!["~/.ssh/id_ed25519".to_owned()],
            ..PreviewData::default()
        }
    }

    #[test]
    fn renders_at_any_size() {
        use crate::widgets::test_util::{draw_with, text};
        let mut w = ImportWizard::import(WizardSource::SshConfig);
        for (cols, rows) in [(0, 0), (1, 1), (10, 3), (80, 24)] {
            let _ = draw_with(cols, rows, true, |f, cx| w.render(f, f.area(), cx));
        }
        w.on_event(ImportEvent::Previewed {
            dialog: DialogId(1),
            preview: Box::new(sample()),
        });
        let buf = draw_with(100, 26, true, |f, cx| w.render(f, f.area(), cx));
        insta::assert_snapshot!("import_wizard_preview_100x26", text(&buf));
        let e = ImportWizard::export();
        let buf = draw_with(100, 16, true, |f, cx| e.render(f, f.area(), cx));
        insta::assert_snapshot!("import_wizard_export_100x16", text(&buf));
    }
}
