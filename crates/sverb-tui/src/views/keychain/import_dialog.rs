//! The keychain dialogs (`IdentityDialog::Keychain`, the Keychain section's
//! dialog slot on the stack).
//!
//! Every dialog records its answer ([`KeychainDialog::take_answer`]); the reducer
//! (`app/keychain/keys.rs`) takes it after the dispatch and drives the operation:
//!
//! - **Path prompts** (import a key / certificate, export public / private): `~`
//!   expansion happens in the service; `Tab` asks the service to complete the path
//!   (`KeychainEffect::CompletePath`, no I/O in the view) and shows the candidates.
//! - **Passphrase prompts** (import, export, up to 3 tries, with "wrong passphrase"
//!   feedback) and **confirmations** (agent-reference key, duplicate → "Use existing",
//!   overwrite, the private-key export warning, delete).
//! - The forms of [`generate_form`](super::generate_form) and a busy note while RSA
//!   keys are generated.

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::model::ItemId;

use super::generate_form::{ChangePassphraseDialog, GenerateDialog, GeneratedDialog, PasteDialog};
use crate::app::keychain::keys::{ConfirmPurpose, KeychainAnswer, PassPurpose, PathPurpose};
use crate::views::{RenderCx, View as _, ViewCx, ViewEvent};
use crate::widgets::{
    dialog::{Button, Modal, ModalAnswer, ModalKind, PromptInput},
    truncate, width,
};

/// A path prompt with service-side completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPrompt {
    /// What the path is for.
    pub purpose: PathPurpose,
    /// The prompt.
    pub modal: Modal,
    /// Completion candidates of the last `Tab`.
    pub candidates: Vec<String>,
}

impl PathPrompt {
    /// A prompt titled `title` prefilled with `initial`.
    pub fn new(purpose: PathPurpose, title: &str, body: &str, initial: &str) -> Self {
        let mut modal = Modal::prompt(title, body, "Path", false);
        if let ModalKind::Prompt {
            input: PromptInput::Text(t),
            ..
        } = &mut modal.kind
        {
            t.set(initial);
        }
        Self {
            purpose,
            modal,
            candidates: Vec::new(),
        }
    }

    /// The typed path.
    pub fn text(&self) -> &str {
        match &self.modal.kind {
            ModalKind::Prompt {
                input: PromptInput::Text(t),
                ..
            } => t.text(),
            _ => "",
        }
    }

    /// Apply a completion for `prefix` (ignored if the text changed meanwhile).
    pub fn complete(&mut self, prefix: &str, completion: &str, candidates: Vec<String>) {
        if self.text() != prefix {
            return;
        }
        if let ModalKind::Prompt {
            input: PromptInput::Text(t),
            ..
        } = &mut self.modal.kind
        {
            t.set(completion);
        }
        self.candidates = if candidates.len() > 1 {
            candidates
        } else {
            Vec::new()
        };
    }
}

/// A passphrase prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphrasePrompt {
    /// What it decrypts / sets.
    pub purpose: PassPurpose,
    /// The prompt.
    pub modal: Modal,
}

impl PassphrasePrompt {
    /// A prompt for `label`; `attempt` > 1 says the last one was wrong.
    pub fn new(purpose: PassPurpose, label: &str, attempt: u8) -> Self {
        let (title, mut body) = match purpose {
            PassPurpose::Import => (
                "Key passphrase",
                format!("\"{label}\" is encrypted. Enter its passphrase."),
            ),
            PassPurpose::ExportCurrent => (
                "Key passphrase",
                format!("Enter the passphrase of \"{label}\" to decrypt it for export."),
            ),
            PassPurpose::ExportNew => (
                "New passphrase",
                format!("Passphrase to encrypt the exported copy of \"{label}\"."),
            ),
        };
        if attempt > 1 {
            body.push_str(&format!(
                "\nWrong passphrase, try again ({attempt}/{}).",
                sverb_core::keychain::PASSPHRASE_TRIES
            ));
        }
        Self {
            purpose,
            modal: Modal::prompt(title, &body, "Passphrase", true),
        }
    }
}

/// A confirmation with a purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialog {
    /// What is being confirmed.
    pub purpose: ConfirmPurpose,
    /// The dialog.
    pub modal: Modal,
}

impl ConfirmDialog {
    /// "Public key only: create a hardware / agent reference?"
    pub fn agent_ref(fingerprint: &str) -> Self {
        Self {
            purpose: ConfirmPurpose::AgentRef,
            modal: Modal::confirm(
                "Public key only",
                &format!(
                    "This is a public key ({fingerprint}) without a private part.\n\
                     Create a hardware / agent key reference? sverb will ask the system \
                     agent (e.g. a FIDO token or ssh-agent) to sign with it."
                ),
                vec![
                    Button::new("create", "create reference", 'c'),
                    Button::new("cancel", "cancel", 'n').safe(),
                ],
                0,
                false,
            ),
        }
    }

    /// "This key already exists": use the existing one or import anyway.
    pub fn duplicate(existing: ItemId, label: &str) -> Self {
        Self {
            purpose: ConfirmPurpose::Duplicate(existing),
            modal: Modal::confirm(
                "Key already in the keychain",
                &format!("A key with the same public key exists: \"{label}\"."),
                vec![
                    Button::new("existing", "use existing", 'u'),
                    Button::new("anyway", "import anyway", 'i'),
                    Button::new("cancel", "cancel", 'n').safe(),
                ],
                0,
                false,
            ),
        }
    }

    /// "`<path>` exists. Overwrite?"
    pub fn overwrite(path: &str) -> Self {
        Self {
            purpose: ConfirmPurpose::Overwrite,
            modal: Modal::confirm(
                "File exists",
                &format!("{path} already exists. Overwrite it?"),
                vec![
                    Button::new("overwrite", "overwrite", 'o').danger(),
                    Button::new("cancel", "cancel", 'n').safe(),
                ],
                1,
                true,
            ),
        }
    }

    /// The private-key export warning, with the encryption choice.
    pub fn private_export(item: ItemId, label: &str, encrypted: bool) -> Self {
        let mut buttons = Vec::new();
        if encrypted {
            buttons.push(Button::new("keep", "keep its passphrase", 'k'));
        }
        buttons.push(Button::new("new", "new passphrase", 'n'));
        buttons.push(Button::new("plain", "unencrypted", 'u').danger());
        buttons.push(Button::new("cancel", "cancel", 'c').safe());
        Self {
            purpose: ConfirmPurpose::PrivateExport(item),
            modal: Modal::confirm(
                "Export private key",
                &format!(
                    "This writes the private key of \"{label}\" to disk, where sverb no \
                     longer protects it (file mode 0600). Choose how the file is encrypted."
                ),
                buttons,
                0,
                true,
            ),
        }
    }

    /// "Delete key …?" with its usage.
    pub fn delete_key(item: ItemId, label: &str, used: usize, certs: usize) -> Self {
        let mut body = if used == 0 {
            "No host or identity uses this key.".to_owned()
        } else {
            format!("Used by {used} host(s) / identities: they will have no key.")
        };
        if certs > 0 {
            body.push_str(&format!("\nIts {certs} certificate(s) are deleted too."));
        }
        Self {
            purpose: ConfirmPurpose::DeleteKey(item),
            modal: Modal::confirm(
                &format!("Delete key \"{}\"?", truncate(label, 30)),
                &body,
                vec![
                    Button::new("delete", "delete", 'd').danger(),
                    Button::new("cancel", "cancel", 'n').safe(),
                ],
                1,
                true,
            ),
        }
    }

    /// "Delete certificate …?"
    pub fn delete_cert(item: ItemId, label: &str) -> Self {
        Self {
            purpose: ConfirmPurpose::DeleteCert(item),
            modal: Modal::confirm(
                &format!("Delete certificate \"{}\"?", truncate(label, 30)),
                "The key stays; only the certificate is removed.",
                vec![
                    Button::new("delete", "delete", 'd').danger(),
                    Button::new("cancel", "cancel", 'n').safe(),
                ],
                1,
                true,
            ),
        }
    }
}

/// A keychain dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainDialogKind {
    /// The generate form.
    Generate(Box<GenerateDialog>),
    /// The generated key's public key and fingerprint.
    Generated(GeneratedDialog),
    /// The paste-import form.
    Paste(Box<PasteDialog>),
    /// The change-passphrase form.
    ChangePassphrase(Box<ChangePassphraseDialog>),
    /// A path prompt.
    Path(PathPrompt),
    /// A passphrase prompt.
    Passphrase(PassphrasePrompt),
    /// A confirmation.
    Confirm(ConfirmDialog),
    /// "Working…" (RSA generation, an import in flight).
    Busy(Modal),
    /// Install on hosts: the host picker.
    InstallPick(Box<super::install::InstallPicker>),
    /// Install on hosts: the per-host results.
    InstallResults(Box<super::install::InstallResults>),
}

/// A keychain dialog and its recorded answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainDialog {
    /// The dialog.
    pub kind: KeychainDialogKind,
    /// The answer, taken by the reducer.
    pub answer: Option<KeychainAnswer>,
}

impl KeychainDialog {
    /// Wrap a dialog.
    pub fn new(kind: KeychainDialogKind) -> Self {
        Self { kind, answer: None }
    }

    /// A busy note.
    pub fn busy(title: &str, body: &str) -> Self {
        Self::new(KeychainDialogKind::Busy(Modal::progress(
            title, body, false,
        )))
    }

    /// The recorded answer (taken once).
    pub fn take_answer(&mut self) -> Option<KeychainAnswer> {
        self.answer.take()
    }

    /// The dialog edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        match &self.kind {
            KeychainDialogKind::Generate(_)
            | KeychainDialogKind::Paste(_)
            | KeychainDialogKind::ChangePassphrase(_) => true,
            KeychainDialogKind::Path(p) => p.modal.wants_text(),
            KeychainDialogKind::Passphrase(p) => p.modal.wants_text(),
            // The picker's filter.
            KeychainDialogKind::InstallPick(_) => true,
            _ => false,
        }
    }

    /// Handle an event (modal: everything is consumed).
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        let answer = match &mut self.kind {
            KeychainDialogKind::Generate(d) => d.handle(ev, cx),
            KeychainDialogKind::Paste(d) => d.handle(ev, cx),
            KeychainDialogKind::ChangePassphrase(d) => d.handle(ev, cx),
            KeychainDialogKind::Generated(d) => match ev {
                ViewEvent::Key(k)
                    if !k
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    match k.code {
                        KeyCode::Char('c') => Some(KeychainAnswer::Copy(d.public_key.clone())),
                        KeyCode::Char('H') => Some(KeychainAnswer::Install(d.item)),
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            cx.close();
                            None
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            KeychainDialogKind::Path(p) => match ev {
                ViewEvent::Key(k) if k.code == KeyCode::Tab => {
                    Some(KeychainAnswer::Complete(p.text().to_owned()))
                }
                ViewEvent::Key(k) => match p.modal.handle_key(k) {
                    Some(ModalAnswer::Text(t)) if !t.trim().is_empty() => {
                        Some(KeychainAnswer::Path(p.purpose.clone(), t.trim().to_owned()))
                    }
                    Some(ModalAnswer::Cancelled) => {
                        cx.close();
                        None
                    }
                    _ => None,
                },
                ViewEvent::Paste(t) => {
                    p.modal.paste(t);
                    None
                }
                ViewEvent::Mouse(_) => None,
            },
            KeychainDialogKind::Passphrase(p) => match ev {
                ViewEvent::Key(k) => match p.modal.handle_key(k) {
                    Some(ModalAnswer::Secret(s)) => Some(KeychainAnswer::Passphrase(p.purpose, s)),
                    Some(ModalAnswer::Cancelled) => {
                        cx.close();
                        None
                    }
                    _ => None,
                },
                ViewEvent::Paste(t) => {
                    p.modal.paste(t);
                    None
                }
                ViewEvent::Mouse(_) => None,
            },
            KeychainDialogKind::Confirm(c) => match ev {
                ViewEvent::Key(k) => match c.modal.handle_key(k) {
                    Some(ModalAnswer::Button(b)) if b != "cancel" => {
                        Some(KeychainAnswer::Confirm(c.purpose.clone(), b))
                    }
                    Some(_) => {
                        cx.close();
                        None
                    }
                    None => None,
                },
                _ => None,
            },
            KeychainDialogKind::Busy(_) => None,
            KeychainDialogKind::InstallPick(p) => p.handle(ev, cx),
            KeychainDialogKind::InstallResults(r) => r.handle(ev, cx),
        };
        if answer.is_some() {
            self.answer = answer;
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match &self.kind {
            KeychainDialogKind::Generate(d) => d.form.render(frame, area, cx),
            KeychainDialogKind::Paste(d) => d.form.render(frame, area, cx),
            KeychainDialogKind::ChangePassphrase(d) => d.form.render(frame, area, cx),
            KeychainDialogKind::Generated(d) => render_generated(d, frame, area, cx),
            KeychainDialogKind::Path(p) => {
                p.modal.render(frame, area, cx);
                render_candidates(&p.candidates, frame, area, cx);
            }
            KeychainDialogKind::Passphrase(p) => p.modal.render(frame, area, cx),
            KeychainDialogKind::Confirm(c) => c.modal.render(frame, area, cx),
            KeychainDialogKind::Busy(m) => m.render(frame, area, cx),
            KeychainDialogKind::InstallPick(p) => p.render(frame, area, cx),
            KeychainDialogKind::InstallResults(r) => r.render(frame, area, cx),
        }
    }
}

fn render_generated(d: &GeneratedDialog, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    let theme = cx.theme;
    let w = area.width.saturating_sub(4).min(100);
    let h = 12.min(area.height);
    if w < 10 || h < 5 {
        return;
    }
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    frame.render_widget(Clear, rect);
    let lines = vec![
        Line::from(vec![
            Span::styled("Fingerprint  ", theme.dim),
            Span::styled(d.fingerprint.clone(), theme.base),
        ]),
        Line::raw(""),
        Line::styled("Public key", theme.accent),
        Line::styled(d.public_key.clone(), theme.base),
        Line::raw(""),
        Line::styled(
            "c copy public key · H install on hosts · esc close",
            theme.dim,
        ),
    ];
    let block = Block::bordered()
        .title(Span::styled(
            format!(" Generated · {} ", truncate(&d.label, 40)),
            theme.title_for(true),
        ))
        .border_style(theme.border_for(true));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(theme.base)
            .block(block),
        rect,
    );
}

fn render_candidates(cands: &[String], frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    if cands.is_empty() || area.height < 4 {
        return;
    }
    let shown: Vec<&String> = cands.iter().take(8).collect();
    let w = shown
        .iter()
        .map(|c| width(c))
        .max()
        .unwrap_or(0)
        .saturating_add(4)
        .min(usize::from(area.width));
    let h = (shown.len() + 2).min(usize::from(area.height));
    let w = u16::try_from(w).unwrap_or(area.width);
    let h = u16::try_from(h).unwrap_or(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + area.height.saturating_sub(h),
        w,
        h,
    );
    frame.render_widget(Clear, rect);
    let mut lines: Vec<Line<'static>> = shown
        .iter()
        .map(|c| Line::styled((*c).clone(), cx.theme.base))
        .collect();
    if cands.len() > shown.len() {
        lines.truncate(shown.len().saturating_sub(1));
        lines.push(Line::styled(
            format!("… {} more", cands.len() - lines.len()),
            cx.theme.dim,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(cx.theme.base)
            .block(Block::bordered().border_style(cx.theme.border_for(true))),
        rect,
    );
}
