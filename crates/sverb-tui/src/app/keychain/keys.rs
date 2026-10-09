//! The Keys and Certificates sub-tabs in the reducer (SPEC §4.5, §4.6, §9.4).
//!
//! The views record requests ([`KeyRequest`], [`CertRequest`]); the keychain dialogs
//! record answers ([`KeychainAnswer`]); both are taken after every dispatch
//! (`App::take_keychain_requests`). Work that needs the vault or the disk goes out as
//! [`KeychainEffect`]s inside `VaultEffect::Items(ItemEffect::Keychain(..))` and comes
//! back as `VaultEvent::Keychain` ([`KeychainEvent`], correlated by a token).
//!
//! The operation in flight ([`KeyOp`]: its last effect and the passphrase tries) lives
//! in the Keys view, so a reply can resend it with what the user just answered: a
//! passphrase (3 tries, then "import aborted": nothing is saved), "create the agent
//! reference", "import anyway", "overwrite". Secrets in effects are [`SecretValue`]s
//! (zeroized on drop, redacted `Debug`).

use sverb_core::model::{ItemId, KeyAlgorithm};

use crate::app::hosts::ItemEffect;
use crate::app::{App, Effect, ToastLevel, VaultEffect};
use crate::views::{
    DialogKind,
    keychain::{
        KeychainRequest, KeychainTab,
        certs::CertRequest,
        generate_form::{
            ChangePassphraseDialog, GenerateDialog, GeneratedDialog, PasteDialog,
            change_passphrase_form, paste_form,
        },
        identity_form::IdentityDialog,
        import_dialog::{
            ConfirmDialog, KeychainDialog, KeychainDialogKind, PassphrasePrompt, PathPrompt,
        },
        keys::KeyRequest,
    },
};
use crate::widgets::form::SecretValue;

// ---------------------------------------------------------------- effect / event types

/// What to generate (from the generate form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateSpec {
    /// The algorithm.
    pub algorithm: KeyAlgorithm,
    /// The label.
    pub label: String,
    /// The key comment.
    pub comment: String,
    /// Encrypt with this passphrase.
    pub passphrase: Option<SecretValue>,
    /// Store the passphrase in the vault.
    pub remember: bool,
}

/// Where key or certificate text comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSource {
    /// A file path (`~` expanded by the service).
    File(String),
    /// Pasted text.
    Text(SecretValue),
}

/// An import request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSpec {
    /// The key text's source.
    pub source: ImportSource,
    /// The label (`None`: the comment, else the file name).
    pub label: Option<String>,
    /// The passphrase, once asked.
    pub passphrase: Option<SecretValue>,
    /// The user confirmed creating an agent / hardware reference from a public key.
    pub allow_agent_ref: bool,
    /// The user chose "import anyway" over an existing key with the same public key.
    pub allow_duplicate: bool,
}

/// How a private key export is encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportHow {
    /// As stored.
    Keep,
    /// With a new passphrase.
    Reencrypt(SecretValue),
    /// Decrypted.
    Decrypted,
}

/// A key flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFlag {
    /// `agent_forwardable`
    Forwardable,
    /// `confirm_on_use`
    ConfirmOnUse,
}

/// Keychain work for the vault service (`services::vault::items::keychain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainEffect {
    /// Generate a key (RSA off the async runtime) and save it.
    Generate {
        /// Correlation token.
        token: u64,
        /// What to generate.
        spec: GenerateSpec,
    },
    /// Import a key.
    Import {
        /// Correlation token.
        token: u64,
        /// What to import.
        spec: ImportSpec,
    },
    /// Write the public key to a file.
    ExportPublic {
        /// Correlation token.
        token: u64,
        /// The key.
        item: ItemId,
        /// Destination.
        path: String,
        /// Overwrite an existing file.
        overwrite: bool,
    },
    /// Write the private key to a file (mode 0600).
    ExportPrivate {
        /// Correlation token.
        token: u64,
        /// The key.
        item: ItemId,
        /// Destination.
        path: String,
        /// Overwrite an existing file.
        overwrite: bool,
        /// Encryption of the copy.
        how: ExportHow,
        /// The current passphrase, when it isn't stored.
        passphrase: Option<SecretValue>,
    },
    /// Re-encrypt a key with a new passphrase (or none).
    ChangePassphrase {
        /// Correlation token.
        token: u64,
        /// The key.
        item: ItemId,
        /// The current passphrase (`None`: the stored one).
        old: Option<SecretValue>,
        /// The new passphrase (`None`: no passphrase).
        new: Option<SecretValue>,
        /// Store the new passphrase.
        remember: bool,
    },
    /// Import a certificate and attach it to `key` (`None`: the key with its public
    /// key).
    AttachCert {
        /// Correlation token.
        token: u64,
        /// The key.
        key: Option<ItemId>,
        /// The certificate text's source.
        source: ImportSource,
    },
    /// Set a key flag.
    SetFlag {
        /// The key.
        item: ItemId,
        /// Which flag.
        flag: KeyFlag,
        /// The value.
        value: bool,
    },
    /// Delete a key and its certificates.
    DeleteKey(ItemId),
    /// Delete a certificate (and detach it from its key).
    DeleteCert(ItemId),
    /// Complete a path prompt.
    CompletePath {
        /// The typed text.
        prefix: String,
    },
    /// Install a key on hosts: run, answer a prompt, cancel.
    Install(super::install::InstallEffect),
}

/// The result of a [`KeychainEffect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainOutcome {
    /// A key was generated and saved.
    Generated {
        /// The new key.
        item: ItemId,
        /// Its label.
        label: String,
        /// The public key line.
        public_key: String,
        /// `SHA256:…`
        fingerprint: String,
    },
    /// A key was imported.
    Imported {
        /// The new key.
        item: ItemId,
        /// Its label.
        label: String,
        /// It is an agent / hardware reference.
        agent_ref: bool,
    },
    /// The key is encrypted: ask for the passphrase.
    NeedsPassphrase,
    /// The passphrase was wrong.
    WrongPassphrase,
    /// A lone public key: confirm the agent reference.
    ConfirmAgentRef {
        /// Its fingerprint.
        fingerprint: String,
    },
    /// The same public key is already in the keychain.
    Duplicate {
        /// The existing key.
        existing: ItemId,
        /// Its label.
        label: String,
    },
    /// The destination exists: confirm the overwrite.
    Exists {
        /// The (expanded) path.
        path: String,
    },
    /// A key was written to a file.
    Exported {
        /// The (expanded) path.
        path: String,
        /// The private key.
        private: bool,
    },
    /// The passphrase was changed.
    PassphraseChanged,
    /// A certificate was attached.
    CertAttached {
        /// The certificate.
        item: ItemId,
        /// The key's label.
        key_label: String,
    },
    /// A path completion.
    Completed {
        /// The text it completes.
        prefix: String,
        /// The longest common completion.
        completion: String,
        /// The candidates.
        candidates: Vec<String>,
    },
    /// Done (flags, deletes).
    Done,
    /// Failed, with a user-facing message.
    Failed(String),
    /// Progress of an install run (token 0).
    Install(super::install::InstallUpdate),
}

/// A keychain result (`VaultEvent::Keychain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainEvent {
    /// The effect's token (0 for untracked effects).
    pub token: u64,
    /// What happened.
    pub outcome: KeychainOutcome,
}

// ---------------------------------------------------------------- dialog answers

/// What a path prompt is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPurpose {
    /// Import a key file.
    ImportKey,
    /// Export a public key.
    ExportPublic(ItemId),
    /// Export a private key.
    ExportPrivate(ItemId, ExportChoice),
    /// Import a certificate for a key (`None`: match by public key).
    AttachCert(Option<ItemId>),
}

/// The private-export encryption choice (before the passphrase is typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportChoice {
    /// Keep the stored encryption.
    Keep,
    /// A new passphrase.
    NewPassphrase,
    /// Unencrypted.
    Decrypted,
}

/// What a passphrase prompt is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassPurpose {
    /// The imported key's passphrase.
    Import,
    /// The stored key's passphrase (export).
    ExportCurrent,
    /// The exported copy's new passphrase.
    ExportNew,
}

/// What a confirmation is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmPurpose {
    /// Create an agent reference from a public key.
    AgentRef,
    /// An existing key with the same public key.
    Duplicate(ItemId),
    /// Overwrite the export destination.
    Overwrite,
    /// The private export warning (buttons `keep` / `new` / `plain`).
    PrivateExport(ItemId),
    /// Delete a key.
    DeleteKey(ItemId),
    /// Delete a certificate.
    DeleteCert(ItemId),
    /// Install a key on the planned hosts (button `install`).
    InstallKey(Box<crate::views::keychain::install::InstallPlan>),
}

/// A keychain dialog's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainAnswer {
    /// The generate form was submitted.
    Generate(GenerateSpec),
    /// A path prompt was submitted.
    Path(PathPurpose, String),
    /// `Tab` in a path prompt.
    Complete(String),
    /// The paste form was submitted.
    Paste {
        /// The key text.
        text: SecretValue,
        /// The label (may be empty).
        label: String,
    },
    /// A passphrase prompt was submitted.
    Passphrase(PassPurpose, SecretValue),
    /// A confirmation button (not cancel).
    Confirm(ConfirmPurpose, String),
    /// The change-passphrase form was submitted.
    ChangePassphrase {
        /// The key.
        item: ItemId,
        /// Current passphrase (when asked).
        old: Option<SecretValue>,
        /// New passphrase.
        new: Option<SecretValue>,
        /// Remember it.
        remember: bool,
    },
    /// Copy text (the generated public key).
    Copy(String),
    /// Install on hosts.
    Install(ItemId),
    /// The host picker was submitted.
    InstallPick {
        /// The key.
        key: ItemId,
        /// Picked hosts, groups and tags.
        targets: Vec<crate::views::keychain::install::InstallTarget>,
    },
    /// `r` in the results: re-run the failed hosts.
    InstallRerun,
}

/// The keychain operation in flight (in the Keys view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOp {
    /// Its token.
    pub token: u64,
    /// The last effect sent (resent with the user's answers).
    pub effect: KeychainEffect,
    /// Wrong passphrases so far.
    pub tries: u8,
    /// The label shown in prompts.
    pub label: String,
}

fn items(op: KeychainEffect) -> Effect {
    Effect::Vault(VaultEffect::Items(ItemEffect::Keychain(op)))
}

fn token_of(e: &KeychainEffect) -> u64 {
    match e {
        KeychainEffect::Generate { token, .. }
        | KeychainEffect::Import { token, .. }
        | KeychainEffect::ExportPublic { token, .. }
        | KeychainEffect::ExportPrivate { token, .. }
        | KeychainEffect::ChangePassphrase { token, .. }
        | KeychainEffect::AttachCert { token, .. } => *token,
        _ => 0,
    }
}

/// `YYYY-MM-DD` (UTC) of a UNIX-ms time.
fn date_of(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map_or_else(String::new, |d| d.format("%Y-%m-%d").to_string())
}

impl App {
    fn keychain_dialog(&mut self, d: KeychainDialog) {
        self.push_dialog(DialogKind::Identity(IdentityDialog::Keychain(Box::new(d))));
    }

    /// Replace the top keychain dialog (or push one).
    fn replace_keychain_dialog(&mut self, d: KeychainDialog) {
        self.pop_keychain_dialog();
        self.keychain_dialog(d);
    }

    /// Close the top dialog if it is a keychain dialog.
    fn pop_keychain_dialog(&mut self) {
        if matches!(
            self.dialogs.last().map(|d| &d.kind),
            Some(DialogKind::Identity(IdentityDialog::Keychain(_)))
        ) {
            self.dialogs.pop();
        }
    }

    /// Start an operation: remember it and send its effect.
    fn start_key_op(&mut self, effect: KeychainEffect, label: String, effects: &mut Vec<Effect>) {
        self.views.keychain.keys_op = Some(KeyOp {
            token: token_of(&effect),
            effect: effect.clone(),
            tries: 0,
            label,
        });
        effects.push(items(effect));
    }

    /// Resend the operation in flight after `change`.
    fn resend_key_op(
        &mut self,
        change: impl FnOnce(&mut KeychainEffect),
        effects: &mut Vec<Effect>,
    ) {
        if let Some(op) = &mut self.views.keychain.keys_op {
            change(&mut op.effect);
            effects.push(items(op.effect.clone()));
        }
    }

    fn next_token(&mut self) -> u64 {
        self.views.keychain.next_token = self.views.keychain.next_token.wrapping_add(1).max(1);
        self.views.keychain.next_token
    }

    fn key_label(&self, id: ItemId) -> String {
        self.views
            .keychain
            .keys
            .info(id)
            .map_or_else(|| id.short(), |k| k.label.clone())
    }

    /// The Keys / Certificates sub-tabs' requests.
    pub(crate) fn on_keychain_key_request(
        &mut self,
        req: &KeychainRequest,
        effects: &mut Vec<Effect>,
    ) {
        self.needs_redraw = true;
        match req {
            KeychainRequest::Key(r) => self.on_key_request(r.clone(), effects),
            KeychainRequest::Cert(r) => self.on_cert_request(r.clone(), effects),
            _ => {}
        }
    }

    fn on_key_request(&mut self, req: KeyRequest, effects: &mut Vec<Effect>) {
        match req {
            KeyRequest::Generate => {
                let today = self
                    .views
                    .keychain
                    .keys
                    .catalog()
                    .map(|c| date_of(c.loaded_at))
                    .unwrap_or_default();
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Generate(Box::new(
                    GenerateDialog::new(&today),
                ))));
            }
            KeyRequest::ImportFile => self.keychain_dialog(KeychainDialog::new(
                KeychainDialogKind::Path(PathPrompt::new(
                    PathPurpose::ImportKey,
                    "Import key",
                    "OpenSSH, PEM (PKCS#1 / SEC1), PKCS#8, PuTTY, or a .pub public key \
                     (a hardware / agent key reference). Tab completes.",
                    "~/.ssh/",
                )),
            )),
            KeyRequest::ImportPaste => {
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Paste(Box::new(
                    PasteDialog { form: paste_form() },
                ))));
            }
            KeyRequest::CopyPublic(id) => {
                if let Some(k) = self.views.keychain.keys.info(id) {
                    let line = k.public_key.clone();
                    effects.push(Effect::CopyToClipboard(line));
                    self.push_toast(ToastLevel::Success, "Public key copied".to_owned(), effects);
                }
            }
            KeyRequest::ExportPublic(id) => {
                let label = self.key_label(id);
                let initial = format!("~/{}.pub", file_name_of(&label));
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Path(
                    PathPrompt::new(
                        PathPurpose::ExportPublic(id),
                        "Export public key",
                        &format!("Write the public key of \"{label}\" to:"),
                        &initial,
                    ),
                )));
            }
            KeyRequest::ExportPrivate(id) => {
                let Some(k) = self.views.keychain.keys.info(id) else {
                    return;
                };
                if k.agent_ref {
                    self.push_toast(
                        ToastLevel::Warning,
                        "This is a hardware / agent key reference: it has no private key"
                            .to_owned(),
                        effects,
                    );
                    return;
                }
                let d = ConfirmDialog::private_export(id, &k.label.clone(), k.encrypted);
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(d)));
            }
            KeyRequest::ChangePassphrase(id) => {
                let Some(k) = self.views.keychain.keys.info(id) else {
                    return;
                };
                if k.agent_ref {
                    self.push_toast(
                        ToastLevel::Warning,
                        "A hardware / agent key reference has no passphrase".to_owned(),
                        effects,
                    );
                    return;
                }
                let ask_current = k.encrypted && !k.has_passphrase;
                let remember = k.has_passphrase || !k.encrypted;
                let form = change_passphrase_form(&k.label.clone(), ask_current, remember);
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::ChangePassphrase(
                    Box::new(ChangePassphraseDialog { item: id, form }),
                )));
            }
            KeyRequest::AttachCert(id) => {
                let label = self.key_label(id);
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Path(
                    PathPrompt::new(
                        PathPurpose::AttachCert(Some(id)),
                        "Attach certificate",
                        &format!("OpenSSH certificate for \"{label}\" (it must certify this key)."),
                        "~/.ssh/",
                    ),
                )));
            }
            KeyRequest::ToggleForwardable(id) | KeyRequest::ToggleConfirm(id) => {
                let Some(k) = self.views.keychain.keys.info(id) else {
                    return;
                };
                let (flag, value, what) = match req {
                    KeyRequest::ToggleForwardable(_) => (
                        KeyFlag::Forwardable,
                        !k.agent_forwardable,
                        "Agent forwarding",
                    ),
                    _ => (KeyFlag::ConfirmOnUse, !k.confirm_on_use, "Confirm on use"),
                };
                effects.push(items(KeychainEffect::SetFlag {
                    item: id,
                    flag,
                    value,
                }));
                let state = if value { "on" } else { "off" };
                self.push_toast(ToastLevel::Info, format!("{what} {state}"), effects);
            }
            KeyRequest::Install(id) => self.open_install_picker(id, effects),
            KeyRequest::Delete(id) => {
                let label = self.key_label(id);
                let used = self.views.keychain.keys.usage(id).total();
                let certs = self
                    .views
                    .keychain
                    .keys
                    .list
                    .rows()
                    .iter()
                    .find(|r| r.id == id)
                    .map_or(0, |r| r.certs);
                let d = ConfirmDialog::delete_key(id, &label, used, certs);
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(d)));
            }
        }
    }

    fn on_cert_request(&mut self, req: CertRequest, effects: &mut Vec<Effect>) {
        match req {
            CertRequest::Import => self.keychain_dialog(KeychainDialog::new(
                KeychainDialogKind::Path(PathPrompt::new(
                    PathPurpose::AttachCert(None),
                    "Import certificate",
                    "OpenSSH certificate (…-cert.pub); it is attached to the key it certifies.",
                    "~/.ssh/",
                )),
            )),
            CertRequest::Copy(id) => {
                if let Some(text) = self.views.keychain.certs.cert_text(id) {
                    effects.push(Effect::CopyToClipboard(text));
                    self.push_toast(
                        ToastLevel::Success,
                        "Certificate copied".to_owned(),
                        effects,
                    );
                }
            }
            CertRequest::Delete(id) => {
                let label = self
                    .views
                    .keychain
                    .certs
                    .label_of(id)
                    .unwrap_or_else(|| id.short());
                let d = ConfirmDialog::delete_cert(id, &label);
                self.keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(d)));
            }
        }
    }

    /// A keychain dialog's answer.
    pub(crate) fn on_keychain_answer(&mut self, answer: KeychainAnswer, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        match answer {
            KeychainAnswer::Generate(spec) => {
                let token = self.next_token();
                let slow = sverb_core::keychain::generate::is_slow(spec.algorithm);
                let label = spec.label.clone();
                self.replace_keychain_dialog(KeychainDialog::busy(
                    "Generating key",
                    if slow {
                        "Generating an RSA key; this can take a few seconds…"
                    } else {
                        "Generating…"
                    },
                ));
                self.start_key_op(KeychainEffect::Generate { token, spec }, label, effects);
            }
            KeychainAnswer::Path(purpose, path) => self.on_path_answer(purpose, path, effects),
            KeychainAnswer::Complete(prefix) => {
                effects.push(items(KeychainEffect::CompletePath { prefix }));
            }
            KeychainAnswer::Paste { text, label } => {
                let token = self.next_token();
                self.replace_keychain_dialog(KeychainDialog::busy("Importing key", "Reading…"));
                let label = (!label.is_empty()).then_some(label);
                self.start_key_op(
                    KeychainEffect::Import {
                        token,
                        spec: ImportSpec {
                            source: ImportSource::Text(text),
                            label: label.clone(),
                            passphrase: None,
                            allow_agent_ref: false,
                            allow_duplicate: false,
                        },
                    },
                    label.unwrap_or_else(|| "pasted key".to_owned()),
                    effects,
                );
            }
            KeychainAnswer::Passphrase(purpose, pass) => {
                self.replace_keychain_dialog(KeychainDialog::busy("Working", "Decrypting…"));
                self.resend_key_op(
                    |e| match (purpose, e) {
                        (PassPurpose::Import, KeychainEffect::Import { spec, .. }) => {
                            spec.passphrase = Some(pass);
                        }
                        (
                            PassPurpose::ExportCurrent,
                            KeychainEffect::ExportPrivate { passphrase, .. },
                        ) => {
                            *passphrase = Some(pass);
                        }
                        (PassPurpose::ExportNew, KeychainEffect::ExportPrivate { how, .. }) => {
                            *how = ExportHow::Reencrypt(pass);
                        }
                        _ => {}
                    },
                    effects,
                );
            }
            KeychainAnswer::Confirm(purpose, button) => self.on_confirm(purpose, &button, effects),
            KeychainAnswer::ChangePassphrase {
                item,
                old,
                new,
                remember,
            } => {
                let token = self.next_token();
                let label = self.key_label(item);
                self.replace_keychain_dialog(KeychainDialog::busy(
                    "Changing passphrase",
                    "Working…",
                ));
                self.start_key_op(
                    KeychainEffect::ChangePassphrase {
                        token,
                        item,
                        old,
                        new,
                        remember,
                    },
                    label,
                    effects,
                );
            }
            KeychainAnswer::Copy(text) => {
                effects.push(Effect::CopyToClipboard(text));
                self.push_toast(ToastLevel::Success, "Public key copied".to_owned(), effects);
            }
            KeychainAnswer::Install(id) => self.open_install_picker(id, effects),
            KeychainAnswer::InstallPick { key, targets } => {
                self.on_install_pick(key, &targets, effects);
            }
            KeychainAnswer::InstallRerun => self.install_rerun(effects),
        }
    }

    fn on_path_answer(&mut self, purpose: PathPurpose, path: String, effects: &mut Vec<Effect>) {
        let token = self.next_token();
        match purpose {
            PathPurpose::ImportKey => {
                self.replace_keychain_dialog(KeychainDialog::busy("Importing key", "Reading…"));
                let label = sverb_core::keychain::import::file_stem(&path)
                    .unwrap_or_else(|| "key".to_owned());
                self.start_key_op(
                    KeychainEffect::Import {
                        token,
                        spec: ImportSpec {
                            source: ImportSource::File(path),
                            label: None,
                            passphrase: None,
                            allow_agent_ref: false,
                            allow_duplicate: false,
                        },
                    },
                    label,
                    effects,
                );
            }
            PathPurpose::ExportPublic(item) => {
                self.pop_keychain_dialog();
                let label = self.key_label(item);
                self.start_key_op(
                    KeychainEffect::ExportPublic {
                        token,
                        item,
                        path,
                        overwrite: false,
                    },
                    label,
                    effects,
                );
            }
            PathPurpose::ExportPrivate(item, choice) => {
                let label = self.key_label(item);
                let effect = KeychainEffect::ExportPrivate {
                    token,
                    item,
                    path,
                    overwrite: false,
                    how: match choice {
                        ExportChoice::Keep => ExportHow::Keep,
                        ExportChoice::Decrypted => ExportHow::Decrypted,
                        // Replaced once the new passphrase is typed.
                        ExportChoice::NewPassphrase => ExportHow::Keep,
                    },
                    passphrase: None,
                };
                if choice == ExportChoice::NewPassphrase {
                    self.views.keychain.keys_op = Some(KeyOp {
                        token,
                        effect,
                        tries: 0,
                        label: label.clone(),
                    });
                    self.replace_keychain_dialog(KeychainDialog::new(
                        KeychainDialogKind::Passphrase(PassphrasePrompt::new(
                            PassPurpose::ExportNew,
                            &label,
                            1,
                        )),
                    ));
                } else {
                    self.replace_keychain_dialog(KeychainDialog::busy("Exporting", "Writing…"));
                    self.start_key_op(effect, label, effects);
                }
            }
            PathPurpose::AttachCert(key) => {
                self.replace_keychain_dialog(KeychainDialog::busy(
                    "Attaching certificate",
                    "Reading…",
                ));
                let label = key.map(|k| self.key_label(k)).unwrap_or_default();
                self.start_key_op(
                    KeychainEffect::AttachCert {
                        token,
                        key,
                        source: ImportSource::File(path),
                    },
                    label,
                    effects,
                );
            }
        }
    }

    fn on_confirm(&mut self, purpose: ConfirmPurpose, button: &str, effects: &mut Vec<Effect>) {
        match purpose {
            ConfirmPurpose::InstallKey(plan) => {
                if button == "install" {
                    self.start_install(*plan, effects);
                }
            }
            ConfirmPurpose::AgentRef => {
                self.replace_keychain_dialog(KeychainDialog::busy("Importing key", "Saving…"));
                self.resend_key_op(
                    |e| {
                        if let KeychainEffect::Import { spec, .. } = e {
                            spec.allow_agent_ref = true;
                        }
                    },
                    effects,
                );
            }
            ConfirmPurpose::Duplicate(existing) => {
                if button == "existing" {
                    self.pop_keychain_dialog();
                    self.views.keychain.keys_op = None;
                    self.views.keychain.tab = KeychainTab::Keys;
                    self.views.keychain.keys.select(existing);
                    let label = self.key_label(existing);
                    self.push_toast(
                        ToastLevel::Info,
                        format!("Using the existing key \"{label}\""),
                        effects,
                    );
                } else {
                    self.replace_keychain_dialog(KeychainDialog::busy("Importing key", "Saving…"));
                    self.resend_key_op(
                        |e| {
                            if let KeychainEffect::Import { spec, .. } = e {
                                spec.allow_duplicate = true;
                            }
                        },
                        effects,
                    );
                }
            }
            ConfirmPurpose::Overwrite => {
                self.replace_keychain_dialog(KeychainDialog::busy("Exporting", "Writing…"));
                self.resend_key_op(
                    |e| match e {
                        KeychainEffect::ExportPublic { overwrite, .. }
                        | KeychainEffect::ExportPrivate { overwrite, .. } => *overwrite = true,
                        _ => {}
                    },
                    effects,
                );
            }
            ConfirmPurpose::PrivateExport(item) => {
                let choice = match button {
                    "keep" => ExportChoice::Keep,
                    "new" => ExportChoice::NewPassphrase,
                    _ => ExportChoice::Decrypted,
                };
                let label = self.key_label(item);
                self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Path(
                    PathPrompt::new(
                        PathPurpose::ExportPrivate(item, choice),
                        "Export private key",
                        &format!("Write the private key of \"{label}\" to (mode 0600):"),
                        &format!("~/{}", file_name_of(&label)),
                    ),
                )));
            }
            ConfirmPurpose::DeleteKey(item) => {
                self.pop_keychain_dialog();
                effects.push(items(KeychainEffect::DeleteKey(item)));
            }
            ConfirmPurpose::DeleteCert(item) => {
                self.pop_keychain_dialog();
                effects.push(items(KeychainEffect::DeleteCert(item)));
            }
        }
    }

    /// A keychain result from the vault service.
    pub(crate) fn on_keychain_event(&mut self, ev: KeychainEvent, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        // Install runs report outside the operation in flight.
        if let KeychainOutcome::Install(update) = ev.outcome {
            self.on_install_update(update, effects);
            return;
        }
        if let KeychainOutcome::Completed {
            prefix,
            completion,
            candidates,
        } = ev.outcome
        {
            if let Some(DialogKind::Identity(IdentityDialog::Keychain(d))) =
                self.dialogs.last_mut().map(|d| &mut d.kind)
                && let KeychainDialogKind::Path(p) = &mut d.kind
            {
                p.complete(&prefix, &completion, candidates);
            }
            return;
        }
        let current = self
            .views
            .keychain
            .keys_op
            .as_ref()
            .is_some_and(|op| op.token == ev.token);
        if ev.token != 0 && !current {
            return; // a stale reply (the operation was replaced or cancelled)
        }
        let label = self
            .views
            .keychain
            .keys_op
            .as_ref()
            .map(|op| op.label.clone())
            .unwrap_or_default();
        match ev.outcome {
            KeychainOutcome::Generated {
                item,
                label,
                public_key,
                fingerprint,
            } => {
                self.views.keychain.keys_op = None;
                self.views.keychain.tab = KeychainTab::Keys;
                self.views.keychain.keys.select(item);
                self.views.keychain.pending_select = Some(item);
                self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Generated(
                    GeneratedDialog {
                        item,
                        label,
                        public_key,
                        fingerprint,
                    },
                )));
            }
            KeychainOutcome::Imported {
                item,
                label,
                agent_ref,
            } => {
                self.views.keychain.keys_op = None;
                self.pop_keychain_dialog();
                self.views.keychain.tab = KeychainTab::Keys;
                self.views.keychain.keys.select(item);
                self.views.keychain.pending_select = Some(item);
                let what = if agent_ref {
                    "Hardware / agent key reference"
                } else {
                    "Key"
                };
                self.push_toast(
                    ToastLevel::Success,
                    format!("{what} \"{label}\" imported"),
                    effects,
                );
            }
            KeychainOutcome::NeedsPassphrase => self.ask_passphrase(&label, false, effects),
            KeychainOutcome::WrongPassphrase => self.ask_passphrase(&label, true, effects),
            KeychainOutcome::ConfirmAgentRef { fingerprint } => {
                self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(
                    ConfirmDialog::agent_ref(&fingerprint),
                )));
            }
            KeychainOutcome::Duplicate { existing, label } => {
                self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(
                    ConfirmDialog::duplicate(existing, &label),
                )));
            }
            KeychainOutcome::Exists { path } => {
                self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(
                    ConfirmDialog::overwrite(&path),
                )));
            }
            KeychainOutcome::Exported { path, private } => {
                self.views.keychain.keys_op = None;
                self.pop_keychain_dialog();
                let what = if private { "Private key" } else { "Public key" };
                self.push_toast(
                    ToastLevel::Success,
                    format!("{what} written to {path}"),
                    effects,
                );
            }
            KeychainOutcome::PassphraseChanged => {
                self.views.keychain.keys_op = None;
                self.pop_keychain_dialog();
                self.push_toast(
                    ToastLevel::Success,
                    format!("Passphrase of \"{label}\" changed"),
                    effects,
                );
            }
            KeychainOutcome::CertAttached { item, key_label } => {
                self.views.keychain.keys_op = None;
                self.pop_keychain_dialog();
                self.views.keychain.certs.select(item);
                self.push_toast(
                    ToastLevel::Success,
                    format!("Certificate attached to \"{key_label}\""),
                    effects,
                );
            }
            KeychainOutcome::Done
            | KeychainOutcome::Completed { .. }
            | KeychainOutcome::Install(_) => {}
            KeychainOutcome::Failed(msg) => {
                self.views.keychain.keys_op = None;
                self.pop_keychain_dialog();
                self.push_toast(ToastLevel::Error, msg, effects);
            }
        }
    }

    /// Ask for the passphrase of the operation in flight (`wrong`: the last one was
    /// wrong). After [`PASSPHRASE_TRIES`](sverb_core::keychain::PASSPHRASE_TRIES) wrong
    /// ones the operation is aborted (an import creates nothing).
    fn ask_passphrase(&mut self, label: &str, wrong: bool, effects: &mut Vec<Effect>) {
        let Some(op) = &mut self.views.keychain.keys_op else {
            return;
        };
        if wrong {
            op.tries += 1;
        }
        let tries = op.tries;
        let purpose = match &op.effect {
            KeychainEffect::Import { .. } => Some(PassPurpose::Import),
            KeychainEffect::ExportPrivate { .. } => Some(PassPurpose::ExportCurrent),
            _ => None,
        };
        let Some(purpose) = purpose.filter(|_| tries < sverb_core::keychain::PASSPHRASE_TRIES)
        else {
            let what = match &op.effect {
                KeychainEffect::Import { .. } => "import aborted, nothing was saved",
                KeychainEffect::ChangePassphrase { .. } => "the passphrase was not changed",
                _ => "aborted",
            };
            let msg = if wrong {
                format!("Wrong passphrase: {what}")
            } else {
                format!("A passphrase is needed: {what}")
            };
            self.views.keychain.keys_op = None;
            self.pop_keychain_dialog();
            self.push_toast(ToastLevel::Error, msg, effects);
            return;
        };
        self.replace_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Passphrase(
            PassphrasePrompt::new(purpose, label, tries + 1),
        )));
    }

    /// The keychain dialog on top: take its answer (after a dispatch).
    pub(crate) fn take_keychain_dialog_answer(&mut self, effects: &mut Vec<Effect>) {
        let answer = match self.dialogs.last_mut().map(|d| &mut d.kind) {
            Some(DialogKind::Identity(IdentityDialog::Keychain(d))) => d.take_answer(),
            _ => None,
        };
        if let Some(answer) = answer {
            self.on_keychain_answer(answer, effects);
        }
    }
}

/// A file-name-safe version of a label.
fn file_name_of(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.trim_matches('_').is_empty() {
        "key".to_owned()
    } else {
        s
    }
}
