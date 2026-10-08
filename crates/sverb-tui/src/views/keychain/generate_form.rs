//! M2-03: the keychain's form dialogs (SPEC §9.4).
//!
//! - **Generate** (`a`): type (Ed25519 default, ECDSA P-256/384/521, RSA
//!   2048/3072/4096), label (default `"<type> <date>"`), comment (default
//!   `user@hostname-sverb`), optional passphrase with confirmation, and "remember
//!   passphrase in vault" (default on). RSA shows a progress note while the service
//!   generates it off the UI thread.
//! - **Generated**: the public key and fingerprint, with `c` copy and `H` install on
//!   hosts (M2-04: unavailable).
//! - **Paste** (`p`): a multiline key field and an optional label.
//! - **Change passphrase** (`P`): current (only when it isn't stored), new, confirm,
//!   remember.

use sverb_core::{
    keychain::{
        algorithm_name,
        generate::{GENERATABLE, default_comment, default_label},
    },
    model::{ItemId, KeyAlgorithm, ValidationError, WireEnum as _},
};

use crate::app::keychain::keys::{GenerateSpec, KeychainAnswer};
use crate::views::{View as _, ViewCx, ViewEvent};
use crate::widgets::form::{
    Field, FieldValue, FieldValues, Form, FormRequest, FormValidator, SecretValue,
    select::SelectOption,
};

fn text_of(values: &FieldValues, key: &str) -> String {
    values
        .get(key)
        .and_then(FieldValue::as_text)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn secret_of(values: &FieldValues, key: &str) -> Option<SecretValue> {
    match values.get(key) {
        Some(FieldValue::Secret(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn flag_of(values: &FieldValues, key: &str) -> bool {
    matches!(values.get(key), Some(FieldValue::Bool(true)))
}

fn passphrases_match(values: &FieldValues) -> Vec<ValidationError> {
    let a = secret_of(values, "passphrase");
    let b = secret_of(values, "confirm");
    if a == b {
        Vec::new()
    } else {
        vec![ValidationError::new(
            "confirm",
            "the passphrases do not match",
        )]
    }
}

/// The generate form. `today` is `YYYY-MM-DD` (the default label's date).
pub fn generate_form(today: &str) -> Form {
    let options = GENERATABLE
        .iter()
        .map(|a| SelectOption::new(a.as_wire(), algorithm_name(*a)))
        .collect();
    let fields = vec![
        Field::select(
            "algorithm",
            "Type",
            options,
            Some(KeyAlgorithm::Ed25519.as_wire()),
        )
        .help("Ed25519 is the default; RSA takes a few seconds"),
        Field::text("label", "Label", "").help(format!(
            "Default: \"{}\"",
            default_label(KeyAlgorithm::Ed25519, today)
        )),
        Field::text("comment", "Comment", &default_comment()),
        Field::secret("passphrase", "Passphrase", None)
            .help("Optional: encrypts the private key (OpenSSH format, bcrypt)"),
        Field::secret("confirm", "Confirm", None),
        Field::toggle("remember", "Remember passphrase in vault", true),
    ];
    Form::new("Generate key")
        .section("Key", fields)
        .validator(FormValidator::new("passphrases_match", passphrases_match))
}

/// The generate form on the dialog stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateDialog {
    /// The form.
    pub form: Form,
    /// The default label's date.
    pub today: String,
    /// "Generating…" (the request is out).
    pub busy: bool,
}

impl GenerateDialog {
    /// A new form for `today`.
    pub fn new(today: &str) -> Self {
        Self {
            form: generate_form(today),
            today: today.to_owned(),
            busy: false,
        }
    }

    /// Handle an event; a save becomes [`KeychainAnswer::Generate`].
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<KeychainAnswer> {
        if self.busy {
            return None;
        }
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(_)) => {
                let values = self.form.values();
                let algorithm = values
                    .get("algorithm")
                    .and_then(|v| match v {
                        FieldValue::Choice(Some(c)) => KeyAlgorithm::from_wire(c),
                        _ => None,
                    })
                    .unwrap_or(KeyAlgorithm::Ed25519);
                let mut label = text_of(&values, "label");
                if label.is_empty() {
                    label = default_label(algorithm, &self.today);
                }
                Some(KeychainAnswer::Generate(GenerateSpec {
                    algorithm,
                    label,
                    comment: text_of(&values, "comment"),
                    passphrase: secret_of(&values, "passphrase"),
                    remember: flag_of(&values, "remember"),
                }))
            }
            Some(FormRequest::Cancel) => {
                cx.close();
                None
            }
            None => None,
        }
    }
}

/// The result of a generation: public key and fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedDialog {
    /// The new key.
    pub item: ItemId,
    /// Its label.
    pub label: String,
    /// The OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:…`
    pub fingerprint: String,
}

/// The paste-import form.
pub fn paste_form() -> Form {
    Form::new("Import key (paste)").section(
        "Key",
        vec![
            Field::multiline("key", "Key", "")
                .required()
                .help("OpenSSH, PEM (PKCS#1 / SEC1), PKCS#8, PuTTY, or a public key line"),
            Field::text("label", "Label", "").help("Default: the key's comment"),
        ],
    )
}

/// The paste-import form on the dialog stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteDialog {
    /// The form.
    pub form: Form,
}

impl PasteDialog {
    /// Handle an event; a save becomes [`KeychainAnswer::Paste`].
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<KeychainAnswer> {
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(_)) => {
                let values = self.form.values();
                let text = values
                    .get("key")
                    .and_then(FieldValue::as_text)
                    .unwrap_or_default();
                Some(KeychainAnswer::Paste {
                    text: SecretValue::from(text),
                    label: text_of(&values, "label"),
                })
            }
            Some(FormRequest::Cancel) => {
                cx.close();
                None
            }
            None => None,
        }
    }
}

/// The change-passphrase form. `ask_current`: the key is encrypted and its passphrase
/// isn't stored.
pub fn change_passphrase_form(label: &str, ask_current: bool, remember: bool) -> Form {
    let mut fields = Vec::new();
    if ask_current {
        fields.push(Field::secret("current", "Current passphrase", None).required());
    }
    fields.push(
        Field::secret("passphrase", "New passphrase", None)
            .help("Empty: store the key without a passphrase (the vault still encrypts it)"),
    );
    fields.push(Field::secret("confirm", "Confirm", None));
    fields.push(Field::toggle(
        "remember",
        "Remember passphrase in vault",
        remember,
    ));
    Form::new(format!("Change passphrase · {label}"))
        .section("Passphrase", fields)
        .validator(FormValidator::new("passphrases_match", passphrases_match))
}

/// The change-passphrase form on the dialog stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePassphraseDialog {
    /// The key.
    pub item: ItemId,
    /// The form.
    pub form: Form,
}

impl ChangePassphraseDialog {
    /// Handle an event; a save becomes [`KeychainAnswer::ChangePassphrase`].
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<KeychainAnswer> {
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(_)) => {
                let values = self.form.values();
                Some(KeychainAnswer::ChangePassphrase {
                    item: self.item,
                    old: secret_of(&values, "current"),
                    new: secret_of(&values, "passphrase"),
                    remember: flag_of(&values, "remember"),
                })
            }
            Some(FormRequest::Cancel) => {
                cx.close();
                None
            }
            None => None,
        }
    }
}
