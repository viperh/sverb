//! M1-06: the full-screen form framework (SPEC §8.6) and its field widgets.
//!
//! A [`Form`] is a title, ordered [`Section`]s of [`Field`]s, a dirty flag and
//! validation hooks. It is plain data with a [`View`] impl, so reducer tests drive it
//! with key events; the owner (e.g. M1-07's host editor) reads the outcome with
//! [`Form::take_request`]:
//! - [`FormRequest::Save`] carries [`FieldChanges`] (only the fields that differ from
//!   the initial values). The owner turns it into its save effect and reports back
//!   with [`Form::save_failed`] (the form stays open, edits intact) or closes it.
//! - [`FormRequest::Cancel`]: `Esc` on a clean form, or "Discard" in the
//!   "Discard changes?" confirm a dirty form shows.
//!
//! Keys (Insert mode, `tasks/03-KEYBINDINGS.md` §4.3): `Tab`/`Shift-Tab` move between
//! fields (`↑/↓` too, where the field does not use them), `ctrl-s` saves, `Esc`
//! cancels, `ctrl-r` reveals a secret field. Everything else goes to the focused field.
//!
//! Validation is inline: per field on blur, and for every field on save. A field's
//! own [`Validator`] runs first, then the form's [`FormValidator`] (cross-field,
//! typically `sverb_core::model::validate::validate_host` over the typed item); its
//! [`ValidationError::field`]s are matched to field keys (`env` also matches `env.X`).
//! Errors render under the field with a `!` marker in the `error` style, so they read
//! the same without color. Saving is blocked while errors exist and focus jumps to the
//! first one.
//!
//! An empty optional field shows its [`Inherited`] value dimmed with its source:
//! `22 (default)`, `2222 (from group "prod")` (provenance from settings resolution,
//! M2-01; until then only global defaults).

pub mod kv_list;
pub mod multiline;
pub mod multiselect;
pub mod number;
pub mod reference;
// M2-05: ordered reference lists (the jump chain).
pub mod ref_list;
pub mod secret;
pub mod select;
pub mod text;

#[cfg(test)]
mod tests;

use std::{cell::Cell, collections::BTreeMap, fmt, sync::Arc};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::{
    model::{ItemId, ItemKind, ValidationError},
    search::IndexSnapshot,
};

use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
    widgets::{confirm, dialog::Modal, truncate, width},
};

pub use kv_list::{KeyCheck, KvListInput};
pub use multiline::MultilineInput;
pub use multiselect::MultiSelectInput;
pub use number::NumberInput;
pub use reference::{RefValue, ReferenceInput};
// M2-05
pub use ref_list::RefListInput;
pub use secret::{SecretInput, SecretValue};
pub use select::{SelectInput, SelectOption};
pub use text::{TextEdit, TextInput};

// ------------------------------------------------------------------ values

/// A field's value, as saved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldValue {
    /// `Text` and `Multiline` fields.
    Text(String),
    /// `Secret` fields.
    Secret(SecretValue),
    /// `Number` fields (`None`: empty, i.e. inherited).
    Number(Option<u64>),
    /// `Toggle` fields.
    Bool(bool),
    /// `Select` fields: the chosen option's value.
    Choice(Option<String>),
    /// `MultiSelect` fields: the checked values.
    Choices(Vec<String>),
    /// `Reference` fields.
    Reference(Option<ItemId>),
    /// `KeyValueList` fields.
    Pairs(Vec<(String, String)>),
    // M2-05
    /// `RefList` fields: the ids in order.
    References(Vec<ItemId>),
}

impl FieldValue {
    /// Whether the value is empty (an optional field then shows its inherited value).
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(s) => s.is_empty(),
            Self::Secret(s) => s.is_empty(),
            Self::Number(n) => n.is_none(),
            Self::Bool(_) => false,
            Self::Choice(c) => c.is_none(),
            Self::Choices(c) => c.is_empty(),
            Self::Reference(r) => r.is_none(),
            Self::Pairs(p) => p.is_empty(),
            // M2-05
            Self::References(r) => r.is_empty(),
        }
    }

    /// The text of a `Text` value.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// The fields a save changes, in form order: `(field key, new value)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldChanges(pub Vec<(String, FieldValue)>);

impl FieldChanges {
    /// The new value of `key`, if it changed.
    pub fn get(&self, key: &str) -> Option<&FieldValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The changed keys.
    pub fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Number of changed fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Nothing changed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// All current values by field key (input to a [`FormValidator`]).
pub type FieldValues = BTreeMap<String, FieldValue>;

// ------------------------------------------------------------------ hooks

/// A per-field check. Function pointers keep the form `Clone + Eq`; equality is by name.
#[derive(Clone, Copy)]
pub struct Validator {
    /// A stable name (for `Debug`/`Eq`).
    pub name: &'static str,
    /// The check: `Err(message)` is shown under the field.
    pub check: fn(&FieldValue) -> Result<(), String>,
}

impl Validator {
    /// A validator.
    pub const fn new(name: &'static str, check: fn(&FieldValue) -> Result<(), String>) -> Self {
        Self { name, check }
    }
}

impl PartialEq for Validator {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Validator {}

impl fmt::Debug for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validator({})", self.name)
    }
}

/// A cross-field check over all values, returning `sverb-core` validation errors.
#[derive(Clone, Copy)]
pub struct FormValidator {
    /// A stable name (for `Debug`/`Eq`).
    pub name: &'static str,
    /// The check.
    pub check: fn(&FieldValues) -> Vec<ValidationError>,
}

impl FormValidator {
    /// A form validator.
    pub const fn new(name: &'static str, check: fn(&FieldValues) -> Vec<ValidationError>) -> Self {
        Self { name, check }
    }
}

impl PartialEq for FormValidator {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for FormValidator {}

impl fmt::Debug for FormValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FormValidator({})", self.name)
    }
}

/// The value an empty optional field inherits, and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inherited {
    /// The resolved value.
    pub value: String,
    /// `None`: the global default; `Some("group \"prod\"")`: an inherited source.
    pub source: Option<String>,
}

impl Inherited {
    /// A global default: `22 (default)`.
    pub fn default_value(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: None,
        }
    }

    /// An inherited value: `2222 (from group "prod")`.
    pub fn from_source(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for Inherited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            None => write!(f, "{} (default)", self.value),
            Some(src) => write!(f, "{} (from {src})", self.value),
        }
    }
}

/// Why a form cannot be edited (SPEC §4.1, §13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadOnly {
    /// The item's schema is newer than this build.
    NewerSchema,
    /// The vault grants only `read`.
    Vault,
}

impl ReadOnly {
    /// The banner text.
    pub fn banner(self) -> &'static str {
        match self {
            Self::NewerSchema => "Update sverb to edit this item",
            Self::Vault => "Read-only vault",
        }
    }
}

// ------------------------------------------------------------------ fields

/// The editor of a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldWidget {
    /// Single-line text.
    Text(TextInput),
    /// Masked secret.
    Secret(SecretInput),
    /// Digits with a range.
    Number(NumberInput),
    /// On/off (`Space`/`Enter`/`←/→` toggle).
    Toggle(bool),
    /// Single choice.
    Select(SelectInput),
    /// Checklist.
    MultiSelect(MultiSelectInput),
    /// Item reference with a fuzzy picker.
    Reference(ReferenceInput),
    /// Key/value rows.
    KeyValueList(KvListInput),
    /// Multi-line text.
    Multiline(Box<MultilineInput>),
    // M2-05
    /// An ordered list of item references.
    RefList(RefListInput),
}

/// One field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The model field name (`address`, `port`, `env`, …); matches
    /// [`ValidationError::field`] and keys [`FieldChanges`].
    pub key: String,
    /// The label shown.
    pub label: String,
    /// The editor.
    pub widget: FieldWidget,
    /// An empty value is an error.
    pub required: bool,
    /// Not reachable and dimmed (e.g. inline credentials while an identity is picked).
    pub disabled: bool,
    /// Not shown at all (fields of features that have not landed, M1-07 §2.3).
    pub hidden: bool,
    /// The inherited value shown when the field is empty.
    pub inherited: Option<Inherited>,
    /// A one-line hint shown dimmed when the field is focused.
    pub help: Option<String>,
    /// The current inline error.
    pub error: Option<String>,
    validator: Option<Validator>,
    initial: FieldValue,
}

impl Field {
    fn new(key: &str, label: &str, widget: FieldWidget) -> Self {
        let mut f = Self {
            key: key.to_owned(),
            label: label.to_owned(),
            widget,
            required: false,
            disabled: false,
            hidden: false,
            inherited: None,
            help: None,
            error: None,
            validator: None,
            initial: FieldValue::Bool(false),
        };
        f.initial = f.value();
        f
    }

    /// A single-line text field.
    pub fn text(key: &str, label: &str, value: &str) -> Self {
        Self::new(key, label, FieldWidget::Text(TextInput::new(value)))
    }

    /// A secret field (masked; `ctrl-r` reveals it while focused).
    pub fn secret(key: &str, label: &str, value: Option<SecretValue>) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::Secret(SecretInput::new(value.unwrap_or_default())),
        )
    }

    /// A number field for `min..=max`.
    pub fn number(key: &str, label: &str, value: Option<u64>, min: u64, max: u64) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::Number(NumberInput::new(value, min, max)),
        )
    }

    /// An on/off field.
    pub fn toggle(key: &str, label: &str, value: bool) -> Self {
        Self::new(key, label, FieldWidget::Toggle(value))
    }

    /// A single-choice field.
    pub fn select(key: &str, label: &str, options: Vec<SelectOption>, value: Option<&str>) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::Select(SelectInput::new(options, value)),
        )
    }

    /// A checklist field.
    pub fn multiselect(
        key: &str,
        label: &str,
        options: Vec<SelectOption>,
        values: &[String],
    ) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::MultiSelect(MultiSelectInput::new(options, values)),
        )
    }

    /// A reference to an item of `kind`.
    pub fn reference(key: &str, label: &str, kind: ItemKind, value: Option<RefValue>) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::Reference(ReferenceInput::new(kind, value)),
        )
    }

    /// A key/value list.
    pub fn key_values(
        key: &str,
        label: &str,
        rows: Vec<(String, String)>,
        check: KeyCheck,
    ) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::KeyValueList(KvListInput::new(rows, check)),
        )
    }

    // M2-05
    /// An ordered list of references to items of `kind`.
    pub fn reference_list(key: &str, label: &str, kind: ItemKind, rows: Vec<RefValue>) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::RefList(RefListInput::new(kind, rows)),
        )
    }

    /// A multi-line text field.
    pub fn multiline(key: &str, label: &str, value: &str) -> Self {
        Self::new(
            key,
            label,
            FieldWidget::Multiline(Box::new(MultilineInput::new(value))),
        )
    }

    /// Mark as required.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Show `inherited` while empty.
    #[must_use]
    pub fn inherited(mut self, inherited: Inherited) -> Self {
        self.inherited = Some(inherited);
        self
    }

    /// Add a field validator.
    #[must_use]
    pub fn validate(mut self, v: Validator) -> Self {
        self.validator = Some(v);
        self
    }

    /// Add a help line.
    #[must_use]
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Disable (skip in tab order, dimmed).
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Hide.
    #[must_use]
    pub fn hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// The current value.
    pub fn value(&self) -> FieldValue {
        match &self.widget {
            FieldWidget::Text(t) => FieldValue::Text(t.text().to_owned()),
            FieldWidget::Secret(s) => FieldValue::Secret(s.value().clone()),
            FieldWidget::Number(n) => FieldValue::Number(n.raw_value()),
            FieldWidget::Toggle(b) => FieldValue::Bool(*b),
            FieldWidget::Select(s) => FieldValue::Choice(s.value().map(str::to_owned)),
            FieldWidget::MultiSelect(m) => FieldValue::Choices(m.values()),
            FieldWidget::Reference(r) => FieldValue::Reference(r.id()),
            FieldWidget::KeyValueList(kv) => {
                let mut kv = kv.clone();
                kv.blur();
                FieldValue::Pairs(kv.rows)
            }
            FieldWidget::Multiline(m) => FieldValue::Text(m.text()),
            // M2-05
            FieldWidget::RefList(l) => FieldValue::References(l.ids()),
        }
    }

    /// The value differs from the initial one.
    pub fn changed(&self) -> bool {
        self.value() != self.initial
    }

    /// The field's own checks: required, number range, list keys, its validator.
    pub fn check(&self) -> Result<(), String> {
        let value = self.value();
        if self.required && value.is_empty() {
            return Err("required".to_owned());
        }
        match &self.widget {
            FieldWidget::Number(n) => {
                n.value()?;
            }
            FieldWidget::KeyValueList(kv) => {
                if let Some((row, msg)) = kv.errors().into_iter().next() {
                    return Err(format!("row {}: {msg}", row + 1));
                }
            }
            // M2-05
            FieldWidget::RefList(l) => {
                if let Some(err) = &l.error {
                    return Err(err.clone());
                }
            }
            _ => {}
        }
        match self.validator {
            Some(v) if !value.is_empty() => (v.check)(&value),
            _ => Ok(()),
        }
    }

    /// A popup or a cell editor is open: it gets every key.
    fn capturing(&self) -> bool {
        match &self.widget {
            FieldWidget::Select(s) => s.is_open(),
            FieldWidget::MultiSelect(m) => m.is_open(),
            FieldWidget::Reference(r) => r.is_open(),
            FieldWidget::KeyValueList(kv) => kv.is_editing(),
            // M2-05
            FieldWidget::RefList(l) => l.is_open(),
            _ => false,
        }
    }

    /// Focus left the field: close popups, commit cell edits, re-mask secrets.
    fn blur(&mut self) {
        match &mut self.widget {
            FieldWidget::Secret(s) => s.blur(),
            FieldWidget::Select(s) => s.blur(),
            FieldWidget::MultiSelect(m) => m.blur(),
            FieldWidget::Reference(r) => r.blur(),
            FieldWidget::KeyValueList(kv) => kv.blur(),
            // M2-05
            FieldWidget::RefList(l) => l.blur(),
            _ => {}
        }
    }

    fn handle_key(&mut self, key: &KeyEvent, index: Option<&IndexSnapshot>) -> TextEdit {
        match &mut self.widget {
            FieldWidget::Text(t) => t.handle_key(key),
            FieldWidget::Secret(s) => s.handle_key(key),
            FieldWidget::Number(n) => n.handle_key(key),
            FieldWidget::Toggle(b) => match key.code {
                KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Left | KeyCode::Right => {
                    *b = !*b;
                    TextEdit::Changed
                }
                _ => TextEdit::Ignored,
            },
            FieldWidget::Select(s) => s.handle_key(key),
            FieldWidget::MultiSelect(m) => m.handle_key(key),
            FieldWidget::Reference(r) => r.handle_key(key, index),
            FieldWidget::KeyValueList(kv) => kv.handle_key(key),
            FieldWidget::Multiline(m) => m.handle_key(key),
            // M2-05
            FieldWidget::RefList(l) => l.handle_key(key, index),
        }
    }

    fn paste(&mut self, s: &str, index: Option<&IndexSnapshot>) -> bool {
        match &mut self.widget {
            FieldWidget::Text(t) => t.insert_str(s),
            FieldWidget::Secret(x) => x.insert_str(s),
            FieldWidget::Number(n) => n.insert_str(s),
            FieldWidget::Reference(r) => r.paste(s, index),
            FieldWidget::KeyValueList(kv) => kv.paste(s),
            FieldWidget::Multiline(m) => m.paste(s),
            // M2-05
            FieldWidget::RefList(l) => l.paste(s, index),
            _ => false,
        }
    }

    fn popup(&self) -> Option<Popup> {
        match &self.widget {
            FieldWidget::Select(s) => s.popup(),
            FieldWidget::MultiSelect(m) => m.popup(),
            FieldWidget::Reference(r) => r.popup(),
            // M2-05
            FieldWidget::RefList(l) => l.popup(),
            _ => None,
        }
    }
}

/// A titled group of fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Heading (empty: none).
    pub title: String,
    /// Fields in tab order.
    pub fields: Vec<Field>,
}

// ------------------------------------------------------------------ popups

/// A dropdown, checklist or picker drawn under its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Popup {
    /// Border title (may be empty).
    pub title: String,
    /// The picker's query line.
    pub query: Option<TextInput>,
    /// Entries.
    pub items: Vec<PopupItem>,
    /// Highlighted entry.
    pub selected: usize,
    /// Text when there are no entries.
    pub empty: String,
}

/// One popup entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopupItem {
    /// The text.
    pub text: String,
    /// Matched char indices (bold + underlined).
    pub highlights: Vec<u32>,
    /// `Some`: a check box (`[x]`/`[ ]`).
    pub checked: Option<bool>,
}

/// `text` with the chars at `highlights` emphasized (bold + underline, so it shows
/// without color too).
pub(crate) fn highlighted(
    text: &str,
    highlights: &[u32],
    base: Style,
    hl: Style,
) -> Vec<Span<'static>> {
    if highlights.is_empty() {
        return vec![Span::styled(text.to_owned(), base)];
    }
    let mut spans = Vec::new();
    let mut cur = String::new();
    let mut cur_hl = false;
    for (i, c) in text.chars().enumerate() {
        let is_hl = u32::try_from(i).is_ok_and(|i| highlights.binary_search(&i).is_ok());
        if is_hl != cur_hl && !cur.is_empty() {
            let style = if cur_hl { hl } else { base };
            spans.push(Span::styled(std::mem::take(&mut cur), style));
        }
        cur_hl = is_hl;
        cur.push(c);
    }
    if !cur.is_empty() {
        spans.push(Span::styled(cur, if cur_hl { hl } else { base }));
    }
    spans
}

/// The highlight style for matches over `base`.
pub(crate) fn match_style(base: Style, theme: &Theme) -> Style {
    base.patch(theme.accent)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Draw `popup` below line `y` (anchored at `x`), clamped to `area`.
pub(crate) fn render_popup(
    popup: &Popup,
    frame: &mut Frame<'_>,
    area: Rect,
    x: u16,
    y: u16,
    theme: &Theme,
) {
    let rows = popup.items.len().clamp(1, 8);
    let query_rows = usize::from(popup.query.is_some());
    let content_w = popup
        .items
        .iter()
        .map(|i| width(&i.text) + 4)
        .max()
        .unwrap_or(0)
        .max(width(&popup.title))
        .max(24);
    let w = u16::try_from(content_w + 2)
        .unwrap_or(u16::MAX)
        .min(area.width);
    let h = u16::try_from(rows + query_rows + 2)
        .unwrap_or(u16::MAX)
        .min(area.height);
    if w < 3 || h < 3 {
        return;
    }
    let below = y.saturating_add(1);
    let top = if below + h <= area.bottom() {
        below
    } else {
        area.bottom().saturating_sub(h).max(area.y)
    };
    let left = x.min(area.right().saturating_sub(w)).max(area.x);
    let rect = Rect::new(left, top, w, h);
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_style(theme.border_focused)
        .title(Span::styled(popup.title.clone(), theme.dim));
    let inner = block.inner(rect);
    frame.render_widget(block.style(theme.base), rect);
    let iw = usize::from(inner.width);
    let mut lines = Vec::new();
    if let Some(q) = &popup.query {
        let mut l = q.line(iw.saturating_sub(2), theme.base, true);
        l.spans.insert(0, Span::styled("/ ", theme.accent));
        lines.push(l);
    }
    let visible = usize::from(inner.height).saturating_sub(query_rows).max(1);
    let skip = (popup.selected + 1).saturating_sub(visible);
    if popup.items.is_empty() {
        lines.push(Line::styled(popup.empty.clone(), theme.dim));
    }
    for (i, item) in popup.items.iter().enumerate().skip(skip).take(visible) {
        let selected = i == popup.selected;
        let base = if selected {
            theme.selection
        } else {
            theme.base
        };
        let mut spans = vec![Span::styled(if selected { "› " } else { "  " }, base)];
        if let Some(c) = item.checked {
            spans.push(Span::styled(if c { "[x] " } else { "[ ] " }, base));
        }
        spans.extend(highlighted(
            &truncate(&item.text, iw.saturating_sub(6)),
            &item.highlights,
            base,
            match_style(base, theme),
        ));
        let used: usize = spans.iter().map(|s| s.width()).sum();
        if selected && used < iw {
            spans.push(Span::styled(" ".repeat(iw - used), base));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

// ------------------------------------------------------------------ form

/// What the form asks its owner to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormRequest {
    /// Save these changes (validated).
    Save(FieldChanges),
    /// Close without saving.
    Cancel,
}

/// A full-screen editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// Title (`New host`, `Edit host`).
    pub title: String,
    sections: Vec<Section>,
    /// Flat index of the focused field (over all sections).
    focus: usize,
    read_only: Option<ReadOnly>,
    validator: Option<FormValidator>,
    /// The "Discard changes?" confirm.
    confirm: Option<Modal>,
    /// A save is in flight.
    saving: bool,
    /// The last save error (shown as a banner).
    save_error: Option<String>,
    request: Option<FormRequest>,
    index: Option<Arc<IndexSnapshot>>,
    /// First rendered body line (kept between frames so scrolling is stable).
    scroll: Cell<usize>,
}

/// Width of the label column, cells.
const LABEL_MAX: usize = 20;

impl Form {
    /// An empty form.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            sections: Vec::new(),
            focus: 0,
            read_only: None,
            validator: None,
            confirm: None,
            saving: false,
            save_error: None,
            request: None,
            index: None,
            scroll: Cell::new(0),
        }
    }

    /// Add a section.
    #[must_use]
    pub fn section(mut self, title: impl Into<String>, fields: Vec<Field>) -> Self {
        self.sections.push(Section {
            title: title.into(),
            fields,
        });
        self.focus = self.first_focusable().unwrap_or(0);
        self
    }

    /// Set the cross-field validator.
    #[must_use]
    pub fn validator(mut self, v: FormValidator) -> Self {
        self.validator = Some(v);
        self
    }

    /// Make the form read-only.
    #[must_use]
    pub fn read_only(mut self, why: ReadOnly) -> Self {
        self.read_only = Some(why);
        self
    }

    /// The search snapshot used by reference pickers.
    pub fn set_index(&mut self, index: Arc<IndexSnapshot>) {
        self.index = Some(index);
    }

    /// Why the form is read-only.
    pub fn read_only_reason(&self) -> Option<ReadOnly> {
        self.read_only
    }

    /// Sections.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn fields(&self) -> impl Iterator<Item = &Field> {
        self.sections.iter().flat_map(|s| s.fields.iter())
    }

    fn field_mut_at(&mut self, i: usize) -> Option<&mut Field> {
        self.sections
            .iter_mut()
            .flat_map(|s| s.fields.iter_mut())
            .nth(i)
    }

    fn field_at(&self, i: usize) -> Option<&Field> {
        self.fields().nth(i)
    }

    /// The field with `key`.
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields().find(|f| f.key == key)
    }

    /// The field with `key`, mutably (e.g. to dim inline credentials).
    pub fn field_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.sections
            .iter_mut()
            .flat_map(|s| s.fields.iter_mut())
            .find(|f| f.key == key)
    }

    /// The focused field.
    pub fn focused(&self) -> Option<&Field> {
        self.field_at(self.focus)
    }

    /// The focused field's key.
    pub fn focused_key(&self) -> Option<&str> {
        self.focused().map(|f| f.key.as_str())
    }

    /// Whether any field differs from its initial value.
    pub fn is_dirty(&self) -> bool {
        self.fields().any(Field::changed)
    }

    /// A save is in flight.
    pub fn is_saving(&self) -> bool {
        self.saving
    }

    /// The "Discard changes?" confirm is open.
    pub fn confirm_open(&self) -> bool {
        self.confirm.is_some()
    }

    /// The form takes text input (Insert mode, M0-10) unless it is read-only.
    pub fn insert_mode(&self) -> bool {
        self.read_only.is_none() || self.confirm.is_some()
    }

    /// All current values by key.
    pub fn values(&self) -> FieldValues {
        self.fields().map(|f| (f.key.clone(), f.value())).collect()
    }

    /// Only the changed fields, in form order.
    pub fn changes(&self) -> FieldChanges {
        FieldChanges(
            self.fields()
                .filter(|f| f.changed())
                .map(|f| (f.key.clone(), f.value()))
                .collect(),
        )
    }

    /// The pending request, if any (taken once).
    pub fn take_request(&mut self) -> Option<FormRequest> {
        self.request.take()
    }

    /// The owner's save failed: stay open with the edits, show `message`.
    pub fn save_failed(&mut self, message: impl Into<String>) {
        self.saving = false;
        self.save_error = Some(message.into());
    }

    /// The owner's save succeeded: the current values become the initial ones.
    pub fn saved(&mut self) {
        self.saving = false;
        self.save_error = None;
        for s in &mut self.sections {
            for f in &mut s.fields {
                f.initial = f.value();
            }
        }
    }

    fn focusable(&self, f: &Field) -> bool {
        !f.hidden && (!f.disabled || self.read_only.is_some())
    }

    fn first_focusable(&self) -> Option<usize> {
        self.fields().position(|f| self.focusable(f))
    }

    fn count(&self) -> usize {
        self.fields().count()
    }

    fn move_focus(&mut self, forward: bool) {
        let n = self.count();
        if n == 0 {
            return;
        }
        let mut i = self.focus;
        for _ in 0..n {
            i = if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            if self.field_at(i).is_some_and(|f| self.focusable(f)) {
                self.set_focus(i);
                return;
            }
        }
    }

    fn set_focus(&mut self, i: usize) {
        if i == self.focus {
            return;
        }
        let old = self.focus;
        if let Some(f) = self.field_mut_at(old) {
            f.blur();
        }
        self.validate_field(old);
        self.focus = i;
    }

    fn form_errors(&self) -> Vec<ValidationError> {
        self.validator
            .map(|v| (v.check)(&self.values()))
            .unwrap_or_default()
    }

    fn error_for(errors: &[ValidationError], key: &str) -> Option<String> {
        errors
            .iter()
            .find(|e| {
                e.field == key
                    || e.field
                        .strip_prefix(key)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .map(|e| e.message.clone())
    }

    /// Validate one field (on blur). Returns whether it is valid.
    fn validate_field(&mut self, i: usize) -> bool {
        let errors = self.form_errors();
        let Some(f) = self.field_mut_at(i) else {
            return true;
        };
        f.error = if f.hidden {
            None
        } else {
            f.check().err().or_else(|| Self::error_for(&errors, &f.key))
        };
        f.error.is_none()
    }

    /// Validate every field (on save). Returns the flat index of the first error.
    pub fn validate_all(&mut self) -> Option<usize> {
        let errors = self.form_errors();
        let mut first = None;
        let mut i = 0;
        for s in &mut self.sections {
            for f in &mut s.fields {
                f.error = if f.hidden {
                    None
                } else {
                    f.check().err().or_else(|| Self::error_for(&errors, &f.key))
                };
                if f.error.is_some() && first.is_none() {
                    first = Some(i);
                }
                i += 1;
            }
        }
        first
    }

    fn save(&mut self) {
        if self.read_only.is_some() || self.saving {
            return;
        }
        if let Some(f) = self.field_mut_at(self.focus) {
            f.blur();
        }
        if let Some(first) = self.validate_all() {
            self.focus = first;
            return;
        }
        self.saving = true;
        self.save_error = None;
        self.request = Some(FormRequest::Save(self.changes()));
    }

    fn cancel(&mut self) {
        if self.is_dirty() && self.read_only.is_none() {
            self.confirm = Some(confirm::discard_changes());
        } else {
            self.request = Some(FormRequest::Cancel);
        }
    }

    fn on_key(&mut self, key: &KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let index = self.index.clone();
        let editable = self.read_only.is_none() && !self.saving;
        let focus = self.focus;
        let capturing = self.field_at(focus).is_some_and(Field::capturing);
        if capturing && editable {
            if let Some(f) = self.field_mut_at(focus)
                && f.handle_key(key, index.as_deref()) == TextEdit::Changed
            {
                f.error = None;
            }
            return;
        }
        match key.code {
            KeyCode::Tab => self.move_focus(!key.modifiers.contains(KeyModifiers::SHIFT)),
            KeyCode::BackTab => self.move_focus(false),
            KeyCode::Char('s') if ctrl => self.save(),
            KeyCode::Esc => self.cancel(),
            _ if !editable => match key.code {
                KeyCode::Down => self.move_focus(true),
                KeyCode::Up => self.move_focus(false),
                _ => {}
            },
            _ => {
                let r = self
                    .field_mut_at(focus)
                    .map_or(TextEdit::Ignored, |f| f.handle_key(key, index.as_deref()));
                match r {
                    TextEdit::Changed => {
                        if let Some(f) = self.field_mut_at(focus) {
                            f.error = None;
                        }
                    }
                    TextEdit::Ignored if key.code == KeyCode::Down => self.move_focus(true),
                    TextEdit::Ignored if key.code == KeyCode::Up => self.move_focus(false),
                    _ => {}
                }
            }
        }
    }

    // ---------------------------------------------------------- rendering

    fn label_width(&self) -> usize {
        self.fields()
            .filter(|f| !f.hidden)
            .map(|f| width(&f.label))
            .max()
            .unwrap_or(0)
            .min(LABEL_MAX)
            + 3
    }

    /// The value line(s) of a field.
    fn value_lines(&self, f: &Field, focused: bool, w: usize, theme: &Theme) -> Vec<Line<'static>> {
        let base = if f.disabled || self.read_only.is_some() {
            theme.dim
        } else {
            theme.base
        };
        let cursor = focused && self.read_only.is_none() && !f.disabled;
        let value = f.value();
        if value.is_empty()
            && !matches!(
                f.widget,
                FieldWidget::KeyValueList(_) | FieldWidget::Multiline(_) | FieldWidget::RefList(_)
            )
            && let Some(inh) = &f.inherited
        {
            let mut spans = Vec::new();
            if cursor {
                spans.push(Span::styled(" ", base.add_modifier(Modifier::REVERSED)));
            }
            spans.push(Span::styled(
                truncate(&inh.to_string(), w.saturating_sub(1)),
                theme.dim,
            ));
            return vec![Line::from(spans)];
        }
        match &f.widget {
            FieldWidget::Text(t) => vec![t.line(w, base, cursor)],
            FieldWidget::Secret(s) => vec![s.line(w, base, cursor)],
            FieldWidget::Number(n) => vec![n.line(w, base, cursor)],
            FieldWidget::Toggle(b) => {
                let text = if *b { "[x] yes" } else { "[ ] no" };
                vec![Line::styled(
                    text,
                    if cursor {
                        base.add_modifier(Modifier::BOLD)
                    } else {
                        base
                    },
                )]
            }
            FieldWidget::Select(s) => {
                let label = if s.selected.is_none() {
                    "(none)"
                } else {
                    s.label()
                };
                let text = if focused {
                    format!("‹ {label} ›")
                } else {
                    label.to_owned()
                };
                vec![Line::styled(truncate(&text, w), base)]
            }
            FieldWidget::MultiSelect(m) => {
                let summary = m.summary();
                let text = if summary.is_empty() {
                    "(none)".to_owned()
                } else {
                    summary
                };
                vec![Line::styled(truncate(&text, w), base)]
            }
            FieldWidget::Reference(r) => {
                let text = r
                    .value
                    .as_ref()
                    .map_or_else(|| "(none)".to_owned(), |v| format!("→ {}", v.label));
                vec![Line::styled(truncate(&text, w), base)]
            }
            FieldWidget::KeyValueList(kv) => kv_lines(kv, focused && cursor, w, base, theme),
            FieldWidget::Multiline(m) => multiline_lines(m, cursor, w, base),
            // M2-05
            FieldWidget::RefList(l) => {
                ref_list_lines(l, f.inherited.as_ref(), focused && cursor, w, base, theme)
            }
        }
    }
}

// M2-05
fn ref_list_lines(
    l: &RefListInput,
    inherited: Option<&Inherited>,
    focused: bool,
    w: usize,
    base: Style,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if l.rows.is_empty() {
        let text = inherited.map_or_else(|| "(none)".to_owned(), ToString::to_string);
        lines.push(Line::styled(truncate(&text, w), theme.dim));
    }
    for (i, r) in l.rows.iter().enumerate() {
        let selected = focused && i == l.selected;
        let marker = if selected { "› " } else { "  " };
        let style = if selected { theme.selection } else { base };
        lines.push(Line::from(vec![
            Span::styled(marker, base),
            Span::styled(
                truncate(&format!("{}. {}", i + 1, r.label), w.saturating_sub(2)),
                style,
            ),
        ]));
    }
    if let Some(note) = &l.note {
        lines.push(Line::styled(truncate(note, w), theme.dim));
    }
    if focused && !l.is_open() {
        lines.push(Line::styled(
            "a add · d remove · K/J move up/down",
            theme.dim,
        ));
    }
    lines
}

fn kv_lines(
    kv: &KvListInput,
    focused: bool,
    w: usize,
    base: Style,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let errors = kv.errors();
    if kv.rows.is_empty() {
        lines.push(Line::styled("(none)", theme.dim));
    }
    for (i, (k, v)) in kv.rows.iter().enumerate() {
        let selected = focused && i == kv.selected;
        let marker = if selected { "› " } else { "  " };
        let mut spans = vec![Span::styled(marker, base)];
        let editing = kv.editing.as_ref().filter(|e| e.row == i);
        let half = w.saturating_sub(5) / 2;
        match editing {
            Some(e) if !e.value => {
                spans.extend(e.input.line(half.max(1), base, true).spans);
                spans.push(Span::styled(format!(" = {}", truncate(v, half)), base));
            }
            Some(e) => {
                spans.push(Span::styled(format!("{} = ", truncate(k, half)), base));
                spans.extend(e.input.line(half.max(1), base, true).spans);
            }
            None => {
                let style = if selected { theme.selection } else { base };
                spans.push(Span::styled(
                    format!("{} = {}", truncate(k, half), truncate(v, half)),
                    style,
                ));
            }
        }
        lines.push(Line::from(spans));
        for (_, msg) in errors.iter().filter(|(r, _)| *r == i) {
            lines.push(Line::styled(
                truncate(&format!("  ! {msg}"), w),
                theme.error,
            ));
        }
    }
    if focused && kv.editing.is_none() {
        lines.push(Line::styled("a add · e edit · d delete", theme.dim));
    }
    lines
}

fn multiline_lines(m: &MultilineInput, cursor: bool, w: usize, base: Style) -> Vec<Line<'static>> {
    let (row, col) = m.cursor();
    let mut lines: Vec<Line<'static>> = m
        .lines()
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if cursor && i == row {
                text::render_line(l, col, w, base, true)
            } else {
                Line::styled(truncate(l, w), base)
            }
        })
        .collect();
    if lines.len() < 3 {
        lines.resize(3, Line::raw(""));
    }
    lines
}

impl View for Form {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        cx.request_redraw();
        if let Some(modal) = &mut self.confirm {
            if let ViewEvent::Key(key) = ev
                && let Some(answer) = modal.handle_key(key)
            {
                self.confirm = None;
                if answer.is_button(confirm::DISCARD) {
                    self.request = Some(FormRequest::Cancel);
                }
            }
            return Outcome::Consumed;
        }
        match ev {
            ViewEvent::Key(key) => self.on_key(key),
            ViewEvent::Paste(text) if self.read_only.is_none() && !self.saving => {
                let index = self.index.clone();
                let focus = self.focus;
                if let Some(f) = self.field_mut_at(focus)
                    && f.paste(text, index.as_deref())
                {
                    f.error = None;
                }
            }
            _ => return Outcome::Ignored,
        }
        Outcome::Consumed
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        if area.width < 4 || area.height < 3 {
            return;
        }
        frame.render_widget(Clear, area);
        let dirty = if self.is_dirty() { " *" } else { "" };
        let hints = if self.read_only.is_some() {
            " tab next · esc close "
        } else {
            " tab next · shift-tab prev · ctrl-s save · esc cancel "
        };
        let block = Block::bordered()
            .title(Span::styled(
                format!(" {}{dirty} ", self.title),
                theme.title_for(cx.focused),
            ))
            .title_bottom(Span::styled(hints, theme.dim))
            .border_style(theme.border_for(cx.focused));
        let inner = block.inner(area);
        frame.render_widget(block.style(theme.base), area);
        let iw = usize::from(inner.width);
        let mut banner: Vec<Line<'static>> = Vec::new();
        if let Some(ro) = self.read_only {
            banner.push(Line::styled(format!("! {}", ro.banner()), theme.warn));
        }
        if self.saving {
            banner.push(Line::styled("Saving…", theme.info));
        }
        if let Some(err) = &self.save_error {
            banner.push(Line::styled(
                truncate(&format!("! Save failed: {err}"), iw),
                theme.error,
            ));
        }

        // Body lines and where the focused field sits.
        let lw = self.label_width();
        let vw = iw.saturating_sub(lw + 1).max(1);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut focus_at: Option<(usize, usize)> = None;
        let mut i = 0;
        for s in &self.sections {
            let visible = s.fields.iter().any(|f| !f.hidden);
            if visible && !s.title.is_empty() {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::styled(s.title.clone(), theme.accent));
            }
            for f in &s.fields {
                let idx = i;
                i += 1;
                if f.hidden {
                    continue;
                }
                let focused = idx == self.focus && cx.focused;
                let start = lines.len();
                let marker = if focused { "› " } else { "  " };
                let label_style = if focused {
                    theme.selection
                } else if f.disabled {
                    theme.dim
                } else {
                    theme.base
                };
                let req = if f.required { "*" } else { "" };
                let label = format!("{}{req}", truncate(&f.label, LABEL_MAX));
                let label = format!("{marker}{label:<w$}", w = lw - 2);
                let values = self.value_lines(f, focused, vw, theme);
                for (n, v) in values.into_iter().enumerate() {
                    let mut spans = if n == 0 {
                        vec![Span::styled(label.clone(), label_style), Span::raw(" ")]
                    } else {
                        vec![Span::raw(" ".repeat(lw + 1))]
                    };
                    spans.extend(v.spans);
                    lines.push(Line::from(spans));
                }
                if let Some(err) = &f.error {
                    lines.push(Line::from(vec![
                        Span::raw(" ".repeat(lw + 1)),
                        Span::styled(truncate(&format!("! {err}"), vw), theme.error),
                    ]));
                }
                if focused && let Some(help) = &f.help {
                    lines.push(Line::from(vec![
                        Span::raw(" ".repeat(lw + 1)),
                        Span::styled(truncate(help, vw), theme.dim),
                    ]));
                }
                if focused {
                    focus_at = Some((start, lines.len()));
                }
            }
        }
        let body_h = usize::from(inner.height)
            .saturating_sub(banner.len())
            .max(1);
        let mut scroll = self.scroll.get().min(lines.len().saturating_sub(body_h));
        if let Some((start, end)) = focus_at {
            if start < scroll {
                scroll = start;
            } else if end > scroll + body_h {
                scroll = end.saturating_sub(body_h).min(start);
            }
        }
        self.scroll.set(scroll);
        let banner_h = u16::try_from(banner.len()).unwrap_or(0).min(inner.height);
        frame.render_widget(
            Paragraph::new(banner),
            Rect {
                height: banner_h,
                ..inner
            },
        );
        let body = Rect {
            y: inner.y + banner_h,
            height: inner.height - banner_h,
            ..inner
        };
        frame.render_widget(
            Paragraph::new(
                lines
                    .into_iter()
                    .skip(scroll)
                    .take(body_h)
                    .collect::<Vec<_>>(),
            ),
            body,
        );
        // A focused field's popup, under its first line.
        if let (Some(f), Some((start, _))) = (self.focused(), focus_at)
            && let Some(popup) = f.popup()
            && start >= scroll
        {
            let y = body.y + u16::try_from(start - scroll).unwrap_or(0);
            let x = body.x + u16::try_from(lw + 1).unwrap_or(0);
            render_popup(&popup, frame, body, x, y, theme);
        }
        if let Some(modal) = &self.confirm {
            modal.render(frame, area, cx);
        }
    }

    fn insert_mode(&self) -> bool {
        Form::insert_mode(self)
    }
}
