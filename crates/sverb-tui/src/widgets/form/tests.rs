#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};
use pretty_assertions::assert_eq;
use sverb_core::{
    model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, ValidationError, VaultId, validate},
    search::ItemIndex,
};

use super::*;
use crate::{
    views::ViewEvent,
    widgets::test_util::{draw, key, keys, send, text, theme, type_text},
};

fn press(form: &mut Form, code: KeyCode) {
    key(form, code, KeyModifiers::NONE);
}

fn ctrl(form: &mut Form, c: char) {
    key(form, KeyCode::Char(c), KeyModifiers::CONTROL);
}

fn address_check(v: &FieldValue) -> Result<(), String> {
    let text = v.as_text().unwrap_or_default();
    validate::validate_address(text)
        .map(|_| ())
        .map_err(|e| e.message)
}

/// Cross-field: a password and an identity are exclusive (form-level hook).
fn host_rules(values: &FieldValues) -> Vec<ValidationError> {
    let has_identity = matches!(values.get("identity"), Some(FieldValue::Reference(Some(_))));
    let has_password =
        matches!(values.get("password"), Some(FieldValue::Secret(s)) if !s.is_empty());
    if has_identity && has_password {
        vec![ValidationError::new(
            "password",
            "clear the identity to use a password",
        )]
    } else {
        Vec::new()
    }
}

fn host_form() -> Form {
    Form::new("Edit host")
        .section(
            "General",
            vec![
                Field::text("label", "Label", "web"),
                Field::text("address", "Address", "10.0.0.1")
                    .required()
                    .validate(Validator::new("address", address_check)),
                Field::number("port", "Port", None, 1, 65535)
                    .inherited(Inherited::default_value("22")),
                Field::toggle("pinned", "Pinned", false),
            ],
        )
        .section(
            "Credentials",
            vec![
                Field::reference("identity", "Identity", ItemKind::Identity, None),
                Field::text("username", "Username", "").disabled(true),
                Field::secret("password", "Password", Some(SecretValue::from("hunter2"))),
            ],
        )
        .validator(FormValidator::new("host", host_rules))
}

#[test]
fn t08_tab_order_follows_fields() {
    let mut form = host_form();
    let mut order = vec![form.focused_key().unwrap().to_owned()];
    for _ in 0..5 {
        press(&mut form, KeyCode::Tab);
        order.push(form.focused_key().unwrap().to_owned());
    }
    // `username` is disabled and skipped; the order wraps.
    assert_eq!(
        order,
        ["label", "address", "port", "pinned", "identity", "password"]
    );
    press(&mut form, KeyCode::Tab);
    assert_eq!(form.focused_key(), Some("label"));
    press(&mut form, KeyCode::BackTab);
    assert_eq!(form.focused_key(), Some("password"));
    press(&mut form, KeyCode::BackTab);
    assert_eq!(form.focused_key(), Some("identity"));
    key(&mut form, KeyCode::Tab, KeyModifiers::SHIFT);
    assert_eq!(form.focused_key(), Some("pinned"));
    // Up/Down move between single-line fields too.
    press(&mut form, KeyCode::Up);
    assert_eq!(form.focused_key(), Some("port"));
    assert!(form.insert_mode());
}

fn focus(form: &mut Form, key: &str) {
    for _ in 0..20 {
        if form.focused_key() == Some(key) {
            return;
        }
        press(form, KeyCode::Tab);
    }
    panic!("no field {key}");
}

#[test]
fn t09_secret_masked_reveal_and_remask() {
    let mut form = host_form();
    focus(&mut form, "password");
    let screen = text(&draw(&form, 80, 24, false));
    assert!(!screen.contains("hunter2"), "{screen}");
    assert!(screen.contains("•••••••"));
    ctrl(&mut form, 'r');
    assert!(text(&draw(&form, 80, 24, false)).contains("hunter2"));
    // Editing while revealed, then focus leaves: masked again.
    type_text(&mut form, "!");
    press(&mut form, KeyCode::Tab);
    let screen = text(&draw(&form, 80, 24, false));
    assert!(!screen.contains("hunter2"), "{screen}");
    assert!(screen.contains("••••••••"));
    // Coming back does not reveal it.
    press(&mut form, KeyCode::BackTab);
    assert!(!text(&draw(&form, 80, 24, false)).contains("hunter2"));
    // Debug output of the form never contains the secret.
    assert!(!format!("{form:?}").contains("hunter2"));
    match form.changes().get("password") {
        Some(FieldValue::Secret(s)) => assert_eq!(s.expose(), "hunter2!"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn t10_number_rejects_letters_and_checks_the_range() {
    let mut form = host_form();
    focus(&mut form, "port");
    type_text(&mut form, "8a0x");
    assert_eq!(
        form.field("port").unwrap().value(),
        FieldValue::Number(Some(80))
    );
    form.field_mut("port").unwrap().widget = FieldWidget::Number(NumberInput::new(None, 1, 65535));
    type_text(&mut form, "70000");
    assert_eq!(form.field("port").unwrap().error, None, "not while typing");
    press(&mut form, KeyCode::Tab);
    let err = form.field("port").unwrap().error.clone().unwrap();
    assert_eq!(err, "must be between 1 and 65535");
    let screen = text(&draw(&form, 80, 24, false));
    assert!(screen.contains("! must be between 1 and 65535"), "{screen}");
    // Pastes must be all digits.
    press(&mut form, KeyCode::BackTab);
    send(&mut form, &ViewEvent::Paste("12x".into()));
    assert_eq!(
        form.field("port").unwrap().value(),
        FieldValue::Number(Some(70000))
    );
}

#[test]
fn t11_save_blocks_on_errors_and_sends_only_changes() {
    let mut form = host_form();
    focus(&mut form, "address");
    ctrl(&mut form, 'u');
    type_text(&mut form, "root@x");
    focus(&mut form, "port");
    type_text(&mut form, "70000");
    focus(&mut form, "label");
    ctrl(&mut form, 's');
    assert_eq!(form.take_request(), None, "save blocked");
    assert_eq!(
        form.focused_key(),
        Some("address"),
        "focus on the first error"
    );
    assert!(form.field("address").unwrap().error.is_some());
    assert!(form.field("port").unwrap().error.is_some());

    // Fix both; the label stays unchanged.
    ctrl(&mut form, 'u');
    type_text(&mut form, "db.example.com");
    focus(&mut form, "port");
    press(&mut form, KeyCode::Backspace);
    press(&mut form, KeyCode::Backspace);
    press(&mut form, KeyCode::Backspace);
    ctrl(&mut form, 's');
    let Some(FormRequest::Save(changes)) = form.take_request() else {
        panic!("expected a save");
    };
    assert_eq!(changes.keys(), ["address", "port"]);
    assert_eq!(
        changes.get("address"),
        Some(&FieldValue::Text("db.example.com".into()))
    );
    assert_eq!(changes.get("port"), Some(&FieldValue::Number(Some(70))));
    assert!(form.is_saving());
}

#[test]
fn t11_form_validator_errors_land_on_their_field() {
    let mut form = host_form();
    form.field_mut("identity").unwrap().widget = FieldWidget::Reference(ReferenceInput::new(
        ItemKind::Identity,
        Some(RefValue {
            id: ItemId::new(),
            label: "ops".into(),
        }),
    ));
    ctrl(&mut form, 's');
    assert_eq!(form.take_request(), None);
    assert_eq!(form.focused_key(), Some("password"));
    assert_eq!(
        form.field("password").unwrap().error.as_deref(),
        Some("clear the identity to use a password")
    );
}

#[test]
fn t12_esc_confirms_when_dirty() {
    let mut clean = host_form();
    press(&mut clean, KeyCode::Esc);
    assert_eq!(clean.take_request(), Some(FormRequest::Cancel));

    let mut form = host_form();
    type_text(&mut form, "x");
    assert!(form.is_dirty());
    press(&mut form, KeyCode::Esc);
    assert!(form.confirm_open());
    assert!(text(&draw(&form, 80, 24, false)).contains("Discard changes?"));
    // Danger dialog: Enter is the safe "Keep editing".
    press(&mut form, KeyCode::Enter);
    assert!(!form.confirm_open());
    assert_eq!(form.take_request(), None);
    assert_eq!(
        form.field("label").unwrap().value(),
        FieldValue::Text("webx".into())
    );
    press(&mut form, KeyCode::Esc);
    keys(&mut form, "d");
    assert_eq!(form.take_request(), Some(FormRequest::Cancel));
}

fn index_with(items: &[(ItemKind, &str)]) -> (Arc<sverb_core::search::IndexSnapshot>, Vec<ItemId>) {
    let mut clock = HlcClock::default();
    let device = DeviceId::new();
    let vault = VaultId::new();
    let mut bodies = Vec::new();
    let mut ids = Vec::new();
    for (kind, label) in items {
        let id = ItemId::new();
        let mut body = ItemBody::new(*kind, 1);
        let field = if *kind == ItemKind::Group {
            "name"
        } else {
            "label"
        };
        body.set(field, *label, &mut clock, device);
        if *kind == ItemKind::Host {
            body.set("address", "10.0.0.1", &mut clock, device);
        }
        bodies.push((id, vault, body));
        ids.push(id);
    }
    let mut index = ItemIndex::build(bodies.iter().map(|(i, v, b)| (*i, *v, b)));
    (index.snapshot(), ids)
}

#[test]
fn t13_reference_picker_filters_by_kind() {
    let (index, ids) = index_with(&[
        (ItemKind::Identity, "alice-ops"),
        (ItemKind::Identity, "bob-dev"),
        (ItemKind::Host, "alice-host"),
        (ItemKind::Group, "alice-group"),
    ]);
    let mut form = host_form();
    form.set_index(index);
    focus(&mut form, "identity");
    press(&mut form, KeyCode::Enter);
    let labels = |form: &Form| match &form.field("identity").unwrap().widget {
        FieldWidget::Reference(r) => r
            .candidates()
            .iter()
            .map(|c| c.label.clone())
            .collect::<Vec<_>>(),
        _ => unreachable!(),
    };
    let mut all = labels(&form);
    all.sort();
    assert_eq!(all, ["alice-ops", "bob-dev"]);
    type_text(&mut form, "ali");
    assert_eq!(labels(&form), ["alice-ops"]);
    let screen = text(&draw(&form, 80, 24, false));
    assert!(screen.contains("pick identity"), "{screen}");
    press(&mut form, KeyCode::Enter);
    assert_eq!(
        form.field("identity").unwrap().value(),
        FieldValue::Reference(Some(ids[0]))
    );
    assert!(text(&draw(&form, 80, 24, false)).contains("→ alice-ops"));
    press(&mut form, KeyCode::Delete);
    assert_eq!(
        form.field("identity").unwrap().value(),
        FieldValue::Reference(None)
    );
}

#[test]
fn t14_key_value_list_add_edit_delete() {
    let mut form = Form::new("Env").section(
        "",
        vec![Field::key_values(
            "env",
            "Environment",
            Vec::new(),
            KeyCheck::EnvName,
        )],
    );
    keys(&mut form, "a");
    type_text(&mut form, "LANG");
    press(&mut form, KeyCode::Enter);
    type_text(&mut form, "C.UTF-8");
    press(&mut form, KeyCode::Enter);
    keys(&mut form, "a");
    type_text(&mut form, "1BAD");
    press(&mut form, KeyCode::Enter);
    type_text(&mut form, "x");
    press(&mut form, KeyCode::Enter);
    assert_eq!(
        form.field("env").unwrap().value(),
        FieldValue::Pairs(vec![
            ("LANG".into(), "C.UTF-8".into()),
            ("1BAD".into(), "x".into())
        ])
    );
    let screen = text(&draw(&form, 80, 24, false));
    assert!(
        screen.contains("! invalid variable name \"1BAD\""),
        "{screen}"
    );
    ctrl(&mut form, 's');
    assert_eq!(form.take_request(), None, "invalid names block the save");
    // Edit the bad row's key.
    keys(&mut form, "e");
    ctrl(&mut form, 'u');
    type_text(&mut form, "GOOD");
    press(&mut form, KeyCode::Enter);
    press(&mut form, KeyCode::Enter);
    assert!(!text(&draw(&form, 80, 24, false)).contains("invalid variable"));
    // Delete the first row.
    press(&mut form, KeyCode::Up);
    keys(&mut form, "d");
    assert_eq!(
        form.field("env").unwrap().value(),
        FieldValue::Pairs(vec![("GOOD".into(), "x".into())])
    );
    // Esc on a freshly added row with an empty key drops it.
    keys(&mut form, "a");
    press(&mut form, KeyCode::Esc);
    assert_eq!(
        form.field("env").unwrap().value(),
        FieldValue::Pairs(vec![("GOOD".into(), "x".into())])
    );
    ctrl(&mut form, 's');
    assert!(matches!(form.take_request(), Some(FormRequest::Save(_))));
}

#[test]
fn t15_inherited_placeholder_is_dimmed() {
    let form = Form::new("Edit host").section(
        "Connection",
        vec![
            Field::text("address", "Address", "10.0.0.1"),
            Field::number("port", "Port", None, 1, 65535).inherited(Inherited::default_value("22")),
            Field::number("keepalive", "Keepalive", None, 0, 3600)
                .inherited(Inherited::from_source("30", "group \"prod\"")),
        ],
    );
    let buf = draw(&form, 60, 10, false);
    let screen = text(&buf);
    assert!(screen.contains("22 (default)"), "{screen}");
    assert!(screen.contains("30 (from group \"prod\")"));
    insta::assert_snapshot!("t15_inherited_60x10", screen);
    let (y, line) = screen
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("22 (default)"))
        .unwrap();
    let x = line.chars().position(|c| c == '2').unwrap();
    let cell = &buf[(u16::try_from(x).unwrap(), u16::try_from(y).unwrap())];
    assert_eq!(cell.fg, theme(false).dim.fg.unwrap(), "dimmed");
    // An empty inherited field is not a change.
    assert!(!form.is_dirty());
}

#[test]
fn t16_read_only_form() {
    let mut form = host_form().read_only(ReadOnly::Vault);
    assert!(!form.insert_mode());
    type_text(&mut form, "zzz");
    assert!(!form.is_dirty());
    ctrl(&mut form, 's');
    assert_eq!(form.take_request(), None);
    let screen = text(&draw(&form, 80, 24, false));
    assert!(screen.contains("! Read-only vault"), "{screen}");
    // Tab still moves (to read everything); Esc closes at once.
    press(&mut form, KeyCode::Tab);
    assert_eq!(form.focused_key(), Some("address"));
    press(&mut form, KeyCode::Esc);
    assert_eq!(form.take_request(), Some(FormRequest::Cancel));
    let newer = host_form().read_only(ReadOnly::NewerSchema);
    assert!(text(&draw(&newer, 80, 24, false)).contains("Update sverb to edit this item"));
}

#[test]
fn t17_failed_save_keeps_the_edits() {
    let mut form = host_form();
    type_text(&mut form, "-2");
    ctrl(&mut form, 's');
    assert!(matches!(form.take_request(), Some(FormRequest::Save(_))));
    // Edits are ignored while the save is in flight.
    type_text(&mut form, "zz");
    form.save_failed("database is locked");
    assert!(!form.is_saving());
    assert!(form.is_dirty());
    assert_eq!(
        form.field("label").unwrap().value(),
        FieldValue::Text("web-2".into())
    );
    let screen = text(&draw(&form, 80, 24, false));
    assert!(
        screen.contains("! Save failed: database is locked"),
        "{screen}"
    );
    ctrl(&mut form, 's');
    let Some(FormRequest::Save(changes)) = form.take_request() else {
        panic!("retry saves again");
    };
    assert_eq!(changes.keys(), ["label"]);
    form.saved();
    assert!(!form.is_dirty());
}

#[test]
fn select_multiselect_multiline_and_toggle() {
    let mut form = Form::new("Misc").section(
        "",
        vec![
            Field::select(
                "charset",
                "Charset",
                select::options(&["utf-8", "latin1", "koi8-r"]),
                Some("utf-8"),
            ),
            Field::multiselect(
                "tags",
                "Tags",
                select::options(&["web", "db", "prod"]),
                &["db".to_owned()],
            ),
            Field::toggle("pinned", "Pinned", false),
            Field::multiline("notes", "Notes", "first"),
        ],
    );
    press(&mut form, KeyCode::Right);
    assert_eq!(
        form.field("charset").unwrap().value(),
        FieldValue::Choice(Some("latin1".into()))
    );
    press(&mut form, KeyCode::Enter);
    let screen = text(&draw(&form, 60, 16, false));
    assert!(screen.contains("koi8-r"), "dropdown open: {screen}");
    press(&mut form, KeyCode::Down);
    press(&mut form, KeyCode::Enter);
    assert_eq!(
        form.field("charset").unwrap().value(),
        FieldValue::Choice(Some("koi8-r".into()))
    );

    press(&mut form, KeyCode::Tab);
    press(&mut form, KeyCode::Enter);
    keys(&mut form, "space down down space");
    press(&mut form, KeyCode::Enter);
    assert_eq!(
        form.field("tags").unwrap().value(),
        FieldValue::Choices(vec!["web".into(), "db".into(), "prod".into()])
    );

    press(&mut form, KeyCode::Tab);
    keys(&mut form, "space");
    assert_eq!(
        form.field("pinned").unwrap().value(),
        FieldValue::Bool(true)
    );

    press(&mut form, KeyCode::Tab);
    press(&mut form, KeyCode::End);
    press(&mut form, KeyCode::Enter);
    type_text(&mut form, "second");
    assert_eq!(
        form.field("notes").unwrap().value(),
        FieldValue::Text("first\nsecond".into())
    );
    let screen = text(&draw(&form, 60, 16, false));
    assert!(screen.contains("second"));
    assert_eq!(
        form.changes().keys(),
        ["charset", "tags", "pinned", "notes"]
    );
}

#[test]
fn every_field_renders_without_color() {
    let form = host_form();
    let buf = draw(&form, 80, 24, true);
    crate::widgets::test_util::assert_no_color(&buf);
}

#[test]
fn form_with_inline_error_snapshot() {
    let mut form = host_form();
    focus(&mut form, "port");
    type_text(&mut form, "70000");
    press(&mut form, KeyCode::Tab);
    insta::assert_snapshot!("form_error_80x24", text(&draw(&form, 80, 24, false)));
}
