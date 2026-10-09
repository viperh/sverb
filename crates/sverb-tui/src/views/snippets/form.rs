//! The snippet editor (SPEC §4.9, §8.5).
//!
//! Fields: name, description, tags, run mode, script (multi-line), variables (a
//! key/value list `name = default`; an empty default means "ask") and the secret
//! variables (comma-separated names: masked in the form, never saved to history).
//!
//! On save the script must parse. Variables the script uses but the list lacks are
//! **auto-added after a prompt** ("Add variables a, b?": `y` adds them with their inline
//! defaults, `n` saves as is; they are asked at run time either way).

use std::collections::BTreeMap;

use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect, widgets::Clear};
use sverb_core::{
    model::{ItemId, RunMode, Snippet, ValidationError, VarDef},
    snippet::{Template, template::valid_name, undeclared},
};

use super::SnippetAnswer;
use crate::views::{RenderCx, View as _, ViewCx, ViewEvent};
use crate::widgets::{
    confirm,
    dialog::Modal,
    form::{
        Field, FieldValue, FieldValues, Form, FormRequest, FormValidator, KeyCheck, SelectOption,
    },
};

const MODE_PASTE: &str = "paste";
const MODE_EXECUTE: &str = "paste-and-execute";
const MODE_EXEC: &str = "exec";

fn text(values: &FieldValues, key: &str) -> String {
    values
        .get(key)
        .and_then(FieldValue::as_text)
        .unwrap_or_default()
        .to_owned()
}

fn secret_names(values: &FieldValues) -> Vec<String> {
    text(values, "secret")
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn pairs(values: &FieldValues) -> Vec<(String, String)> {
    match values.get("variables") {
        Some(FieldValue::Pairs(p)) => p.clone(),
        _ => Vec::new(),
    }
}

fn check(values: &FieldValues) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    if let Err(e) = Template::parse(&text(values, "script")) {
        errors.push(ValidationError::new("script", e.to_string()));
    }
    let declared = pairs(values);
    for (name, _) in &declared {
        if !valid_name(name.trim()) {
            errors.push(ValidationError::new(
                "variables",
                format!("invalid variable name {name:?}"),
            ));
        } else if sverb_core::snippet::is_builtin(name.trim()) {
            errors.push(ValidationError::new(
                "variables",
                format!("{name} is a built-in variable"),
            ));
        }
    }
    let script_vars = Template::parse(&text(values, "script"))
        .map(|t| t.user_vars())
        .unwrap_or_default();
    for s in secret_names(values) {
        let known =
            declared.iter().any(|(n, _)| n.trim() == s) || script_vars.iter().any(|v| v.name == s);
        if !known {
            errors.push(ValidationError::new(
                "secret",
                format!("no variable named {s}"),
            ));
        }
    }
    errors
}

/// The snippet the form describes (`tags` resolved by the caller's options).
fn snippet_of(values: &FieldValues) -> Snippet {
    let secret = secret_names(values);
    let variables = pairs(values)
        .into_iter()
        .map(|(n, d)| {
            let name = n.trim().to_owned();
            VarDef {
                secret: secret.contains(&name),
                default: (!d.is_empty()).then_some(d),
                name,
            }
        })
        .collect();
    let run_mode = match values.get("run_mode") {
        Some(FieldValue::Choice(Some(m))) if m == MODE_EXECUTE => RunMode::PasteAndExecute,
        Some(FieldValue::Choice(Some(m))) if m == MODE_EXEC => RunMode::Exec,
        _ => RunMode::Paste,
    };
    let tags = match values.get("tags") {
        Some(FieldValue::Choices(c)) => c.iter().filter_map(|t| t.parse().ok()).collect(),
        _ => Vec::new(),
    };
    let description = text(values, "description");
    Snippet {
        name: text(values, "name").trim().to_owned(),
        script: text(values, "script"),
        description: (!description.trim().is_empty()).then_some(description),
        tags,
        variables,
        run_mode,
        read_only: false,
    }
}

/// The add / edit dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetFormDialog {
    /// The item (`None`: new).
    pub id: Option<ItemId>,
    /// The form.
    pub form: Box<Form>,
    /// "Add variables …?" with the snippet waiting for the answer.
    pub confirm: Option<(Modal, Snippet)>,
}

impl SnippetFormDialog {
    /// The form for `snippet` (`None`: new), with the vault's tags to pick from.
    pub fn new(
        id: Option<ItemId>,
        snippet: Option<&Snippet>,
        tag_names: &BTreeMap<ItemId, String>,
    ) -> Self {
        let modes = vec![
            SelectOption::new(MODE_PASTE, "Paste (no trailing newline)"),
            SelectOption::new(MODE_EXECUTE, "Paste & execute (each line + Enter)"),
            SelectOption::new(MODE_EXEC, "Exec on hosts"),
        ];
        let mode = match snippet.map(|s| s.run_mode) {
            Some(RunMode::PasteAndExecute) => MODE_EXECUTE,
            Some(RunMode::Exec) => MODE_EXEC,
            _ => MODE_PASTE,
        };
        let mut tag_options: Vec<SelectOption> = tag_names
            .iter()
            .map(|(id, n)| SelectOption::new(id.to_string(), format!("#{n}")))
            .collect();
        tag_options.sort_by_key(|o| o.label.to_lowercase());
        let tags: Vec<String> = snippet
            .map(|s| s.tags.iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        let vars: Vec<(String, String)> = snippet
            .map(|s| {
                s.variables
                    .iter()
                    .map(|v| (v.name.clone(), v.default.clone().unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        let secret: Vec<String> = snippet
            .map(|s| {
                s.variables
                    .iter()
                    .filter(|v| v.secret)
                    .map(|v| v.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let title = if id.is_some() {
            "Edit snippet"
        } else {
            "New snippet"
        };
        let form = Form::new(title)
            .section(
                "Snippet",
                vec![
                    Field::text("name", "Name", snippet.map_or("", |s| s.name.as_str()))
                        .required(),
                    Field::text(
                        "description",
                        "Description",
                        snippet
                            .and_then(|s| s.description.as_deref())
                            .unwrap_or_default(),
                    ),
                    Field::multiselect("tags", "Tags", tag_options, &tags),
                    Field::select("run_mode", "Run mode", modes, Some(mode)),
                ],
            )
            .section(
                "Script",
                vec![
                    Field::multiline("script", "Script", snippet.map_or("", |s| s.script.as_str()))
                        .required()
                        .help(r"{{name}}, {{name:default}}, {{name|q}} (shell-quoted), {{host.label}}, {{host.address}}, {{host.user}}, {{date}}; \{{ is a literal {{"),
                ],
            )
            .section(
                "Variables",
                vec![
                    Field::key_values("variables", "Variables", vars, KeyCheck::NonEmpty)
                        .help("name = default (empty: asked at run time)"),
                    Field::text("secret", "Secret variables", &secret.join(", "))
                        .help("Comma-separated names: masked, never saved to history"),
                ],
            )
            .validator(FormValidator::new("snippet", check));
        Self {
            id,
            form: Box::new(form),
            confirm: None,
        }
    }

    /// The dialog edits text.
    pub fn wants_text(&self) -> bool {
        self.confirm.is_none() && self.form.insert_mode()
    }

    /// Handle input; a save answers [`SnippetAnswer::Save`] and closes.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Option<SnippetAnswer> {
        if let Some((modal, mut snippet)) = self.confirm.take() {
            let ViewEvent::Key(k) = ev else {
                self.confirm = Some((modal, snippet));
                return None;
            };
            let mut modal = modal;
            return match modal.handle_key(k).map(|a| a.route_key()) {
                Some(route) if route == format!("button:{}", confirm::YES) => {
                    if let Ok(t) = Template::parse(&snippet.script) {
                        let added = undeclared(&t, &snippet.variables);
                        snippet.variables.extend(added);
                    }
                    Some(SnippetAnswer::Save {
                        id: self.id,
                        snippet,
                    })
                }
                Some(route) if route == format!("button:{}", confirm::NO) => {
                    Some(SnippetAnswer::Save {
                        id: self.id,
                        snippet,
                    })
                }
                Some(_) => {
                    // Cancelled: back to the form.
                    self.form.save_failed("Not saved");
                    None
                }
                None => {
                    if k.code != KeyCode::Esc {
                        self.confirm = Some((modal, snippet));
                    }
                    None
                }
            };
        }
        self.form.handle(ev, cx);
        match self.form.take_request() {
            Some(FormRequest::Save(_)) => {
                let snippet = snippet_of(&self.form.values());
                let added = Template::parse(&snippet.script)
                    .map(|t| undeclared(&t, &snippet.variables))
                    .unwrap_or_default();
                if added.is_empty() {
                    return Some(SnippetAnswer::Save {
                        id: self.id,
                        snippet,
                    });
                }
                let names: Vec<&str> = added.iter().map(|v| v.name.as_str()).collect();
                let modal = confirm::yes_no(
                    "Add variables?",
                    &format!(
                        "The script uses {} but the snippet does not declare {}. Add {}?",
                        names.join(", "),
                        if names.len() == 1 { "it" } else { "them" },
                        if names.len() == 1 { "it" } else { "them" },
                    ),
                );
                self.confirm = Some((modal, snippet));
                None
            }
            Some(FormRequest::Cancel) => {
                cx.close();
                None
            }
            None => None,
        }
    }

    /// Draw.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        frame.render_widget(Clear, area);
        self.form.render(frame, area, cx);
        if let Some((modal, _)) = &self.confirm {
            modal.render(frame, area, cx);
        }
    }
}
