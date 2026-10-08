//! M2-09: snippet variables (SPEC §4.9, §9.7).
//!
//! - [`effective_vars`]: the snippet's declared [`VarDef`]s plus the variables its
//!   script uses but does not declare (auto-added, with the inline `{{name:default}}`
//!   as default). [`undeclared`] lists the latter, so the editor can ask before saving.
//! - [`Values`]: what the user typed. Secret values are held as [`SecretString`]
//!   (redacted when formatted, zeroized on drop); `Debug` never prints them.
//! - [`Builtins`]: `host.label`, `host.address`, `host.user` and `date` of one target.

use std::collections::BTreeMap;
use std::fmt;

use super::template::{Template, is_builtin};
use crate::model::VarDef;
use crate::secret::SecretString;

struct Value {
    text: SecretString,
    secret: bool,
}

impl Clone for Value {
    fn clone(&self) -> Self {
        Self {
            text: SecretString::from(self.text.expose()),
            secret: self.secret,
        }
    }
}

/// Variable values by name.
#[derive(Clone, Default)]
pub struct Values(BTreeMap<String, Value>);

impl Values {
    /// No values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `name` (a secret one is masked in previews and kept out of history).
    pub fn set(&mut self, name: impl Into<String>, value: &str, secret: bool) {
        self.0.insert(
            name.into(),
            Value {
                text: SecretString::from(value),
                secret,
            },
        );
    }

    /// Builder form of [`Values::set`].
    #[must_use]
    pub fn with(mut self, name: &str, value: &str, secret: bool) -> Self {
        self.set(name, value, secret);
        self
    }

    /// The value of `name` and whether it is secret.
    pub fn get(&self, name: &str) -> Option<(&str, bool)> {
        self.0.get(name).map(|v| (v.text.expose(), v.secret))
    }

    /// Whether `name` has a value.
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// Remove `name`.
    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    /// The names with values.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Whether any value is secret.
    pub fn has_secrets(&self) -> bool {
        self.0.values().any(|v| v.secret)
    }

    /// Mark the values of secret `vars` secret (values given on the command line).
    pub fn mark_secrets(&mut self, vars: &[VarDef]) {
        for v in vars.iter().filter(|v| v.secret) {
            if let Some(value) = self.0.get_mut(&v.name) {
                value.secret = true;
            }
        }
    }
}

impl PartialEq for Values {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|((ka, a), (kb, b))| ka == kb && a.secret == b.secret && a.text.ct_eq(&b.text))
    }
}

impl Eq for Values {}

impl fmt::Debug for Values {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names only: even non-secret values may be user data (SPEC §17).
        f.debug_set().entries(self.0.keys()).finish()
    }
}

/// The built-in variables of one target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builtins {
    /// `{{host.label}}`
    pub label: String,
    /// `{{host.address}}`
    pub address: String,
    /// `{{host.user}}`
    pub user: String,
    /// `{{date}}`: ISO `YYYY-MM-DD` (local date, supplied by the caller).
    pub date: String,
}

impl Builtins {
    /// The value of built-in `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        Some(match name {
            "host.label" => &self.label,
            "host.address" => &self.address,
            "host.user" => &self.user,
            "date" => &self.date,
            _ => return None,
        })
    }
}

/// The variables a run asks for: `declared` first (their defaults, else the inline
/// default), then the ones the script uses without declaring them.
pub fn effective_vars(template: &Template, declared: &[VarDef]) -> Vec<VarDef> {
    let used = template.user_vars();
    let mut out: Vec<VarDef> = declared
        .iter()
        .filter(|d| !is_builtin(&d.name))
        .map(|d| {
            let mut d = d.clone();
            if d.default.is_none() {
                d.default = used
                    .iter()
                    .find(|u| u.name == d.name)
                    .and_then(|u| u.default.clone());
            }
            d
        })
        .collect();
    for u in used {
        if !out.iter().any(|d| d.name == u.name) {
            out.push(VarDef {
                name: u.name,
                default: u.default,
                secret: false,
            });
        }
    }
    out
}

/// Variables the script uses that `declared` lacks (auto-added on save, after asking).
pub fn undeclared(template: &Template, declared: &[VarDef]) -> Vec<VarDef> {
    template
        .user_vars()
        .into_iter()
        .filter(|u| !declared.iter().any(|d| d.name == u.name))
        .map(|u| VarDef {
            name: u.name,
            default: u.default,
            secret: false,
        })
        .collect()
}

/// `given` plus every default not overridden (secret flags from `vars`).
pub fn with_defaults(vars: &[VarDef], given: &Values) -> Values {
    let mut out = given.clone();
    for v in vars {
        if !out.contains(&v.name)
            && let Some(d) = &v.default
        {
            out.set(v.name.clone(), d, v.secret);
        }
    }
    out.mark_secrets(vars);
    out
}

/// Variables with neither a value in `given` nor a default (in `vars` order).
pub fn missing(vars: &[VarDef], given: &Values) -> Vec<String> {
    vars.iter()
        .filter(|v| v.default.is_none() && !given.contains(&v.name))
        .map(|v| v.name.clone())
        .collect()
}
