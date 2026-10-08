//! M2-09: snippet templates (SPEC §4.9, §9.7).
//!
//! # Syntax
//! | Text | Meaning |
//! |---|---|
//! | `{{name}}` / `{{ name }}` | the variable `name` (whitespace inside the braces is ignored) |
//! | `{{name:default}}` | with a default: everything after the **first** `:` (`{{a:with:colons}}` → `with:colons`) |
//! | `{{name\|q}}`, `{{name:default\|q}}` | the value as one POSIX shell word (`'…'`, [`posix_single_quote`]) |
//! | `{{host.label}}`, `{{host.address}}`, `{{host.user}}`, `{{date}}` | built-ins, per target host ([`BUILTINS`]) |
//! | `\{{` | a literal `{{` (the backslash is dropped); `{{{{` is **not** special |
//!
//! Names match `[A-Za-z_][A-Za-z0-9_.]*`. A trailing `|word` is a filter: only `q`
//! exists, any other word is an error; so a default cannot end in `|word`. An
//! unclosed `{{` is an error with its position.
//!
//! # Substitution
//! Substitution is **literal** text replacement, no escaping (§9.7), except with `|q`.
//! The final text is always previewed before it runs. `|q` quotes in every run mode
//! (the spec names it for Exec on hosts; a pasted command line goes to a shell too).
//!
//! [`Template::render`] has three [`RenderStyle`]s:
//! - [`RenderStyle::Final`]: the text that runs; a variable without a value or default
//!   is an error ([`RenderError::Missing`]).
//! - [`RenderStyle::Preview`]: secrets are `••••`, missing values stay `{{name}}`.
//! - [`RenderStyle::History`]: secrets (and missing values) stay `{{name}}`, so the text
//!   can go to history (M7-01) without the secret.

use std::fmt;
use std::ops::Range;

use super::vars::{Builtins, Values};
use crate::shell_quote::{ShellQuoteError, posix_single_quote};

/// The built-in variables, resolved per target host.
pub const BUILTINS: [&str; 4] = ["host.label", "host.address", "host.user", "date"];

/// What a secret shows as in previews.
pub const MASK: &str = "••••";

/// Whether `name` is a built-in variable.
pub fn is_builtin(name: &str) -> bool {
    BUILTINS.contains(&name)
}

/// A filter after `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// `|q`: POSIX single-quote the value.
    Quote,
}

/// A `{{…}}` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarRef {
    /// The variable name.
    pub name: String,
    /// `{{name:default}}`
    pub default: Option<String>,
    /// `{{name|q}}`
    pub filter: Option<Filter>,
    /// Byte range of the whole `{{…}}` in the source.
    pub span: Range<usize>,
}

/// One piece of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Text copied as is (`\{{` already unescaped).
    Literal(String),
    /// A variable reference.
    Var(VarRef),
}

/// A parsed snippet script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Template {
    /// Literals and variables, in source order.
    pub parts: Vec<Part>,
}

/// Why a script does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateErrorKind {
    /// `{{` without a matching `}}`.
    Unclosed,
    /// The name does not match `[A-Za-z_][A-Za-z0-9_.]*`.
    InvalidName(String),
    /// A filter other than `|q`.
    UnknownFilter(String),
}

/// A parse error with its position (of the `{{`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateError {
    /// What is wrong.
    pub kind: TemplateErrorKind,
    /// Byte offset.
    pub offset: usize,
    /// 1-based line.
    pub line: usize,
    /// 1-based column (characters).
    pub column: usize,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            TemplateErrorKind::Unclosed => write!(f, "unclosed {{{{")?,
            TemplateErrorKind::InvalidName(n) => write!(f, "invalid variable name {n:?}")?,
            TemplateErrorKind::UnknownFilter(x) => {
                write!(f, "unknown filter |{x} (only |q is supported)")?;
            }
        }
        write!(f, " at line {}, column {}", self.line, self.column)
    }
}

impl std::error::Error for TemplateError {}

/// Why a template cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// Variables without a value or default (in first-use order).
    Missing(Vec<String>),
    /// A `|q` value cannot be quoted (it holds a NUL byte).
    Quote {
        /// The variable.
        name: String,
        /// Why.
        error: ShellQuoteError,
    },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(names) => write!(f, "missing values for: {}", names.join(", ")),
            Self::Quote { name, error } => write!(f, "{{{{{name}|q}}}}: {error}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// How secrets and missing values are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderStyle {
    /// The text that runs.
    Final,
    /// For the preview: secrets masked, missing values as `{{name}}`.
    Preview,
    /// For history: secrets and missing values as `{{name}}`.
    History,
}

/// Validates a variable name: `[A-Za-z_][A-Za-z0-9_.]*`.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn position(src: &str, offset: usize) -> (usize, usize) {
    let before = &src[..offset];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let column = src[line_start..offset].chars().count() + 1;
    (line, column)
}

fn error(src: &str, offset: usize, kind: TemplateErrorKind) -> TemplateError {
    let (line, column) = position(src, offset);
    TemplateError {
        kind,
        offset,
        line,
        column,
    }
}

/// `body|filter` when the text after the last `|` is a word.
fn split_filter(inner: &str) -> (&str, Option<&str>) {
    match inner.rsplit_once('|') {
        Some((body, f))
            if !f.trim().is_empty()
                && f.trim()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
        {
            (body.trim_end(), Some(f.trim()))
        }
        _ => (inner, None),
    }
}

impl Template {
    /// Parse `src`.
    ///
    /// # Errors
    /// An unclosed `{{`, an invalid name or an unknown filter, with its position.
    pub fn parse(src: &str) -> Result<Self, TemplateError> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut pos = 0;
        while pos < src.len() {
            let rest = &src[pos..];
            if rest.starts_with("\\{{") {
                lit.push_str("{{");
                pos += 3;
                continue;
            }
            if rest.starts_with("{{") {
                let inner_start = pos + 2;
                let Some(len) = src[inner_start..].find("}}") else {
                    return Err(error(src, pos, TemplateErrorKind::Unclosed));
                };
                let end = inner_start + len + 2;
                let inner = src[inner_start..inner_start + len].trim();
                let (body, filter) = split_filter(inner);
                let filter = match filter {
                    None => None,
                    Some("q") => Some(Filter::Quote),
                    Some(other) => {
                        return Err(error(
                            src,
                            pos,
                            TemplateErrorKind::UnknownFilter(other.to_owned()),
                        ));
                    }
                };
                let (name, default) = match body.split_once(':') {
                    Some((n, d)) => (n.trim(), Some(d.to_owned())),
                    None => (body.trim(), None),
                };
                if !valid_name(name) {
                    return Err(error(
                        src,
                        pos,
                        TemplateErrorKind::InvalidName(name.to_owned()),
                    ));
                }
                if !lit.is_empty() {
                    parts.push(Part::Literal(std::mem::take(&mut lit)));
                }
                parts.push(Part::Var(VarRef {
                    name: name.to_owned(),
                    default,
                    filter,
                    span: pos..end,
                }));
                pos = end;
                continue;
            }
            // One character (keeps `pos` on a char boundary).
            let c = rest.chars().next().unwrap_or_default();
            lit.push(c);
            pos += c.len_utf8().max(1);
        }
        if !lit.is_empty() {
            parts.push(Part::Literal(lit));
        }
        Ok(Self { parts })
    }

    /// Every reference, in source order.
    pub fn refs(&self) -> impl Iterator<Item = &VarRef> {
        self.parts.iter().filter_map(|p| match p {
            Part::Var(v) => Some(v),
            Part::Literal(_) => None,
        })
    }

    /// The user variables (not built-ins), first use first, without duplicates; the
    /// default is the first one written.
    pub fn user_vars(&self) -> Vec<VarRef> {
        let mut out: Vec<VarRef> = Vec::new();
        for r in self.refs().filter(|r| !is_builtin(&r.name)) {
            match out.iter_mut().find(|o| o.name == r.name) {
                Some(o) => {
                    if o.default.is_none() {
                        o.default.clone_from(&r.default);
                    }
                }
                None => out.push(r.clone()),
            }
        }
        out
    }

    /// Whether any built-in is used (Exec runs then differ per host).
    pub fn uses_builtins(&self) -> bool {
        self.refs().any(|r| is_builtin(&r.name))
    }

    /// Substitute `values` and `builtins` (see the module docs).
    ///
    /// # Errors
    /// [`RenderStyle::Final`] only: missing values; a `|q` value with a NUL byte.
    pub fn render(
        &self,
        values: &Values,
        builtins: &Builtins,
        style: RenderStyle,
    ) -> Result<String, RenderError> {
        let mut out = String::new();
        let mut missing: Vec<String> = Vec::new();
        for part in &self.parts {
            let r = match part {
                Part::Literal(s) => {
                    out.push_str(s);
                    continue;
                }
                Part::Var(r) => r,
            };
            let placeholder = || format!("{{{{{}}}}}", r.name);
            let (text, secret): (String, bool) = if let Some(b) = builtins.get(&r.name) {
                (b.to_owned(), false)
            } else if let Some((v, secret)) = values.get(&r.name) {
                (v.to_owned(), secret)
            } else if let Some(d) = &r.default {
                (d.clone(), false)
            } else {
                match style {
                    RenderStyle::Final => {
                        if !missing.contains(&r.name) {
                            missing.push(r.name.clone());
                        }
                    }
                    RenderStyle::Preview | RenderStyle::History => out.push_str(&placeholder()),
                }
                continue;
            };
            let text = match (secret, style) {
                (true, RenderStyle::Preview) => MASK.to_owned(),
                (true, RenderStyle::History) => {
                    out.push_str(&placeholder());
                    continue;
                }
                _ => text,
            };
            match r.filter {
                None => out.push_str(&text),
                Some(Filter::Quote) => match posix_single_quote(&text) {
                    Ok(q) => out.push_str(&q),
                    Err(error) if style == RenderStyle::Final => {
                        return Err(RenderError::Quote {
                            name: r.name.clone(),
                            error,
                        });
                    }
                    Err(_) => out.push_str(&placeholder()),
                },
            }
        }
        if missing.is_empty() {
            Ok(out)
        } else {
            Err(RenderError::Missing(missing))
        }
    }
}
