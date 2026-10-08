//! M2-09: snippets (SPEC §4.9, §9.7): the pure template engine and run helpers.
//!
//! - [`template`]: `{{name}}`, `{{name:default}}`, `{{name|q}}`, built-ins, `\{{`.
//! - [`vars`]: declared + auto-added variables, values (secrets redacted), built-ins.
//! - [`targets`]: `--on <host|#tag|group>` resolution.
//! - [`results`]: per-host results, JSON / Markdown / text exports, the overall outcome.
//! - [`history`]: the history seam; secret values never reach it.
//!
//! Run modes (§9.7) on the rendered text:
//! - *Paste*: [`paste_text`] (no trailing newline); the session brackets it when the
//!   remote enabled mode 2004 (M1-11 paste encoding, terminator stripping included).
//! - *Paste & execute*: [`paste_execute_bytes`]: each line followed by `\r`, never
//!   bracketed, so the shell runs each line. Lines are sent at once, like a paste: an
//!   interactive prompt in the middle of the script reads the lines after it.
//! - *Exec on hosts*: the text is the exec command (rendered per host).

// M7-01: snippets shipped with sverb (the shell integration installer).
pub mod builtin;
pub mod history;
pub mod results;
pub mod targets;
pub mod template;
pub mod vars;

#[cfg(test)]
mod tests;

pub use history::{HistoryRecord, HistorySink, NoHistory, record_run};
pub use results::{HostRunResult, RunStatus, Summary};
pub use targets::{TargetCatalog, TargetError, TargetHost};
pub use template::{
    BUILTINS, Filter, MASK, Part, RenderError, RenderStyle, Template, TemplateError,
    TemplateErrorKind, VarRef, is_builtin,
};
pub use vars::{Builtins, Values, effective_vars, missing, undeclared, with_defaults};

/// The *Paste* text: `rendered` without trailing line breaks.
pub fn paste_text(rendered: &str) -> String {
    rendered.trim_end_matches(['\r', '\n']).to_owned()
}

/// The *Paste & execute* bytes: every line (`\n`, `\r\n` or `\r` separated) followed
/// by `\r`. A trailing line break does not add an empty line.
pub fn paste_execute_bytes(rendered: &str) -> Vec<u8> {
    let text = rendered.replace("\r\n", "\n").replace('\r', "\n");
    let text = text.strip_suffix('\n').unwrap_or(&text);
    if text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(text.len() + 1);
    for line in text.split('\n') {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\r');
    }
    out
}

/// What a host's startup snippet types once the shell is up (§9.7, §6.1.1 step 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// *Paste & execute* text (each line ends with `\r`), with defaults and built-ins.
    Ready(String),
    /// Variables without defaults: the variable form asks for them at connect time.
    NeedsValues(Vec<String>),
    /// The script does not parse.
    Invalid(String),
}

impl Startup {
    /// The text, when nothing has to be asked.
    pub fn ready(self) -> Option<String> {
        match self {
            Self::Ready(s) => Some(s),
            _ => None,
        }
    }
}

/// The startup input of `snippet` for a host with `builtins`. Always *Paste & execute*
/// semantics, whatever the snippet's run mode.
pub fn startup(snippet: &crate::model::Snippet, builtins: &Builtins) -> Startup {
    let template = match Template::parse(&snippet.script) {
        Ok(t) => t,
        Err(e) => return Startup::Invalid(e.to_string()),
    };
    let vars = effective_vars(&template, &snippet.variables);
    let absent = missing(&vars, &Values::new());
    if !absent.is_empty() {
        return Startup::NeedsValues(absent);
    }
    let values = with_defaults(&vars, &Values::new());
    match template.render(&values, builtins, RenderStyle::Final) {
        Ok(text) => {
            Startup::Ready(String::from_utf8_lossy(&paste_execute_bytes(&text)).into_owned())
        }
        Err(e) => Startup::Invalid(e.to_string()),
    }
}
