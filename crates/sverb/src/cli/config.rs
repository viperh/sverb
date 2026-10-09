//! `sverb config --check | --print-default | --path` (and hidden `--schema`),
//! using `sverb_core::config`.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::{ArgGroup, Args};
use sverb_core::{
    config::{Config, ConfigError, DEFAULT_CONFIG_TOML, schema},
    error_report::ErrorReport,
};

use super::{CliError, Ctx, write_out};

/// `sverb config …`
#[derive(Args, Debug, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("action")
        .required(true)
        .args(["check", "print_default", "path", "schema"])
))]
pub(crate) struct ConfigArgs {
    /// Validate config.toml; prints `OK` or `file:line:col: …` errors
    #[arg(long)]
    pub check: bool,
    /// Print the default config.toml
    #[arg(long)]
    pub print_default: bool,
    /// Print the path of config.toml
    #[arg(long)]
    pub path: bool,
    /// Print the JSON schema of config.toml
    #[arg(long, hide = true)]
    pub schema: bool,
    /// With --check: validate this file instead
    #[arg(long, value_name = "FILE", requires = "check")]
    pub file: Option<PathBuf>,
}

pub(crate) fn run(args: ConfigArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    if args.print_default {
        write_out(out, DEFAULT_CONFIG_TOML)?;
    } else if args.path {
        write_out(out, &format!("{}\n", ctx.paths.config_file().display()))?;
    } else if args.schema {
        write_out(out, &format!("{}\n", schema::json_schema()))?;
    } else {
        check(args.file, ctx, out)?;
    }
    Ok(super::exit::OK)
}

fn check(file: Option<PathBuf>, ctx: &Ctx, out: &mut dyn Write) -> Result<(), CliError> {
    let explicit = file.is_some();
    let file = file.unwrap_or_else(|| ctx.paths.config_file());
    if !file.exists() {
        if explicit {
            return Err(CliError::NotFound(format!(
                "no such file: {}",
                file.display()
            )));
        }
        eprintln!(
            "note: {} does not exist; the defaults are in effect",
            file.display()
        );
        return write_out(out, "OK\n");
    }
    let outcome = Config::load_file(&file, &ctx.validators, None);
    for warning in &outcome.warnings {
        eprintln!("warning: {}", located(&file, warning));
    }
    if outcome.is_ok() {
        return write_out(out, "OK\n");
    }
    for error in &outcome.errors {
        eprintln!("{}", located(&file, error));
    }
    let n = outcome.errors.len();
    Err(CliError::Failure(ErrorReport::msg(format!(
        "{} has {n} error{}",
        file.display(),
        if n == 1 { "" } else { "s" }
    ))))
}

/// `file:line:col: key: message (hint)`; unknown parts are left out.
pub(crate) fn located(file: &Path, e: &ConfigError) -> String {
    let mut s = file.display().to_string();
    if e.line > 0 {
        s.push_str(&format!(":{}:{}", e.line, e.col));
    }
    s.push_str(": ");
    if !e.path.is_empty() {
        s.push_str(&format!("{}: ", e.path));
    }
    s.push_str(&e.message);
    if let Some(hint) = &e.hint {
        s.push_str(&format!(" ({hint})"));
    }
    s
}
