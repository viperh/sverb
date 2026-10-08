//! `~/.ssh/config` import (§9.13): lexer ([`lexer`]), `Include` ([`include`]), blocks
//! ([`parser`]) and the mapping to hosts, groups and forwards ([`map`]).
//!
//! The parser is pure and reusable (a future live read-only mode, `ssh.read_ssh_config`,
//! is an open question). [`parse_str_no_include`] never touches the file system (the
//! fuzz target uses it).

use std::path::{Path, PathBuf};

use super::{ImportError, ImportPlan, preview::fill_fields};

pub mod include;
pub mod lexer;
pub mod map;
pub mod parser;

pub use include::{IncludeRoots, MAX_INCLUDE_DEPTH};
pub use map::DEFAULTS_GROUP;

/// Where `Include` and `~` resolve.
#[derive(Debug, Clone)]
pub struct SshConfigOptions {
    /// Relative `Include`s resolve here (`~/.ssh`).
    pub ssh_dir: PathBuf,
    /// `~` expands here.
    pub home: Option<PathBuf>,
}

impl SshConfigOptions {
    /// `~/.ssh` of the current user (`HOME` / `USERPROFILE`).
    pub fn user() -> Self {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        Self {
            ssh_dir: home
                .as_ref()
                .map_or_else(|| PathBuf::from(".ssh"), |h| h.join(".ssh")),
            home,
        }
    }

    /// Includes resolve in `dir` (tests, fixtures).
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            home: Some(dir.clone()),
            ssh_dir: dir,
        }
    }

    fn roots(&self, display_root: &Path) -> IncludeRoots {
        IncludeRoots {
            ssh_dir: self.ssh_dir.clone(),
            home: self.home.clone(),
            display_root: display_root.to_path_buf(),
        }
    }
}

/// The default path: `~/.ssh/config`.
pub fn default_path(opts: &SshConfigOptions) -> PathBuf {
    opts.ssh_dir.join("config")
}

/// Parses `path` (and its includes) into a plan (all items `New`).
///
/// # Errors
/// [`ImportError::Read`] when `path` cannot be read.
pub fn parse_file(path: &Path, opts: &SshConfigOptions) -> Result<ImportPlan, ImportError> {
    let root = path.parent().unwrap_or(Path::new("")).to_path_buf();
    let flat = include::flatten_file(path, &opts.roots(&root)).map_err(|e| ImportError::Read {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    Ok(finish(flat))
}

/// Parses `text` (includes are read from disk, relative to `opts.ssh_dir`).
pub fn parse_str(text: &str, opts: &SshConfigOptions) -> ImportPlan {
    let flat = include::flatten_str(text, Path::new("config"), &opts.roots(Path::new("")));
    finish(flat)
}

/// Parses `text` ignoring `Include` lines (no file-system access).
pub fn parse_str_no_include(text: &str) -> ImportPlan {
    let (lines, errors) = lexer::lex(text);
    let mut flat = include::Flattened::default();
    for e in errors {
        flat.skipped.push(super::Skipped::new(
            Some(format!("config:{}", e.line)),
            format!("cannot read the line: {}", e.reason),
        ));
    }
    for line in lines {
        let at = format!("config:{}", line.line);
        if line.keyword == "include" {
            flat.warnings
                .push(format!("{at}: Include not followed (no file access)"));
            continue;
        }
        flat.lines.push(include::SourcedLine { at, line });
    }
    finish(flat)
}

fn finish(flat: include::Flattened) -> ImportPlan {
    let parsed = parser::parse(&flat.lines);
    let mut plan = map::map(&parsed);
    let mut skipped = flat.skipped;
    skipped.append(&mut plan.skipped);
    plan.skipped = skipped;
    let mut warnings = flat.warnings;
    warnings.append(&mut plan.warnings);
    plan.warnings = warnings;
    fill_fields(&mut plan);
    plan
}
