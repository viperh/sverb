//! `Include` (ssh_config(5)): the included files' lines are spliced in place, in glob
//! order. Relative paths resolve against the ssh directory (`~/.ssh/`), `~` expands to
//! the home directory, globs are supported, nesting is limited to
//! [`MAX_INCLUDE_DEPTH`] and cycles are detected (reported as a warning and not
//! followed).

use std::path::{Path, PathBuf};

use super::lexer::{self, Line};
use crate::importers::Skipped;

/// OpenSSH's `READCONF_MAX_DEPTH`.
pub const MAX_INCLUDE_DEPTH: usize = 16;

/// A lexed line and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedLine {
    /// `file:line` for messages (the file relative to the top file's directory).
    pub at: String,
    /// The line.
    pub line: Line,
}

/// The flattened configuration.
#[derive(Debug, Default)]
pub struct Flattened {
    /// Every line, includes spliced in.
    pub lines: Vec<SourcedLine>,
    /// Lines that could not be lexed.
    pub skipped: Vec<Skipped>,
    /// Include problems (cycles, depth, unreadable files).
    pub warnings: Vec<String>,
}

/// Where includes resolve.
#[derive(Debug, Clone)]
pub struct IncludeRoots {
    /// Relative `Include` paths resolve here (`~/.ssh`).
    pub ssh_dir: PathBuf,
    /// `~` expands here (`None`: not expanded).
    pub home: Option<PathBuf>,
    /// File names in messages are shown relative to this directory.
    pub display_root: PathBuf,
}

impl IncludeRoots {
    fn resolve(&self, pattern: &str) -> PathBuf {
        if let Some(rest) = pattern.strip_prefix("~/")
            && let Some(home) = &self.home
        {
            return home.join(rest);
        }
        let p = Path::new(pattern);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.ssh_dir.join(p)
        }
    }

    fn display(&self, path: &Path) -> String {
        path.strip_prefix(&self.display_root)
            .unwrap_or(path)
            .display()
            .to_string()
            .replace('\\', "/")
    }
}

/// Reads `path` and its includes.
///
/// # Errors
/// The top file cannot be read (an unreadable *included* file is a warning).
pub fn flatten_file(path: &Path, roots: &IncludeRoots) -> std::io::Result<Flattened> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Flattened::default();
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut stack = vec![canon];
    walk(&text, path, roots, 0, &mut stack, &mut out);
    Ok(out)
}

/// Flattens `text` (named `name` in messages). Includes are read from disk.
pub fn flatten_str(text: &str, name: &Path, roots: &IncludeRoots) -> Flattened {
    let mut out = Flattened::default();
    let mut stack = vec![name.to_path_buf()];
    walk(text, name, roots, 0, &mut stack, &mut out);
    out
}

fn walk(
    text: &str,
    file: &Path,
    roots: &IncludeRoots,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    out: &mut Flattened,
) {
    let shown = roots.display(file);
    let (lines, errors) = lexer::lex(text);
    for e in errors {
        out.skipped.push(Skipped::new(
            Some(format!("{shown}:{}", e.line)),
            format!("cannot read the line: {}", e.reason),
        ));
    }
    for line in lines {
        let at = format!("{shown}:{}", line.line);
        if line.keyword != "include" {
            out.lines.push(SourcedLine { at, line });
            continue;
        }
        if line.args.is_empty() {
            out.skipped
                .push(Skipped::new(Some(at), "Include without a file"));
            continue;
        }
        for pattern in &line.args {
            include(pattern, &at, roots, depth, stack, out);
        }
    }
}

fn include(
    pattern: &str,
    at: &str,
    roots: &IncludeRoots,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    out: &mut Flattened,
) {
    if depth + 1 > MAX_INCLUDE_DEPTH {
        out.warnings.push(format!(
            "{at}: Include {pattern} not followed: nested deeper than {MAX_INCLUDE_DEPTH} levels"
        ));
        return;
    }
    let full = roots.resolve(pattern);
    let full_str = full.to_string_lossy().into_owned();
    let mut files: Vec<PathBuf> = match glob::glob(&full_str) {
        Ok(paths) => paths.filter_map(Result::ok).collect(),
        Err(e) => {
            out.warnings
                .push(format!("{at}: Include {pattern}: invalid pattern ({e})"));
            return;
        }
    };
    files.sort();
    // OpenSSH ignores patterns that match nothing.
    for f in files {
        if f.is_dir() {
            continue;
        }
        let canon = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
        if stack.contains(&canon) {
            let chain: Vec<String> = stack
                .iter()
                .chain(std::iter::once(&canon))
                .map(|p| {
                    p.file_name()
                        .map_or_else(|| p.display().to_string(), |n| n.to_string_lossy().into())
                })
                .collect();
            out.warnings.push(format!(
                "{at}: Include cycle detected ({}); not followed",
                chain.join(" -> ")
            ));
            continue;
        }
        match std::fs::read_to_string(&f) {
            Ok(text) => {
                stack.push(canon);
                walk(&text, &f, roots, depth + 1, stack, out);
                stack.pop();
            }
            Err(e) => out
                .warnings
                .push(format!("{at}: cannot read {}: {e}", roots.display(&f))),
        }
    }
}
