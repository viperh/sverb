//! User-facing error reports: a short message plus the `source()` chain.
//!
//! Every toast and dialog that shows an error uses this type ("short message with
//! expandable detail chain", SPEC §18), and the CLI prints it as
//! `error: <short>` followed by `  caused by: …` lines.
//!
//! - `short` is the outermost message; `chain` holds the `source()` messages below it,
//!   outermost first,
//! - a cause whose message repeats the previous one (wrappers that print their source
//!   verbatim) is dropped, and blank messages are skipped,
//! - [`ErrorReport::from_chain`] accepts any chain iterator, e.g. `eyre::Report::chain()`
//!   in the binary, so the TUI and the CLI render errors identically.

use std::fmt;

/// A short message and the chain of underlying causes, outermost first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReport {
    /// The outermost error message, suitable for a one-line toast.
    pub short: String,
    /// Messages of the `source()` chain below `short`, outermost first.
    pub chain: Vec<String>,
}

impl ErrorReport {
    /// A report with just a message and no causes.
    pub fn msg(short: impl Into<String>) -> Self {
        Self {
            short: short.into(),
            chain: Vec::new(),
        }
    }

    /// Build a report by walking `err.source()`.
    pub fn from_error(err: &(dyn std::error::Error + 'static)) -> Self {
        // Same rules as `from_chain`.
        let mut errors = Vec::new();
        let mut cur = Some(err);
        while let Some(e) = cur {
            errors.push(e);
            cur = e.source();
        }
        Self::from_chain(errors)
    }

    /// Build a report from an error chain, outermost first (e.g.
    /// `eyre::Report::chain()`). An empty chain gives the message `"unknown error"`.
    pub fn from_chain<'a, I>(chain: I) -> Self
    where
        I: IntoIterator<Item = &'a (dyn std::error::Error + 'static)>,
    {
        Self::from_messages(chain.into_iter().map(ToString::to_string))
    }

    /// Build a report from messages, outermost first, applying the module's
    /// formatting rules (blank and repeated messages are dropped).
    pub fn from_messages<I, S>(messages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut kept: Vec<String> = Vec::new();
        for msg in messages {
            let msg = msg.into().trim().to_owned();
            if msg.is_empty() || kept.last() == Some(&msg) {
                continue;
            }
            kept.push(msg);
        }
        let mut kept = kept.into_iter();
        Self {
            short: kept.next().unwrap_or_else(|| "unknown error".to_owned()),
            chain: kept.collect(),
        }
    }

    /// Whether there is a detail chain to expand.
    pub fn has_detail(&self) -> bool {
        !self.chain.is_empty()
    }

    /// The CLI rendering as lines: `error: <short>` then `  caused by: …`.
    /// Same text as [`fmt::Display`].
    pub fn cli_lines(&self) -> Vec<String> {
        std::iter::once(format!("error: {}", self.short))
            .chain(self.chain.iter().map(|c| format!("  caused by: {c}")))
            .collect()
    }
}

impl fmt::Display for ErrorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {}", self.short)?;
        for cause in &self.chain {
            write!(f, "\n  caused by: {cause}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct E(&'static str, Option<Box<E>>);
    impl fmt::Display for E {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for E {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|e| e as _)
        }
    }

    #[test]
    fn walks_the_source_chain() {
        let err = E(
            "outer",
            Some(Box::new(E("mid", Some(Box::new(E("inner", None)))))),
        );
        let report = ErrorReport::from_error(&err);
        assert_eq!(report.short, "outer");
        assert_eq!(report.chain, vec!["mid".to_owned(), "inner".to_owned()]);
        assert_eq!(
            report.to_string(),
            "error: outer\n  caused by: mid\n  caused by: inner"
        );
    }

    fn chain(messages: &[&'static str]) -> E {
        messages
            .iter()
            .rev()
            .fold(None, |source, msg| Some(E(msg, source.map(Box::new))))
            .unwrap_or(E("", None))
    }

    // An error with a 3-deep source chain.
    #[test]
    fn three_deep_chain_and_cli_snapshot() {
        let err = chain(&[
            "cannot connect to prod",
            "ssh handshake failed",
            "connection reset by peer",
            "os error 104",
        ]);
        let report = ErrorReport::from_error(&err);
        assert_eq!(report.short, "cannot connect to prod");
        assert_eq!(report.chain.len(), 3);
        assert!(report.has_detail());
        // Snapshot of the CLI rendering.
        let expected = "\
error: cannot connect to prod
  caused by: ssh handshake failed
  caused by: connection reset by peer
  caused by: os error 104";
        assert_eq!(report.to_string(), expected);
        assert_eq!(report.cli_lines().join("\n"), expected);
    }

    #[test]
    fn from_chain_matches_from_error() {
        let err = chain(&["a", "b", "c"]);
        let mut items: Vec<&(dyn std::error::Error + 'static)> = Vec::new();
        let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = cur {
            items.push(e);
            cur = e.source();
        }
        assert_eq!(
            ErrorReport::from_chain(items),
            ErrorReport::from_error(&err)
        );
    }

    #[test]
    fn repeated_and_blank_causes_are_dropped() {
        let report = ErrorReport::from_messages(["read config", "read config", " ", "denied"]);
        assert_eq!(report.short, "read config");
        assert_eq!(report.chain, vec!["denied".to_owned()]);
        let empty = ErrorReport::from_messages(Vec::<String>::new());
        assert_eq!(empty.short, "unknown error");
        assert!(!empty.has_detail());
        assert_eq!(
            ErrorReport::msg("x").cli_lines(),
            vec!["error: x".to_owned()]
        );
    }
}
