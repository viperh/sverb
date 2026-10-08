//! M0-07: resolving a `<host>` command-line argument (SPEC §16).
//!
//! Every CLI command that takes a host (`hosts rm`, `approve`, `connect`, `snippet run
//! --on`, …) resolves it the same way, in this order:
//!
//! 1. a host whose **label** equals the argument,
//! 2. a host whose **address** equals the argument,
//! 3. exactly one **fuzzy** match on label or address,
//! 4. otherwise an error: ambiguous (listing at most [`MAX_CANDIDATES`]) or not found.
//!
//! The function is pure: callers pass the candidate hosts. M1-05: fuzzy matching uses
//! `nucleo-matcher` (case-insensitive, Unicode-normalized fuzzy atom); callers that
//! hold the decrypted index use [`crate::search::resolve_host_arg`], which feeds the
//! index's hosts in view order.

use std::fmt;

// M1-05: nucleo fuzzy matching.
use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// At most this many candidates are listed in an ambiguity error.
pub const MAX_CANDIDATES: usize = 5;

/// A host as seen by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidate<Id> {
    /// The caller's handle for the host (e.g. its item id).
    pub id: Id,
    /// The host's label.
    pub label: String,
    /// The host's address (hostname or IP).
    pub address: String,
}

/// How a host argument matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// Exact label.
    Label,
    /// Exact address.
    Address,
    /// The only fuzzy match.
    Fuzzy,
}

/// Why a host argument did not resolve to exactly one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostArgError {
    /// Nothing matched.
    NotFound {
        /// The argument as given.
        query: String,
    },
    /// Several hosts matched.
    Ambiguous {
        /// The argument as given.
        query: String,
        /// Labels of the first [`MAX_CANDIDATES`] matches, in input order.
        candidates: Vec<String>,
        /// How many hosts matched in total.
        total: usize,
    },
}

impl fmt::Display for HostArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { query } => write!(f, "no host matches `{query}`"),
            Self::Ambiguous {
                query,
                candidates,
                total,
            } => {
                write!(
                    f,
                    "`{query}` matches {total} hosts: {}",
                    candidates.join(", ")
                )?;
                if *total > candidates.len() {
                    write!(f, ", …")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for HostArgError {}

/// Resolve `query` against `hosts`. See the [module docs](self) for the order.
pub fn resolve_host_arg<'a, Id>(
    query: &str,
    hosts: &'a [HostCandidate<Id>],
) -> Result<(&'a HostCandidate<Id>, MatchKind), HostArgError> {
    if let Some(h) = unique(hosts.iter().filter(|h| h.label == query)) {
        return Ok((h, MatchKind::Label));
    }
    if let Some(h) = unique(hosts.iter().filter(|h| h.address == query)) {
        return Ok((h, MatchKind::Address));
    }
    // M1-05: nucleo fuzzy atom instead of a subsequence test.
    let mut fuzzy = FuzzyMatch::new(query);
    let matches: Vec<_> = hosts
        .iter()
        .filter(|h| fuzzy.matches(&h.label) || fuzzy.matches(&h.address))
        .collect();
    match matches.as_slice() {
        [] => Err(HostArgError::NotFound {
            query: query.to_owned(),
        }),
        [one] => Ok((one, MatchKind::Fuzzy)),
        many => Err(HostArgError::Ambiguous {
            query: query.to_owned(),
            candidates: many
                .iter()
                .take(MAX_CANDIDATES)
                .map(|h| h.label.clone())
                .collect(),
            total: many.len(),
        }),
    }
}

/// The single item of `iter`, if there is exactly one.
fn unique<T>(mut iter: impl Iterator<Item = T>) -> Option<T> {
    let first = iter.next()?;
    iter.next().is_none().then_some(first)
}

/// M1-05: a case-insensitive `nucleo` fuzzy matcher for one needle.
struct FuzzyMatch {
    atom: Option<Atom>,
    matcher: Matcher,
    buf: Vec<char>,
}

impl FuzzyMatch {
    fn new(needle: &str) -> Self {
        let atom = (!needle.trim().is_empty()).then(|| {
            Atom::new(
                needle,
                CaseMatching::Ignore,
                Normalization::Smart,
                AtomKind::Fuzzy,
                false,
            )
        });
        Self {
            atom,
            matcher: Matcher::new(Config::DEFAULT),
            buf: Vec::new(),
        }
    }

    fn matches(&mut self, hay: &str) -> bool {
        let Some(atom) = &self.atom else {
            return false;
        };
        atom.score(Utf32Str::new(hay, &mut self.buf), &mut self.matcher)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<HostCandidate<u32>> {
        [
            (1, "prod-web-1", "10.0.0.1"),
            (2, "prod-web-2", "10.0.0.2"),
            (3, "db", "10.0.1.5"),
        ]
        .into_iter()
        .map(|(id, label, address)| HostCandidate {
            id,
            label: label.to_owned(),
            address: address.to_owned(),
        })
        .collect()
    }

    // T-07
    #[test]
    fn resolution_table() {
        let hosts = hosts();
        let ok = |q: &str| resolve_host_arg(q, &hosts).map(|(h, kind)| (h.id, kind));
        assert_eq!(ok("db"), Ok((3, MatchKind::Label)));
        assert_eq!(ok("10.0.0.1"), Ok((1, MatchKind::Address)));
        assert_eq!(ok("web-2"), Ok((2, MatchKind::Fuzzy)));
        assert_eq!(
            ok("web"),
            Err(HostArgError::Ambiguous {
                query: "web".into(),
                candidates: vec!["prod-web-1".into(), "prod-web-2".into()],
                total: 2,
            })
        );
        assert_eq!(
            ok("zzz"),
            Err(HostArgError::NotFound {
                query: "zzz".into()
            })
        );
    }

    #[test]
    fn exact_label_beats_fuzzy_and_ambiguity_lists_at_most_five() {
        let mut hosts: Vec<_> = (0..8)
            .map(|i| HostCandidate {
                id: i,
                label: format!("web{i}"),
                address: format!("192.168.0.{i}"),
            })
            .collect();
        hosts.push(HostCandidate {
            id: 99,
            label: "web".into(),
            address: "x".into(),
        });
        assert_eq!(resolve_host_arg("web", &hosts).map(|(h, _)| h.id), Ok(99));
        let Err(HostArgError::Ambiguous {
            candidates, total, ..
        }) = resolve_host_arg("wb", &hosts)
        else {
            panic!("expected ambiguity");
        };
        assert_eq!(candidates.len(), MAX_CANDIDATES);
        assert_eq!(total, 9);
    }
}
