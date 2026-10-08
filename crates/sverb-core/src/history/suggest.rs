//! M7-01: suggestion sources and ranking for the autocomplete overlay (SPEC §9.10).
//!
//! Sources, in this order:
//! 1. **H** per-host history (entries of the pane's host; local panes and unsaved
//!    targets use the entries without a host),
//! 2. **G** global history (every other host; commands already in H are not repeated),
//! 3. **S** snippets (matched by name and by the script's first line),
//! 4. **C** the static set of common commands (not repeated when already in H or G).
//!
//! History is ranked most recent first, frequency-weighted: each earlier use of the same
//! command counts like [`FREQUENCY_WEIGHT_SECS`] of recency. With a query the fuzzy score
//! (`nucleo`, smart case) ranks first inside each source. With a known command-line
//! prefix (tier 1), only candidates that extend it are offered.

use std::collections::HashMap;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};

use crate::model::{HistoryEntry, ItemId, UnixMillis};

/// One earlier use of a command is worth this much recency.
pub const FREQUENCY_WEIGHT_SECS: i64 = 3600;
/// Default number of suggestions.
pub const DEFAULT_LIMIT: usize = 50;

/// Where a suggestion comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// This host's history.
    Host,
    /// Other hosts' history.
    Global,
    /// A snippet.
    Snippet,
    /// The static set of common commands.
    Common,
}

impl Source {
    /// The one-letter row icon.
    pub fn icon(self) -> char {
        match self {
            Self::Host => 'H',
            Self::Global => 'G',
            Self::Snippet => 'S',
            Self::Common => 'C',
        }
    }
}

/// A snippet as a suggestion source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetSource {
    /// The snippet item.
    pub id: ItemId,
    /// Its name.
    pub name: String,
    /// The first line of its script.
    pub first_line: String,
}

/// One row of the overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// The command text (a snippet's first line).
    pub text: String,
    /// The source.
    pub source: Source,
    /// The snippet's name (snippets only).
    pub name: Option<String>,
    /// The snippet (snippets only; they run through the snippet flow).
    pub snippet: Option<ItemId>,
    /// History: every use was unverified (heuristic tier).
    pub unverified: bool,
    /// History: the exit code of the latest use.
    pub exit_code: Option<i32>,
    /// History: number of uses.
    pub count: u32,
    /// History: the latest use.
    pub last_used: UnixMillis,
}

/// What to suggest for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuggestRequest<'a> {
    /// The pane's host (`None`: a local shell or an unsaved target).
    pub host: Option<ItemId>,
    /// The command line typed so far (tier 1 only; empty when unknown).
    pub prefix: &'a str,
    /// The overlay's search text.
    pub query: &'a str,
    /// At most this many rows.
    pub limit: usize,
}

#[derive(Debug, Default)]
struct Group {
    count: u32,
    last: UnixMillis,
    exit_code: Option<i32>,
    verified: bool,
}

fn group(entries: impl Iterator<Item = HistoryEntry>) -> Vec<(String, Group)> {
    let mut map: HashMap<String, Group> = HashMap::new();
    for e in entries {
        let g = map.entry(e.command).or_default();
        g.count += 1;
        g.verified |= e.verified;
        if g.count == 1 || e.executed_at >= g.last {
            g.last = e.executed_at;
            g.exit_code = e.exit_code;
        }
    }
    map.into_iter().collect()
}

fn history_weight(s: &Suggestion) -> i64 {
    s.last_used.0 / 1000 + i64::from(s.count.saturating_sub(1)) * FREQUENCY_WEIGHT_SECS
}

fn fuzzy(
    atom: Option<&Atom>,
    matcher: &mut Matcher,
    buf: &mut Vec<char>,
    texts: &[&str],
) -> Option<u16> {
    let Some(atom) = atom else {
        return Some(0);
    };
    texts
        .iter()
        .filter_map(|t| atom.score(Utf32Str::new(t, buf), matcher))
        .max()
}

/// The suggestions for `req`, best first (see the module docs for the order).
pub fn suggest(
    req: &SuggestRequest<'_>,
    history: &[HistoryEntry],
    snippets: &[SnippetSource],
    commons: &[&str],
) -> Vec<Suggestion> {
    let extends =
        |text: &str| req.prefix.is_empty() || (text.starts_with(req.prefix) && text != req.prefix);
    let to_suggestion = |source: Source, (text, g): (String, Group)| Suggestion {
        text,
        source,
        name: None,
        snippet: None,
        unverified: !g.verified,
        exit_code: g.exit_code,
        count: g.count,
        last_used: g.last,
    };
    let host: Vec<Suggestion> = group(history.iter().filter(|e| e.host_id == req.host).cloned())
        .into_iter()
        .map(|g| to_suggestion(Source::Host, g))
        .collect();
    let in_host: std::collections::HashSet<&str> = host.iter().map(|s| s.text.as_str()).collect();
    let global: Vec<Suggestion> = group(
        history
            .iter()
            .filter(|e| e.host_id != req.host && !in_host.contains(e.command.as_str()))
            .cloned(),
    )
    .into_iter()
    .map(|g| to_suggestion(Source::Global, g))
    .collect();
    let known: std::collections::HashSet<String> =
        host.iter().chain(&global).map(|s| s.text.clone()).collect();
    let snippet_rows = snippets.iter().map(|s| Suggestion {
        text: s.first_line.clone(),
        source: Source::Snippet,
        name: Some(s.name.clone()),
        snippet: Some(s.id),
        unverified: false,
        exit_code: None,
        count: 0,
        last_used: UnixMillis::default(),
    });
    let common_rows = commons
        .iter()
        .filter(|c| !known.contains(**c))
        .map(|c| Suggestion {
            text: (*c).to_owned(),
            source: Source::Common,
            name: None,
            snippet: None,
            unverified: false,
            exit_code: None,
            count: 0,
            last_used: UnixMillis::default(),
        });

    let atom = (!req.query.trim().is_empty()).then(|| {
        Atom::new(
            req.query.trim(),
            CaseMatching::Smart,
            Normalization::Smart,
            AtomKind::Fuzzy,
            false,
        )
    });
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();
    let mut scored: Vec<(u16, i64, Suggestion)> = host
        .into_iter()
        .chain(global)
        .chain(snippet_rows)
        .chain(common_rows)
        .filter(|s| extends(&s.text))
        .filter_map(|s| {
            let texts: Vec<&str> = std::iter::once(s.text.as_str())
                .chain(s.name.as_deref())
                .collect();
            let score = fuzzy(atom.as_ref(), &mut matcher, &mut buf, &texts)?;
            let weight = history_weight(&s);
            Some((score, weight, s))
        })
        .collect();
    // Source first, then the fuzzy score, then frequency-weighted recency, then the text
    // (deterministic).
    scored.sort_by(|(sa, wa, a), (sb, wb, b)| {
        a.source
            .cmp(&b.source)
            .then(sb.cmp(sa))
            .then(wb.cmp(wa))
            .then_with(|| a.text.cmp(&b.text))
    });
    scored
        .into_iter()
        .map(|(_, _, s)| s)
        .take(req.limit)
        .collect()
}

/// What accepting `text` types after `prefix` is already on the command line: the rest
/// of `text`, or all of it when it does not extend `prefix`.
pub fn remainder<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.strip_prefix(prefix).unwrap_or(text)
}

/// The ghost-text suggestion for `prefix`: the best per-host, else global, history
/// command that extends it (none for a blank prefix). Cheap enough to run per frame: no
/// allocation per entry.
pub fn ghost_suggestion<'a>(
    host: Option<ItemId>,
    prefix: &str,
    history: &'a [HistoryEntry],
) -> Option<&'a str> {
    if prefix.trim().is_empty() {
        return None;
    }
    let mut groups: HashMap<(bool, &'a str), (u32, i64)> = HashMap::new();
    for e in history {
        if e.command.len() > prefix.len() && e.command.starts_with(prefix) {
            let g = groups
                .entry((e.host_id == host, e.command.as_str()))
                .or_insert((0, i64::MIN));
            g.0 += 1;
            g.1 = g.1.max(e.executed_at.0);
        }
    }
    groups
        .into_iter()
        .map(|((own, text), (count, last))| {
            let weight = last / 1000 + i64::from(count.saturating_sub(1)) * FREQUENCY_WEIGHT_SECS;
            (own, weight, text)
        })
        .max_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(b.2.cmp(a.2)))
        .map(|(_, _, text)| text)
}
