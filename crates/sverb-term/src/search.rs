//! Regex search across the screen and scrollback, and URL detection (SPEC §7.1, §17).
//!
//! Search runs on **logical lines**: rows that soft-wrap are joined first, so a match can
//! span a wrap. Each logical line's trailing blanks are dropped (so `foo$` finds `foo` at the
//! end of a line). Patterns use Rust's `regex` syntax; an invalid pattern falls back to a
//! literal search and keeps the error for the UI ([`SearchPattern::error`]).
//!
//! Matches are [`Match`]es with inclusive ends; a wide character's end covers its spacer.

use regex::Regex;

use crate::emulator::{Direction, GridPoint, Match};
use crate::selection::{TextGrid, logical_bounds};

/// Counting stops here (the UI shows `1000+`).
pub const MATCH_COUNT_CAP: usize = 1000;

/// A compiled search pattern. Compares equal by its source text.
#[derive(Debug, Clone)]
pub struct SearchPattern {
    regex: Regex,
    source: String,
    error: Option<String>,
}

impl PartialEq for SearchPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for SearchPattern {}

impl SearchPattern {
    /// Compile `pattern`. An invalid regex becomes a literal search, with the error kept.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        match Regex::new(pattern) {
            Ok(regex) => Self {
                regex,
                source: pattern.to_owned(),
                error: None,
            },
            Err(err) => {
                let msg = err.to_string();
                let msg = msg.lines().last().unwrap_or("invalid regex").trim();
                // An escaped literal always compiles; if even that failed (size limits),
                // fall back to a pattern that never matches.
                let regex = Regex::new(&regex::escape(pattern))
                    .or_else(|_| Regex::new(r"[^\s\S]"))
                    .unwrap_or_else(|_| unreachable_regex());
                Self {
                    regex,
                    source: pattern.to_owned(),
                    error: Some(msg.trim_start_matches("error: ").to_owned()),
                }
            }
        }
    }

    /// The pattern as typed.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Why the pattern isn't a valid regex (then it is searched literally).
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The regex actually used.
    #[must_use]
    pub fn regex(&self) -> &Regex {
        &self.regex
    }
}

// `[^\s\S]` always compiles; this only exists so `new` has no panic path.
#[allow(clippy::unwrap_used)]
fn unreachable_regex() -> Regex {
    Regex::new("$^").unwrap()
}

/// A search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchHit {
    /// The match.
    pub found: Match,
    /// The search went past the end (or start) of the scrollback and continued from the
    /// other end ("search wrapped").
    pub wrapped: bool,
}

/// A logical line's text and where each character sits.
struct LogicalLine {
    first: i32,
    last: i32,
    text: String,
    /// (byte offset, start point, last column) per character cell.
    map: Vec<(usize, GridPoint, usize)>,
}

impl LogicalLine {
    fn read(grid: &dyn TextGrid, line: i32) -> Self {
        let (first, last) = logical_bounds(grid, line);
        let mut text = String::new();
        let mut map = Vec::new();
        for l in first..=last {
            let Some(row) = grid.row(l) else { continue };
            for (col, cell) in row.cells.iter().enumerate() {
                if cell.width == 0 {
                    continue;
                }
                map.push((
                    text.len(),
                    GridPoint::new(l, col),
                    col + usize::from(cell.width) - 1,
                ));
                text.push(if cell.c == '\0' { ' ' } else { cell.c });
                text.extend(cell.zerowidth.iter());
            }
        }
        let trimmed = text.trim_end().len();
        text.truncate(trimmed);
        map.retain(|(b, _, _)| *b < trimmed);
        Self {
            first,
            last,
            text,
            map,
        }
    }

    fn entry(&self, byte: usize) -> Option<&(usize, GridPoint, usize)> {
        let i = self.map.partition_point(|(b, _, _)| *b <= byte);
        self.map.get(i.checked_sub(1)?)
    }

    fn to_match(&self, start: usize, end: usize) -> Option<Match> {
        let (_, s, _) = *self.entry(start)?;
        let (_, e, last_col) = *self.entry(end.checked_sub(1)?)?;
        Some(Match {
            start: s,
            end: GridPoint::new(e.line, last_col),
        })
    }

    fn matches(&self, re: &Regex) -> Vec<Match> {
        re.find_iter(&self.text)
            .filter(|m| !m.is_empty())
            .filter_map(|m| self.to_match(m.start(), m.end()))
            .collect()
    }
}

/// The next match strictly after (`Forward`) or before (`Backward`) `from`, wrapping around
/// the ends of the grid once.
#[must_use]
pub fn find_next(
    grid: &dyn TextGrid,
    pattern: &SearchPattern,
    from: GridPoint,
    dir: Direction,
) -> Option<SearchHit> {
    let (top, bottom) = (grid.top_line(), grid.bottom_line());
    if bottom < top {
        return None;
    }
    let from = grid.clamp(from);
    let re = pattern.regex();
    let origin = LogicalLine::read(grid, from.line);
    let pick = |ms: Vec<Match>, wrapped: bool| -> Option<SearchHit> {
        let m = match dir {
            Direction::Forward => ms.into_iter().next(),
            Direction::Backward => ms.into_iter().last(),
        }?;
        Some(SearchHit { found: m, wrapped })
    };
    let all = origin.matches(re);
    let (before, after): (Vec<Match>, Vec<Match>) = all.iter().partition(|m| m.start < from);
    let after: Vec<Match> = after.into_iter().filter(|m| m.start != from).collect();
    let here = match dir {
        Direction::Forward => after.clone(),
        Direction::Backward => before.clone(),
    };
    if let Some(hit) = pick(here, false) {
        return Some(hit);
    }
    // Walk the other logical lines in `dir`, wrapping once, back to the origin line.
    let mut line = match dir {
        Direction::Forward => origin.last + 1,
        Direction::Backward => origin.first - 1,
    };
    let mut wrapped = false;
    loop {
        if line > bottom {
            line = top;
            wrapped = true;
        } else if line < top {
            line = bottom;
            wrapped = true;
        }
        let ll = LogicalLine::read(grid, line);
        if ll.first == origin.first {
            // Back where we started: the rest of the origin line (or the match at `from`).
            let rest = match dir {
                Direction::Forward => {
                    let mut ms: Vec<Match> = before;
                    ms.extend(all.iter().filter(|m| m.start == from));
                    ms
                }
                Direction::Backward => all.clone(),
            };
            return pick(rest, true);
        }
        if let Some(hit) = pick(ll.matches(re), wrapped) {
            return Some(hit);
        }
        line = match dir {
            Direction::Forward => ll.last + 1,
            Direction::Backward => ll.first - 1,
        };
    }
}

/// Every match on the logical lines touching `first..=last` (the visible rows), for the
/// highlight overlay.
#[must_use]
pub fn matches_between(
    grid: &dyn TextGrid,
    pattern: &SearchPattern,
    first: i32,
    last: i32,
) -> Vec<Match> {
    let (first, last) = (first.max(grid.top_line()), last.min(grid.bottom_line()));
    let mut out = Vec::new();
    let mut line = first;
    while line <= last {
        let ll = LogicalLine::read(grid, line);
        out.extend(ll.matches(pattern.regex()));
        line = ll.last + 1;
    }
    out
}

/// Number of matches in the whole grid, counting at most `cap` (then `true`).
#[must_use]
pub fn count_matches(grid: &dyn TextGrid, pattern: &SearchPattern, cap: usize) -> (usize, bool) {
    let mut n = 0;
    let mut line = grid.top_line();
    while line <= grid.bottom_line() {
        let ll = LogicalLine::read(grid, line);
        n += pattern
            .regex()
            .find_iter(&ll.text)
            .filter(|m| !m.is_empty())
            .count();
        if n >= cap {
            return (cap, true);
        }
        line = ll.last + 1;
    }
    (n, false)
}

/// The auto-detected URL under `p` (`http`, `https`, `ftp`, `file`, `mailto`), with its
/// cells. Trailing punctuation (`.`, `,`, `)`, …) isn't part of the URL.
#[must_use]
pub fn url_at(grid: &dyn TextGrid, p: GridPoint) -> Option<(Match, String)> {
    static URL: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
    let re = URL
        .get_or_init(|| {
            Regex::new(r#"(?:(?:https?|ftp|file)://|mailto:)[^\s<>"'`{}|\\^\x00-\x1f]+"#).ok()
        })
        .as_ref()?;
    let p = grid.clamp(p);
    let ll = LogicalLine::read(grid, p.line);
    for m in re.find_iter(&ll.text) {
        let url = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '\'', '"']);
        if url.is_empty() {
            continue;
        }
        let found = ll.to_match(m.start(), m.start() + url.len())?;
        if found.start <= p && found.end >= p {
            return Some((found, url.to_owned()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::selection::VecGrid;

    fn p(line: i32, column: usize) -> GridPoint {
        GridPoint::new(line, column)
    }

    fn grid() -> VecGrid {
        // 3 scrollback lines, 3 screen lines.
        VecGrid::from_lines(
            &["error one", "ok", "error two", "fine", "error three", "$ "],
            20,
            3,
        )
    }

    /// Backwards across the scrollback, then `n` wraps with a flag.
    #[test]
    fn t04_backward_search_and_wrap() {
        let g = grid();
        assert_eq!(g.top, -3);
        let pat = SearchPattern::new(r"error \w+");
        let hit = find_next(&g, &pat, p(2, 0), Direction::Backward).unwrap();
        assert_eq!(
            hit.found,
            Match {
                start: p(1, 0),
                end: p(1, 10)
            }
        );
        assert!(!hit.wrapped);
        let hit = find_next(&g, &pat, hit.found.start, Direction::Backward).unwrap();
        assert_eq!(hit.found.start, p(-1, 0));
        let hit = find_next(&g, &pat, hit.found.start, Direction::Backward).unwrap();
        assert_eq!(hit.found.start, p(-3, 0));
        assert!(!hit.wrapped);
        // `n` past the oldest match wraps to the newest.
        let hit = find_next(&g, &pat, hit.found.start, Direction::Backward).unwrap();
        assert_eq!(hit.found.start, p(1, 0));
        assert!(hit.wrapped, "search wrapped");
        // Forward from the newest wraps to the oldest.
        let hit = find_next(&g, &pat, p(1, 0), Direction::Forward).unwrap();
        assert_eq!((hit.found.start, hit.wrapped), (p(-3, 0), true));
        assert_eq!(count_matches(&g, &pat, MATCH_COUNT_CAP), (3, false));
        assert_eq!(count_matches(&g, &pat, 2), (2, true));
        // A single match: `n` finds it again, wrapped.
        let one = SearchPattern::new("fine");
        let hit = find_next(&g, &one, p(0, 0), Direction::Forward).unwrap();
        assert_eq!((hit.found.start, hit.wrapped), (p(0, 0), true));
        assert!(find_next(&g, &SearchPattern::new("nope"), p(0, 0), Direction::Forward).is_none());
    }

    /// An invalid regex reports an error and searches literally.
    #[test]
    fn t05_invalid_regex_is_literal() {
        let pat = SearchPattern::new("(");
        assert!(pat.error().is_some());
        assert_eq!(pat.source(), "(");
        let g = VecGrid::from_lines(&["f(x)", "g"], 10, 2);
        let hit = find_next(&g, &pat, p(1, 0), Direction::Backward).unwrap();
        assert_eq!(
            hit.found,
            Match {
                start: p(0, 1),
                end: p(0, 1)
            }
        );
        assert!(SearchPattern::new("a+").error().is_none());
    }

    #[test]
    fn matches_span_wraps_and_wide_chars() {
        let g = VecGrid::from_lines(&["xx hello world", "漢字 abc"], 8, 3);
        let pat = SearchPattern::new("hello world");
        let ms = matches_between(&g, &pat, 1, 1);
        assert_eq!(
            ms,
            vec![Match {
                start: p(0, 3),
                end: p(1, 5)
            }]
        );
        let ms = matches_between(&g, &SearchPattern::new("字"), 0, 2);
        assert_eq!(
            ms,
            vec![Match {
                start: p(2, 2),
                end: p(2, 3)
            }]
        );
        // `$` is the end of the text, not of the padding.
        let ms = matches_between(&g, &SearchPattern::new("abc$"), 0, 2);
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn urls() {
        let g = VecGrid::from_lines(
            &["see https://example.com/a?b=1. ok", "mailto:x@y.z"],
            40,
            2,
        );
        let (m, url) = url_at(&g, p(0, 10)).unwrap();
        assert_eq!(url, "https://example.com/a?b=1");
        assert_eq!((m.start, m.end), (p(0, 4), p(0, 28)));
        assert!(url_at(&g, p(0, 1)).is_none());
        assert!(
            url_at(&g, p(0, 29)).is_none(),
            "the trailing dot isn't part of it"
        );
        assert_eq!(url_at(&g, p(1, 0)).unwrap().1, "mailto:x@y.z");
    }
}
