//!
//! | Token | Meaning |
//! |---|---|
//! | `word` | fuzzy match (smart case, Unicode normalization) |
//! | `"exact phrase"` | substring match (smart case) |
//! | `#tag` | exact tag name, case-insensitive; several are ANDed |
//! | `@vault` | vault name prefix, case-insensitive; several are ORed |
//! | `kind:host` | item kind (`host`, `snippet`, `port-forward`, plural accepted); ORed |
//!
//! A lone `#` or `@` is ignored. An unknown `kind:` matches nothing. An unterminated
//! quote runs to the end of the input.

use crate::model::ItemKind;

/// A parsed query (`word` fuzzy, `"phrase"` substring, `#tag` exact and ANDed,
/// `@vault` prefix and ORed, `kind:` ORed; an unknown kind matches nothing). Pure data: [`IndexSnapshot::query`](super::IndexSnapshot::query)
/// compiles it into matcher atoms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Free-text words, fuzzy-matched (all must match).
    pub terms: Vec<String>,
    /// Quoted phrases, substring-matched (all must match).
    pub phrases: Vec<String>,
    /// `#tag` names, lowercased (all must be present).
    pub tags: Vec<String>,
    /// `@vault` prefixes, lowercased (any may match).
    pub vaults: Vec<String>,
    /// `kind:` filters (any may match).
    pub kinds: Vec<ItemKind>,
    /// A `kind:` token named no known kind: nothing matches.
    pub unknown_kind: bool,
}

impl Query {
    /// Parse the query language: `word`, `"phrase"`, `#tag`, `@vault`, `kind:host`
    /// (see [`Query`]).
    pub fn parse(input: &str) -> Self {
        let mut q = Self::default();
        let mut chars = input.char_indices().peekable();
        while let Some(&(start, c)) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
                continue;
            }
            if c == '"' {
                chars.next();
                let mut phrase = String::new();
                for (_, c) in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                    phrase.push(c);
                }
                if !phrase.trim().is_empty() {
                    q.phrases.push(phrase);
                }
                continue;
            }
            let mut end = input.len();
            while let Some(&(i, c)) = chars.peek() {
                if c.is_whitespace() {
                    end = i;
                    break;
                }
                chars.next();
            }
            q.push_token(&input[start..end]);
        }
        q
    }

    fn push_token(&mut self, token: &str) {
        if let Some(tag) = token.strip_prefix('#') {
            if !tag.is_empty() {
                self.tags.push(tag.to_lowercase());
            }
        } else if let Some(vault) = token.strip_prefix('@') {
            if !vault.is_empty() {
                self.vaults.push(vault.to_lowercase());
            }
        } else if let Some(kind) = token.strip_prefix("kind:") {
            match parse_kind(kind) {
                Some(k) => {
                    if !self.kinds.contains(&k) {
                        self.kinds.push(k);
                    }
                }
                None => self.unknown_kind = true,
            }
        } else {
            self.terms.push(token.to_owned());
        }
    }

    /// No text to match (only filters, or nothing at all).
    pub fn has_text(&self) -> bool {
        !self.terms.is_empty() || !self.phrases.is_empty()
    }

    /// Nothing at all: every item in scope matches.
    pub fn is_empty(&self) -> bool {
        !self.has_text()
            && self.tags.is_empty()
            && self.vaults.is_empty()
            && self.kinds.is_empty()
            && !self.unknown_kind
    }
}

/// `host`, `Hosts`, `port-forward`, `port_forward`, `forwards`… → the kind.
pub fn parse_kind(s: &str) -> Option<ItemKind> {
    let s = s.to_lowercase().replace('_', "-");
    let find = |name: &str| ItemKind::ALL.into_iter().find(|k| k.as_str() == name);
    if let Some(k) = find(&s).or_else(|| s.strip_suffix('s').and_then(find)) {
        return Some(k);
    }
    match s.as_str() {
        "forward" | "forwards" | "pf" => Some(ItemKind::PortForward),
        "known-hosts" | "knownhost" | "knownhosts" => Some(ItemKind::KnownHost),
        "cert" | "certs" => Some(ItemKind::Certificate),
        "history" => Some(ItemKind::HistoryEntry),
        _ => None,
    }
}
