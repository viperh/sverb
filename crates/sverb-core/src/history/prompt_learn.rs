//! M7-01: learning the shell prompt for the heuristic capture tier (SPEC §9.10).
//!
//! Without shell integration sverb does not know where the prompt ends. It watches the
//! text left of the cursor at moments when the shell is waiting for input (the cursor at
//! the end of its line, output settled) and keeps the last [`OBSERVATIONS`] of them. The
//! longest common prefix of those that is at least [`MIN_PROMPT_CHARS`] long and ends with
//! a prompt sigil (`$`, `#`, `%`, `>` or `❯`) plus a space is the prompt pattern.
//!
//! A prompt that contains the working directory (`user@h:~/src$ `) changes after `cd`, so
//! the plain common prefix of `user@h:~$ ` and `user@h:/tmp$ ` (`user@h:`) is not a full
//! prompt. When every observation ends with the same sigil and a space, the learner then
//! uses the common prefix as an anchor and strips up to the first `"<sigil> "` after it.

use std::collections::VecDeque;

/// Observations kept.
pub const OBSERVATIONS: usize = 5;
/// Shortest prompt pattern.
pub const MIN_PROMPT_CHARS: usize = 2;
/// Characters a prompt ends with (followed by a space).
pub const PROMPT_SIGILS: &[char] = &['$', '#', '%', '>', '❯'];
/// Longest observation kept (a longer "prompt" is output, not a prompt).
const MAX_OBSERVATION_CHARS: usize = 256;

/// The learned prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptPattern {
    /// Every observation starts with this text (it ends with a sigil and a space).
    Exact(String),
    /// Observations start with `anchor` and end with `sigil` + space; the prompt runs up
    /// to the first `"<sigil> "` after the anchor.
    Anchored {
        /// The common start (may be empty only if it is not needed, never here).
        anchor: String,
        /// The common final sigil.
        sigil: char,
    },
}

/// Learns the prompt of one pane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptLearner {
    observations: VecDeque<String>,
    pattern: Option<PromptPattern>,
}

/// Whether `text` ends with a prompt sigil followed by a space.
pub fn ends_like_prompt(text: &str) -> bool {
    let mut rev = text.chars().rev();
    rev.next() == Some(' ') && rev.next().is_some_and(|c| PROMPT_SIGILS.contains(&c))
}

fn common_prefix<'a>(a: &'a str, b: &str) -> &'a str {
    let end = a
        .char_indices()
        .zip(b.chars())
        .find(|((_, x), y)| x != y)
        .map_or_else(|| a.len().min(b.len()), |((i, _), _)| i);
    // `end` is a char boundary of `a` (from `char_indices`, or the shorter length, which
    // is a boundary because both strings agree up to it).
    &a[..end]
}

/// The longest prefix of `prefix` that ends with a sigil and a space.
fn trim_to_sigil(prefix: &str) -> Option<&str> {
    let mut best = None;
    for (i, c) in prefix.char_indices() {
        if c == ' '
            && prefix[..i]
                .chars()
                .next_back()
                .is_some_and(|p| PROMPT_SIGILS.contains(&p))
        {
            best = Some(&prefix[..=i]);
        }
    }
    best.filter(|p| p.chars().count() >= MIN_PROMPT_CHARS)
}

impl PromptLearner {
    /// A learner with no observations.
    pub fn new() -> Self {
        Self::default()
    }

    /// The learned pattern, if any.
    pub fn pattern(&self) -> Option<&PromptPattern> {
        self.pattern.as_ref()
    }

    /// Whether a prompt is known.
    pub fn is_learned(&self) -> bool {
        self.pattern.is_some()
    }

    /// Record the text left of the cursor while the shell waits for input. Text that does
    /// not end like a prompt is ignored (a password prompt, a pager, partial output).
    pub fn observe(&mut self, left_of_cursor: &str) {
        let text = left_of_cursor.trim_start_matches(['\r', '\n']);
        if !ends_like_prompt(text)
            || text.chars().count() < MIN_PROMPT_CHARS
            || text.chars().count() > MAX_OBSERVATION_CHARS
            || text.chars().any(char::is_control)
        {
            return;
        }
        if self.observations.len() == OBSERVATIONS {
            self.observations.pop_front();
        }
        self.observations.push_back(text.to_owned());
        self.pattern = self.learn();
    }

    fn learn(&self) -> Option<PromptPattern> {
        let mut iter = self.observations.iter();
        let first = iter.next()?;
        let mut prefix: &str = first;
        for o in iter {
            prefix = common_prefix(prefix, o);
        }
        if let Some(exact) = trim_to_sigil(prefix)
            && exact.len() == prefix.len()
        {
            return Some(PromptPattern::Exact(exact.to_owned()));
        }
        // A prompt with a changing part (the cwd): same final sigil everywhere, anchored on
        // the common start.
        let sigil = first.chars().rev().nth(1)?;
        let same_end = self
            .observations
            .iter()
            .all(|o| o.chars().rev().nth(1) == Some(sigil));
        if same_end && prefix.chars().count() >= MIN_PROMPT_CHARS {
            // An anchor that already contains a full prompt is the exact case above; here
            // the anchor is a strict start of each observation.
            return Some(PromptPattern::Anchored {
                anchor: prefix.to_owned(),
                sigil,
            });
        }
        // Different prompts (a REPL, `sudo -i`): fall back to the latest one.
        trim_to_sigil(prefix)
            .map(|p| PromptPattern::Exact(p.to_owned()))
            .or_else(|| {
                self.observations
                    .back()
                    .map(|o| PromptPattern::Exact(o.clone()))
            })
    }

    /// `line` without the learned prompt; `None` if no prompt is learned or `line` does
    /// not start with it.
    pub fn strip<'a>(&self, line: &'a str) -> Option<&'a str> {
        match self.pattern.as_ref()? {
            PromptPattern::Exact(p) => line.strip_prefix(p.as_str()),
            PromptPattern::Anchored { anchor, sigil } => {
                let rest = line.strip_prefix(anchor.as_str())?;
                let mut marker = String::with_capacity(2);
                marker.push(*sigil);
                marker.push(' ');
                let at = rest.find(&marker)?;
                Some(&rest[at + marker.len()..])
            }
        }
    }
}
