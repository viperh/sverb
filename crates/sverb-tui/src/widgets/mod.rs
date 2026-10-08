//! Shell chrome widgets (M0-11). Each is a set of free functions over plain data and
//! a resolved [`Theme`](crate::theme::Theme); rendering is infallible at every size.
//!
//! - [`topbar`]: app name, vault selector, sync indicator, lock icon,
//! - [`tabbar`]: session tabs (M1-17 fills in the real tab model),
//! - [`statusbar`]: mode, session, forwards, REC, BROADCAST, sync, key hint, dropped
//!   right-to-left by priority when space is short,
//! - [`toast`]: the toast stack (top right),
//! - [`which_key`]: the which-key popup (bottom right, above the status bar),
//! - [`log_pane`]: the `--debug` log pane,
//! - [`terminal_pane`] (M1-10): a session's terminal content with its border and overlays.
//!
//! M1-06 adds the shared components (plain state + `View` impls, reducer-testable):
//! - [`list`]: `ListView<R>`, the one list every section view uses (fuzzy filter,
//!   multi-select, sort, tree mode, detail pane, virtualized rendering),
//! - [`form`]: the full-screen form framework and its field widgets,
//! - [`dialog`] / [`confirm`]: generic modal dialogs and ready-made confirmations.

pub mod log_pane;
pub mod statusbar;
pub mod tabbar;
// M1-10: the session pane (terminal content, title, state overlays).
pub mod terminal_pane;
pub mod toast;
pub mod topbar;
pub mod which_key;
// M1-13: SSH session details (status bar latency, session info panel).
pub mod session_info;
// M1-06: shared list, form and dialog components.
pub mod confirm;
pub mod dialog;
#[cfg(test)]
mod dialog_tests;
pub mod form;
pub mod list;
#[cfg(test)]
mod list_tests;
#[cfg(test)]
pub(crate) mod test_util;
// M1-14: the auth prompt dialog and the per-session prompt queue.
pub mod auth_prompt;
// M2-04: per-host results of exec runs (install key; M2-09 snippet runs).
pub mod results_table;

use ratatui::text::Span;

/// Display width of `s` in cells.
pub(crate) fn width(s: &str) -> usize {
    Span::raw(s).width()
}

/// Wrap `text` at word boundaries into lines of at most `max` cells, keeping at most
/// `max_lines` lines (the last one ends in `…` when text was cut).
pub(crate) fn wrap(text: &str, max: usize, max_lines: usize) -> Vec<String> {
    let max = max.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let mut word = word.to_owned();
        loop {
            let sep = usize::from(!cur.is_empty());
            if width(&cur) + sep + width(&word) <= max {
                if sep == 1 {
                    cur.push(' ');
                }
                cur.push_str(&word);
                break;
            }
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
                continue;
            }
            // A word longer than a line: hard-split it (at least one char per line).
            let mut head = String::new();
            let mut taken = 0;
            for c in word.chars() {
                let w = width(c.encode_utf8(&mut [0; 4]));
                if !head.is_empty() && width(&head) + w > max {
                    break;
                }
                head.push(c);
                taken += c.len_utf8();
            }
            word = word[taken..].to_owned();
            if word.is_empty() {
                cur = head;
                break;
            }
            lines.push(head);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.len() > max_lines {
        lines.truncate(max_lines);
        if let Some(last) = lines.last_mut() {
            while width(last) + 1 > max && last.pop().is_some() {}
            last.push('…');
        }
    }
    lines
}

/// `s` cut to at most `max` cells, with `…` when cut.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    for c in s.chars() {
        if width(&out) + width(c.encode_utf8(&mut [0; 4])) + 1 > max {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_respects_width_and_line_limit() {
        let lines = wrap("the quick brown fox jumps over the lazy dog", 10, 3);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| width(l) <= 10), "{lines:?}");
        assert!(lines[2].ends_with('…'));
        assert_eq!(wrap("short", 10, 3), ["short"]);
        let long = wrap("aaaaaaaaaaaaaaaaaaaa", 8, 3);
        assert_eq!(long, ["aaaaaaaa", "aaaaaaaa", "aaaa"]);
        assert!(wrap("", 5, 3).is_empty());
    }

    #[test]
    fn truncate_adds_an_ellipsis() {
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("hello", 0), "");
    }
}
