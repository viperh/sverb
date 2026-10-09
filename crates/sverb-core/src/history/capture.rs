//! The heuristic capture tier (SPEC §9.10 tier 2).
//!
//! Without OSC 133 (never seen in the session), `Enter` with the alternate screen off
//! captures the cursor line, strips the learned prompt and records the rest as an
//! **unverified** command. Nothing is captured when:
//! - the alternate screen is on (vim, less, htop),
//! - no prompt is learned yet, or the line does not start with it,
//! - a sverb secret prompt is open,
//! - the cursor line or the previous output line looks like a secret prompt
//!   (`password`, `passphrase` or `token`, any case, ending with `:`): echo is probably
//!   off and the "command" would be a secret.

use super::prompt_learn::PromptLearner;

/// Longest command kept (longer lines are truncated output, not commands).
pub const MAX_COMMAND_CHARS: usize = 4096;

/// What the heuristic sees when `Enter` is pressed in a pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureContext<'a> {
    /// The cursor line (soft-wrapped rows joined), trailing blanks trimmed.
    pub cursor_line: &'a str,
    /// The line above the cursor line, if any.
    pub previous_line: Option<&'a str>,
    /// The alternate screen is on.
    pub alt_screen: bool,
    /// A sverb secret prompt (auth, vault) is open.
    pub secret_prompt_open: bool,
}

/// Whether `line` looks like a password / passphrase / token prompt.
pub fn is_secret_prompt(line: &str) -> bool {
    let trimmed = line.trim_end();
    if !trimmed.ends_with(':') {
        return false;
    }
    let lower = trimmed.to_lowercase();
    ["password", "passphrase", "token"]
        .iter()
        .any(|w| lower.contains(w))
}

/// A command as typed: control characters removed, surrounding blanks trimmed, at most
/// [`MAX_COMMAND_CHARS`]. `None` when nothing is left.
pub fn clean_command(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_COMMAND_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_owned())
}

/// The unverified command for `ctx`, if one may be captured.
pub fn heuristic_capture(ctx: &CaptureContext<'_>, prompt: &PromptLearner) -> Option<String> {
    if ctx.alt_screen || ctx.secret_prompt_open {
        return None;
    }
    if is_secret_prompt(ctx.cursor_line) || ctx.previous_line.is_some_and(is_secret_prompt) {
        return None;
    }
    let command = prompt.strip(ctx.cursor_line)?;
    clean_command(command)
}
