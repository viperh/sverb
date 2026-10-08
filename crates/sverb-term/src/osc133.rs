//! M7-01: shell integration (OSC 133) command tracking (SPEC §9.10 tier 1).
//!
//! The side scanner (`alacritty::sidechannel`) recognizes `OSC 133 ; A|B|C|D[;exit]`,
//! split across reads at any byte, and the emulator reports each mark with the cursor
//! position at the moment it was parsed. [`CommandTracker`] turns the marks into
//! commands:
//!
//! - `A` prompt start, `B` command start (prompt end: the command line begins at the
//!   cursor), `C` command executed (output starts), `D[;exit]` command finished.
//! - At `C` the command text is read from the grid, from the `B` position up to the
//!   cell before the `C` cursor (rows joined; soft-wrapped rows without a newline, so a
//!   long wrapped command comes back as one line). It is read **while the mark is
//!   processed**, before any output of the command touches the grid.
//! - At `D` the command is reported with its exit code. A new prompt (`A` / `B`) without
//!   a `D` reports it without one. Stray marks (a `D` with no command, a `C` without a
//!   `B`) are ignored, so duplicated hooks (fish 4's own marks plus sverb's) are harmless.
//!
//! Positions are kept as absolute rows (`history_len + line`), so output that scrolls the
//! screen between `B` and the read does not shift them.

use crate::emulator::{Emulator, GridPoint, PromptMarkKind};

/// Longest command kept, in chars.
pub const MAX_COMMAND_CHARS: usize = 4096;

/// A command the shell ran, captured through OSC 133.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommand {
    /// The command line as typed (trimmed; continuation lines joined with `\n`).
    pub command: String,
    /// `D;<exit>`, if the shell reported it.
    pub exit_code: Option<i32>,
}

/// The shell-integration state of a pane, for the autocomplete overlay and ghost text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptState {
    /// OSC 133 marks were seen in this session (tier 1 is active).
    pub integrated: bool,
    /// The shell is reading a command line: the text typed so far, from the `B` mark to
    /// the cursor (`None` while a command runs, or before the first prompt).
    pub input: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Stage {
    #[default]
    Idle,
    /// After `A`.
    Prompt,
    /// After `B`: the command line starts at this absolute row and column.
    Input { row: i64, column: usize },
    /// After `C`.
    Running,
}

/// Follows OSC 133 marks of one emulator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandTracker {
    seen: bool,
    stage: Stage,
    /// The command read at `C`, reported at `D` (or the next prompt).
    running: Option<String>,
}

fn abs_row(line: i32, history_len: usize) -> i64 {
    i64::try_from(history_len).unwrap_or(i64::MAX) + i64::from(line)
}

fn live_line(row: i64, history_len: usize) -> Option<i32> {
    i32::try_from(row - i64::try_from(history_len).ok()?).ok()
}

/// Rows trimmed at the end; blank results are `None`.
fn clean(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let joined: String = lines
        .join("\n")
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_COMMAND_CHARS)
        .collect();
    let trimmed = joined.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

impl CommandTracker {
    /// A tracker that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any OSC 133 mark was seen.
    pub fn seen(&self) -> bool {
        self.seen
    }

    /// Forget everything (a reconnect or restart starts a new shell).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn flush(&mut self, exit_code: Option<i32>) -> Option<ShellCommand> {
        self.running
            .take()
            .map(|command| ShellCommand { command, exit_code })
    }

    /// Apply one mark. `cursor` and `history_len` are the emulator's at the mark; `term`
    /// is read for the command text at `C` (its grid must still be as it was at the mark).
    pub fn on_mark(
        &mut self,
        kind: PromptMarkKind,
        cursor: GridPoint,
        history_len: usize,
        term: &dyn Emulator,
    ) -> Option<ShellCommand> {
        self.seen = true;
        match kind {
            PromptMarkKind::PromptStart => {
                let done = self.flush(None);
                self.stage = Stage::Prompt;
                done
            }
            PromptMarkKind::CommandStart => {
                let done = self.flush(None);
                self.stage = Stage::Input {
                    row: abs_row(cursor.line, history_len),
                    column: cursor.column,
                };
                done
            }
            PromptMarkKind::OutputStart => {
                if let Stage::Input { row, column } = self.stage {
                    self.running = read_command(term, row, column, cursor, history_len);
                    self.stage = Stage::Running;
                }
                None
            }
            PromptMarkKind::CommandFinished { exit_code } => {
                let done = if self.stage == Stage::Running {
                    self.flush(exit_code)
                } else {
                    None
                };
                self.stage = Stage::Idle;
                done
            }
        }
    }

    /// The pane's prompt state now (`cursor` / `history_len` are the emulator's).
    pub fn prompt_state(
        &self,
        cursor: GridPoint,
        history_len: usize,
        term: &dyn Emulator,
    ) -> PromptState {
        let input = match self.stage {
            Stage::Input { row, column } => {
                read_range(term, row, column, cursor, history_len).map(|mut t| {
                    // The grid drops trailing blanks; what was typed may end with spaces
                    // (`git `). On one logical line the cell count says how many.
                    if !t.contains('\n')
                        && let Some(start) = live_line(row, history_len)
                    {
                        let (cols, _) = term.size();
                        let cells = i64::from(cursor.line - start) * i64::from(cols)
                            + i64::try_from(cursor.column).unwrap_or(0)
                            - i64::try_from(column).unwrap_or(0);
                        let have = i64::try_from(t.chars().count()).unwrap_or(i64::MAX);
                        for _ in have..cells {
                            t.push(' ');
                        }
                    }
                    t
                })
            }
            _ => None,
        };
        PromptState {
            integrated: self.seen,
            input,
        }
    }
}

/// The text from (`row`, `column`) to the cell before `end` (both on the grid as of
/// `history_len`). `Some("")` when the range is empty, `None` when it left the grid.
fn read_range(
    term: &dyn Emulator,
    row: i64,
    column: usize,
    end: GridPoint,
    history_len: usize,
) -> Option<String> {
    let start_line = live_line(row, history_len)?;
    let start = GridPoint::new(start_line, column);
    let (cols, _) = term.size();
    let last_col = usize::from(cols.max(1)) - 1;
    let end = if end.column == 0 {
        GridPoint::new(end.line - 1, last_col)
    } else {
        GridPoint::new(end.line, end.column - 1)
    };
    if end < start {
        return Some(String::new());
    }
    if -start_line > i32::try_from(term.scrollback_len()).unwrap_or(i32::MAX) {
        return None;
    }
    Some(term.grid_text(start, end))
}

fn read_command(
    term: &dyn Emulator,
    row: i64,
    column: usize,
    cursor: GridPoint,
    history_len: usize,
) -> Option<String> {
    read_range(term, row, column, cursor, history_len).and_then(|t| clean(&t))
}
