//! Ready-made confirmations built on [`Modal`].

use super::dialog::{Button, Modal};

/// Button id of "Discard" in [`discard_changes`].
pub const DISCARD: &str = "discard";
/// Button id of "Keep editing" in [`discard_changes`].
pub const KEEP: &str = "keep";
/// Button id of the confirming button in [`delete`] and [`yes_no`].
pub const YES: &str = "yes";
/// Button id of the cancelling button in [`delete`] and [`yes_no`].
pub const NO: &str = "no";

/// "Discard changes?" for `Esc` on a dirty form. Danger: `Enter` keeps editing.
pub fn discard_changes() -> Modal {
    Modal::confirm(
        "Discard changes?",
        "Your edits will be lost.",
        vec![
            Button::new(DISCARD, "Discard", 'd').danger(),
            Button::new(KEEP, "Keep editing", 'k').safe(),
        ],
        0,
        true,
    )
}

/// "Delete N `<noun>`s?" (bulk actions). Danger: `Enter` cancels.
pub fn delete(count: usize, noun: &str) -> Modal {
    let what = if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    };
    Modal::confirm(
        &format!("Delete {what}?"),
        "This cannot be undone.",
        vec![
            Button::new(YES, "Delete", 'd').danger(),
            Button::new(NO, "Cancel", 'c').safe(),
        ],
        0,
        true,
    )
}

/// A plain yes/no question; `Enter` answers yes.
pub fn yes_no(title: &str, body: &str) -> Modal {
    Modal::confirm(
        title,
        body,
        vec![
            Button::new(YES, "Yes", 'y'),
            Button::new(NO, "No", 'n').safe(),
        ],
        0,
        false,
    )
}
