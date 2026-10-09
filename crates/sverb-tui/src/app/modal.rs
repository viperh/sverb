//! Generic modal dialogs on the app's stack (`DialogKind::Modal`).
//!
//! Keys reach the top dialog through the normal dispatch (dialog first, modal). This
//! module adds time: a dialog with a timeout or a spinner gets a 1 s
//! `TimerKind::DialogTick`; each tick advances it by one second of virtual time, and
//! when the timeout runs out its answer's effects are pushed and the dialog closes.

use std::time::Duration;

use super::{App, Effect, TimerKind};
use crate::views::{DialogId, DialogKind, dialogs::ModalDialog};

/// Tick period of countdowns and spinners.
pub(crate) const DIALOG_TICK: Duration = Duration::from_secs(1);

impl App {
    /// Push a generic modal on top of the stack (scheduling its tick if it has a
    /// tests can open one; the effects it adds must be executed like any others.
    pub fn push_modal(&mut self, dialog: ModalDialog, effects: &mut Vec<Effect>) -> DialogId {
        let ticks = dialog.modal.ticks();
        let id = self.push_dialog(DialogKind::Modal(dialog));
        if ticks {
            effects.push(Effect::ScheduleTimer {
                kind: TimerKind::DialogTick(id),
                after: DIALOG_TICK,
            });
        }
        id
    }

    /// A dialog tick fired. Stale ticks (the dialog was answered) are ignored.
    pub(crate) fn on_dialog_tick(&mut self, id: DialogId, effects: &mut Vec<Effect>) {
        // Auto-reconnect countdowns tick with ids allocated from the dialog ids.
        if self.on_reconnect_tick(id, effects) {
            return;
        }
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let DialogKind::Modal(m) = &mut self.dialogs[pos].kind else {
            return;
        };
        self.needs_redraw = true;
        match m.modal.tick(DIALOG_TICK) {
            Some(answer) => {
                effects.extend(m.effects_for(&answer));
                self.dialogs.remove(pos);
            }
            None => effects.push(Effect::ScheduleTimer {
                kind: TimerKind::DialogTick(id),
                after: DIALOG_TICK,
            }),
        }
    }
}
