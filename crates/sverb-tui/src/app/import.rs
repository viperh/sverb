//! M2-11: results of the import / export wizard (`services::import`).
//!
//! A result finds its wizard by dialog id: a preview or an error updates it; a
//! finished import or export closes it and shows a toast. A result whose wizard was
//! closed meanwhile still shows its toast (or the error).

use sverb_core::error_report::ErrorReport;

use super::{App, Effect, ToastLevel};
use crate::views::{DialogKind, import_wizard::ImportEvent};

impl App {
    /// A result from the import service.
    pub(crate) fn on_import(&mut self, ev: ImportEvent, effects: &mut Vec<Effect>) {
        let dialog = match &ev {
            ImportEvent::Previewed { dialog, .. }
            | ImportEvent::Applied { dialog, .. }
            | ImportEvent::Exported { dialog, .. }
            | ImportEvent::Failed { dialog, .. } => *dialog,
        };
        let toast = match &ev {
            ImportEvent::Applied { summary, .. } | ImportEvent::Exported { summary, .. } => {
                Some(summary.clone())
            }
            _ => None,
        };
        let open = self.dialogs.iter_mut().find_map(|d| match &mut d.kind {
            DialogKind::ImportWizard(w) if d.id == dialog => Some(w),
            _ => None,
        });
        match open {
            Some(wizard) => {
                if wizard.on_event(ev) {
                    self.dialogs.retain(|d| d.id != dialog);
                }
                self.needs_redraw = true;
            }
            None => {
                if let ImportEvent::Failed { message, .. } = ev {
                    self.push_error(&ErrorReport::msg(message), effects);
                }
            }
        }
        if let Some(msg) = toast {
            self.push_toast(ToastLevel::Success, msg, effects);
        }
    }
}
