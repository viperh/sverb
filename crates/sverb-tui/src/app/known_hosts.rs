//! Known hosts in the reducer (SPEC §9.5, §8.5).
//!
//! - **Host-key prompts:** `SessionEvent::HostKey` opens the unknown-key modal or the
//!   changed-key screen (`views/dialogs/host_key.rs`) for that session; its answer is
//!   `Effect::HostKeyDecision`, which the session service turns into
//!   `SessionCmd::HostKeyDecision`. "Accept & save" (and the confirmed replacement of a
//!   changed key) is saved by the verifier's store (`services/known_hosts.rs`), which
//!   reports it back as `KnownHostsEvent::Saved`. When the session leaves
//!   `AwaitingHostKey` (answered, 120 s timeout, closed) its dialog closes.
//! - **The Known Hosts view:** loaded through `KnownHostsEffect::Load` after unlock and
//!   on every index update (one load in flight); cleared on lock. Its requests: delete
//!   (confirm, then `ItemEffect::Delete`), edit (a form → `KnownHostsEffect::Save`),
//!   import / export (a path prompt → `KnownHostsEffect::Import` / `Export`).

use sverb_conn::{SessionState, Verification};
use sverb_core::{
    error_report::ErrorReport,
    model::{ItemId, KnownHost},
    vault::LockState,
};

use super::{App, Effect, SessionId, ToastLevel, VaultEffect, hosts::ItemEffect};
use crate::{
    views::{
        DialogKind,
        dialogs::{ModalDialog, host_key::HostKeyDialog},
        known_hosts::{FilePrompt, KnownHostsDialog, KnownHostsRequest},
    },
    widgets::confirm,
};

/// Known-hosts requests for the vault and the file system (`services/known_hosts.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownHostsEffect {
    /// Load every KnownHost item (answered with `KnownHostsEvent::Loaded`).
    Load,
    /// Create (`item: None`, in the Personal vault) or update an entry.
    Save {
        /// The item.
        item: Option<ItemId>,
        /// The entry.
        entry: KnownHost,
    },
    /// Import a `known_hosts` file (`~` expands to the home directory).
    Import {
        /// The file.
        path: String,
    },
    /// Write every entry as a `known_hosts` file.
    Export {
        /// The file.
        path: String,
    },
}

/// Results from the known-hosts service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownHostsEvent {
    /// Every KnownHost item.
    Loaded(Vec<(ItemId, KnownHost)>),
    /// The verifier saved a host key (`auto`: by `accept-new`, without asking).
    Saved {
        /// `host` or `[host]:port`.
        host: String,
        /// Saved without asking.
        auto: bool,
    },
    /// An import finished.
    Imported {
        /// New entries.
        added: usize,
        /// Entries already known.
        skipped: usize,
        /// Lines that could not be read.
        warnings: usize,
    },
    /// An export finished.
    Exported {
        /// The file written.
        path: String,
        /// Entries written.
        count: usize,
    },
    /// Something failed (load, save, import, export).
    Failed(ErrorReport),
}

impl App {
    // ------------------------------------------------------------ host-key prompts

    /// A session asks about a host key: open its dialog (replacing an older one).
    pub(crate) fn on_host_key(&mut self, id: SessionId, v: Verification) {
        self.close_host_key_dialog(id);
        let label = self
            .panes
            .get(&id)
            .map(|p| p.label.clone())
            .unwrap_or_default();
        self.push_dialog(DialogKind::HostKey(HostKeyDialog::new(id, label, v)));
    }

    /// The session's state changed: a prompt that is no longer awaited closes.
    pub(crate) fn host_key_on_state(&mut self, id: SessionId, state: &SessionState) {
        if !matches!(state, SessionState::AwaitingHostKey(_)) {
            self.close_host_key_dialog(id);
        }
    }

    fn close_host_key_dialog(&mut self, id: SessionId) {
        let before = self.dialogs.len();
        self.dialogs
            .retain(|d| !matches!(&d.kind, DialogKind::HostKey(h) if h.session == id));
        if self.dialogs.len() != before {
            self.needs_redraw = true;
        }
    }

    // ------------------------------------------------------------ the view's data

    /// Reload the Known Hosts view (unlock, index updates). One load in flight.
    pub(crate) fn known_hosts_on_index(&mut self, effects: &mut Vec<Effect>) {
        if self.lock_state() == LockState::Locked && self.vault.active {
            return;
        }
        let view = &mut self.views.known_hosts;
        if view.loading {
            view.reload = true;
            return;
        }
        view.loading = true;
        effects.push(Effect::KnownHosts(KnownHostsEffect::Load));
    }

    /// Locking drops the decrypted entries.
    pub(crate) fn known_hosts_lock_transition(&mut self, was: LockState) {
        let now = self.lock_state();
        if now != was && now != LockState::Unlocked {
            self.views.known_hosts.clear();
        }
    }

    /// A result from the known-hosts service.
    pub(crate) fn on_known_hosts(&mut self, ev: KnownHostsEvent, effects: &mut Vec<Effect>) {
        match ev {
            KnownHostsEvent::Loaded(entries) => {
                self.views.known_hosts.loading = false;
                if self.lock_state() == LockState::Locked && self.vault.active {
                    return;
                }
                self.views.known_hosts.set_entries(entries);
                self.needs_redraw = true;
                if std::mem::take(&mut self.views.known_hosts.reload) {
                    self.known_hosts_on_index(effects);
                }
            }
            KnownHostsEvent::Saved { host, auto } => {
                let msg = if auto {
                    format!("Added host key for {host} (accept-new)")
                } else {
                    format!("Saved host key for {host}")
                };
                self.push_toast(ToastLevel::Success, msg, effects);
            }
            KnownHostsEvent::Imported {
                added,
                skipped,
                warnings,
            } => {
                let mut msg = format!("Imported {added} known hosts");
                if skipped > 0 {
                    msg.push_str(&format!(", {skipped} already known"));
                }
                if warnings > 0 {
                    msg.push_str(&format!(", {warnings} lines skipped (see the log)"));
                }
                self.push_toast(ToastLevel::Success, msg, effects);
            }
            KnownHostsEvent::Exported { path, count } => {
                self.push_toast(
                    ToastLevel::Success,
                    format!("Exported {count} known hosts to {path}"),
                    effects,
                );
            }
            KnownHostsEvent::Failed(report) => {
                self.views.known_hosts.loading = false;
                self.push_error(&report, effects);
            }
        }
    }

    // ------------------------------------------------------------ the view's requests

    /// Carry out the Known Hosts view's request (after a key).
    pub(crate) fn take_known_hosts_request(&mut self, effects: &mut Vec<Effect>) {
        let Some(request) = self.views.known_hosts.request.take() else {
            return;
        };
        match request {
            KnownHostsRequest::Delete(ids) => {
                let mut modal = confirm::delete(ids.len(), "known host");
                let names: Vec<String> = ids
                    .iter()
                    .take(5)
                    .filter_map(|id| self.views.known_hosts.get(*id))
                    .map(|r| r.display.clone())
                    .collect();
                if !names.is_empty() {
                    modal.body = format!("{}. {}", names.join(", "), modal.body);
                }
                let deletes = ids
                    .iter()
                    .map(|id| Effect::Vault(VaultEffect::Items(ItemEffect::Delete(*id))))
                    .collect();
                let route = format!("button:{}", confirm::YES);
                self.push_modal(ModalDialog::new(modal).on(&route, deletes), effects);
            }
            KnownHostsRequest::Edit(id) => {
                let Some(row) = self.views.known_hosts.get(id) else {
                    return;
                };
                if row.entry.read_only {
                    self.push_toast(
                        ToastLevel::Info,
                        "This entry was written by a newer sverb and is read-only".to_owned(),
                        effects,
                    );
                    return;
                }
                let dialog = KnownHostsDialog::edit(id, row.entry.clone());
                self.push_dialog(DialogKind::KnownHosts(dialog));
            }
            // The import pipeline (dry-run preview, target, duplicates).
            KnownHostsRequest::Import => {
                self.push_dialog(DialogKind::ImportWizard(Box::new(
                    crate::views::import_wizard::ImportWizard::import(
                        crate::views::import_wizard::WizardSource::KnownHosts,
                    ),
                )));
            }
            KnownHostsRequest::Export => {
                self.push_dialog(DialogKind::KnownHosts(KnownHostsDialog::file(
                    FilePrompt::Export,
                )));
            }
        }
    }
}

#[cfg(test)]
#[path = "known_hosts_tests.rs"]
mod tests;
