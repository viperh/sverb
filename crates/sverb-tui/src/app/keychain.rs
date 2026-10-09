//! The Keychain section in the reducer (SPEC §8.5, §9.3).
//!
//! - Carries out the Identities sub-tab's requests: add / edit (the identity form,
//!   edit loads the password first: `ItemEffect::LoadIdentity`), duplicate, delete
//!   (the dialog with the usage counts and "convert to inline"), and the "Used by"
//!   list, whose pick jumps to the host in the Hosts view.
//! - "+ new identity" in a host form's identity picker opens the identity form on top
//!   (in the host's vault); once saved, the new identity is put into that host form.
//! - The view gets its index and catalog with the Hosts view (`app/hosts.rs`) and
//!   drops them on lock.
//! - The Keys and Certificates sub-tabs and their dialogs ([`keys`]).

use sverb_core::model::ItemId;

// Keys and certificates (generate, import, export, passphrase, certificates).
pub mod keys;
#[cfg(test)]
mod keys_tests;
// Install key on host.
pub mod install;
#[cfg(test)]
mod install_tests;

use super::{App, Effect, EffectOutput, EffectResult, PendingKind, ToastLevel, VaultEffect};
use crate::app::hosts::ItemEffect;
use crate::views::{
    DialogId, DialogKind, Section,
    hosts::form::{CREDENTIALS_IDENTITY, CREDENTIALS_MODE, sync_identity},
    keychain::{
        KeychainRequest,
        identities::IdentityRequest,
        identity_form::{
            DeleteIdentityDialog, IdentityDialog, IdentityFormDialog, IdentityRecord, UsedByDialog,
            identity_form,
        },
    },
};
use crate::widgets::form::{FieldValue, FieldWidget, RefValue};

impl App {
    /// After a dispatch: the Keychain view's request, a "Used by" pick and a host
    /// form's "+ new identity".
    pub(crate) fn take_keychain_requests(&mut self, effects: &mut Vec<Effect>) {
        if let Some(req) = self.views.keychain.take_request() {
            match req {
                KeychainRequest::Identity(r) => self.on_identity_request(r, effects),
                r @ (KeychainRequest::Key(_) | KeychainRequest::Cert(_)) => {
                    self.on_keychain_key_request(&r, effects);
                }
            }
        }
        // A keychain dialog's answer.
        self.take_keychain_dialog_answer(effects);
        // Host-key decisions for install connections go to the run.
        self.reroute_install_answers(effects);
        let Some(top) = self.dialogs.last_mut() else {
            return;
        };
        let top_id = top.id;
        match &mut top.kind {
            DialogKind::Identity(IdentityDialog::UsedBy(d)) => {
                if let Some(host) = d.take_answer() {
                    self.dialogs.pop();
                    self.jump_to_host(host);
                }
            }
            DialogKind::HostForm(d) => {
                let create = d
                    .form
                    .field_mut("identity_id")
                    .and_then(|f| match &mut f.widget {
                        FieldWidget::Reference(r) => Some((r.take_create(), r.vault())),
                        _ => None,
                    });
                if let Some((true, vault)) = create {
                    let record = IdentityRecord {
                        vault,
                        ..IdentityRecord::default()
                    };
                    self.open_identity_form(record, Some(top_id));
                }
            }
            _ => {}
        }
    }

    fn on_identity_request(&mut self, req: IdentityRequest, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        let view = &self.views.keychain.identities;
        match req {
            IdentityRequest::Add => {
                let vault = view.catalog().and_then(|c| c.personal_vault);
                self.open_identity_form(
                    IdentityRecord {
                        vault,
                        ..IdentityRecord::default()
                    },
                    None,
                );
            }
            IdentityRequest::Edit(item) => {
                let id = self.ids.effect();
                self.pending.insert(id, PendingKind::EditIdentity);
                effects.push(Effect::Vault(VaultEffect::Items(
                    ItemEffect::LoadIdentity { id, item },
                )));
            }
            IdentityRequest::Duplicate(items) => {
                for item in items {
                    effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::Duplicate(
                        item,
                    ))));
                }
                self.views.keychain.identities.list.clear_marks();
            }
            IdentityRequest::Delete(item) => {
                let label = view.label_of(item).unwrap_or_else(|| item.short());
                let usage = view.usage(item);
                self.push_dialog(DialogKind::Identity(IdentityDialog::Delete(
                    DeleteIdentityDialog {
                        identity: item,
                        label,
                        usage,
                        convert: false,
                    },
                )));
            }
            IdentityRequest::UsedBy(item) => {
                let label = view.label_of(item).unwrap_or_else(|| item.short());
                let usage = view.usage(item);
                let dialog = UsedByDialog::new(label, &usage, view.catalog().map(AsRef::as_ref));
                self.push_dialog(DialogKind::Identity(IdentityDialog::UsedBy(dialog)));
            }
        }
    }

    /// Open the identity form (`for_host`: the host form that asked for it).
    pub(crate) fn open_identity_form(
        &mut self,
        record: IdentityRecord,
        for_host: Option<DialogId>,
    ) {
        let catalog = self.views.keychain.identities.catalog().cloned();
        let form = identity_form(&record, catalog.as_deref(), self.index().cloned());
        let vault = record
            .vault
            .or_else(|| catalog.as_ref().and_then(|c| c.personal_vault));
        self.push_dialog(DialogKind::Identity(IdentityDialog::Form(Box::new(
            IdentityFormDialog {
                item: record.id,
                vault,
                for_host,
                form,
            },
        ))));
    }

    /// Show `host` in the Hosts view.
    fn jump_to_host(&mut self, host: ItemId) {
        self.open_section(Section::Hosts);
        self.views.hosts.select(host);
        self.needs_redraw = true;
    }

    /// Results of identity saves and loads.
    pub(crate) fn keychain_on_effect_done(
        &mut self,
        kind: &PendingKind,
        result: EffectResult,
        effects: &mut Vec<Effect>,
    ) {
        match kind {
            PendingKind::SaveIdentity { dialog } => {
                let pos = self.dialogs.iter().position(|d| d.id == *dialog);
                match result {
                    Ok(out) => {
                        let mut for_host = None;
                        let mut label = String::new();
                        if let Some(pos) = pos {
                            if let DialogKind::Identity(IdentityDialog::Form(f)) =
                                &self.dialogs[pos].kind
                            {
                                for_host = f.for_host;
                                if let Some(FieldValue::Text(l)) = f.form.values().get("label") {
                                    label = l.trim().to_owned();
                                }
                            }
                            self.dialogs.remove(pos);
                        }
                        if let EffectOutput::Item(id) = out {
                            self.views.keychain.identities.select(id);
                            if let Some(host_form) = for_host {
                                self.put_identity_in_host_form(host_form, id, label);
                            }
                        }
                        self.push_toast(ToastLevel::Success, "Identity saved".to_owned(), effects);
                    }
                    Err(report) => {
                        if let Some(DialogKind::Identity(IdentityDialog::Form(f))) =
                            pos.map(|p| &mut self.dialogs[p].kind)
                        {
                            f.form.save_failed(report.short.clone());
                        }
                        self.push_error(&report, effects);
                    }
                }
                self.needs_redraw = true;
            }
            PendingKind::EditIdentity => match result {
                Ok(EffectOutput::Identity(record)) => self.open_identity_form(*record, None),
                Ok(_) => {}
                Err(report) => self.push_error(&report, effects),
            },
            _ => {}
        }
    }

    /// A new identity made from a host form's picker goes into that form.
    fn put_identity_in_host_form(&mut self, dialog: DialogId, id: ItemId, label: String) {
        let Some(DialogKind::HostForm(d)) = self
            .dialogs
            .iter_mut()
            .find(|x| x.id == dialog)
            .map(|x| &mut x.kind)
        else {
            return;
        };
        if let Some(FieldWidget::Reference(r)) =
            d.form.field_mut("identity_id").map(|f| &mut f.widget)
        {
            r.value = Some(RefValue { id, label });
        }
        if let Some(FieldWidget::Select(s)) =
            d.form.field_mut(CREDENTIALS_MODE).map(|f| &mut f.widget)
        {
            s.selected = s
                .options
                .iter()
                .position(|o| o.value == CREDENTIALS_IDENTITY);
        }
        sync_identity(&mut d.form);
        d.sync_inherited();
    }
}
