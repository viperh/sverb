//! M5-02: shared-vault actions of the Hosts view in the reducer (SPEC §13.1,
//! §13.4, §4.13):
//! * **Move / copy to vault** (`M` / `C`): a choice of target vaults (not the
//!   items' own, not read-only ones), then `ItemEffect::Transfer`. When the hosts
//!   reference items that would stay outside a shared target (an identity, a
//!   key, a group), the service answers [`SharedVaultEvent::TransferBlocked`] and
//!   the user picks "Also copy them", "Also move them" or cancel.
//! * **"Use my own credentials…"** (`O` on a shared host): a choice of the
//!   personal identities (their user, password and key become this user's
//!   credentials for the host), or "Remove my override".

use sverb_core::model::vault_refs::RefPolicy;
use sverb_core::model::{ItemId, VaultId};

use super::ItemEffect;
use crate::app::{App, Effect, ToastLevel, VaultEffect};
use crate::views::dialogs::ModalDialog;
use crate::widgets::dialog::{Button, Modal};

/// Results of the shared-vault item effects (`VaultEvent::Shared`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedVaultEvent {
    /// A move / copy into a shared vault would leave references behind.
    TransferBlocked {
        /// The items.
        items: Vec<ItemId>,
        /// The target.
        target: VaultId,
        /// Copy (else move).
        copy: bool,
        /// The referenced items, as `identity "deploy"`.
        refs: Vec<String>,
    },
    /// Done (toast text).
    Done(String),
}

/// The vault selected at unlock for `general.default_vault`: `all` (every vault,
/// merged), `personal`, or a vault's name (case-insensitive; unknown names fall
/// back to all).
pub(crate) fn default_vault(
    catalog: &crate::views::hosts::catalog::HostCatalog,
    setting: &str,
) -> Option<VaultId> {
    let s = setting.trim();
    if s.eq_ignore_ascii_case("all") {
        return None;
    }
    if s.eq_ignore_ascii_case("personal") {
        // Only one vault: nothing to select.
        return catalog
            .personal_vault
            .filter(|_| catalog.vault_names.len() > 1);
    }
    catalog
        .vault_names
        .iter()
        .find(|(_, n)| n.eq_ignore_ascii_case(s))
        .map(|(v, _)| *v)
}

fn transfer(items: Vec<ItemId>, target: VaultId, copy: bool, refs: RefPolicy) -> Effect {
    Effect::Vault(VaultEffect::Items(ItemEffect::Transfer {
        items,
        target,
        copy,
        refs,
    }))
}

impl App {
    /// `M` / `C`: pick the target vault.
    pub(crate) fn pick_target_vault(
        &mut self,
        items: Vec<ItemId>,
        copy: bool,
        effects: &mut Vec<Effect>,
    ) {
        let Some(c) = self.views.hosts.catalog().cloned() else {
            return;
        };
        let sources: Vec<VaultId> = items
            .iter()
            .filter_map(|id| c.hosts.get(id).map(|h| h.vault))
            .collect();
        if !copy && sources.iter().any(|v| c.is_read_only_vault(*v)) {
            self.push_toast(
                ToastLevel::Error,
                "Read-only vault: copy the hosts instead of moving them".to_owned(),
                effects,
            );
            return;
        }
        let targets: Vec<(VaultId, String)> = c
            .vault_names
            .iter()
            .filter(|(v, _)| !c.is_read_only_vault(**v))
            .filter(|(v, _)| !(sources.len() == items.len() && sources.iter().all(|s| s == *v)))
            .map(|(v, n)| (*v, n.clone()))
            .collect();
        if targets.is_empty() {
            self.push_toast(
                ToastLevel::Info,
                "No other vault to move to: shared vaults come with an org (Settings → Vaults)"
                    .to_owned(),
                effects,
            );
            return;
        }
        let what = if items.len() == 1 {
            "the host".to_owned()
        } else {
            format!("{} hosts", items.len())
        };
        let (title, body) = if copy {
            ("Copy to vault", format!("Copy {what} to:"))
        } else {
            (
                "Move to vault",
                format!("Move {what} to (re-encrypted under the target vault's key):"),
            )
        };
        let modal = Modal::choice(
            title,
            &body,
            targets.iter().map(|(_, n)| n.clone()).collect(),
        );
        let mut dialog = ModalDialog::new(modal);
        for (i, (v, _)) in targets.into_iter().enumerate() {
            dialog = dialog.on(
                &format!("choice:{i}"),
                vec![transfer(items.clone(), v, copy, RefPolicy::Block)],
            );
        }
        self.push_modal(dialog, effects);
        self.views.hosts.clear_marks();
    }

    /// `O` on a shared host: pick a personal identity (or remove the override).
    pub(crate) fn pick_override(&mut self, host: ItemId, effects: &mut Vec<Effect>) {
        let Some(c) = self.views.hosts.catalog().cloned() else {
            return;
        };
        let Some(personal) = c.personal_vault else {
            return;
        };
        let label = c
            .hosts
            .get(&host)
            .map_or_else(|| "this host".to_owned(), |h| h.display_label().to_owned());
        let mut options: Vec<(Option<ItemId>, String)> = c
            .identities
            .iter()
            .filter(|(id, _)| c.identity_vaults.get(*id) == Some(&personal))
            .map(|(id, i)| {
                let user = if i.username.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", i.username)
                };
                (Some(*id), format!("Use identity “{}”{user}", i.label))
            })
            .collect();
        if c.overrides.contains_key(&host) {
            options.push((None, "Remove my override".to_owned()));
        }
        if options.is_empty() {
            self.push_toast(
                ToastLevel::Info,
                "Create an identity in your personal vault first (Keychain → Identities)"
                    .to_owned(),
                effects,
            );
            return;
        }
        let modal = Modal::choice(
            "Use my own credentials",
            &format!(
                "Your own credentials for “{label}”, kept in your personal vault and used on \
                 your devices only. Other members keep the shared ones."
            ),
            options.iter().map(|(_, l)| l.clone()).collect(),
        );
        let mut dialog = ModalDialog::new(modal);
        for (i, (identity, _)) in options.into_iter().enumerate() {
            dialog = dialog.on(
                &format!("choice:{i}"),
                vec![Effect::Vault(VaultEffect::Items(ItemEffect::SetOverride {
                    host,
                    identity,
                }))],
            );
        }
        self.push_modal(dialog, effects);
    }

    pub(crate) fn on_shared_vault_event(
        &mut self,
        ev: SharedVaultEvent,
        effects: &mut Vec<Effect>,
    ) {
        match ev {
            SharedVaultEvent::Done(msg) => {
                self.push_toast(ToastLevel::Success, msg, effects);
            }
            SharedVaultEvent::TransferBlocked {
                items,
                target,
                copy,
                refs,
            } => {
                let modal = Modal::confirm(
                    "Referenced items",
                    &format!(
                        "A host in a shared vault can only use items of that vault (§13.4). \
                         These are elsewhere: {}.",
                        refs.join(", ")
                    ),
                    vec![
                        Button::new("copy", "Also copy them", 'c'),
                        Button::new("move", "Also move them", 'm'),
                        Button::new("cancel", "Cancel", 'x').safe(),
                    ],
                    0,
                    true,
                );
                self.push_modal(
                    ModalDialog::new(modal)
                        .on(
                            "button:copy",
                            vec![transfer(items.clone(), target, copy, RefPolicy::Copy)],
                        )
                        .on(
                            "button:move",
                            vec![transfer(items, target, copy, RefPolicy::Move)],
                        ),
                    effects,
                );
            }
        }
        self.needs_redraw = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::hosts::catalog::HostCatalog;

    #[test]
    fn default_vault_setting() {
        let personal = VaultId::from_bytes([1; 16]);
        let ops = VaultId::from_bytes([2; 16]);
        let mut c = HostCatalog {
            personal_vault: Some(personal),
            ..HostCatalog::default()
        };
        c.vault_names.insert(personal, "Personal".into());
        // One vault: nothing to select.
        assert_eq!(default_vault(&c, "personal"), None);
        c.vault_names.insert(ops, "Ops".into());
        assert_eq!(default_vault(&c, "personal"), Some(personal));
        assert_eq!(default_vault(&c, "All"), None);
        assert_eq!(default_vault(&c, "ops"), Some(ops));
        assert_eq!(default_vault(&c, "nope"), None);
    }
}
