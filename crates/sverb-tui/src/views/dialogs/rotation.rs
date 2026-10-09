//! The key rotation dialogs (SPEC §13.2): the progress of a running
//! rotation, the prompt to restart an abandoned one, and the revoke
//! confirmation text (a revocation starts a rotation; the revoked member keeps
//! what they already synced).
//!
//! Plain builders: the reducer (`app/sync/vaults.rs`) opens them and routes the
//! answers to [`SyncEffect::Vaults`].

use super::ModalDialog;
use crate::app::Effect;
use crate::app::sync_ui::{SyncEffect, VaultOp};
use crate::widgets::dialog::{Button, Modal};

/// Title of the progress dialog.
pub const PROGRESS_TITLE: &str = "Rotating the vault key";

/// The progress line: `Uploading 120/480` (no counts while starting or
/// committing).
#[must_use]
pub fn progress_body(vault_name: &str, phase: &str, done: usize, total: usize) -> String {
    let counts = if total > 0 {
        format!(" {done}/{total}")
    } else {
        String::new()
    };
    format!(
        "\"{vault_name}\": {phase}{counts}…\nPushes to this vault are paused until the rotation \
         completes. You can close this dialog; the rotation continues."
    )
}

/// The progress dialog (a spinner; `Esc` hides it, the rotation goes on).
#[must_use]
pub fn progress(vault_name: &str) -> ModalDialog {
    ModalDialog::new(Modal::progress(
        PROGRESS_TITLE,
        &progress_body(vault_name, "Starting", 0, 0),
        true,
    ))
}

/// The confirmation of a revocation. Revoking someone else rotates the key.
#[must_use]
pub fn revoke_text(
    vault_name: &str,
    email: &str,
    me: bool,
) -> (&'static str, String, &'static str) {
    if me {
        (
            "Leave the vault?",
            format!("You lose access to \"{vault_name}\"."),
            "Leave",
        )
    } else {
        (
            "Revoke access?",
            format!(
                "{email} loses access to \"{vault_name}\" at once, and the vault key is rotated \
                 right away (pushes pause meanwhile). Data they already synced stays with them; \
                 the rotation protects only future changes."
            ),
            "Revoke",
        )
    }
}

/// "A key rotation was interrupted": restart it now (`r`) or later.
#[must_use]
pub fn abandoned_prompt(vault: &str, vault_name: &str) -> ModalDialog {
    let modal = Modal::confirm(
        "Key rotation interrupted",
        &format!(
            "A key rotation of \"{vault_name}\" stopped more than 15 minutes ago without \
             finishing. Pushes to the vault stay paused until it is restarted."
        ),
        vec![
            Button::new("restart", "Restart rotation", 'r'),
            Button::new("later", "Later", 'l').safe(),
        ],
        0,
        false,
    );
    ModalDialog::new(modal).on(
        "button:restart",
        vec![Effect::Sync(SyncEffect::Vaults(VaultOp::Rotate {
            vault: vault.to_owned(),
        }))],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn texts() {
        assert_eq!(
            progress_body("Ops", "Uploading", 3, 10).lines().next(),
            Some("\"Ops\": Uploading 3/10…")
        );
        assert!(progress_body("Ops", "Starting", 0, 0).starts_with("\"Ops\": Starting…"));
        let (_, body, label) = revoke_text("Ops", "carol@example.test", false);
        assert!(body.contains("rotated") && body.contains("already synced"));
        assert_eq!(label, "Revoke");
        assert_eq!(revoke_text("Ops", "", true).2, "Leave");
        let d = abandoned_prompt("v1", "Ops");
        assert_eq!(
            d.on_answer.get("button:restart"),
            Some(&vec![Effect::Sync(SyncEffect::Vaults(VaultOp::Rotate {
                vault: "v1".into()
            }))])
        );
        assert!(progress("Ops").modal.ticks());
    }
}
