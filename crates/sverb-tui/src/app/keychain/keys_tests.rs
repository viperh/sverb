//! replies (passphrase tries → T-04, agent reference → T-05, duplicate "Use existing"
//! → T-06, overwrite, private export warning; `H` opens the install picker).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use super::keys::{ExportHow, ImportSource, KeychainEffect, KeychainEvent, KeychainOutcome};
use crate::app::hosts::ItemEffect;
use crate::app::{Config, Effect, InputEvent, UiEvent, VaultEffect, VaultEvent};
use crate::testing::AppHarness;
use crate::views::keychain::import_dialog::KeychainDialogKind;
use crate::views::keychain::{
    KeychainTab,
    identity_form::IdentityDialog,
    tests::{CERT, KEY, YUBI, add_sample_keys, id, sample},
};
use crate::views::{DialogKind, Section};

fn keychain() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    let (index, mut cat) = sample();
    add_sample_keys(&mut cat);
    let cat = Arc::new(cat);
    h.send(UiEvent::IndexUpdated(index));
    h.take_effects();
    let app = h.app_mut();
    app.views.keychain.set_catalog(Arc::clone(&cat));
    app.views.hosts.set_catalog(cat);
    app.open_section(Section::Keychain);
    assert_eq!(app.views.keychain.tab, KeychainTab::Keys);
    h
}

fn keychain_ops(effects: &[Effect]) -> Vec<KeychainEffect> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Vault(VaultEffect::Items(ItemEffect::Keychain(op))) => Some(op.clone()),
            _ => None,
        })
        .collect()
}

fn top(h: &AppHarness) -> Option<&KeychainDialogKind> {
    match &h.app().dialogs().last()?.kind {
        DialogKind::Identity(IdentityDialog::Keychain(d)) => Some(&d.kind),
        _ => None,
    }
}

fn reply(h: &mut AppHarness, token: u64, outcome: KeychainOutcome) {
    h.send(UiEvent::Vault(VaultEvent::Keychain(KeychainEvent {
        token,
        outcome,
    })));
}

fn toasted(h: &AppHarness, needle: &str) -> bool {
    h.app().toasts().iter().any(|t| t.message.contains(needle))
}

fn paste(h: &mut AppHarness, text: &str) {
    h.send(UiEvent::Input(InputEvent::Paste(text.to_owned())));
}

/// Start a file import of `path`; returns its token.
fn start_import(h: &mut AppHarness, path: &str) -> u64 {
    h.keys("I");
    assert!(matches!(top(h), Some(KeychainDialogKind::Path(_))));
    h.keys("ctrl-u");
    paste(h, path);
    h.keys("enter");
    let ops = keychain_ops(&h.take_effects());
    let [KeychainEffect::Import { token, spec }] = ops.as_slice() else {
        panic!("no import: {ops:?}");
    };
    assert_eq!(spec.source, ImportSource::File(path.to_owned()));
    assert!(spec.passphrase.is_none());
    *token
}

// T-04 (UI half): three wrong passphrases abort the import; nothing is saved.
#[test]
fn t04_three_wrong_passphrases_abort_the_import() {
    let mut h = keychain();
    let token = start_import(&mut h, "/keys/id_enc");
    reply(&mut h, token, KeychainOutcome::NeedsPassphrase);
    for attempt in 1..=3 {
        let Some(KeychainDialogKind::Passphrase(p)) = top(&h) else {
            panic!(
                "no passphrase prompt (attempt {attempt}): {:?}",
                h.app().dialogs()
            );
        };
        if attempt > 1 {
            assert!(
                p.modal.body.contains("Wrong passphrase"),
                "{}",
                p.modal.body
            );
        }
        paste(&mut h, "wrong");
        h.keys("enter");
        let ops = keychain_ops(&h.take_effects());
        let [KeychainEffect::Import { token: t, spec }] = ops.as_slice() else {
            panic!("no retry: {ops:?}");
        };
        assert_eq!(*t, token);
        assert_eq!(spec.passphrase.as_ref().map(|p| p.expose()), Some("wrong"));
        reply(&mut h, token, KeychainOutcome::WrongPassphrase);
    }
    assert!(top(&h).is_none(), "{:?}", h.app().dialogs());
    assert!(h.app().views.keychain.keys_op.is_none());
    assert!(toasted(
        &h,
        "Wrong passphrase: import aborted, nothing was saved"
    ));
    // Nothing more is sent.
    assert!(keychain_ops(h.effects()).is_empty());
}

// T-05 (UI half): a public key asks first, then creates the agent reference.
#[test]
fn t05_public_key_import_confirms_agent_reference() {
    let mut h = keychain();
    let token = start_import(&mut h, "/keys/yubi.pub");
    reply(
        &mut h,
        token,
        KeychainOutcome::ConfirmAgentRef {
            fingerprint: "SHA256:abc".into(),
        },
    );
    assert!(matches!(top(&h), Some(KeychainDialogKind::Confirm(_))));
    h.keys("c");
    let ops = keychain_ops(&h.take_effects());
    let [KeychainEffect::Import { spec, .. }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert!(spec.allow_agent_ref);
    reply(
        &mut h,
        token,
        KeychainOutcome::Imported {
            item: id(YUBI),
            label: "yubikey".into(),
            agent_ref: true,
        },
    );
    assert!(top(&h).is_none());
    assert!(toasted(&h, "agent key reference \"yubikey\" imported"));
}

// T-06 (UI half): a duplicate offers "Use existing", which selects that key.
#[test]
fn t06_duplicate_offers_use_existing() {
    let mut h = keychain();
    let token = start_import(&mut h, "/keys/id_ed25519");
    reply(
        &mut h,
        token,
        KeychainOutcome::Duplicate {
            existing: id(KEY),
            label: "laptop".into(),
        },
    );
    let screen = h.render(160, 48);
    assert!(screen.contains("se existing"), "{screen}");
    h.keys("u");
    assert!(top(&h).is_none());
    assert!(keychain_ops(h.effects()).is_empty());
    assert_eq!(
        h.app().views.keychain.keys.list.selected_key(),
        Some(id(KEY))
    );

    // "Import anyway" resends with the duplicate allowed.
    let token = start_import(&mut h, "/keys/id_ed25519");
    reply(
        &mut h,
        token,
        KeychainOutcome::Duplicate {
            existing: id(KEY),
            label: "laptop".into(),
        },
    );
    h.keys("i");
    let ops = keychain_ops(&h.take_effects());
    assert!(
        matches!(ops.as_slice(), [KeychainEffect::Import { spec, .. }] if spec.allow_duplicate)
    );
}

#[test]
fn generate_form_submits_and_shows_the_public_key() {
    let mut h = keychain();
    h.keys("a");
    assert!(matches!(top(&h), Some(KeychainDialogKind::Generate(_))));
    h.keys("ctrl-s");
    let ops = keychain_ops(&h.take_effects());
    let [KeychainEffect::Generate { token, spec }] = ops.as_slice() else {
        panic!("{ops:?}: {:?}", h.app().dialogs());
    };
    assert_eq!(spec.algorithm, sverb_core::model::KeyAlgorithm::Ed25519);
    // The default label: "<type> <date of the catalog>".
    assert_eq!(spec.label, "Ed25519 2035-12-29");
    assert!(spec.comment.ends_with("-sverb"));
    assert!(spec.passphrase.is_none() && spec.remember);
    assert!(matches!(top(&h), Some(KeychainDialogKind::Busy(_))));
    reply(
        &mut h,
        *token,
        KeychainOutcome::Generated {
            item: id(40),
            label: "Ed25519 2035-12-29".into(),
            public_key: "ssh-ed25519 AAAATEST me@host-sverb".into(),
            fingerprint: "SHA256:test".into(),
        },
    );
    let screen = h.render(160, 48);
    assert!(
        screen.contains("ssh-ed25519 AAAATEST me@host-sverb"),
        "{screen}"
    );
    assert!(screen.contains("SHA256:test"));
    assert_eq!(h.app().views.keychain.pending_select, Some(id(40)));
    h.keys("c");
    assert!(h.effects().iter().any(
        |e| matches!(e, Effect::CopyToClipboard(t) if t == "ssh-ed25519 AAAATEST me@host-sverb")
    ));
    h.keys("H");
    // Install on hosts opens the host picker.
    assert!(matches!(top(&h), Some(KeychainDialogKind::InstallPick(_))));
}

#[test]
fn generate_form_rejects_mismatched_passphrases() {
    let mut h = keychain();
    h.keys("a");
    // Type, Label, Comment, Passphrase.
    h.keys("tab tab tab");
    paste(&mut h, "one");
    h.keys("tab");
    paste(&mut h, "two");
    h.keys("ctrl-s");
    assert!(keychain_ops(h.effects()).is_empty());
    assert!(matches!(top(&h), Some(KeychainDialogKind::Generate(_))));
    assert!(h.render(160, 48).contains("do not match"));
}

#[test]
fn copy_public_key_and_toggle_flags() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(KEY)));
    h.keys("c");
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::CopyToClipboard(t) if t.starts_with("ssh-ed25519 ")))
    );
    h.keys("f o");
    let ops = keychain_ops(&h.take_effects());
    assert_eq!(
        ops,
        [
            KeychainEffect::SetFlag {
                item: id(KEY),
                flag: super::keys::KeyFlag::Forwardable,
                value: true
            },
            KeychainEffect::SetFlag {
                item: id(KEY),
                flag: super::keys::KeyFlag::ConfirmOnUse,
                value: true
            }
        ]
    );
}

#[test]
fn private_export_warns_then_asks_overwrite() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(KEY)));
    h.keys("X");
    let screen = h.render(160, 48);
    assert!(
        screen.contains("no") && screen.contains("longer protects it"),
        "{screen}"
    );
    // Unencrypted key: new passphrase / unencrypted / cancel.
    h.keys("u");
    assert!(matches!(top(&h), Some(KeychainDialogKind::Path(_))));
    h.keys("ctrl-u");
    paste(&mut h, "/tmp/out");
    h.keys("enter");
    let ops = keychain_ops(&h.take_effects());
    let [
        KeychainEffect::ExportPrivate {
            token,
            how,
            overwrite,
            ..
        },
    ] = ops.as_slice()
    else {
        panic!("{ops:?}");
    };
    assert_eq!(*how, ExportHow::Decrypted);
    assert!(!overwrite);
    let token = *token;
    reply(
        &mut h,
        token,
        KeychainOutcome::Exists {
            path: "/tmp/out".into(),
        },
    );
    h.keys("o");
    let ops = keychain_ops(&h.take_effects());
    assert!(matches!(
        ops.as_slice(),
        [KeychainEffect::ExportPrivate {
            overwrite: true,
            ..
        }]
    ));
    reply(
        &mut h,
        token,
        KeychainOutcome::Exported {
            path: "/tmp/out".into(),
            private: true,
        },
    );
    assert!(toasted(&h, "Private key written to /tmp/out"));
}

#[test]
fn private_export_with_a_new_passphrase() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(KEY)));
    h.keys("X n");
    h.keys("ctrl-u");
    paste(&mut h, "/tmp/out2");
    h.keys("enter");
    assert!(keychain_ops(h.effects()).is_empty());
    assert!(matches!(top(&h), Some(KeychainDialogKind::Passphrase(_))));
    paste(&mut h, "fresh");
    h.keys("enter");
    let ops = keychain_ops(&h.take_effects());
    let [
        KeychainEffect::ExportPrivate {
            how: ExportHow::Reencrypt(p),
            ..
        },
    ] = ops.as_slice()
    else {
        panic!("{ops:?}");
    };
    assert_eq!(p.expose(), "fresh");
}

#[test]
fn agent_reference_keys_have_no_private_export() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(YUBI)));
    h.keys("X");
    assert!(top(&h).is_none());
    assert!(toasted(&h, "no private key"));
}

#[test]
fn delete_key_and_certificate_confirm_first() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(KEY)));
    h.keys("d");
    let screen = h.render(160, 48);
    assert!(screen.contains("Delete key \"laptop\"?"), "{screen}");
    assert!(
        screen.contains("certificate(s) are deleted too"),
        "{screen}"
    );
    h.keys("d");
    assert_eq!(
        keychain_ops(&h.take_effects()),
        [KeychainEffect::DeleteKey(id(KEY))]
    );
    h.keys("]");
    h.keys("d");
    h.keys("d");
    assert_eq!(
        keychain_ops(&h.take_effects()),
        [KeychainEffect::DeleteCert(id(CERT))]
    );
}

#[test]
fn attach_certificate_and_path_completion() {
    let mut h = keychain();
    assert!(h.app_mut().views.keychain.keys.select(id(KEY)));
    h.keys("t");
    h.keys("ctrl-u");
    paste(&mut h, "/keys/id_c");
    h.keys("tab");
    let ops = keychain_ops(&h.take_effects());
    assert_eq!(
        ops,
        [KeychainEffect::CompletePath {
            prefix: "/keys/id_c".into()
        }]
    );
    reply(
        &mut h,
        0,
        KeychainOutcome::Completed {
            prefix: "/keys/id_c".into(),
            completion: "/keys/id_cert".into(),
            candidates: vec!["id_cert-cert.pub".into(), "id_cert.pub".into()],
        },
    );
    let Some(KeychainDialogKind::Path(p)) = top(&h) else {
        panic!();
    };
    assert_eq!(p.text(), "/keys/id_cert");
    assert!(h.render(160, 48).contains("id_cert-cert.pub"));
    paste(&mut h, "-cert.pub");
    h.keys("enter");
    let ops = keychain_ops(&h.take_effects());
    let [KeychainEffect::AttachCert { key, source, token }] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_eq!(*key, Some(id(KEY)));
    assert_eq!(*source, ImportSource::File("/keys/id_cert-cert.pub".into()));
    let token = *token;
    reply(
        &mut h,
        token,
        KeychainOutcome::Failed("the certificate is for a different key".into()),
    );
    assert!(toasted(&h, "for a different key"));
}

#[test]
fn stale_replies_are_ignored_and_lock_clears() {
    let mut h = keychain();
    let token = start_import(&mut h, "/keys/a");
    reply(&mut h, token + 100, KeychainOutcome::NeedsPassphrase);
    assert!(matches!(top(&h), Some(KeychainDialogKind::Busy(_))));
    h.app_mut().views.keychain.clear();
    assert!(h.app().views.keychain.keys.list.rows().is_empty());
    assert!(h.app().views.keychain.keys_op.is_none());
}
