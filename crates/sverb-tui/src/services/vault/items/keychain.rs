//! M2-03: keychain work for the TUI (`ItemEffect::Keychain`) and the CLI (`sverb keys`).
//!
//! [`ItemOps`] gains the keychain writes (create a key, set its flags or passphrase,
//! attach / delete certificates, delete a key with its certificates); [`run`] executes
//! a [`KeychainEffect`] and answers with a `VaultEvent::Keychain`. Key generation and
//! decryption (bcrypt-pbkdf, RSA primes) run in `spawn_blocking`. File paths are
//! `~`-expanded here, never in the reducer.

use sverb_core::{
    keychain::{
        self, KeychainError, cert,
        export::{self as kexport, PrivateExport},
        generate::{GenerateRequest, generate},
        import::{self as kimport, ImportOptions, ImportedKey, find_duplicate},
    },
    model::{Certificate, ItemId, ItemKind, Key, ValidationError},
    secret::SecretString,
};
use tracing::debug;

use super::{ItemError, ItemOps, Loaded, Written};
use crate::app::keychain::keys::{
    ExportHow, ImportSource, ImportSpec, KeyFlag, KeychainEffect, KeychainEvent, KeychainOutcome,
};

fn invalid(e: impl ToString) -> Vec<ValidationError> {
    vec![ValidationError::new("item", e.to_string())]
}

impl ItemOps {
    /// Every live key with its id.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn keys(&self) -> Result<Vec<(Loaded, Key)>, ItemError> {
        Ok(self
            .list(&[ItemKind::Key])
            .await?
            .into_iter()
            .filter_map(|l| Key::try_from(&l.body).ok().map(|k| (l, k)))
            .collect())
    }

    /// Every live certificate with its id.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn certificates(&self) -> Result<Vec<(Loaded, Certificate)>, ItemError> {
        Ok(self
            .list(&[ItemKind::Certificate])
            .await?
            .into_iter()
            .filter_map(|l| Certificate::try_from(&l.body).ok().map(|c| (l, c)))
            .collect())
    }

    /// The existing key with the same public key as `public_line`.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn duplicate_key(
        &self,
        public_line: &str,
    ) -> Result<Option<(ItemId, String)>, ItemError> {
        let keys = self.keys().await?;
        let id = find_duplicate(
            public_line,
            keys.iter().map(|(l, k)| (l.id, k.public_key.as_str())),
        );
        Ok(id.and_then(|id| {
            keys.iter()
                .find(|(l, _)| l.id == id)
                .map(|(_, k)| (id, k.label.clone()))
        }))
    }

    /// Store a new Key item.
    ///
    /// # Errors
    /// As [`ItemOps::save`].
    pub async fn create_key(&self, key: Key) -> Result<Written, ItemError> {
        self.save(ItemKind::Key, None, None, move |body, clock, device| {
            key.apply_to(body, clock, device);
            Ok(())
        })
        .await
    }

    /// Edit a Key item through its typed view.
    ///
    /// # Errors
    /// [`ItemError::Invalid`] when `edit` fails; as [`ItemOps::save`].
    pub async fn edit_key(
        &self,
        id: ItemId,
        edit: impl FnOnce(&mut Key) -> Result<(), KeychainError> + Send,
    ) -> Result<Written, ItemError> {
        self.save(ItemKind::Key, Some(id), None, move |body, clock, device| {
            let mut key = Key::try_from(&*body).map_err(invalid)?;
            edit(&mut key).map_err(invalid)?;
            key.apply_to(body, clock, device);
            Ok(())
        })
        .await
    }

    /// Load a key's typed view.
    ///
    /// # Errors
    /// [`ItemError::NotFound`], [`ItemError::WrongKind`], storage failures.
    pub async fn load_key(&self, id: ItemId) -> Result<Key, ItemError> {
        let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
        if loaded.body.kind != ItemKind::Key {
            return Err(ItemError::WrongKind(ItemKind::Key));
        }
        Key::try_from(&loaded.body).map_err(|e| ItemError::Storage(e.to_string()))
    }

    /// Store `text` as a certificate of `key` (validated against its public key) and
    /// list it in the key's `certificate_ids`. Returns the certificate's write and the
    /// key's.
    ///
    /// # Errors
    /// [`ItemError::Invalid`] (not a certificate, or for another key); storage failures.
    pub async fn attach_certificate(
        &self,
        key: ItemId,
        text: &str,
    ) -> Result<(Written, Written), ItemError> {
        let k = self.load_key(key).await?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_owned();
        cert::validate_for_key(&line, &k.public_key).map_err(|e| ItemError::Invalid(invalid(e)))?;
        let label = cert::suggested_label(&line);
        let c = Certificate {
            label,
            cert: line,
            key_id: Some(key),
            read_only: false,
        };
        let written = self
            .save(
                ItemKind::Certificate,
                None,
                None,
                move |body, clock, device| {
                    c.apply_to(body, clock, device);
                    Ok(())
                },
            )
            .await?;
        let id = written.id;
        let key_w = self
            .edit_key(key, move |k| {
                if !k.certificate_ids.contains(&id) {
                    k.certificate_ids.push(id);
                }
                Ok(())
            })
            .await?;
        Ok((written, key_w))
    }

    /// The key whose public key a certificate certifies.
    ///
    /// # Errors
    /// [`ItemError::Invalid`] when it isn't a certificate or no key matches.
    pub async fn key_for_certificate(&self, text: &str) -> Result<ItemId, ItemError> {
        let info = cert::parse_cert(text).map_err(|e| ItemError::Invalid(invalid(e)))?;
        let keys = self.keys().await?;
        keys.iter()
            .find(|(_, k)| {
                keychain::fingerprint(&k.public_key).as_deref() == Some(&info.key_fingerprint)
            })
            .map(|(l, _)| l.id)
            .ok_or_else(|| {
                ItemError::Invalid(invalid(
                    "no key in the keychain matches this certificate; import the key first",
                ))
            })
    }

    /// Delete a certificate and drop it from its key's `certificate_ids`.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn delete_certificate(&self, id: ItemId) -> Result<Vec<Written>, ItemError> {
        let mut out = Vec::new();
        for (l, k) in self.keys().await? {
            if k.certificate_ids.contains(&id) {
                out.push(
                    self.edit_key(l.id, move |k| {
                        k.certificate_ids.retain(|c| *c != id);
                        Ok(())
                    })
                    .await?,
                );
            }
        }
        out.push(self.delete(id).await?);
        Ok(out)
    }

    /// Delete a key and the certificates attached to it.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn delete_key(&self, id: ItemId) -> Result<Vec<Written>, ItemError> {
        let key = self.load_key(id).await?;
        let mut out = Vec::new();
        for (l, c) in self.certificates().await? {
            if c.key_id == Some(id) || key.certificate_ids.contains(&l.id) {
                out.push(self.delete(l.id).await?);
            }
        }
        out.push(self.delete(id).await?);
        Ok(out)
    }
}

fn outcome_of(err: &KeychainError) -> KeychainOutcome {
    match err {
        KeychainError::NeedsPassphrase => KeychainOutcome::NeedsPassphrase,
        KeychainError::WrongPassphrase => KeychainOutcome::WrongPassphrase,
        other => KeychainOutcome::Failed(other.to_string()),
    }
}

fn failed(err: &ItemError) -> KeychainOutcome {
    KeychainOutcome::Failed(err.to_string())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, KeychainError> + Send + 'static,
) -> Result<T, KeychainError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| KeychainError::Invalid(e.to_string()))?
}

fn read_source(source: &ImportSource) -> Result<SecretString, KeychainError> {
    match source {
        ImportSource::File(path) => kimport::read_key_file(path),
        ImportSource::Text(t) => Ok(SecretString::from(t.expose())),
    }
}

/// Run an import step: decode, confirm agent references and duplicates, save.
async fn import(ops: &ItemOps, spec: ImportSpec) -> (KeychainOutcome, Vec<Written>) {
    let text = match read_source(&spec.source) {
        Ok(t) => t,
        Err(e) => return (outcome_of(&e), Vec::new()),
    };
    let pass = spec.passphrase.as_ref().map(|p| p.expose().to_owned());
    // An encrypted key always gets its passphrase asked (and checked) here, even
    // OpenSSH ones the importer could store without it.
    let needs = kimport::needs_passphrase(text.expose());
    if needs && pass.is_none() {
        return (KeychainOutcome::NeedsPassphrase, Vec::new());
    }
    let imported: Result<ImportedKey, KeychainError> = blocking(move || {
        kimport::import_text(text.expose(), pass.as_deref(), ImportOptions::default())
    })
    .await;
    let imported = match imported {
        Ok(k) => k,
        Err(e) => return (outcome_of(&e), Vec::new()),
    };
    if imported.is_agent_ref() && !spec.allow_agent_ref {
        return (
            KeychainOutcome::ConfirmAgentRef {
                fingerprint: imported.fingerprint.clone(),
            },
            Vec::new(),
        );
    }
    if !spec.allow_duplicate {
        match ops.duplicate_key(&imported.public_key).await {
            Ok(Some((existing, label))) => {
                return (KeychainOutcome::Duplicate { existing, label }, Vec::new());
            }
            Ok(None) => {}
            Err(e) => return (failed(&e), Vec::new()),
        }
    }
    let fallback = match &spec.source {
        ImportSource::File(p) => kimport::file_stem(p),
        ImportSource::Text(_) => None,
    };
    let label = spec
        .label
        .clone()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| imported.suggested_label(fallback.as_deref()));
    let agent_ref = imported.is_agent_ref();
    match ops.create_key(imported.into_key(label.clone())).await {
        Ok(w) => (
            KeychainOutcome::Imported {
                item: w.id,
                label,
                agent_ref,
            },
            vec![w],
        ),
        Err(e) => (failed(&e), Vec::new()),
    }
}

async fn export_private(
    ops: &ItemOps,
    item: ItemId,
    path: String,
    overwrite: bool,
    how: ExportHow,
    passphrase: Option<String>,
) -> KeychainOutcome {
    let key = match ops.load_key(item).await {
        Ok(k) => k,
        Err(e) => return failed(&e),
    };
    let target = keychain::expand_home(path.trim());
    let shown = target.display().to_string();
    if !overwrite && target.exists() {
        return KeychainOutcome::Exists { path: shown };
    }
    let how = match how {
        ExportHow::Keep => PrivateExport::Keep,
        ExportHow::Decrypted => PrivateExport::Decrypted,
        ExportHow::Reencrypt(p) => PrivateExport::Reencrypt(SecretString::from(p.expose())),
    };
    let result = blocking(move || {
        let text = kexport::private_export(&key, &how, passphrase.as_deref())?;
        kexport::write_private_file(&target, &text, overwrite)
    })
    .await;
    match result {
        Ok(()) => KeychainOutcome::Exported {
            path: shown,
            private: true,
        },
        Err(KeychainError::Exists(p)) => KeychainOutcome::Exists { path: p },
        Err(e) => outcome_of(&e),
    }
}

/// Execute a keychain effect: the result goes out as `VaultEvent::Keychain`; every
/// write is handed to `index` (the search index and the catalog follow).
pub async fn run(ops: &ItemOps, op: KeychainEffect, index: impl Fn(&Written)) -> KeychainEvent {
    let mut token = 0;
    let outcome = match op {
        KeychainEffect::Generate { token: t, spec } => {
            token = t;
            let req = GenerateRequest {
                algorithm: spec.algorithm,
                comment: spec.comment.clone(),
                passphrase: spec
                    .passphrase
                    .as_ref()
                    .map(|p| SecretString::from(p.expose())),
            };
            match blocking(move || generate(&req)).await {
                Ok(g) => {
                    let public_key = g.public_key.clone();
                    let fingerprint = g.fingerprint.clone();
                    let pass = spec
                        .passphrase
                        .as_ref()
                        .map(|p| SecretString::from(p.expose()));
                    let key = g.into_key(spec.label.clone(), pass, spec.remember);
                    match ops.create_key(key).await {
                        Ok(w) => {
                            index(&w);
                            KeychainOutcome::Generated {
                                item: w.id,
                                label: spec.label,
                                public_key,
                                fingerprint,
                            }
                        }
                        Err(e) => failed(&e),
                    }
                }
                Err(e) => outcome_of(&e),
            }
        }
        KeychainEffect::Import { token: t, spec } => {
            token = t;
            let (outcome, written) = import(ops, spec).await;
            written.iter().for_each(&index);
            outcome
        }
        KeychainEffect::ExportPublic {
            token: t,
            item,
            path,
            overwrite,
        } => {
            token = t;
            match ops.load_key(item).await {
                Ok(key) => {
                    let target = keychain::expand_home(path.trim());
                    let shown = target.display().to_string();
                    match kexport::write_public_file(
                        &target,
                        &kexport::public_export(&key),
                        overwrite,
                    ) {
                        Ok(()) => KeychainOutcome::Exported {
                            path: shown,
                            private: false,
                        },
                        Err(KeychainError::Exists(p)) => KeychainOutcome::Exists { path: p },
                        Err(e) => outcome_of(&e),
                    }
                }
                Err(e) => failed(&e),
            }
        }
        KeychainEffect::ExportPrivate {
            token: t,
            item,
            path,
            overwrite,
            how,
            passphrase,
        } => {
            token = t;
            let pass = passphrase.map(|p| p.expose().to_owned());
            export_private(ops, item, path, overwrite, how, pass).await
        }
        KeychainEffect::ChangePassphrase {
            token: t,
            item,
            old,
            new,
            remember,
        } => {
            token = t;
            let old = old.map(|p| p.expose().to_owned());
            let new = new.map(|p| p.expose().to_owned());
            // Decrypt / encrypt off the runtime, then write the result.
            let changed = match ops.load_key(item).await {
                Ok(mut key) => {
                    blocking(move || {
                        kexport::change_passphrase(
                            &mut key,
                            old.as_deref(),
                            new.as_deref(),
                            remember,
                        )
                        .map(|()| (key.private_key, key.passphrase))
                    })
                    .await
                }
                Err(e) => Err(KeychainError::Invalid(e.to_string())),
            };
            match changed {
                Ok((private_key, passphrase)) => {
                    match ops
                        .edit_key(item, move |k| {
                            k.private_key = private_key;
                            k.passphrase = passphrase;
                            Ok(())
                        })
                        .await
                    {
                        Ok(w) => {
                            index(&w);
                            KeychainOutcome::PassphraseChanged
                        }
                        Err(e) => failed(&e),
                    }
                }
                Err(e) => outcome_of(&e),
            }
        }
        KeychainEffect::AttachCert {
            token: t,
            key,
            source,
        } => {
            token = t;
            match read_source(&source) {
                Ok(text) => {
                    let key = match key {
                        Some(k) => Ok(k),
                        None => ops.key_for_certificate(text.expose()).await,
                    };
                    match key {
                        Ok(key) => match ops.attach_certificate(key, text.expose()).await {
                            Ok((c, k)) => {
                                index(&c);
                                index(&k);
                                let key_label =
                                    Key::try_from(&k.body).map(|k| k.label).unwrap_or_default();
                                KeychainOutcome::CertAttached {
                                    item: c.id,
                                    key_label,
                                }
                            }
                            Err(e) => failed(&e),
                        },
                        Err(e) => failed(&e),
                    }
                }
                Err(e) => outcome_of(&e),
            }
        }
        KeychainEffect::SetFlag { item, flag, value } => {
            match ops
                .edit_key(item, move |k| {
                    match flag {
                        KeyFlag::Forwardable => k.agent_forwardable = value,
                        KeyFlag::ConfirmOnUse => k.confirm_on_use = value,
                    }
                    Ok(())
                })
                .await
            {
                Ok(w) => {
                    index(&w);
                    KeychainOutcome::Done
                }
                Err(e) => failed(&e),
            }
        }
        KeychainEffect::DeleteKey(item) => match ops.delete_key(item).await {
            Ok(ws) => {
                ws.iter().for_each(&index);
                KeychainOutcome::Done
            }
            Err(e) => failed(&e),
        },
        KeychainEffect::DeleteCert(item) => match ops.delete_certificate(item).await {
            Ok(ws) => {
                ws.iter().for_each(&index);
                KeychainOutcome::Done
            }
            Err(e) => failed(&e),
        },
        KeychainEffect::CompletePath { prefix } => {
            let p = prefix.clone();
            let (completion, candidates) =
                tokio::task::spawn_blocking(move || kimport::complete_path(&p))
                    .await
                    .unwrap_or_else(|_| (prefix.clone(), Vec::new()));
            KeychainOutcome::Completed {
                prefix,
                completion,
                candidates,
            }
        }
        // M2-04: install runs go to `items::install` before this (they report
        // progress over time).
        KeychainEffect::Install(_) => KeychainOutcome::Done,
    };
    debug!(token, "keychain effect done");
    KeychainEvent { token, outcome }
}
