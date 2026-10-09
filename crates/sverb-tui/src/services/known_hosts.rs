//! Known hosts in the vault.
//!
//! - [`VaultKnownHosts`] is the SSH verifier's [`KnownHostsStore`]: before each
//!   connection (and jump hop) it reloads the KnownHost items from the vault; saves
//!   ("accept & save", the confirmed replacement of a changed key, `accept-new`) go into
//!   its snapshot at once and are written in the background (stamped, encrypted, in the
//!   Personal vault), replacing the host's old entry of that key type. Each save is
//!   reported as `KnownHostsEvent::Saved` (the "Added host key for X" toast).
//! - [`execute`] runs the Known Hosts view's effects: load, save (edit), import from a
//!   OpenSSH text.

use std::sync::{Arc, PoisonError, RwLock};

use async_trait::async_trait;
use sverb_conn::ssh::{KnownHostsStore, KnownHostsVerifier, VerifyOptions};
use sverb_core::{
    config::Config,
    error_report::ErrorReport,
    known_hosts::{export, parse_known_hosts},
    model::{ItemId, ItemKind, KnownHost, UnixMillis},
};
use tracing::{debug, warn};

use super::{
    EventSender,
    vault::{VaultService, items::ItemOps},
};
use crate::app::{KnownHostsEffect, KnownHostsEvent, UiEvent};

/// The verifier's store over the vault (see the module docs).
#[derive(Debug)]
pub struct VaultKnownHosts {
    vault: Option<VaultService>,
    events: Option<EventSender>,
    /// The snapshot the handshake reads: `(item, entry)`; `None` for saves in flight.
    cache: RwLock<Vec<(Option<ItemId>, KnownHost)>>,
}

impl VaultKnownHosts {
    /// A store over `vault` (`None`: memory only) reporting on `events`.
    pub fn new(vault: Option<VaultService>, events: Option<EventSender>) -> Self {
        Self {
            vault,
            events,
            cache: RwLock::new(Vec::new()),
        }
    }
}

fn send(tx: Option<&EventSender>, ev: KnownHostsEvent) {
    if let Some(tx) = tx {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(UiEvent::KnownHosts(ev)).await;
        });
    }
}

/// Every live KnownHost item.
async fn load(ops: &ItemOps) -> Result<Vec<(ItemId, KnownHost)>, ErrorReport> {
    let items = ops
        .list(&[ItemKind::KnownHost])
        .await
        .map_err(|e| e.report())?;
    Ok(items
        .iter()
        .filter_map(|i| match KnownHost::try_from(&i.body) {
            Ok(k) => Some((i.id, k)),
            Err(e) => {
                debug!(item = %i.id.short(), error = %e, "known host skipped");
                None
            }
        })
        .collect())
}

/// Create (`item: None`) or update an entry, and update the index.
async fn save_entry(
    vault: &VaultService,
    ops: &ItemOps,
    item: Option<ItemId>,
    entry: KnownHost,
    tx: &EventSender,
) -> Result<ItemId, ErrorReport> {
    let written = ops
        .save(
            ItemKind::KnownHost,
            item,
            None,
            move |body, clock, device| {
                entry.apply_to(body, clock, device);
                Ok(())
            },
        )
        .await
        .map_err(|e| e.report())?;
    vault.index_upsert(written.id, written.vault, &written.body, tx);
    Ok(written.id)
}

#[async_trait]
impl KnownHostsStore for VaultKnownHosts {
    fn entries(&self) -> Vec<KnownHost> {
        self.cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    fn save(&self, host: &str, entry: KnownHost, replaces: Vec<KnownHost>, auto: bool) {
        let replaced: Vec<ItemId> = {
            let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
            let ids = cache
                .iter()
                .filter(|(_, e)| replaces.contains(e))
                .filter_map(|(id, _)| *id)
                .collect();
            cache.retain(|(_, e)| !replaces.contains(e));
            cache.push((None, entry.clone()));
            ids
        };
        let host = host.to_owned();
        let Some(vault) = self.vault.clone() else {
            send(self.events.as_ref(), KnownHostsEvent::Saved { host, auto });
            return;
        };
        let events = self.events.clone();
        tokio::spawn(async move {
            let Some(ops) = vault.item_ops() else {
                send(
                    events.as_ref(),
                    KnownHostsEvent::Failed(ErrorReport::msg(
                        "The host key was trusted for this connection but not saved: the vault is locked",
                    )),
                );
                return;
            };
            // Without a UI channel the index updates go nowhere.
            let (unused, _) = tokio::sync::mpsc::channel(1);
            let tx = events.clone().unwrap_or(unused);
            let result = save_entry(&vault, &ops, None, entry, &tx).await;
            for id in replaced {
                match ops.delete(id).await {
                    Ok(w) => vault.index_upsert(w.id, w.vault, &w.body, &tx),
                    Err(e) => warn!(error = %e, "the replaced host key was not deleted"),
                }
            }
            match result {
                Ok(_) => send(events.as_ref(), KnownHostsEvent::Saved { host, auto }),
                Err(report) => send(events.as_ref(), KnownHostsEvent::Failed(report)),
            }
        });
    }

    async fn refresh(&self) {
        let Some(ops) = self.vault.as_ref().and_then(VaultService::item_ops) else {
            return;
        };
        match load(&ops).await {
            Ok(entries) => {
                *self.cache.write().unwrap_or_else(PoisonError::into_inner) =
                    entries.into_iter().map(|(id, e)| (Some(id), e)).collect();
            }
            Err(report) => warn!(error = %report.short, "known hosts not reloaded"),
        }
    }
}

/// The SSH verifier for the TUI: known hosts in the vault, `ssh.host_key_policy` and
/// `ssh.hash_known_hosts` from `config`.
pub fn verifier(
    vault: Option<VaultService>,
    config: &Config,
    events: Option<EventSender>,
) -> KnownHostsVerifier {
    KnownHostsVerifier::new(
        Arc::new(VaultKnownHosts::new(vault, events)),
        VerifyOptions {
            policy: config.ssh.host_key_policy,
            hash_known_hosts: config.ssh.hash_known_hosts,
        },
    )
}

/// `~/…` → the home directory.
fn expand(path: &str) -> std::path::PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => std::path::PathBuf::from(home).join(rest),
        _ => std::path::PathBuf::from(path),
    }
}

/// Import the entries of `text` that are not known yet (same pattern, type, key and
/// marker). Returns `(added, skipped, warnings)`.
async fn import_text(
    vault: &VaultService,
    ops: &ItemOps,
    text: &str,
    tx: &EventSender,
) -> Result<(usize, usize, usize), ErrorReport> {
    let (entries, warnings) = parse_known_hosts(text);
    for w in &warnings {
        warn!(line = w.line, reason = %w.reason, "known_hosts line skipped");
    }
    let existing: Vec<KnownHost> = load(ops).await?.into_iter().map(|(_, e)| e).collect();
    let same = |a: &KnownHost, b: &KnownHost| {
        a.host_pattern == b.host_pattern
            && a.key_type == b.key_type
            && a.public_key == b.public_key
            && a.marker == b.marker
    };
    let now = UnixMillis::now();
    let (mut added, mut skipped) = (0, 0);
    let mut seen: Vec<KnownHost> = Vec::new();
    for mut entry in entries {
        if existing.iter().chain(&seen).any(|e| same(e, &entry)) {
            skipped += 1;
            continue;
        }
        entry.added_at = now;
        seen.push(entry.clone());
        save_entry(vault, ops, None, entry, tx).await?;
        added += 1;
    }
    Ok((added, skipped, warnings.len()))
}

/// Run a Known Hosts effect. Results come back as `UiEvent::KnownHosts`.
pub fn execute(vault: Option<&VaultService>, op: KnownHostsEffect, tx: &EventSender) {
    let tx = tx.clone();
    let Some(vault) = vault.cloned() else {
        let ev = match op {
            KnownHostsEffect::Load => KnownHostsEvent::Loaded(Vec::new()),
            _ => KnownHostsEvent::Failed(ErrorReport::msg("Known hosts need a vault")),
        };
        send(Some(&tx), ev);
        return;
    };
    tokio::spawn(async move {
        let Some(ops) = vault.item_ops() else {
            let ev = match op {
                // Locked: nothing to show.
                KnownHostsEffect::Load => KnownHostsEvent::Loaded(Vec::new()),
                _ => KnownHostsEvent::Failed(ErrorReport::msg("The vault is locked")),
            };
            let _ = tx.send(UiEvent::KnownHosts(ev)).await;
            return;
        };
        let ev = match op {
            KnownHostsEffect::Load => match load(&ops).await {
                Ok(entries) => KnownHostsEvent::Loaded(entries),
                Err(r) => KnownHostsEvent::Failed(r),
            },
            KnownHostsEffect::Save { item, entry } => {
                match save_entry(&vault, &ops, item, entry, &tx).await {
                    // The index update reloads the view.
                    Ok(_) => return,
                    Err(r) => KnownHostsEvent::Failed(ErrorReport {
                        short: format!("Known host not saved: {}", r.short),
                        ..r
                    }),
                }
            }
            KnownHostsEffect::Import { path } => {
                let file = expand(&path);
                match tokio::fs::read_to_string(&file).await {
                    Ok(text) => match import_text(&vault, &ops, &text, &tx).await {
                        Ok((added, skipped, warnings)) => KnownHostsEvent::Imported {
                            added,
                            skipped,
                            warnings,
                        },
                        Err(r) => KnownHostsEvent::Failed(r),
                    },
                    Err(e) => KnownHostsEvent::Failed(ErrorReport::msg(format!(
                        "Cannot read {}: {e}",
                        file.display()
                    ))),
                }
            }
            KnownHostsEffect::Export { path } => {
                let file = expand(&path);
                match load(&ops).await {
                    Ok(entries) => {
                        let text = export(entries.iter().map(|(_, e)| e));
                        match tokio::fs::write(&file, text).await {
                            Ok(()) => KnownHostsEvent::Exported {
                                path: file.display().to_string(),
                                count: entries.len(),
                            },
                            Err(e) => KnownHostsEvent::Failed(ErrorReport::msg(format!(
                                "Cannot write {}: {e}",
                                file.display()
                            ))),
                        }
                    }
                    Err(r) => KnownHostsEvent::Failed(r),
                }
            }
        };
        let _ = tx.send(UiEvent::KnownHosts(ev)).await;
    });
}
