//! The workspace service (SPEC §9.9). Workspaces are synced items
//! (`ItemKind::Workspace`) written through the vault's item service: every write is
//! HLC-stamped, sealed and marked dirty for sync (outbox rule).
//!
//! Every successful write is followed by a fresh `WorkspacesEvent::Loaded`.

use sverb_core::{
    error_report::ErrorReport,
    model::{ItemKind, Workspace, workspace::WorkspaceSpec},
};
use tokio::sync::mpsc;

use super::{
    EventSender,
    vault::{VaultService, items::ItemOps},
};
use crate::app::{
    UiEvent,
    workspaces::{WorkspaceEntry, WorkspacesEffect, WorkspacesEvent},
};

fn send(tx: &EventSender, ev: WorkspacesEvent) {
    let ev = UiEvent::Workspaces(ev);
    if let Err(mpsc::error::TrySendError::Full(ev)) = tx.try_send(ev) {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(ev).await;
        });
    }
}

fn failed(tx: &EventSender, msg: impl Into<String>) {
    send(tx, WorkspacesEvent::Failed(ErrorReport::msg(msg.into())));
}

/// Every live workspace (unreadable layouts are listed with their error).
///
/// # Errors
/// Storage failures (as a message).
pub async fn list(ops: &ItemOps) -> Result<Vec<WorkspaceEntry>, String> {
    let items = ops
        .list(&[ItemKind::Workspace])
        .await
        .map_err(|e| e.report().short)?;
    Ok(items
        .into_iter()
        .filter_map(|i| {
            let view = Workspace::try_from(&i.body).ok()?;
            let spec = if view.read_only {
                Err("saved by a newer sverb".to_owned())
            } else {
                WorkspaceSpec::from_item(&view).map_err(|e| e.to_string())
            };
            Some(WorkspaceEntry {
                id: i.id,
                vault: i.vault,
                name: view.name,
                spec,
            })
        })
        .collect())
}

async fn reload(ops: &ItemOps, tx: &EventSender) {
    match list(ops).await {
        Ok(entries) => send(tx, WorkspacesEvent::Loaded(entries)),
        Err(e) => failed(tx, e),
    }
}

/// Execute a workspace effect.
pub fn execute(vault: Option<&VaultService>, op: WorkspacesEffect, tx: &EventSender) {
    let Some(vault) = vault.cloned() else {
        failed(tx, "Workspaces need a vault");
        return;
    };
    let tx = tx.clone();
    tokio::spawn(async move {
        let Some(ops) = vault.item_ops() else {
            return failed(&tx, "The vault is locked");
        };
        let done = match op {
            WorkspacesEffect::Load => return reload(&ops, &tx).await,
            WorkspacesEffect::Save { id, vault, spec } => {
                let name = spec.name.clone();
                let item = spec.to_item();
                ops.save(
                    ItemKind::Workspace,
                    id,
                    vault,
                    move |body, clock, device| {
                        item.apply_to(body, clock, device);
                        Ok(())
                    },
                )
                .await
                .map(|_| format!("Workspace \"{name}\" saved"))
            }
            WorkspacesEffect::Rename { id, name } => {
                let msg = format!("Workspace renamed to \"{name}\"");
                ops.save(
                    ItemKind::Workspace,
                    Some(id),
                    None,
                    move |body, clock, device| {
                        let mut view = Workspace::try_from(&*body).map_err(|_| Vec::new())?;
                        view.name = name;
                        view.apply_to(body, clock, device);
                        Ok(())
                    },
                )
                .await
                .map(|_| msg)
            }
            WorkspacesEffect::Delete(id) => {
                ops.delete(id).await.map(|_| "Workspace deleted".to_owned())
            }
            WorkspacesEffect::Duplicate(id) => ops
                .duplicate(id)
                .await
                .map(|_| "Workspace duplicated".to_owned()),
        };
        match done {
            Ok(msg) => {
                send(&tx, WorkspacesEvent::Done(msg));
                reload(&ops, &tx).await;
            }
            Err(e) => send(&tx, WorkspacesEvent::Failed(e.report())),
        }
    });
}
