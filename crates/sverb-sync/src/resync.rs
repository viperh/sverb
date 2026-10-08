//! Full resync after `410 Gone` (§12.2): the cursor is below the server's GC
//! floor, so tombstones the device never saw may have been purged.
//!
//! 1. Pull everything from `since = 0` into memory.
//! 2. In one transaction: apply every server item as a normal page (merging
//!    into dirty local copies), delete local **clean** items the server no
//!    longer has, and queue local **dirty** items the server doesn't have as
//!    new items (`base_revision = 0`, same id: the server purged the
//!    tombstone, so a new item with that id is accepted), then set the
//!    cursor to the head.
//! 3. The following push uploads them.

use std::collections::HashSet;

use sverb_core::model::{ItemId, VaultId};
use sverb_store::RemoteItem as StoreItem;

use crate::engine::Ctx;
use crate::error::SyncError;
use crate::pull::{PageReport, incoming, wire_rev};

impl Ctx {
    /// See the module docs.
    pub(crate) async fn full_resync(&mut self, vault: VaultId) -> Result<(), SyncError> {
        tracing::info!(%vault, "cursor below the server's GC floor: full resync");
        let mut all = Vec::new();
        let mut since = 0u64;
        let head = loop {
            let limit = self.config.page_limit;
            let page = self
                .call(move |api, t| async move { api.pull(&t, vault.uuid(), since, limit).await })
                .await?;
            let last = page.items.last().map(|i| i.revision);
            all.extend(page.items);
            match last {
                Some(l) if page.more => since = l,
                _ => break page.head_revision,
            }
        };

        let keys = self.keys.clone();
        let hlc = self.hlc.clone();
        let (report, repushed) = self
            .store
            .write(move |w| {
                let k = keys.read();
                let mut h = hlc.lock();
                let server: HashSet<ItemId> = all.iter().map(|i| ItemId::from_uuid(i.id)).collect();
                let mut report = PageReport::default();
                let mut page = Vec::with_capacity(all.len());
                for it in &all {
                    if let Some(si) = incoming(w.as_read(), &k, &mut h, vault, it, &mut report)? {
                        page.push(si);
                    }
                }
                let mut repushed = 0usize;
                let mut purged = Vec::new();
                for local in w.as_read().list_items(vault)? {
                    if server.contains(&local.id) {
                        continue;
                    }
                    if local.dirty {
                        // Re-queue as a new item (base 0).
                        page.push(StoreItem {
                            id: local.id,
                            revision: 0,
                            key_version: local.key_version,
                            envelope: local.envelope,
                            deleted: local.deleted,
                            local_pending: true,
                        });
                        repushed += 1;
                    } else {
                        w.purge_item(local.id)?;
                        purged.push(local.id);
                    }
                }
                w.apply_remote(vault, &page, wire_rev(head))?;
                report.applied = page.iter().map(|p| p.id).chain(purged).collect();
                Ok((report, repushed))
            })
            .await?;
        tracing::info!(%vault, items = report.applied.len(), repushed, "full resync applied");
        self.after_page(vault, report);
        Ok(())
    }
}
