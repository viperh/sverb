//! M2-12: the command palette's recent picks, persisted in the store's `meta` table.
//!
//! `meta` is device-local (never synced, never an item), so the recency boost of one
//! device never leaks to another. The value is a JSON array of strings
//! ([`PaletteTarget::recent_key`](crate::views::palette::PaletteTarget::recent_key)),
//! most recent first, at most [`RECENTS_LEN`].

use sverb_store::Store;
use tracing::warn;

use super::EventSender;
use crate::app::UiEvent;
use crate::views::palette::{PaletteEffect, PaletteEvent, RECENTS_LEN, RECENTS_META_KEY};

/// Read the recent picks (missing or unreadable: none).
pub async fn load_recents(store: &Store) -> Vec<String> {
    match store.get_meta(RECENTS_META_KEY).await {
        Ok(Some(bytes)) => decode(&bytes),
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!(error = %e, "cannot read the palette recents");
            Vec::new()
        }
    }
}

/// Store the recent picks (truncated to [`RECENTS_LEN`]).
pub async fn save_recents(store: &Store, recents: &[String]) -> sverb_store::Result<()> {
    let list: Vec<&String> = recents.iter().take(RECENTS_LEN).collect();
    let bytes = serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec());
    store.set_meta(RECENTS_META_KEY, bytes).await
}

fn decode(bytes: &[u8]) -> Vec<String> {
    let mut list: Vec<String> = serde_json::from_slice(bytes).unwrap_or_default();
    list.truncate(RECENTS_LEN);
    list
}

/// Execute a palette effect on `store` (spawned; results come back as `UiEvent`s).
pub fn execute(store: Option<&Store>, op: PaletteEffect, tx: &EventSender) {
    let Some(store) = store.cloned() else {
        // No database (tests, `--no-store`): nothing is remembered.
        if matches!(op, PaletteEffect::LoadRecents) {
            let _ = tx.try_send(UiEvent::Palette(PaletteEvent::Recents(Vec::new())));
        }
        return;
    };
    let tx = tx.clone();
    match op {
        PaletteEffect::LoadRecents => {
            tokio::spawn(async move {
                let recents = load_recents(&store).await;
                let _ = tx
                    .send(UiEvent::Palette(PaletteEvent::Recents(recents)))
                    .await;
            });
        }
        PaletteEffect::SaveRecents(recents) => {
            tokio::spawn(async move {
                if let Err(e) = save_recents(&store, &recents).await {
                    warn!(error = %e, "cannot store the palette recents");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use super::*;

    fn temp_store(tag: &str) -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "sverb-m2-12-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open_at(dir.join("sverb.db"), Arc::new(sverb_store::SystemClock))
            .expect("open store");
        (store, dir)
    }

    // T-10: recents live in `meta` (device-local) and never in an item.
    #[tokio::test]
    async fn t10_recents_are_stored_in_meta_not_items() {
        let (store, dir) = temp_store("t10");
        assert!(load_recents(&store).await.is_empty());
        let picks: Vec<String> = (0..25).map(|i| format!("action:a{i}")).collect();
        save_recents(&store, &picks).await.unwrap();
        let loaded = load_recents(&store).await;
        assert_eq!(loaded.len(), RECENTS_LEN);
        assert_eq!(loaded[0], "action:a0");
        let raw = store.get_meta(RECENTS_META_KEY).await.unwrap().unwrap();
        assert!(
            String::from_utf8(raw)
                .unwrap()
                .starts_with("[\"action:a0\"")
        );
        let items: i64 = store
            .read(|r| {
                Ok(r.conn()
                    .query_row("SELECT count(*) FROM items", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(items, 0, "palette recents must never become an item");
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn garbage_meta_decodes_to_nothing() {
        assert!(decode(b"not json").is_empty());
        assert_eq!(decode(br#"["a","b"]"#), ["a", "b"]);
    }

    #[tokio::test]
    async fn without_a_store_loading_answers_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        execute(None, PaletteEffect::LoadRecents, &tx);
        assert_eq!(
            rx.recv().await,
            Some(UiEvent::Palette(PaletteEvent::Recents(Vec::new())))
        );
        execute(None, PaletteEffect::SaveRecents(vec!["x".into()]), &tx);
        assert!(rx.try_recv().is_err());
    }
}
