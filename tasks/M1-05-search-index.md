# M1-05 — In-memory decrypted index and fuzzy search (`nucleo`)

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-core/src/search/{mod.rs, index.rs, query.rs}`, `crates/sverb-tui/src/services/vault.rs` (index ownership) |
| **Spec refs** | §5.2 (item_index, nucleo, 10k items ≈ 50 ms), §8.5 (fuzzy filter, `#tag`), §9.1 ordering, §16 host resolution |
| **Depends on** | M1-04 |
| **Blocks** | M1-06, M1-07, M2-12 (palette), M0-07 host resolution |

---

## 1. Current state in the codebase
Nothing exists yet. M1-03 decided that the decrypted index lives in **Rust memory** (not a disk table), and the
TEMP table is optional.

## 2. Detailed description

### 2.1 Index model
`ItemIndex` holds one `IndexEntry` per non-deleted item in unlocked vaults:
`{ item_id, vault_id, kind, label, address (hosts), user, tags: Vec<String> (resolved tag names),
group_path: String ("prod / eu / web"), search_text: String }`. `search_text` is the space-joined
lowercase concatenation used by the matcher. Secrets are **never** included (passwords, private keys, snippet bodies
marked secret).
- Snippet bodies **are** searchable (they're not secrets), but only in the Snippets view and the palette, and are
  excluded from the Hosts filter.
- The index is owned by the vault service. The reducer gets **read-only snapshots** (`Arc<IndexSnapshot>`) on
  change, so views can render and filter without locking.

### 2.2 Lifecycle
- **Full build** on unlock: decrypt all items (parallel across `rayon` or `spawn_blocking` chunks),
  target ≈ 50 ms for 10k items (§5.2).
- **Incremental update** on every item write and on every remote apply (M4-07): replace or remove the entry,
  and recompute dependent entries when a tag or group is renamed (every host referencing it).
- **Drop and zeroize** on lock (`Zeroizing<String>` for labels, or overwrite the buffers on drop).

### 2.3 Query language
- Free text → fuzzy match with `nucleo-matcher` (`Matcher::fuzzy_match` with smart case,
  normalization on) over `search_text`.
- `#tag` tokens → exact (case-insensitive) tag filter. Several are combined with AND.
- `@vault` token → filter by vault name (prefix match), §8.5 "Filter by … vault".
- `kind:host` etc. → the kind filter (used by the palette).
- Quoted `"exact phrase"` → substring.
- Results are ranked by match score, then by the view's ordering. For hosts: pinned → frecency → alphabetical
  (§9.1). Match highlights (char indices) are returned for rendering.

### 2.4 API (pure, in core)
- `IndexSnapshot::query(&self, q: &Query, scope: Scope) -> Vec<Hit { item_id, score, highlights }>`.
- `Query::parse(&str) -> Query`.
- `resolve_host_arg(&IndexSnapshot, &str) -> Result<ItemId, ResolveError{NotFound, Ambiguous(Vec)}>`
  (used by the CLI and `sverb connect`, M0-07 §2.3).
- Ordering helpers take a `DeviceLocalLookup` (frecency, pinned).

### 2.5 Performance
- Querying 10k entries with a 5-char pattern takes < 5 ms (single thread).
- Rendering visible results only (virtualized list, M1-06).

## 3. Codebase changes
- **Create** `sverb-core::search` (depends on `nucleo-matcher`, not the full `nucleo` worker, because
  the matcher is enough and keeps it deterministic). Add `rayon` if parallel decrypt is needed.
- **Wire** the vault service to build and update snapshots and send `UiEvent::IndexUpdated(Arc<…>)`.
- Bench `benches/search.rs`.

## 4. Test cases to implement

**T-01 (unit) Fuzzy basic.** Hosts `prod-web-1`, `prod-db`, `staging-web`: query `pw1` → `prod-web-1`
first.

**T-02 (unit) Tag filter.** `#prod web` → only hosts tagged `prod` matching `web`. Tag matching is case-insensitive.

**T-03 (unit) Multiple tags AND.** `#prod #eu`.

**T-04 (unit) Vault filter** `@team`.

**T-05 (unit) Quoted phrase** `"db-primary"` → substring-only matching.

**T-06 (unit) Ordering.** With equal scores, pinned first, then higher frecency, then alphabetical.

**T-07 (unit) No secrets indexed.** A host with password `CANARY-PW` and a snippet with a secret variable
default `CANARY-VAR`: no query returns them, and `search_text` doesn't contain them.

**T-08 (unit) Incremental.** Rename tag `prod` → `production`. Every host entry referencing it updates, and
`#production` finds them.

**T-09 (unit) Deleted items** are removed from the index.

**T-10 (unit) resolve_host_arg** table (same as M0-07 T-07).

**T-11 (unit) Highlights** point to the correct char indices for Unicode labels (`bücher-host`).

**T-12 (bench)** Full build of 10k synthetic items (decrypt included) is < 150 ms on CI (spec target ≈ 50 ms on a
modern CPU; CI is slower). Query < 5 ms.

**T-13 (integration) Lock drops the index.** After lock, the snapshot `Arc` count from the service is zero, and
queries are unavailable (`LockState::Locked`).

## 5. Passing functional characteristics
- [ ] Decrypted labels, addresses, tags and group paths are indexed in memory only, built on unlock and updated
      incrementally.
- [ ] Fuzzy search supports `#tag`, `@vault`, `kind:` and quoted phrases, with match highlights.
- [ ] Host ordering is pinned → frecency → alphabetical.
- [ ] Secrets are never indexed.
- [ ] The index is dropped and zeroized on lock.
- [ ] Performance targets are met (build ≈ 50 ms per 10k on modern hardware, query < 5 ms).
