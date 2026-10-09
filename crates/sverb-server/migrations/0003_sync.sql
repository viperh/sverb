-- M4-04: sync (SPEC §12.2). Indexes only; the tables are in 0001.

-- Tombstone GC scans for old tombstones (`admin gc`, background job).
CREATE INDEX items_tombstones_updated_at ON items (updated_at) WHERE deleted;
