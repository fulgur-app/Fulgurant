-- Add optional deduplication hash to shares for UPSERT-based deduplication.
-- When deduplication_hash is NULL (default), no dedup occurs because
-- SQLite treats NULLs as distinct in UNIQUE indexes.
ALTER TABLE shares ADD COLUMN deduplication_hash TEXT;

-- UNIQUE index enables ON CONFLICT for same source/destination/hash combo
CREATE UNIQUE INDEX idx_shares_dedup ON shares(source_device_id, destination_device_id, deduplication_hash);

-- Drop the old single-column index since the new composite index covers source_device_id lookups
DROP INDEX IF EXISTS idx_shares_source_device;
