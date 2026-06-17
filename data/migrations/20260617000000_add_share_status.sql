-- Add a lifecycle status column to shares.
--
-- Shares are no longer hard-deleted on download, expiry, or manual deletion.
-- Instead their status is updated and their content cleared, keeping the row
-- as a historic/stat record. Possible values:
--   available  -> shared by a device, not yet downloaded
--   downloaded -> downloaded by the destination device
--   expired    -> expired before the destination device downloaded it
--   deleted    -> manually deleted by the user
ALTER TABLE shares
    ADD COLUMN status TEXT NOT NULL DEFAULT 'available'
    CHECK (status IN ('available', 'downloaded', 'expired', 'deleted'));

-- Index for the hot path: fetching available shares for a destination device
CREATE INDEX IF NOT EXISTS idx_shares_destination_status
    ON shares(destination_device_id, status);
