-- Drop the hardcoded 1 MB CHECK on shares.file_size.

CREATE TABLE shares_new (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    source_device_id TEXT NOT NULL,
    destination_device_id TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER,
    expires_at INTEGER,
    deduplication_hash TEXT,
    status TEXT NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'downloaded', 'expired', 'deleted')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (source_device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

INSERT INTO shares_new (
    id, user_id, source_device_id, destination_device_id, file_hash, file_name,
    file_size, content, created_at, expires_at, deduplication_hash, status
)
SELECT
    id, user_id, source_device_id, destination_device_id, file_hash, file_name,
    file_size, content, created_at, expires_at, deduplication_hash, status
FROM shares;

DROP TABLE shares;

ALTER TABLE shares_new RENAME TO shares;

-- Recreate the indexes that lived on the old table.
CREATE INDEX IF NOT EXISTS idx_shares_user_id ON shares(user_id);
CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_dedup
    ON shares(source_device_id, destination_device_id, deduplication_hash);
CREATE INDEX IF NOT EXISTS idx_shares_destination_device
    ON shares(destination_device_id);
CREATE INDEX IF NOT EXISTS idx_shares_destination_status
    ON shares(destination_device_id, status);
