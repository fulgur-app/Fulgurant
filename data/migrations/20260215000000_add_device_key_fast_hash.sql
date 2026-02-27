-- Add SHA256 fast hash for O(1) device key lookup
-- This enables fast device identification before expensive Argon2 verification
-- Migration strategy: Nullable for backward compatibility, populated lazily

ALTER TABLE devices ADD COLUMN device_key_fast_hash TEXT;

-- Index for fast lookup (UNIQUE to detect collisions early)
CREATE UNIQUE INDEX idx_devices_key_fast_hash
ON devices(device_key_fast_hash)
WHERE device_key_fast_hash IS NOT NULL;
