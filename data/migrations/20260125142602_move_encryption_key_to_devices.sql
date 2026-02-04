-- Migration: Add encryption_key to devices table
-- This allows each device to optionally have its own encryption key
-- Encryption keys are nullable and no migration of existing keys is performed
-- Note: The encryption_key column in users table is now deprecated but left in place for backwards compatibility

-- Step 1: Add encryption_key column to devices table (nullable)
ALTER TABLE devices ADD COLUMN encryption_key TEXT;

-- Step 2: Update the devices table trigger to include encryption_key
DROP TRIGGER IF EXISTS trg_devices_set_updated_at_after_update;

CREATE TRIGGER IF NOT EXISTS trg_devices_set_updated_at_after_update
AFTER UPDATE OF user_id, device_id, device_key, name, device_type, expires_at, encryption_key ON devices
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE devices
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.id;
END;
