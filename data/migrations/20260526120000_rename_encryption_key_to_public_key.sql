-- Migration: Rename devices.encryption_key to public_key and drop users.encryption_key
--
-- Context: the column historically stored an AES-256-GCM symmetric key, but the
-- live protocol (age / X25519) treats this column as the device's age public key
-- (format: "age1..."). The name "encryption_key" is misleading. The companion
-- column on the users table is dead: no handler reads it after the per-device
-- migration. This migration renames the device column to match reality and drops
-- the dead users column. No data transformation is required.

-- ============================================================================
-- USERS: rebuild trigger without the dead column, then drop the column
-- ============================================================================

DROP TRIGGER IF EXISTS trg_users_set_updated_at_after_update;

CREATE TRIGGER trg_users_set_updated_at_after_update
AFTER UPDATE OF email, first_name, last_name, email_verified, password_hash, role, force_password_update ON users
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE users SET updated_at = unixepoch('now') WHERE id = NEW.id;
END;

ALTER TABLE users DROP COLUMN encryption_key;

-- ============================================================================
-- DEVICES: rename the column, then rebuild the trigger to reference public_key
-- ============================================================================

DROP TRIGGER IF EXISTS trg_devices_set_updated_at_after_update;

ALTER TABLE devices RENAME COLUMN encryption_key TO public_key;

CREATE TRIGGER trg_devices_set_updated_at_after_update
AFTER UPDATE OF name, device_type, device_key, device_key_fast_hash, public_key ON devices
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE devices SET updated_at = unixepoch('now') WHERE device_id = NEW.device_id;
END;
