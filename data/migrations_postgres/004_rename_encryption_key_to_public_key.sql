-- Migration: Rename devices.encryption_key to public_key and drop users.encryption_key
--
-- See the matching SQLite migration for the full rationale. In short: the column
-- stores the device's age (X25519) public key, not an AES symmetric key, and the
-- users.encryption_key column is dead code. No data transformation required.

-- ============================================================================
-- USERS: rebuild trigger without the dead column, then drop the column
-- ============================================================================

DROP TRIGGER IF EXISTS trg_users_set_updated_at_after_update ON users;

CREATE TRIGGER trg_users_set_updated_at_after_update
    BEFORE UPDATE OF email, first_name, last_name, email_verified, password_hash,
                      role, force_password_update
    ON users
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_users_set_updated_at();

ALTER TABLE users DROP COLUMN encryption_key;

-- ============================================================================
-- DEVICES: rename the column, then rebuild the trigger to reference public_key
-- ============================================================================

DROP TRIGGER IF EXISTS trg_devices_set_updated_at_after_update ON devices;

ALTER TABLE devices RENAME COLUMN encryption_key TO public_key;

CREATE TRIGGER trg_devices_set_updated_at_after_update
    BEFORE UPDATE OF name, device_type, device_key, device_key_fast_hash, public_key
    ON devices
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_devices_set_updated_at();
