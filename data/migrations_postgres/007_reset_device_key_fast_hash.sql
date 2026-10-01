-- Reset device key fast hashes written as SHA256(argon2_hash) instead of SHA256(raw_key).
-- Raw keys cannot be recovered, so the /api/token lazy migration repopulates correct
-- values on each device's next successful token request.

UPDATE devices SET device_key_fast_hash = NULL WHERE device_key_fast_hash IS NOT NULL;
