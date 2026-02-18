-- Add index on shares.destination_device_id to speed up device share lookups.
CREATE INDEX IF NOT EXISTS idx_shares_destination_device ON shares(destination_device_id);
