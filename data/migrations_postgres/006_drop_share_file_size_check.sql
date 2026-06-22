-- Drop the hardcoded 1 MB CHECK on shares.file_size.

ALTER TABLE shares DROP CONSTRAINT IF EXISTS shares_file_size_check;
