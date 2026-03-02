UPDATE users SET srp_salt = '' WHERE srp_salt IS NULL;
UPDATE users SET srp_verifier = '' WHERE srp_verifier IS NULL;
ALTER TABLE users ALTER COLUMN srp_salt SET NOT NULL;
ALTER TABLE users ALTER COLUMN srp_verifier SET NOT NULL;
