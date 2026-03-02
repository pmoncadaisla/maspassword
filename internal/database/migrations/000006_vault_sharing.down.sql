DROP TABLE IF EXISTS vault_keys;
DROP INDEX IF EXISTS idx_vaults_team_id;
ALTER TABLE vaults DROP COLUMN team_id;
