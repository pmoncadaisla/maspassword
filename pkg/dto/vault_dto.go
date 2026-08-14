package dto

import "time"

type CreateVaultRequest struct {
	NameEncrypted string `json:"name_encrypted" binding:"required"`
}

type CreateTeamVaultRequest struct {
	NameEncrypted string          `json:"name_encrypted" binding:"required"`
	VaultKeys     []VaultKeyEntry `json:"vault_keys" binding:"required"`
}

type VaultKeyEntry struct {
	UserID            string `json:"user_id" binding:"required"`
	EncryptedVaultKey string `json:"encrypted_vault_key" binding:"required"`
}

type ShareVaultRequest struct {
	VaultKeys []VaultKeyEntry `json:"vault_keys" binding:"required"`
}

type VaultKeyResponse struct {
	EncryptedVaultKey string `json:"encrypted_vault_key"`
}

// VaultShareInfo describes a team a vault is shared with.
type VaultShareInfo struct {
	TeamID   string    `json:"team_id"`
	TeamName string    `json:"team_name"`
	SharedAt time.Time `json:"shared_at"`
}
