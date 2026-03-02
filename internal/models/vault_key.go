package models

import (
	"time"

	"github.com/google/uuid"
)

type VaultKey struct {
	ID                uuid.UUID `db:"id" json:"id"`
	VaultID           uuid.UUID `db:"vault_id" json:"vault_id"`
	UserID            uuid.UUID `db:"user_id" json:"user_id"`
	EncryptedVaultKey string    `db:"encrypted_vault_key" json:"encrypted_vault_key"`
	CreatedAt         time.Time `db:"created_at" json:"created_at"`
}
