package models

import (
	"time"

	"github.com/google/uuid"
)

type Item struct {
	ID            uuid.UUID `db:"id" json:"id"`
	VaultID       uuid.UUID `db:"vault_id" json:"vault_id"`
	DataEncrypted string    `db:"data_encrypted" json:"data_encrypted"`
	Version       int       `db:"version" json:"version"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
}
