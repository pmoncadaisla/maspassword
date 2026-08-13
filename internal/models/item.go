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

// ItemHistory is an immutable snapshot of a prior version of an item. It stores
// only the opaque ciphertext (DataEncrypted) — the server never decrypts it.
type ItemHistory struct {
	ID            uuid.UUID `db:"id" json:"id"`
	ItemID        uuid.UUID `db:"item_id" json:"item_id"`
	DataEncrypted string    `db:"data_encrypted" json:"data_encrypted"`
	Version       int       `db:"version" json:"version"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}
