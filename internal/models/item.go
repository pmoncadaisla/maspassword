package models

import (
	"time"

	"github.com/google/uuid"
)

type Item struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	VaultID       uuid.UUID  `db:"vault_id" json:"vault_id"`
	DataEncrypted string     `db:"data_encrypted" json:"data_encrypted"`
	Version       int        `db:"version" json:"version"`
	UpdatedBy     *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
}

// ItemHistory is an immutable snapshot of a prior version of an item. It stores
// only the opaque ciphertext (DataEncrypted) — the server never decrypts it.
// ChangedBy records the user who authored the archived version (may be nil).
type ItemHistory struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	ItemID        uuid.UUID  `db:"item_id" json:"item_id"`
	DataEncrypted string     `db:"data_encrypted" json:"data_encrypted"`
	Version       int        `db:"version" json:"version"`
	ChangedBy     *uuid.UUID `db:"changed_by" json:"changed_by,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
}
